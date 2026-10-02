"""klay (Kernel Relay): collect and analyze Windows VM kernel crashes on the host."""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import datetime as dt
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

__version__ = "0.1.0"
LOG = logging.getLogger("klay")
DONE_MARKER = "KLAY_ANALYSIS_DONE"


def default_data_root() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "Klay"
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "klay"


def default_config_path() -> Path:
    return default_data_root() / "config.json"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (FileNotFoundError, OSError, ValueError):
        return default


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".partial")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def parse_time(value: str | None):
    if not value:
        return None
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.replace(tzinfo=dt.timezone.utc) if result.tzinfo is None else result
    except ValueError:
        return None


def parse_analysis(text: str) -> dict:
    result = {}
    code = re.search(r"(?im)^\s*Bugcheck code\s+(?:0x)?([0-9a-f]+)\b", text)
    if not code:
        code = re.search(r"(?im)^\s*BUGCHECK_CODE:\s*(?:0x)?([0-9a-f]+)\b", text)
    if code:
        result["bugcheckCode"] = f"0x{int(code.group(1), 16):08X}"
    arguments = re.search(r"(?im)^\s*Arguments\s+([0-9a-f`]+)\s+([0-9a-f`]+)\s+([0-9a-f`]+)\s+([0-9a-f`]+)\b", text)
    if arguments:
        result["bugcheckParameters"] = [f"0x{int(value.replace('`', ''), 16):016x}" for value in arguments.groups()]
    name = re.search(r"(?m)^([A-Z][A-Z0-9_]+)\s+\(([0-9a-fA-F]+)\)\s*$", text)
    if name:
        result["bugcheckName"] = name.group(1)
    for field, key in (("MODULE_NAME", "module"), ("IMAGE_NAME", "image"), ("FAILURE_BUCKET_ID", "failureBucket"), ("PROCESS_NAME", "process")):
        match = re.search(r"(?m)^\s*" + field + r":\s*(.+)$", text)
        if match:
            result[key] = match.group(1).strip()
    return result


def find_debugger(config: dict) -> Path:
    supplied = config.get("debugger")
    if supplied:
        if Path(supplied).is_file():
            return Path(supplied)
        raise RuntimeError(f"Configured KD does not exist: {supplied}")
    sdk = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits/10/Debuggers/x64/kd.exe"
    if sdk.is_file():
        return sdk
    powershell = shutil.which("powershell.exe")
    if powershell:
        command = "Get-AppxPackage Microsoft.WinDbg | Select-Object -First 1 -ExpandProperty InstallLocation"
        found = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        install = found.stdout.strip()
        if install:
            candidate = Path(install) / "amd64/kd.exe"
            if candidate.is_file():
                return candidate
    raise RuntimeError("KD was not found. Install Microsoft WinDbg or set debugger in your configuration.")


def crash_summary(folder: Path) -> dict | None:
    metadata = read_json(folder / "crash.json")
    if not isinstance(metadata, dict) or metadata.get("crashId") != folder.name:
        return None
    ready = read_json(folder / "ready.json")
    analysis = read_json(folder / "analysis.json", {})
    return {
        "schema": 1,
        "crashId": folder.name,
        "reportTimeUtc": metadata.get("reportTimeUtc"),
        "bootTimeUtc": metadata.get("bootTimeUtc"),
        "bugcheckCode": analysis.get("bugcheckCode", metadata.get("bugcheckCode")),
        "bugcheckParameters": metadata.get("bugcheckParameters"),
        "bugcheckName": analysis.get("bugcheckName"),
        "source": metadata.get("source"),
        "crashDirectory": str(folder.resolve()),
        "metadataPath": str((folder / "crash.json").resolve()),
        "dumpPath": str((folder / "memory.dmp").resolve()) if ready else None,
        "dumpSha256": ready.get("sha256") if isinstance(ready, dict) else None,
        "analysisPath": str((folder / "analysis.txt").resolve()) if (folder / "analysis.txt").is_file() else None,
        "analysisState": analysis.get("state", "pending" if ready else "waiting_for_dump"),
        "error": analysis.get("error") or metadata.get("error"),
        "armedBuild": metadata.get("armedBuild"),
        "module": analysis.get("module"),
        "image": analysis.get("image"),
    }


def validate_ready(folder: Path) -> dict:
    ready = read_json(folder / "ready.json")
    if not isinstance(ready, dict) or ready.get("crashId") != folder.name or ready.get("file") != "memory.dmp":
        raise ValueError("Invalid ready manifest.")
    dump = folder / "memory.dmp"
    if dump.stat().st_size != ready.get("bytes") or sha256(dump) != ready.get("sha256"):
        raise ValueError("Dump size/SHA-256 mismatch. The incomplete/corrupt dump was not analyzed.")
    return ready


def analyze(folder: Path, config: dict, extra_commands: Path | None = None) -> dict:
    state = {"schema": 1, "state": "running", "startedAtUtc": utc_now(), "error": None}
    write_json(folder / "analysis.json", state)
    temporary_log = folder / "analysis.txt.partial"
    try:
        ready = validate_ready(folder)
        metadata = read_json(folder / "crash.json", {})
        debugger = find_debugger(config)
        cache = Path(config["runtime_root"]) / "symbols"
        cache.mkdir(parents=True, exist_ok=True)
        symbol_paths = [f"srv*{cache}*https://msdl.microsoft.com/download/symbols"]
        commands = [".sympath", ".time", "vertarget", ".bugcheck"]
        requested_build = metadata.get("armedBuild") or {}
        build = {}
        build_id = requested_build.get("buildId", "")
        if re.fullmatch(r"[a-zA-Z0-9_-]+", build_id):
            # The VM cannot redirect KD to arbitrary host paths through its manifest.
            local_build = Path(config["build_root"]) / build_id
            archived = read_json(local_build / "build.json", {})
            if archived.get("buildId") == build_id:
                for key, hash_key in (("driver", "driverSha256"), ("pdb", "pdbSha256")):
                    name = archived.get(key, "")
                    if Path(name).name != name or sha256(local_build / name) != archived.get(hash_key):
                        raise ValueError("Archived build integrity check failed.")
                build = {**archived, "directory": str(local_build.resolve())}
        image_path = None
        build_directory = build.get("directory")
        if build_directory and Path(build_directory).is_dir():
            image_path = build_directory
            symbol_paths.insert(0, build_directory)
            module = build.get("module")
            if module and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module):
                commands.extend([f".reload /f {module}.sys", f"lmvm {module}"])
        commands.extend(["!analyze -v", "kv", "r", "lm t n", "lm u", "!thread", "!irql", "!blackboxbsd", "!blackboxpnp", "!blackboxntfs", "!verifier"])
        if extra_commands:
            commands.append(extra_commands.read_text(encoding="utf-8-sig"))
        commands.extend([".echo " + DONE_MARKER, "q"])
        command_file = folder / "analysis.commands.txt"
        command_file.write_text("\n".join(commands) + "\n", encoding="utf-8")
        args = [str(debugger), "-noshell", "-sins", "-ses", "-lines", "-y", ";".join(symbol_paths), "-z", str(folder / "memory.dmp"), "-cf", str(command_file)]
        if image_path:
            args.extend(["-i", image_path])
        source = build.get("sourceDirectory")
        if source and Path(source).is_dir():
            args.extend(["-srcpath", source])
        state.update({"debugger": str(debugger), "dumpSha256": ready["sha256"], "commandFile": str(command_file)})
        write_json(folder / "analysis.json", state)
        with temporary_log.open("wb") as output:
            process = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT, timeout=config.get("analysis_timeout_seconds", 600), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        os.replace(temporary_log, folder / "analysis.txt")
        text = (folder / "analysis.txt").read_bytes().decode("utf-8", errors="replace")
        parsed = parse_analysis(text)
        if process.returncode != 0 or DONE_MARKER not in text or not parsed.get("bugcheckCode"):
            raise RuntimeError(f"KD did not finish a valid kernel-dump analysis (exit {process.returncode}). Read analysis.txt.")
        if metadata.get("bugcheckCode") and parsed["bugcheckCode"] != metadata["bugcheckCode"]:
            raise RuntimeError("Dump bugcheck code differs from the event. Do not attribute this dump to the test.")
        expected_parameters = metadata.get("bugcheckParameters") or []
        if expected_parameters and parsed.get("bugcheckParameters"):
            expected = [int(value, 16) for value in expected_parameters]
            actual = [int(value, 16) for value in parsed["bugcheckParameters"]]
            if expected != actual:
                raise RuntimeError("Dump bugcheck parameters differ from the event. Do not attribute this dump to the test.")
        state.update(parsed)
        state.update({"state": "complete", "finishedAtUtc": utc_now(), "exitCode": process.returncode})
    except Exception as error:
        if temporary_log.exists():
            os.replace(temporary_log, folder / "analysis.txt")
        state.update({"state": "failed", "finishedAtUtc": utc_now(), "error": str(error)})
        LOG.exception("Analysis failed for %s", folder.name)
    write_json(folder / "analysis.json", state)
    return state


def refresh(config: dict) -> list[Path]:
    shared = Path(config["shared_root"])
    runtime = Path(config["runtime_root"])
    guest = read_json(shared / "guest-status.json", {})
    heartbeat_time = parse_time(guest.get("timeUtc"))
    age = (dt.datetime.now(dt.timezone.utc) - heartbeat_time).total_seconds() if heartbeat_time else None
    summaries = []
    pending = []
    capture_root = shared / "crashes"
    if capture_root.is_dir():
        for folder in capture_root.iterdir():
            if not folder.is_dir():
                continue
            summary = crash_summary(folder)
            if not summary:
                continue
            summaries.append(summary)
            if summary["analysisState"] == "pending":
                pending.append(folder)
    latest = max(summaries, key=lambda item: item.get("bootTimeUtc") or "", default=None)
    write_json(runtime / "latest.json", latest or {"schema": 1, "crashId": None, "analysisState": "no_crash_observed"})
    installation = read_json(shared / "installation.json", {})
    installed = parse_time(installation.get("installedAtUtc"))
    boot = parse_time(guest.get("bootTimeUtc"))
    reboot_pending = bool(installation.get("rebootRequired") and (not boot or (installed and boot <= installed)))
    dump_errors = []
    for event in guest.get("recentSystemEvents", []):
        event_time = parse_time(event.get("timeUtc"))
        if event.get("provider") == "volmgr" and event.get("id") in (46, 161) and boot and event_time and event_time >= boot:
            dump_errors.append(event)
    write_json(runtime / "status.json", {
        "schema": 1, "hostTimeUtc": utc_now(), "hostPid": os.getpid(),
        "guestHeartbeatAgeSeconds": round(age, 1) if age is not None else None,
        "guestReachability": "online" if age is not None and 0 <= age <= config.get("guest_stale_seconds", 120) else "unknown",
        "guestHeartbeat": guest, "rebootRequired": reboot_pending,
        "currentBootDumpErrors": dump_errors,
        "latestCrashId": latest["crashId"] if latest else None,
        "note": "A stale heartbeat alone is not evidence of a bugcheck. Dump transfer can also delay the heartbeat.",
    })
    return sorted(pending, key=lambda folder: folder.name)


@contextlib.contextmanager
def monitor_lock(runtime: Path):
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime / "monitor.lock").open("a+b") as stream:
        stream.seek(0)
        if stream.read(1) == b"":
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise RuntimeError("A host monitor is already running.") from error
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def watch(config: dict, once: bool = False) -> None:
    runtime = Path(config["runtime_root"])
    with monitor_lock(runtime), concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        write_json(runtime / "monitor.json", {"pid": os.getpid(), "startedAtUtc": utc_now(), "script": str(Path(__file__).resolve())})
        futures: dict[str, concurrent.futures.Future] = {}
        try:
            # A terminated host may leave running.json behind; retry preserved dumps.
            for folder in (Path(config["shared_root"]) / "crashes").glob("*/analysis.json"):
                old = read_json(folder, {})
                if old.get("state") == "running":
                    write_json(folder, {"schema": 1, "state": "pending", "error": None})
            while True:
                try:
                    pending = refresh(config)
                    for folder in pending:
                        if folder.name not in futures:
                            futures[folder.name] = executor.submit(analyze, folder, config)
                    for key, future in list(futures.items()):
                        if future.done():
                            future.result()
                            del futures[key]
                    if once:
                        for future in futures.values():
                            future.result()
                        refresh(config)
                        return
                except Exception:
                    LOG.exception("Monitor poll failed; retrying")
                    if once:
                        raise
                time.sleep(config.get("poll_seconds", 5))
        finally:
            write_json(runtime / "monitor.json", {"pid": os.getpid(), "stoppedAtUtc": utc_now(), "script": str(Path(__file__).resolve())})


def arm(args, config: dict) -> dict:
    driver = args.driver.resolve(strict=True)
    pdb = args.pdb.resolve(strict=True)
    if driver.suffix.lower() != ".sys" or pdb.suffix.lower() != ".pdb":
        raise ValueError("Provide the .sys and matching .pdb produced by the same build.")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", driver.stem):
        raise ValueError("Driver module name must contain only letters, digits and underscores.")
    build_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    directory = Path(config["build_root"]) / build_id
    directory.mkdir(parents=True, exist_ok=False)
    for file in (driver, pdb):
        shutil.copy2(file, directory / file.name)
    source = args.source.resolve(strict=True) if args.source else None
    revision = None
    dirty = None
    if source:
        revision_process = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if revision_process.returncode == 0:
            revision = revision_process.stdout.strip()
            dirty = bool(subprocess.run(["git", "-C", str(source), "status", "--porcelain"], capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.strip())
    manifest = {
        "schema": 1, "buildId": build_id, "armedAtUtc": utc_now(), "directory": str(directory),
        "module": driver.stem, "driver": driver.name, "driverSha256": sha256(directory / driver.name),
        "pdb": pdb.name, "pdbSha256": sha256(directory / pdb.name),
        "sourceDirectory": str(source) if source else None, "sourceRevision": revision, "sourceDirty": dirty,
        "note": args.note, "provenance": "armed_for_test; confirm the loaded module and matching PDB in analysis.txt",
    }
    write_json(directory / "build.json", manifest)
    write_json(Path(config["shared_root"]) / "active-run.json", manifest)
    return manifest


def wait_for_crash(config: dict, timeout: float, after: str | None, require_analysis: bool) -> dict | None:
    deadline = time.monotonic() + timeout
    while True:
        latest = read_json(Path(config["runtime_root"]) / "latest.json", {})
        if latest.get("crashId") and latest["crashId"] != after:
            if not require_analysis or latest.get("analysisState") in ("complete", "failed"):
                return latest
        if time.monotonic() >= deadline:
            return None
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def load_config(path: Path) -> dict:
    config = read_json(path)
    if not isinstance(config, dict):
        raise ValueError(f"Config not found or invalid: {path}")
    for key in ("shared_root", "runtime_root", "build_root"):
        if not isinstance(config.get(key), str) or not Path(config[key]).is_absolute():
            raise ValueError(f"Config {key} must be an absolute path.")
    for key in ("poll_seconds", "guest_stale_seconds", "analysis_timeout_seconds"):
        value = config.get(key, {"poll_seconds": 5, "guest_stale_seconds": 120, "analysis_timeout_seconds": 600}[key])
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"Config {key} must be a finite positive number.")
    debugger = config.get("debugger")
    if debugger is not None and (not isinstance(debugger, str) or not Path(debugger).is_absolute()):
        raise ValueError("Config debugger must be null or an absolute path to kd.exe.")
    return config


def initialize(path: Path, shared_root: Path, data_root: Path | None = None, debugger: Path | None = None) -> dict:
    if path.exists():
        raise ValueError(f"Configuration already exists: {path}. Edit it explicitly instead of overwriting it.")
    if not shared_root.is_absolute() or (data_root is not None and not data_root.is_absolute()) or (debugger is not None and not debugger.is_absolute()):
        raise ValueError("Supply absolute paths for shared-root, data-root and debugger.")
    data = data_root or path.parent
    config = {
        "shared_root": str(shared_root), "runtime_root": str(data / "runtime"),
        "build_root": str(data / "builds"), "debugger": str(debugger) if debugger else None,
        "poll_seconds": 5, "guest_stale_seconds": 120, "analysis_timeout_seconds": 600,
    }
    write_json(path, config)
    return {"configPath": str(path), **config}


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="klay", description=__doc__)
    parser.add_argument("--version", action="version", version=f"klay {__version__}")
    parser.add_argument("--config", type=Path, default=default_config_path())
    commands = parser.add_subparsers(dest="command", required=True)
    init_parser = commands.add_parser("init", help="Create a local configuration without storing VM credentials.")
    init_parser.add_argument("--shared-root", type=Path, required=True)
    init_parser.add_argument("--data-root", type=Path)
    init_parser.add_argument("--debugger", type=Path)
    commands.add_parser("watch")
    commands.add_parser("once")
    commands.add_parser("status")
    arm_parser = commands.add_parser("arm")
    arm_parser.add_argument("--driver", type=Path, required=True)
    arm_parser.add_argument("--pdb", type=Path, required=True)
    arm_parser.add_argument("--source", type=Path)
    arm_parser.add_argument("--note", default="")
    analyze_parser = commands.add_parser("analyze")
    analyze_parser.add_argument("crash_id")
    analyze_parser.add_argument("--commands-file", type=Path)
    wait_parser = commands.add_parser("wait")
    wait_parser.add_argument("--timeout", type=float, default=600)
    wait_parser.add_argument("--after")
    wait_parser.add_argument("--require-analysis", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "init":
        print(json.dumps(initialize(args.config.resolve(), args.shared_root, args.data_root, args.debugger), indent=2))
        return 0
    if args.command == "wait" and (not math.isfinite(args.timeout) or args.timeout < 0):
        raise ValueError("Timeout must be a finite nonnegative number.")
    config = load_config(args.config.resolve())
    runtime = Path(config["runtime_root"])
    runtime.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(runtime / "host.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)
    if args.command in ("watch", "once"):
        watch(config, once=args.command == "once")
    elif args.command == "status":
        print(json.dumps({"status": read_json(runtime / "status.json", {}), "latest": read_json(runtime / "latest.json", {})}, indent=2, ensure_ascii=False))
    elif args.command == "arm":
        print(json.dumps(arm(args, config), indent=2, ensure_ascii=False))
    elif args.command == "analyze":
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", args.crash_id):
            raise ValueError("Invalid crash ID.")
        with monitor_lock(runtime):
            folder = Path(config["shared_root"]) / "crashes" / args.crash_id
            result = analyze(folder, config, args.commands_file)
            refresh(config)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["state"] == "complete" else 1
    elif args.command == "wait":
        result = wait_for_crash(config, args.timeout, args.after, args.require_analysis)
        if result is None:
            print(json.dumps({"state": "timeout", "after": args.after, "timeoutSeconds": args.timeout}))
            return 2
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1 if result.get("analysisState") == "failed" else 0
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except (RuntimeError, ValueError, OSError) as error:
        LOG.error("%s", error)
        if sys.stderr is not None:
            print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
