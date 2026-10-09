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
import struct
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


def write_json(path: Path, value, *, immutable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".partial")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Windows readers may briefly hold the destination without delete sharing.
        # Retry only publication of the already flushed file, never its contents.
        for attempt in range(5):
            try:
                if immutable:
                    if os.name == "nt":
                        os.rename(temporary, path)  # Windows rename refuses an existing destination.
                    else:
                        os.link(temporary, path)  # Atomic exclusive publication on POSIX.
                else:
                    os.replace(temporary, path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.1 * (attempt + 1))
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
    else:
        parameters = [re.search(rf"(?im)^\s*BUGCHECK_P{index}:\s*(?:0x)?([0-9a-f`]+)\b", text) for index in range(1, 5)]
        if all(parameters):
            result["bugcheckParameters"] = [f"0x{int(item.group(1).replace('`', ''), 16):016x}" for item in parameters]
    name = re.search(r"(?m)^([A-Z][A-Z0-9_]+)\s+\(([0-9a-fA-F]+)\)\s*$", text)
    if name:
        result["bugcheckName"] = name.group(1)
    fields = (("MODULE_NAME", "module"), ("IMAGE_NAME", "image"), ("FAILURE_BUCKET_ID", "failureBucket"), ("PROCESS_NAME", "process"),
              ("SYMBOL_NAME", "symbolName"), ("STACK_COMMAND", "stackCommand"), ("FAULTING_THREAD", "faultingThread"),
              ("TRAP_FRAME", "trapFrame"), ("CONTEXT", "contextRecord"), ("EXCEPTION_RECORD", "exceptionRecord"),
              ("EXCEPTION_CODE", "exceptionCode"), ("EXCEPTION_ADDRESS", "exceptionAddress"), ("READ_ADDRESS", "readAddress"),
              ("WRITE_ADDRESS", "writeAddress"), ("IMAGE_VERSION", "imageVersion"), ("OS_VERSION", "osVersion"),
              ("BUILDLAB_STR", "buildLab"), ("DUMP_FILE_ATTRIBUTES", "dumpAttributes"), ("FAILURE_ID_HASH", "failureIdHash"))
    for field, key in fields:
        match = re.search(r"(?m)^[ \t]*" + field + r":[ \t]*(\S.*)$", text)
        if match:
            result[key] = match.group(1).strip()
    details = []
    for match in re.finditer(r"(?im)^[ \t]*Arg([1-4]):[ \t]*(?:0x)?([0-9a-f`]+)\b,?[ \t]*(.*?)[ \t]*\r?$", text):
        details.append({"index": int(match.group(1)), "value": f"0x{int(match.group(2).replace('`', ''), 16):016x}", "description": match.group(3)})
    if details:
        result["bugcheckParameterDetails"] = details
    # Keep quoted evidence and line numbers. A debugger's module guess is not proof of causality.
    stack = []
    warnings = []
    registers = []
    symbol_summary = False
    for number, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*[0-9a-f`]{8,17}\s+[0-9a-f`]{8,17}\s+(?::|[0-9a-f`]{8,17}\s)", line, re.I):
            stack.append({"line": number, "text": line.rstrip()})
        if "symbol loading error summary" in line.lower():
            symbol_summary = True
            warnings.append({"line": number, "text": line.rstrip(), "kind": "symbol_loading"})
        elif symbol_summary and re.match(r"^\s*[A-Za-z0-9_.-]+\s{2,}\S", line) and not re.match(r"^\s*Module name\s+Error\s*$", line, re.I):
            warnings.append({"line": number, "text": line.rstrip(), "kind": "symbol_loading"})
        elif re.search(r"Page\s+\S+\s+too large to be in the dump file", line, re.I):
            warnings.append({"line": number, "text": line.rstrip(), "kind": "dump_memory"})
        elif re.search(r"(?:\*\*\*\s*(?:WARNING|ERROR)|unable to (?:load|verify|read)|symbols could not be loaded|wrong symbols|mismatched|not present in the dump|memory read error)", line, re.I):
            warnings.append({"line": number, "text": line.rstrip()})
        if symbol_summary and (not line.strip() or re.match(r"^\s*(?:[0-9a-f]+:\s*)?kd>", line, re.I)):
            symbol_summary = False
        if re.match(r"^\s*(?:[re](?:ax|bx|cx|dx|si|di|ip|sp|bp)|r(?:[8-9]|1[0-5])|[cdefgs]s|efl)=[0-9a-f]+\b", line, re.I):
            registers.append({"line": number, "text": line.rstrip()})
    if result:
        result["stackEvidence"] = stack[:256]
        result["stackEvidenceTruncated"] = len(stack) > 256
        result["debuggerWarnings"] = warnings[:128]
        result["debuggerWarningsTruncated"] = len(warnings) > 128
        result["registerEvidence"] = registers[:64]
        result["registerEvidenceTruncated"] = len(registers) > 64
        faulting = re.search(r"(?m)^\s*(?:FAULTING_IP|IP_IN_PAGED_CODE):\s*\r?\n([^\r\n]+)(?:\r?\n([^\r\n]+))?", text)
        if faulting:
            result["faultingInstruction"] = "\n".join(value for value in faulting.groups() if value)
        result["limitations"] = []
        if not stack:
            result["limitations"].append("No stack frames were extracted. Read the complete debugger output before attributing a cause.")
        if warnings:
            result["limitations"].append("Debugger warnings may limit symbols, memory access or stack interpretation; inspect their quoted evidence.")
        system = re.search(r"(?m)^\s*KLAY_SYSTEM_BEGIN\s*\r?\n([\s\S]*?)^\s*KLAY_SYSTEM_END\s*$", text)
        if system:
            result["systemEvidence"] = system.group(1).strip()[:32768]
            result["systemEvidenceTruncated"] = len(system.group(1).strip()) > 32768
    return result


def _read_binary(stream, offset: int, size: int, file_size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > file_size:
        raise ValueError("Invalid or truncated binary metadata.")
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("Truncated binary metadata.")
    return data


def driver_identity(path: Path) -> dict:
    """Read PE metadata and RSDS identity without loading or executing the driver."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        read = lambda offset, count: _read_binary(stream, offset, count, size)
        dos = read(0, 64)
        if dos[:2] != b"MZ":
            raise ValueError("Driver is not a PE image.")
        pe = struct.unpack_from("<I", dos, 60)[0]
        header = read(pe, 24)
        if header[:4] != b"PE\0\0":
            raise ValueError("Driver has no valid PE header.")
        machine, sections, timestamp = struct.unpack_from("<HHI", header, 4)
        optional_size = struct.unpack_from("<H", header, 20)[0]
        if sections > 96 or optional_size < 96 or optional_size > 4096:
            raise ValueError("Unsupported or invalid PE headers.")
        optional = read(pe + 24, optional_size)
        magic = struct.unpack_from("<H", optional)[0]
        if magic not in (0x10B, 0x20B):
            raise ValueError("Unsupported PE optional header.")
        directory_start = 112 if magic == 0x20B else 96
        result = {"machine": f"0x{machine:04X}", "timeDateStamp": f"0x{timestamp:08X}",
                  "sizeOfImage": struct.unpack_from("<I", optional, 56)[0], "codeView": None}
        if optional_size < directory_start or struct.unpack_from("<I", optional, directory_start - 4)[0] <= 6:
            return result
        if optional_size < directory_start + 56:
            raise ValueError("Truncated PE data directories.")
        debug_rva, debug_size = struct.unpack_from("<II", optional, directory_start + 48)
        if not debug_rva or not debug_size:
            return result
        if debug_size > 65536 or debug_size % 28:
            raise ValueError("Invalid PE debug directory size.")
        section_table = read(pe + 24 + optional_size, sections * 40)
        def file_offset(rva, count):
            for index in range(sections):
                virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", section_table, index * 40 + 8)
                if virtual_address <= rva and rva - virtual_address + count <= raw_size:
                    return raw_offset + rva - virtual_address
            if rva + count <= struct.unpack_from("<I", optional, 60)[0]:
                return rva
            raise ValueError("PE debug RVA is outside file-backed sections.")
        debug = read(file_offset(debug_rva, debug_size), debug_size)
        for offset in range(0, debug_size, 28):
            kind, count, rva, pointer = struct.unpack_from("<IIII", debug, offset + 12)
            if kind != 2:
                continue
            if count < 4 or count > 16384:
                raise ValueError("Invalid CodeView record size.")
            record = read(pointer or file_offset(rva, count), count)
            if record[:4] != b"RSDS":
                continue  # Older NB10 metadata does not provide a GUID+Age identity.
            if count < 24:
                raise ValueError("Truncated RSDS CodeView record.")
            identity = {"guid": str(uuid.UUID(bytes_le=record[4:20])), "age": struct.unpack_from("<I", record, 20)[0],
                        "pdbPath": record[24:].split(b"\0", 1)[0].decode("utf-8", errors="replace")}
            if result["codeView"] and result["codeView"] != identity:
                raise ValueError("Conflicting CodeView identities in the driver.")
            result["codeView"] = identity
        return result


def pdb_identity(path: Path) -> dict:
    """Read stream 1 of an MSF 7 PDB; bound allocations before following block lists."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        read = lambda offset, count: _read_binary(stream, offset, count, size)
        header = read(0, 56)
        if header[:32] != b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0":
            if header.startswith(b"Microsoft C/C++ program database 2.00"):
                return {"format": "MSF2", "guid": None, "age": None}
            raise ValueError("PDB is not a supported Microsoft program database.")
        block_size, _, blocks, directory_size, _, block_map = struct.unpack_from("<6I", header, 32)
        if block_size not in (512, 1024, 2048, 4096) or blocks * block_size > size or directory_size > 16 * 1024 * 1024:
            raise ValueError("Invalid or excessive PDB directory metadata.")
        directory_blocks = (directory_size + block_size - 1) // block_size
        if directory_blocks * 4 > block_size or not directory_blocks:
            raise ValueError("Unsupported PDB directory block map.")
        indexes = struct.unpack(f"<{directory_blocks}I", read(block_map * block_size, directory_blocks * 4))
        if any(index >= blocks for index in indexes):
            raise ValueError("PDB directory block is outside the file.")
        directory = b"".join(read(index * block_size, block_size) for index in indexes)[:directory_size]
        if len(directory) < 12:
            raise ValueError("PDB info stream is missing.")
        count = struct.unpack_from("<I", directory)[0]
        if count < 2 or count > 100000 or 4 + count * 4 > len(directory):
            raise ValueError("Invalid PDB stream directory.")
        sizes = struct.unpack_from(f"<{count}I", directory, 4)
        cursor = 4 + count * 4
        cursor += 0 if sizes[0] == 0xFFFFFFFF else ((sizes[0] + block_size - 1) // block_size) * 4
        if sizes[1] == 0xFFFFFFFF or sizes[1] < 28 or cursor + ((sizes[1] + block_size - 1) // block_size) * 4 > len(directory):
            raise ValueError("Invalid PDB info stream.")
        info_block = struct.unpack_from("<I", directory, cursor)[0]
        if info_block >= blocks:
            raise ValueError("PDB info block is outside the file.")
        info = read(info_block * block_size, 28)
        return {"format": "MSF7", "guid": str(uuid.UUID(bytes_le=info[12:28])), "age": struct.unpack_from("<I", info, 8)[0]}


def symbol_quality(text: str, build: dict, warnings: list) -> dict:
    module = build.get("module")
    block = re.search(r"(?m)^\s*KLAY_BUILD_MODULE_BEGIN\s*\r?\n([\s\S]*?)^\s*KLAY_BUILD_MODULE_END\s*$", text)
    evidence = block.group(1).strip() if block else ""
    loaded = "unverified"
    if "private pdb symbols" in evidence.lower():
        loaded = "private"
    elif "pdb symbols" in evidence.lower():
        loaded = "pdb"
    elif "export symbols" in evidence.lower():
        loaded = "export"
    elif re.search(r"(?:deferred|no symbols|symbols could not be loaded)", evidence, re.I):
        loaded = "missing"
    provided = bool(build.get("pdb"))
    symbol_warnings = [item for item in warnings if item.get("kind") == "symbol_loading" or re.search(r"symbol|pdb|verify timestamp", item["text"], re.I)]
    state = "unverified"
    if loaded == "private":
        state = "private_symbols_loaded"
    elif loaded == "pdb":
        state = "pdb_symbols_loaded"
    elif loaded == "export":
        state = "export_symbols_only"
    elif build and not provided:
        state = "no_private_symbols"
    if symbol_warnings:
        state = "degraded"
    identity = build.get("driverIdentity") or {}
    timestamp = re.search(r"(?im)^\s*Timestamp:.*\(([0-9a-f]{8})\)\s*$", evidence)
    image_size = re.search(r"(?im)^\s*ImageSize:\s*([0-9a-f]+)\s*$", evidence)
    metadata_match = "unverified"
    if timestamp and image_size and identity:
        metadata_match = "matched" if int(timestamp.group(1), 16) == int(identity["timeDateStamp"], 16) and int(image_size.group(1), 16) == identity["sizeOfImage"] else "mismatch"
    if metadata_match == "mismatch":
        state = "degraded"
    return {"state": state, "privateSymbolsProvided": provided, "pdbIdentityMatch": build.get("pdbMatch", "unverified"),
            "module": module, "loadedSymbols": loaded, "moduleMetadataMatch": metadata_match,
            "moduleEvidence": evidence[:32768], "moduleEvidenceTruncated": len(evidence) > 32768, "warnings": symbol_warnings}


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
        "analysisJsonPath": str((folder / "analysis.json").resolve()) if (folder / "analysis.json").is_file() else None,
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
        commands = [".sympath", ".time", "vertarget", ".echo KLAY_SYSTEM_BEGIN", "!sysinfo machineid", "!sysinfo smbios", "!cpuinfo", ".echo KLAY_SYSTEM_END", ".bugcheck"]
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
                    if key == "pdb" and name is None:
                        if archived.get(hash_key) is not None or not archived.get("noPrivateSymbols"):
                            raise ValueError("Invalid archived build PDB metadata.")
                        continue
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
                commands.extend([f".reload /f {module}.sys", ".echo KLAY_BUILD_MODULE_BEGIN", f"lmvm {module}", ".echo KLAY_BUILD_MODULE_END"])
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
        state["evidencePaths"] = {"analysisText": str((folder / "analysis.txt").resolve()), "crashMetadata": str((folder / "crash.json").resolve()),
                                  "dump": str((folder / "memory.dmp").resolve()), "readyManifest": str((folder / "ready.json").resolve())}
        write_json(folder / "analysis.json", state)
        started = time.monotonic()
        with temporary_log.open("wb") as output:
            process = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT, timeout=config.get("analysis_timeout_seconds", 600), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        state.update({"exitCode": process.returncode, "elapsedSeconds": round(time.monotonic() - started, 3)})
        os.replace(temporary_log, folder / "analysis.txt")
        text = (folder / "analysis.txt").read_bytes().decode("utf-8", errors="replace")
        parsed = parse_analysis(text)
        state.update(parsed)
        quality = symbol_quality(text, build, parsed.get("debuggerWarnings", []))
        state["symbolQuality"] = quality
        limitations = state.setdefault("limitations", [])
        limitations.append("Debugger module and bucket labels are investigative leads, not proof that a driver caused the crash.")
        if not build:
            limitations.append("No locally verified armed build was available; driver/PDB correspondence is unverified.")
        else:
            state["buildEvidence"] = {key: build.get(key) for key in ("buildId", "module", "driverSha256", "pdbSha256", "driverIdentity", "pdbIdentity", "pdbMatch", "noPrivateSymbols", "sourceRevision", "sourceDirty")}
            if not build.get("pdb"):
                limitations.append("No private PDB was provided for the armed driver; private functions, types and source lines may be unavailable.")
            elif build.get("pdbMatch") != "matched":
                limitations.append("The archived driver/PDB GUID+Age match was not verified.")
            if build.get("sourceDirectory"):
                limitations.append("Source files were not snapshotted; preserve the exact source revision used for this build.")
            if quality["moduleMetadataMatch"] == "mismatch":
                limitations.append("The loaded module timestamp/image size differs from the armed driver; do not attribute this dump to that build.")
            elif quality["moduleMetadataMatch"] == "matched":
                limitations.append("Loaded module timestamp/image size matches the archive; this is metadata evidence, not a hash of the loaded image.")
            if quality["loadedSymbols"] == "unverified":
                limitations.append("The armed module's loaded symbols were not confirmed in the debugger output.")
        if process.returncode != 0 or DONE_MARKER not in text or not parsed.get("bugcheckCode"):
            raise RuntimeError(f"KD did not finish a valid kernel-dump analysis (exit {process.returncode}). Read analysis.txt.")
        consistency = {"dumpIntegrity": "verified", "eventCode": "not_available", "eventParameters": "not_available"}
        state["eventConsistency"] = consistency
        state["eventBugcheckCode"] = metadata.get("bugcheckCode")
        state["eventBugcheckParameters"] = metadata.get("bugcheckParameters")
        if metadata.get("bugcheckCode"):
            consistency["eventCode"] = "matched" if parsed["bugcheckCode"] == metadata["bugcheckCode"] else "mismatch"
        if metadata.get("bugcheckCode") and parsed["bugcheckCode"] != metadata["bugcheckCode"]:
            raise RuntimeError("Dump bugcheck code differs from the event. Do not attribute this dump to the test.")
        expected_parameters = metadata.get("bugcheckParameters") or []
        if expected_parameters and not parsed.get("bugcheckParameters"):
            consistency["eventParameters"] = "not_reported_by_debugger"
            limitations.append("Debugger parameters were not extracted; event/dump parameter consistency is unverified.")
        if expected_parameters and parsed.get("bugcheckParameters"):
            expected = [int(value, 16) for value in expected_parameters]
            actual = [int(value, 16) for value in parsed["bugcheckParameters"]]
            consistency["eventParameters"] = "matched" if expected == actual else "mismatch"
            if expected != actual:
                raise RuntimeError("Dump bugcheck parameters differ from the event. Do not attribute this dump to the test.")
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


def watch(config: dict, once: bool = False) -> bool:
    runtime = Path(config["runtime_root"])
    with monitor_lock(runtime), concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        write_json(runtime / "monitor.json", {"pid": os.getpid(), "startedAtUtc": utc_now(), "script": str(Path(__file__).resolve())})
        futures: dict[str, concurrent.futures.Future] = {}
        analysis_failed = False
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
                            analysis_failed = future.result().get("state") == "failed" or analysis_failed
                            del futures[key]
                    if once:
                        for future in futures.values():
                            analysis_failed = future.result().get("state") == "failed" or analysis_failed
                        refresh(config)
                        return not analysis_failed
                except Exception:
                    LOG.exception("Monitor poll failed; retrying")
                    if once:
                        raise
                time.sleep(config.get("poll_seconds", 5))
        finally:
            write_json(runtime / "monitor.json", {"pid": os.getpid(), "stoppedAtUtc": utc_now(), "script": str(Path(__file__).resolve())})


def arm(args, config: dict) -> dict:
    driver = args.driver.resolve(strict=True)
    pdb = args.pdb.resolve(strict=True) if args.pdb else None
    if driver.suffix.lower() != ".sys" or (pdb and pdb.suffix.lower() != ".pdb"):
        raise ValueError("Provide a .sys and, optionally, its matching .pdb from the same build.")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", driver.stem):
        raise ValueError("Driver module name must contain only letters, digits and underscores.")
    image_identity = driver_identity(driver)
    symbols_identity = pdb_identity(pdb) if pdb else None
    code_view = image_identity["codeView"]
    match = "not_provided" if not pdb else "unverified"
    if code_view and symbols_identity and symbols_identity.get("guid"):
        if (code_view["guid"], code_view["age"]) != (symbols_identity["guid"], symbols_identity["age"]):
            raise ValueError("Driver and PDB GUID+Age do not match. Provide the PDB produced by this exact build.")
        match = "matched"
    build_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    directory = Path(config["build_root"]) / build_id
    directory.mkdir(parents=True, exist_ok=False)
    for file in (driver, pdb) if pdb else (driver,):
        shutil.copy2(file, directory / file.name)
    if driver_identity(directory / driver.name) != image_identity or (pdb and pdb_identity(directory / pdb.name) != symbols_identity):
        raise ValueError("Driver/PDB metadata changed while archiving. Rebuild or retry with stable files.")
    source = args.source.resolve(strict=True) if args.source else None
    revision = None
    dirty = None
    if source:
        revision_process = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if revision_process.returncode == 0:
            revision = revision_process.stdout.strip()
            dirty = bool(subprocess.run(["git", "-C", str(source), "status", "--porcelain"], capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.strip())
    armed_at = dt.datetime.now(dt.timezone.utc)
    selection_record = armed_at.strftime("%Y%m%dT%H%M%S%fZ_") + build_id + ".json"
    manifest = {
        "schema": 1, "buildId": build_id, "armedAtUtc": armed_at.isoformat(), "directory": str(directory),
        "selectionProtocol": "immutable_v1", "selectionRecord": selection_record,
        "module": driver.stem, "driver": driver.name, "driverSha256": sha256(directory / driver.name),
        "pdb": pdb.name if pdb else None, "pdbSha256": sha256(directory / pdb.name) if pdb else None,
        "noPrivateSymbols": pdb is None, "driverIdentity": image_identity, "pdbIdentity": symbols_identity, "pdbMatch": match,
        "sourceDirectory": str(source) if source else None, "sourceRevision": revision, "sourceDirty": dirty,
        "note": args.note, "provenance": "armed_for_test; confirm the loaded module and matching PDB in analysis.txt",
    }
    if len((json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")) > 65536:
        raise ValueError("Build selection exceeds the 64 KiB guest input limit. Shorten its note or paths.")
    write_json(directory / "build.json", manifest)
    write_json(Path(config["shared_root"]) / "build-selections" / selection_record, manifest, immutable=True)
    result = {**manifest, "legacyPointerUpdated": True}
    try:
        write_json(Path(config["shared_root"]) / "active-run.json", manifest)
    except PermissionError:
        warning = "The immutable build selection was published, but legacy active-run.json is locked. Update the guest exporter and confirm observedBuild before testing."
        result.update({"legacyPointerUpdated": False, "compatibilityWarning": warning})
        LOG.warning(warning)
    return result


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
    arm_parser.add_argument("--pdb", type=Path, help="Matching private PDB; omit when it is unavailable.")
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
        if not watch(config, once=args.command == "once"):
            return 1
    elif args.command == "status":
        print(json.dumps({"status": read_json(runtime / "status.json", {}), "latest": read_json(runtime / "latest.json", {})}, indent=2))
    elif args.command == "arm":
        result = arm(args, config)
        if result.get("compatibilityWarning") and sys.stderr is not None:
            print("Warning: " + result["compatibilityWarning"], file=sys.stderr)
        print(json.dumps(result, indent=2))
    elif args.command == "analyze":
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", args.crash_id):
            raise ValueError("Invalid crash ID.")
        with monitor_lock(runtime):
            folder = Path(config["shared_root"]) / "crashes" / args.crash_id
            result = analyze(folder, config, args.commands_file)
            refresh(config)
        print(json.dumps(result, indent=2))
        return 0 if result["state"] == "complete" else 1
    elif args.command == "wait":
        result = wait_for_crash(config, args.timeout, args.after, args.require_analysis)
        if result is None:
            print(json.dumps({"state": "timeout", "after": args.after, "timeoutSeconds": args.timeout}))
            return 2
        print(json.dumps(result, indent=2))
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
