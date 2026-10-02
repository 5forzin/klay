import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import klay


class KlayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="klay-test-")
        self.root = Path(self.temporary.name)
        self.config = {"shared_root": str(self.root / "share"), "runtime_root": str(self.root / "runtime"), "build_root": str(self.root / "builds"), "debugger": str(self.root / "kd.exe")}
        Path(self.config["shared_root"]).mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def crash(self, crash_id="desktop-20261002T080000Z", boot="2026-10-02T08:00:00Z", ready=False):
        folder = Path(self.config["shared_root"]) / "crashes" / crash_id
        folder.mkdir(parents=True)
        klay.write_json(folder / "crash.json", {"crashId": crash_id, "bootTimeUtc": boot, "reportTimeUtc": boot, "bugcheckCode": "0x000000D1", "bugcheckParameters": ["0x1", "0x2", "0x3", "0x4"]})
        if ready:
            (folder / "memory.dmp").write_bytes(b"test fixture, not a crash dump")
            klay.write_json(folder / "ready.json", {"crashId": crash_id, "file": "memory.dmp", "bytes": (folder / "memory.dmp").stat().st_size, "sha256": klay.sha256(folder / "memory.dmp")})
        return folder

    def test_parses_code_arguments_and_module_without_guessing_cause(self):
        result = klay.parse_analysis("Bugcheck code 000000d1\nArguments fffff802`00112233 00000000`00000002 00000000`00000000 fffff802`44556677\nDRIVER_IRQL_NOT_LESS_OR_EQUAL (d1)\nMODULE_NAME: testdriver\nIMAGE_NAME: testdriver.sys\n")
        self.assertEqual(result["bugcheckCode"], "0x000000D1")
        self.assertEqual(result["bugcheckParameters"][0], "0xfffff80200112233")
        self.assertEqual(result["bugcheckName"], "DRIVER_IRQL_NOT_LESS_OR_EQUAL")
        self.assertEqual(result["image"], "testdriver.sys")
        self.assertEqual(klay.parse_analysis("Loading Dump File failed"), {})

    def test_partial_dump_is_not_scheduled(self):
        folder = self.crash()
        (folder / "memory.dmp.partial").write_bytes(b"unfinished")
        self.assertEqual(klay.refresh(self.config), [])
        latest = klay.read_json(Path(self.config["runtime_root"]) / "latest.json")
        self.assertEqual(latest["analysisState"], "waiting_for_dump")
        self.assertIsNone(latest["dumpPath"])

    def test_ready_dump_has_integrity_verified(self):
        folder = self.crash(ready=True)
        self.assertEqual(klay.validate_ready(folder)["file"], "memory.dmp")
        (folder / "memory.dmp").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            klay.validate_ready(folder)

    def test_manifest_cannot_escape_crash_directory(self):
        folder = self.crash(ready=True)
        ready = klay.read_json(folder / "ready.json")
        ready["file"] = "../other.dmp"
        klay.write_json(folder / "ready.json", ready)
        with self.assertRaisesRegex(ValueError, "Invalid ready"):
            klay.validate_ready(folder)

    def test_stale_heartbeat_does_not_report_crash(self):
        klay.write_json(Path(self.config["shared_root"]) / "guest-status.json", {"timeUtc": "2020-01-01T00:00:00Z"})
        klay.refresh(self.config)
        runtime = Path(self.config["runtime_root"])
        self.assertEqual(klay.read_json(runtime / "status.json")["guestReachability"], "unknown")
        self.assertIsNone(klay.read_json(runtime / "latest.json")["crashId"])

    def test_latest_uses_newest_boot_and_keeps_completed_state(self):
        self.crash("newer", "2026-10-02T09:00:00Z", ready=True)
        older = self.crash("older", "2026-10-02T08:00:00Z", ready=True)
        klay.write_json(older / "analysis.json", {"state": "complete"})
        self.assertEqual([path.name for path in klay.refresh(self.config)], ["newer"])
        self.assertEqual(klay.read_json(Path(self.config["runtime_root"]) / "latest.json")["crashId"], "newer")

    def test_wait_ignores_prior_crash_and_times_out_explicitly(self):
        runtime = Path(self.config["runtime_root"])
        klay.write_json(runtime / "latest.json", {"crashId": "old", "analysisState": "complete"})
        self.assertIsNone(klay.wait_for_crash(self.config, timeout=0, after="old", require_analysis=True))
        klay.write_json(runtime / "latest.json", {"crashId": "new", "analysisState": "failed"})
        self.assertEqual(klay.wait_for_crash(self.config, timeout=0, after="old", require_analysis=True)["analysisState"], "failed")

    def test_build_preserves_exact_binaries_and_arming_reference(self):
        driver = self.root / "testdriver.sys"
        pdb = self.root / "testdriver.pdb"
        driver.write_bytes(b"driver from this exact build")
        pdb.write_bytes(b"PDB from this exact build")
        args = argparse.Namespace(driver=driver, pdb=pdb, source=None, note="isolated fixture")
        result = klay.arm(args, self.config)
        driver.write_bytes(b"next build")
        archived = Path(result["directory"]) / result["driver"]
        self.assertEqual(klay.sha256(archived), result["driverSha256"])
        self.assertEqual(klay.read_json(Path(self.config["shared_root"]) / "active-run.json")["buildId"], result["buildId"])

    def test_kd_failure_does_not_become_success(self):
        folder = self.crash(ready=True)
        def reject(args, stdout, **kwargs):
            stdout.write(b"Could not open dump file\n")
            return argparse.Namespace(returncode=1)
        with self.assertLogs(klay.LOG, level='ERROR'), patch.object(klay, "find_debugger", return_value=Path(self.config["debugger"])), patch.object(klay.subprocess, "run", side_effect=reject):
            result = klay.analyze(folder, self.config)
        self.assertEqual(result["state"], "failed")
        self.assertTrue((folder / "analysis.txt").is_file())

    def test_same_code_with_different_arguments_is_rejected(self):
        folder = self.crash(ready=True)
        def mismatch(args, stdout, **kwargs):
            stdout.write(("Bugcheck code 000000d1\nArguments 1 2 3 5\n" + klay.DONE_MARKER).encode())
            return argparse.Namespace(returncode=0)
        with self.assertLogs(klay.LOG, level='ERROR'), patch.object(klay, "find_debugger", return_value=Path(self.config["debugger"])), patch.object(klay.subprocess, "run", side_effect=mismatch):
            result = klay.analyze(folder, self.config)
        self.assertEqual(result["state"], "failed")
        self.assertIn("parameters differ", result["error"])

    @unittest.skipUnless(os.name == 'nt', 'Real KD check requires Windows')
    def test_installed_kd_rejects_invalid_dump_without_false_success(self):
        try:
            debugger = klay.find_debugger({})
        except RuntimeError:
            self.skipTest('KD is not installed')
        self.config['debugger'] = str(debugger)
        self.config['analysis_timeout_seconds'] = 30
        folder = self.crash(ready=True)
        with self.assertLogs(klay.LOG, level='ERROR'):
            result = klay.analyze(folder, self.config)
        self.assertEqual(result['state'], 'failed')
        self.assertIn('did not finish', result['error'])
        self.assertTrue((folder / 'analysis.txt').read_text(errors='replace').strip())

    def test_restart_pending_clears_only_after_new_boot(self):
        shared = Path(self.config['shared_root'])
        runtime = Path(self.config['runtime_root'])
        klay.write_json(shared / 'installation.json', {'rebootRequired': True, 'installedAtUtc': '2026-10-02T08:00:00Z'})
        klay.write_json(shared / 'guest-status.json', {'bootTimeUtc': '2026-10-02T07:00:00Z'})
        klay.refresh(self.config)
        self.assertTrue(klay.read_json(runtime / 'status.json')['rebootRequired'])
        klay.write_json(shared / 'guest-status.json', {'bootTimeUtc': '2026-10-02T09:00:00Z'})
        klay.refresh(self.config)
        self.assertFalse(klay.read_json(runtime / 'status.json')['rebootRequired'])

    def test_dump_initialization_errors_are_scoped_to_current_boot(self):
        shared = Path(self.config['shared_root'])
        klay.write_json(shared / 'guest-status.json', {
            'bootTimeUtc': '2026-10-02T09:00:00Z',
            'recentSystemEvents': [
                {'provider': 'volmgr', 'id': 46, 'timeUtc': '2026-10-02T08:00:00Z'},
                {'provider': 'volmgr', 'id': 161, 'timeUtc': '2026-10-02T09:01:00Z'},
                {'provider': 'Microsoft-Windows-Kernel-Power', 'id': 41, 'timeUtc': '2026-10-02T09:00:00Z'},
            ],
        })
        klay.refresh(self.config)
        result = klay.read_json(Path(self.config['runtime_root']) / 'status.json')
        self.assertEqual([event['id'] for event in result['currentBootDumpErrors']], [161])


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="klay-config-test-")
        self.root = Path(self.temporary.name)
        self.path = self.root / "local/config.json"

    def tearDown(self):
        self.temporary.cleanup()

    def cli(self, *arguments):
        return subprocess.run([sys.executable, str(Path(klay.__file__).resolve()), "--config", str(self.path), *arguments], capture_output=True, text=True, timeout=15)

    def test_fresh_configuration_supports_once_status_and_timeout_without_a_vm(self):
        share = self.root / "share"
        share.mkdir()
        result = self.cli("init", "--shared-root", str(share))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["configPath"], str(self.path))
        config = klay.load_config(self.path)
        self.assertEqual(self.cli("once").returncode, 0)
        status = self.cli("status")
        self.assertEqual(status.returncode, 0, status.stderr)
        report = json.loads(status.stdout)
        self.assertEqual(report["latest"]["analysisState"], "no_crash_observed")
        self.assertEqual(report["status"]["guestReachability"], "unknown")
        self.assertTrue((Path(config["runtime_root"]) / "monitor.json").is_file())
        waiting = self.cli("wait", "--timeout", "0", "--require-analysis")
        self.assertEqual(waiting.returncode, 2, waiting.stderr)
        self.assertEqual(json.loads(waiting.stdout)["state"], "timeout")

    def test_init_preserves_an_existing_configuration(self):
        klay.write_json(self.path, {"operatorData": "preserve this"})
        original = self.path.read_bytes()
        result = self.cli("init", "--shared-root", str(self.root / "share"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(self.path.read_bytes(), original)

    def test_invalid_paths_and_poll_limits_fail_before_monitoring(self):
        with self.assertRaisesRegex(ValueError, "absolute paths"):
            klay.initialize(self.path, Path("relative"))
        self.assertFalse(self.path.exists())
        config = {"shared_root": str(self.root / "share"), "runtime_root": str(self.root / "runtime"), "build_root": str(self.root / "builds")}
        for key, value in (("shared_root", "relative"), ("poll_seconds", 0), ("guest_stale_seconds", -1), ("analysis_timeout_seconds", float("inf")), ("debugger", "kd.exe")):
            with self.subTest(key=key):
                klay.write_json(self.path, {**config, key: value})
                with self.assertRaises(ValueError):
                    klay.load_config(self.path)

    def test_explicit_missing_debugger_does_not_silently_use_another_installation(self):
        with self.assertRaisesRegex(RuntimeError, "Configured KD does not exist"):
            klay.find_debugger({"debugger": str(self.root / "missing-kd.exe")})

    def test_version_does_not_require_configuration_or_write_runtime_files(self):
        result = self.cli("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "klay " + klay.__version__)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
