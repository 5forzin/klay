import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import klay


TEST_GUID = uuid.UUID("1f7c182a-3008-47d1-b6f4-111a96fc7c54")


def pe_fixture(guid=TEST_GUID, age=1, with_codeview=True):
    """Synthetic PE metadata only; never load this fixture as a driver."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHI", data, 132, 0x8664, 1, 0x65010203)
    struct.pack_into("<H", data, 148, 240)
    optional = 152
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<II", data, optional + 56, 0x2000, 512)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<IIII", data, 392 + 8, 512, 0x1000, 512, 512)
    if with_codeview:
        record = b"RSDS" + guid.bytes_le + struct.pack("<I", age) + b"C:\\build\\testdriver.pdb\0"
        struct.pack_into("<II", data, optional + 160, 0x1000, 28)
        struct.pack_into("<IIII", data, 512 + 12, 2, len(record), 0x1040, 576)
        data[576:576 + len(record)] = record
    return bytes(data)


def pdb_fixture(guid=TEST_GUID, age=1):
    """Synthetic MSF7 identity stream only; not a debugger symbol fixture."""
    data = bytearray(2048)
    data[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
    struct.pack_into("<6I", data, 32, 512, 1, 4, 16, 0, 1)
    struct.pack_into("<I", data, 512, 2)
    struct.pack_into("<4I", data, 1024, 2, 0xFFFFFFFF, 28, 3)
    struct.pack_into("<3I", data, 1536, 20000404, 0, age)
    data[1548:1564] = guid.bytes_le
    return bytes(data)


class KlayTests(unittest.TestCase):
    def setUp(self):
        self.original_handlers = list(klay.LOG.handlers)
        self.temporary = tempfile.TemporaryDirectory(prefix="klay-test-")
        self.root = Path(self.temporary.name)
        self.config = {"shared_root": str(self.root / "share"), "runtime_root": str(self.root / "runtime"), "build_root": str(self.root / "builds"), "debugger": str(self.root / "kd.exe")}
        Path(self.config["shared_root"]).mkdir()

    def tearDown(self):
        for handler in list(klay.LOG.handlers):
            if handler not in self.original_handlers:
                klay.LOG.removeHandler(handler)
                handler.close()
        self.temporary.cleanup()

    def test_atomic_json_publication_retries_only_the_same_flushed_file(self):
        destination = self.root / "atomic.json"
        destination.write_text('{"previous": true}', encoding="utf-8")
        original_replace = klay.os.replace
        sources = []
        def temporarily_busy(source, target):
            sources.append(source)
            if len(sources) < 3:
                raise PermissionError("Synthetic reader holds destination")
            return original_replace(source, target)
        with patch.object(klay.os, "replace", side_effect=temporarily_busy), patch.object(klay.time, "sleep") as sleep, patch.object(klay.json, "dump", wraps=klay.json.dump) as dump:
            klay.write_json(destination, {"current": True})
        self.assertEqual(klay.read_json(destination), {"current": True})
        self.assertEqual(len(sources), 3)
        self.assertEqual(len(set(sources)), 1)
        self.assertEqual(dump.call_count, 1)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.1, 0.2])
        self.assertEqual(list(self.root.glob("atomic.json.*.partial")), [])

    def test_atomic_json_publication_propagates_permanent_permission_failure(self):
        destination = self.root / "atomic.json"
        previous = '{"previous": true}'
        destination.write_text(previous, encoding="utf-8")
        with patch.object(klay.os, "replace", side_effect=PermissionError("Synthetic permanent denial")) as replace, patch.object(klay.time, "sleep") as sleep:
            with self.assertRaisesRegex(PermissionError, "permanent denial"):
                klay.write_json(destination, {"current": True})
        self.assertEqual(replace.call_count, 5)
        self.assertEqual(sleep.call_count, 4)
        self.assertLess(sum(call.args[0] for call in sleep.call_args_list), 2)
        self.assertEqual(destination.read_text(encoding="utf-8"), previous)
        self.assertEqual(list(self.root.glob("atomic.json.*.partial")), [])

    def test_atomic_json_publication_does_not_retry_other_errors(self):
        destination = self.root / "atomic.json"
        with patch.object(klay.os, "replace", side_effect=ValueError("Synthetic non-transient error")) as replace, patch.object(klay.time, "sleep") as sleep:
            with self.assertRaisesRegex(ValueError, "non-transient"):
                klay.write_json(destination, {"current": True})
        self.assertEqual(replace.call_count, 1)
        sleep.assert_not_called()
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob("atomic.json.*.partial")), [])

    def test_immutable_json_publication_never_replaces_an_existing_record(self):
        destination = self.root / "selection.json"
        previous = '{"previous": true}'
        destination.write_text(previous, encoding="utf-8")
        with self.assertRaises(FileExistsError):
            klay.write_json(destination, {"current": True}, immutable=True)
        self.assertEqual(destination.read_text(encoding="utf-8"), previous)
        self.assertEqual(list(self.root.glob("selection.json.*.partial")), [])

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
        driver.write_bytes(pe_fixture())
        pdb.write_bytes(pdb_fixture())
        args = argparse.Namespace(driver=driver, pdb=pdb, source=None, note="isolated fixture")
        result = klay.arm(args, self.config)
        driver.write_bytes(b"next build")
        archived = Path(result["directory"]) / result["driver"]
        self.assertEqual(klay.sha256(archived), result["driverSha256"])
        self.assertEqual(klay.read_json(Path(self.config["shared_root"]) / "active-run.json")["buildId"], result["buildId"])
        self.assertEqual(result["pdbMatch"], "matched")
        self.assertFalse(result["noPrivateSymbols"])

    def test_arm_without_pdb_records_missing_private_symbols_and_can_be_analyzed(self):
        driver = self.root / "testdriver.sys"
        driver.write_bytes(pe_fixture())
        build = klay.arm(argparse.Namespace(driver=driver, pdb=None, source=None, note="no symbols available"), self.config)
        self.assertIsNone(build["pdb"])
        self.assertIsNone(build["pdbSha256"])
        self.assertTrue(build["noPrivateSymbols"])
        self.assertEqual(build["pdbMatch"], "not_provided")
        self.assertEqual(build["driverIdentity"]["codeView"]["guid"], str(TEST_GUID))
        folder = self.crash(ready=True)
        metadata = klay.read_json(folder / "crash.json")
        metadata["armedBuild"] = build
        klay.write_json(folder / "crash.json", metadata)
        def accepted(args, stdout, **kwargs):
            stdout.write(("Bugcheck code 000000d1\nArguments 1 2 3 4\n" + klay.DONE_MARKER).encode())
            return argparse.Namespace(returncode=0)
        with patch.object(klay, "find_debugger", return_value=Path(self.config["debugger"])), patch.object(klay.subprocess, "run", side_effect=accepted):
            result = klay.analyze(folder, self.config)
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["symbolQuality"]["state"], "no_private_symbols")
        self.assertTrue(any("No private PDB" in item for item in result["limitations"]))
        self.assertEqual(result["buildEvidence"]["buildId"], build["buildId"])

    def test_arm_publishes_immutable_selection_when_legacy_pointer_is_locked(self):
        driver = self.root / "testdriver.sys"
        driver.write_bytes(pe_fixture())
        legacy = Path(self.config["shared_root"]) / "active-run.json"
        legacy.write_text('{"buildId": "old"}', encoding="utf-8")
        original_replace = klay.os.replace
        def legacy_locked(source, destination):
            if Path(destination) == legacy:
                raise PermissionError("Synthetic persistent HGFS reader")
            return original_replace(source, destination)
        with patch.object(klay.os, "replace", side_effect=legacy_locked), patch.object(klay.time, "sleep"), self.assertLogs(klay.LOG, level="WARNING"):
            result = klay.arm(argparse.Namespace(driver=driver, pdb=None, source=None, note="immutable selection"), self.config)
        record = Path(self.config["shared_root"]) / "build-selections" / result["selectionRecord"]
        published = klay.read_json(record)
        expected_name = klay.parse_time(result["armedAtUtc"]).strftime("%Y%m%dT%H%M%S%fZ_") + result["buildId"] + ".json"
        self.assertEqual(record.name, expected_name)
        self.assertEqual(published["selectionProtocol"], "immutable_v1")
        self.assertEqual(published["buildId"], result["buildId"])
        self.assertEqual(published, klay.read_json(Path(result["directory"]) / "build.json"))
        self.assertLessEqual(record.stat().st_size, 65536)
        self.assertFalse(result["legacyPointerUpdated"])
        self.assertIn("Update the guest exporter", result["compatibilityWarning"])
        self.assertEqual(klay.read_json(legacy), {"buildId": "old"})
        self.assertNotIn("observedBuild", result)
        self.assertNotIn("guestAcknowledged", result)

    def test_arm_rejects_selection_larger_than_guest_utf8_limit(self):
        driver = self.root / "testdriver.sys"
        driver.write_bytes(pe_fixture())
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            klay.arm(argparse.Namespace(driver=driver, pdb=None, source=None, note="é" * 40000), self.config)
        self.assertFalse((Path(self.config["shared_root"]) / "active-run.json").exists())
        self.assertFalse((Path(self.config["shared_root"]) / "build-selections").exists())

    def test_arm_rejects_pdb_guid_or_age_mismatch_before_publication(self):
        driver, pdb = self.root / "testdriver.sys", self.root / "testdriver.pdb"
        driver.write_bytes(pe_fixture())
        for guid, age in ((uuid.UUID(int=1), 1), (TEST_GUID, 2)):
            with self.subTest(guid=guid, age=age):
                pdb.write_bytes(pdb_fixture(guid, age))
                with self.assertRaisesRegex(ValueError, r"GUID\+Age"):
                    klay.arm(argparse.Namespace(driver=driver, pdb=pdb, source=None, note=""), self.config)
        self.assertFalse((Path(self.config["shared_root"]) / "active-run.json").exists())

    def test_binary_identity_rejects_out_of_bounds_or_excessive_metadata(self):
        driver, pdb = self.root / "testdriver.sys", self.root / "testdriver.pdb"
        driver.write_bytes(pe_fixture()[:200])
        with self.assertRaisesRegex(ValueError, "truncated"):
            klay.driver_identity(driver)
        pdb_data = bytearray(pdb_fixture())
        struct.pack_into("<I", pdb_data, 44, 0xFFFFFFFF)
        pdb.write_bytes(pdb_data)
        with self.assertRaisesRegex(ValueError, "excessive"):
            klay.pdb_identity(pdb)

    def test_pe_without_rsds_does_not_claim_a_pdb_match(self):
        driver, pdb = self.root / "testdriver.sys", self.root / "testdriver.pdb"
        driver.write_bytes(pe_fixture(with_codeview=False))
        pdb.write_bytes(pdb_fixture())
        result = klay.arm(argparse.Namespace(driver=driver, pdb=pdb, source=None, note=""), self.config)
        self.assertEqual(result["pdbMatch"], "unverified")
        self.assertIsNone(result["driverIdentity"]["codeView"])

    def test_structured_report_quotes_stack_and_warnings_without_assigning_blame(self):
        report = """DRIVER_IRQL_NOT_LESS_OR_EQUAL (d1)
BUGCHECK_CODE: d1
BUGCHECK_P1: 1
BUGCHECK_P2: 2
BUGCHECK_P3: 3
BUGCHECK_P4: 4
Arg1: 0000000000000001, memory referenced
PROCESS_NAME: example.exe
FAULTING_THREAD: ffff800011223344
SYMBOL_NAME: testdriver!Work+0x12
FAILURE_BUCKET_ID: AV_testdriver!Work
FAULTING_IP:
testdriver!Work+0x12
fffff80033334444 mov eax,dword ptr [rcx]
rax=0000000000000001 rbx=0000000000000002 rcx=0000000000000003
STACK_TEXT:
ffff8000`11112222 fffff800`33334444 : 00000000`00000001 00000000`00000002 : testdriver!Work+0x12
*** ERROR: Module load completed but symbols could not be loaded for testdriver.sys
Probably caused by : testdriver.sys
"""
        result = klay.parse_analysis(report)
        self.assertEqual(result["bugcheckParameters"], [f"0x{number:016x}" for number in range(1, 5)])
        self.assertEqual(result["bugcheckParameterDetails"][0]["description"], "memory referenced")
        self.assertEqual(result["failureBucket"], "AV_testdriver!Work")
        self.assertEqual(result["symbolName"], "testdriver!Work+0x12")
        self.assertEqual(result["process"], "example.exe")
        for item in result["stackEvidence"] + result["debuggerWarnings"]:
            self.assertEqual(report.splitlines()[item["line"] - 1], item["text"])
        self.assertEqual(len(result["stackEvidence"]), 1)
        self.assertEqual(len(result["debuggerWarnings"]), 1)
        self.assertEqual(len(result["registerEvidence"]), 1)
        self.assertIn("mov eax", result["faultingInstruction"])
        self.assertNotIn("cause", result)

    def test_evidence_is_bounded_and_points_to_complete_raw_report(self):
        frame = "ffff8000`11112222 fffff800`33334444 : 00000000`00000001 : testdriver!Work"
        report = "Bugcheck code 000000d1\n" + "\n".join([frame] * 260)
        result = klay.parse_analysis(report)
        self.assertEqual(len(result["stackEvidence"]), 256)
        self.assertTrue(result["stackEvidenceTruncated"])
        self.assertEqual(result["stackEvidence"][-1]["line"], 257)

    def test_empty_debugger_heading_never_steals_the_next_line(self):
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)):
                report = newline.join(("Bugcheck code 0000003b", "EXCEPTION_RECORD:  ", "ExceptionAddress: fffff80012345678 (example!Work)", "TRAP_FRAME:", "PROCESS_NAME: example.exe", "CONTEXT: ffff800012345678", ""))
                result = klay.parse_analysis(report)
                self.assertNotIn("exceptionRecord", result)
                self.assertNotIn("trapFrame", result)
                self.assertEqual(result["process"], "example.exe")
                self.assertEqual(result["contextRecord"], "ffff800012345678")

    def test_bugcheck_descriptions_accept_hex_prefix_without_truncating_the_value(self):
        report = "Bugcheck code 000000d1\nArg1: 0xffff800012345678, memory referenced\nArg2: 0X00000000`00000002, IRQL\n"
        details = klay.parse_analysis(report)["bugcheckParameterDetails"]
        self.assertEqual(details[0], {"index": 1, "value": "0xffff800012345678", "description": "memory referenced"})
        self.assertEqual(details[1], {"index": 2, "value": "0x0000000000000002", "description": "IRQL"})

    def test_paged_code_instruction_and_dump_symbol_warnings_keep_raw_provenance(self):
        report = """Bugcheck code 000000D1
Page 2001bed0c too large to be in the dump file.
************* Symbol Loading Error Summary **************
Module name            Error
exampledriver          The system cannot find the file specified

IP_IN_PAGED_CODE:
exampledriver+23
fffff800`12345678 8b03            mov     eax,dword ptr [rbx]
"""
        result = klay.parse_analysis(report)
        self.assertIn("exampledriver+23", result["faultingInstruction"])
        self.assertIn("mov     eax,dword ptr [rbx]", result["faultingInstruction"])
        self.assertEqual([item.get("kind") for item in result["debuggerWarnings"]], ["dump_memory", "symbol_loading", "symbol_loading"])
        for item in result["debuggerWarnings"]:
            self.assertEqual(report.splitlines()[item["line"] - 1], item["text"])
        quality = klay.symbol_quality(report, {"module": "exampledriver", "pdb": None, "pdbMatch": "not_provided"}, result["debuggerWarnings"])
        self.assertEqual(quality["state"], "degraded")
        self.assertEqual(len(quality["warnings"]), 2)
        self.assertFalse(quality["privateSymbolsProvided"])
        self.assertNotIn("cause", result)

    def test_symbol_loading_table_ends_before_other_debugger_output(self):
        report = """Bugcheck code 000000D1
************* Symbol Loading Error Summary **************
Module name            Error
exampledriver          The system cannot find the file specified
0: kd> !analyze -v
PROCESS_NAME:          example.exe
"""
        result = klay.parse_analysis(report)
        self.assertEqual(len(result["debuggerWarnings"]), 2)
        self.assertEqual(result["process"], "example.exe")

    def test_symbol_failure_is_separate_from_pipeline_completion(self):
        folder = self.crash(ready=True)
        def accepted(args, stdout, **kwargs):
            stdout.write(("Bugcheck code 000000d1\nArguments 1 2 3 4\n*** ERROR: symbols could not be loaded for testdriver.sys\n" + klay.DONE_MARKER).encode())
            return argparse.Namespace(returncode=0)
        with patch.object(klay, "find_debugger", return_value=Path(self.config["debugger"])), patch.object(klay.subprocess, "run", side_effect=accepted):
            result = klay.analyze(folder, self.config)
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["symbolQuality"]["state"], "degraded")
        self.assertTrue(result["limitations"])

    def test_symbol_quality_uses_module_metadata_and_reports_identity_limit(self):
        text = """KLAY_BUILD_MODULE_BEGIN
ffff8000 fffff000 testdriver (private pdb symbols)
    Timestamp: Tue Sep 12 00:00:00 2023 (65010203)
    ImageSize: 00002000
KLAY_BUILD_MODULE_END
"""
        build = {"module": "testdriver", "pdb": "testdriver.pdb", "pdbMatch": "matched", "driverIdentity": {"timeDateStamp": "0x65010203", "sizeOfImage": 8192}}
        result = klay.symbol_quality(text, build, [])
        self.assertEqual(result["state"], "private_symbols_loaded")
        self.assertEqual(result["moduleMetadataMatch"], "matched")
        build["driverIdentity"]["sizeOfImage"] = 4096
        self.assertEqual(klay.symbol_quality(text, build, [])["moduleMetadataMatch"], "mismatch")

    def test_missing_lmvm_does_not_borrow_kernel_symbols(self):
        text = """nt (private pdb symbols)
*** WARNING: Unable to verify timestamp for ntoskrnl.exe
KLAY_BUILD_MODULE_BEGIN
Unable to enumerate module 'testdriver'
KLAY_BUILD_MODULE_END
"""
        warnings = [{"line": 2, "text": text.splitlines()[1]}]
        result = klay.symbol_quality(text, {"module": "testdriver", "pdb": "testdriver.pdb", "pdbMatch": "matched"}, warnings)
        self.assertEqual(result["loadedSymbols"], "unverified")
        self.assertEqual(result["moduleMetadataMatch"], "unverified")
        self.assertEqual(result["state"], "degraded")
        self.assertNotIn("private pdb symbols", result["moduleEvidence"])

    def test_once_returns_failure_when_kd_analysis_failed(self):
        self.crash(ready=True)
        config_path = self.root / "config.json"
        klay.write_json(config_path, self.config)
        def reject(args, stdout, **kwargs):
            stdout.write(b"Could not open dump file\n")
            return argparse.Namespace(returncode=1)
        with patch.object(klay, "find_debugger", return_value=Path(self.config["debugger"])), patch.object(klay.subprocess, "run", side_effect=reject):
            self.assertEqual(klay._main(["--config", str(config_path), "once"]), 1)

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
        self.assertTrue(self.path.samefile(Path(json.loads(result.stdout)["configPath"])))
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

    def test_json_output_preserves_unicode_on_a_windows_ansi_console(self):
        share = self.root / "share"
        klay.initialize(self.path, share, self.root / "data")
        config = klay.load_config(self.path)
        runtime = Path(config["runtime_root"])
        message = "\u200eS\u00e3o Paulo \u2192 dump"
        latest = {"crashId": "new", "analysisState": "complete", "message": message}
        klay.write_json(runtime / "status.json", {"message": message})
        klay.write_json(runtime / "latest.json", latest)
        environment = {**os.environ, "PYTHONIOENCODING": "cp1252:strict"}
        for command in (("status",), ("wait", "--timeout", "0", "--require-analysis")):
            with self.subTest(command=command[0]):
                result = subprocess.run(
                    [sys.executable, str(Path(klay.__file__).resolve()), "--config", str(self.path), *command],
                    capture_output=True, text=True, encoding="cp1252", env=environment, timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                if command[0] == "status":
                    self.assertEqual(report["status"]["message"], message)
                    report = report["latest"]
                self.assertEqual(report, latest)

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

    def test_cli_arm_accepts_driver_without_a_pdb(self):
        driver = self.root / "example.sys"
        driver.write_bytes(pe_fixture())
        klay.initialize(self.path, self.root / "share")
        result = self.cli("arm", "--driver", str(driver))
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(result.stdout)
        self.assertTrue(manifest["noPrivateSymbols"])
        self.assertIsNone(manifest["pdb"])
        self.assertEqual(manifest["pdbMatch"], "not_provided")


if __name__ == "__main__":
    unittest.main()
