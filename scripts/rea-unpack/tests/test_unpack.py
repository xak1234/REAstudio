"""Offline reconstruction and evidence-boundary checks on complete PE bytes."""

from __future__ import annotations

import copy
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_live_imports import make_image  # noqa: E402

from pe_rebuild import PEFormatError, parse_pe  # noqa: E402
from unpack import (  # noqa: E402
    _terminate_owned_process,
    atomic_publish,
    json_bytes,
    make_review_plan,
    missing_required_ranges,
    preflight_paths,
    rebuild_from_plan,
    sha256,
    source_import_hints,
    validate_review_plan,
)


def evidence_fixture(directory: Path, *, is64: bool = False) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    """Construct a complete PE plus declarative capture data for parser tests."""
    image = bytearray(make_image([], is64=is64))
    struct.pack_into("<I", image, 0x98 + 60, 0x400)  # Room for the additional section header.
    width, format_code = (8, "<Q") if is64 else (4, "<I")
    base = 0x180000000 if is64 else 0x76000000
    struct.pack_into(format_code, image, 0x3000, base + 0x1100)
    struct.pack_into(format_code, image, 0x3000 + width, base + 0x1120)
    memory = bytes(image)
    memory_path = directory / "capture.memory.bin"
    source_path = directory / "source.exe"
    memory_path.write_bytes(memory)
    source_path.write_bytes(memory)
    symbols = [{"dll": "host.dll", "name": "First", "ordinal": None},
               {"dll": "host.dll", "name": None, "ordinal": 2}]
    slots = [
        {"rva": 0x3000 + position * width, "address": base + target,
         "status": "resolved", "selected": symbol, "candidates": [symbol]}
        for position, (target, symbol) in enumerate(zip((0x1100, 0x1120), symbols, strict=True))
    ]
    slots.append({"rva": 0x3000 + 2 * width, "address": 0, "status": "empty",
                  "selected": None, "candidates": []})
    capture: dict[str, Any] = {
        "schema_version": 1, "kind": "rea-memory-capture",
        "source": {"path": str(source_path), "sha256": sha256(memory), "is64": is64},
        "memory": {"path": str(memory_path), "sha256": sha256(memory), "size": len(memory),
                   "complete": True, "missing_ranges": []},
        "process": {"loaded_base": 0x140000000 if is64 else 0x400000,
                    "identity_stable": True, "pid": 1, "creation_filetime": 1},
        "oep": {"rva": 0x1000},
        "iat": {"ranges": [{"rva": 0x3000, "size": 3 * width}], "slots": slots},
    }
    capture_path = directory / "capture.json"
    capture_raw = json_bytes(capture)
    capture_path.write_bytes(capture_raw)
    plan = make_review_plan(capture, capture_path, sha256(capture_raw))
    plan["reviewed"] = True
    return memory, capture, plan


class OfflineReviewTests(unittest.TestCase):
    def test_cleanup_fallback_stops_only_its_owned_real_process(self) -> None:
        command = [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"]
        owned = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        other = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        try:
            self.assertIsNone(owned.poll())
            self.assertIsNone(other.poll())
            note = _terminate_owned_process(owned)
            self.assertIsNotNone(owned.poll())
            self.assertIn(str(owned.pid), note)
            self.assertIsNone(other.poll())
        finally:
            for process in (owned, other):
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                if process.stdin is not None:
                    process.stdin.close()

    def test_real_byte_rebuild_both_architectures(self) -> None:
        for is64 in (False, True):
            with self.subTest(is64=is64), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                _, _, plan = evidence_fixture(directory, is64=is64)
                plan_path = directory / "imports.json"
                plan_path.write_bytes(json_bytes(plan))
                output = directory / "rebuilt.exe"
                result = rebuild_from_plan(plan_path, output)
                self.assertTrue(result["ok"])
                self.assertTrue(result["imports_rebuilt"])
                self.assertFalse(result["portable_verified"])
                info = parse_pe(output.read_bytes(), "file")
                self.assertEqual(info.entry_rva, 0x1000)
                self.assertGreater(info.directory(1).size, 0)
                self.assertEqual(sha256(output.read_bytes()), result["output_sha256"])
                self.assertEqual(json.loads(Path(str(output) + ".report.json").read_bytes()), result)

    def test_plan_requires_explicit_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            memory, capture, plan = evidence_fixture(Path(temporary))
            plan["reviewed"] = False
            with self.assertRaisesRegex(PEFormatError, "reviewed=true"):
                validate_review_plan(plan, capture, memory)

    def test_reviewed_equal_address_alias_must_be_a_recorded_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            memory, capture, _ = evidence_fixture(directory)
            entry = capture["iat"]["slots"][0]
            entry["status"] = "ambiguous"
            entry["selected"] = None
            entry["candidates"] = [
                {"dll": "host.dll", "name": "ExitProcess", "ordinal": None},
                {"dll": "host.dll", "name": "FatalExit", "ordinal": None},
            ]
            capture_path = directory / "capture.json"
            capture_raw = json_bytes(capture)
            capture_path.write_bytes(capture_raw)
            plan = make_review_plan(capture, capture_path, sha256(capture_raw))
            plan["reviewed"] = True
            with self.assertRaisesRegex(PEFormatError, "evidenced DLL name"):
                validate_review_plan(plan, capture, memory)

            plan["imports"][0].update(entry["candidates"][0])
            _, slots, _, _ = validate_review_plan(plan, capture, memory)
            self.assertEqual(slots[0].address, entry["address"])
            self.assertEqual(slots[0].symbol.name, "ExitProcess")
            self.assertEqual(len(slots), 2)

            plan["imports"][0]["name"] = "InventedProcessExit"
            with self.assertRaisesRegex(PEFormatError, "not an exact candidate"):
                validate_review_plan(plan, capture, memory)

    def test_tampered_memory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            memory, capture, plan = evidence_fixture(Path(temporary))
            changed = bytearray(memory)
            changed[0x1000] ^= 1
            with self.assertRaisesRegex(PEFormatError, "SHA-256"):
                validate_review_plan(plan, capture, bytes(changed))

    def test_tampered_capture_json_is_refused_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, _, plan = evidence_fixture(directory)
            plan_path = directory / "imports.json"
            plan_path.write_bytes(json_bytes(plan))
            capture_path = directory / "capture.json"
            capture_path.write_bytes(capture_path.read_bytes() + b" ")
            output = directory / "rebuilt.exe"
            with self.assertRaisesRegex(PEFormatError, "Capture JSON SHA-256"):
                rebuild_from_plan(plan_path, output)
            self.assertFalse(output.exists())

    def test_unknown_symbol_and_changed_pointer_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            memory, capture, plan = evidence_fixture(Path(temporary))
            for field, value in (("name", "InventedApi"), ("address", 0x76543210)):
                with self.subTest(field=field):
                    modified = copy.deepcopy(plan)
                    modified["imports"][0][field] = value
                    with self.assertRaises(PEFormatError):
                        validate_review_plan(modified, capture, memory)

    def test_missing_and_duplicate_imports_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            memory, capture, plan = evidence_fixture(Path(temporary))
            modified = copy.deepcopy(plan)
            modified["imports"].pop()
            with self.assertRaisesRegex(PEFormatError, "drops nonzero slots"):
                validate_review_plan(modified, capture, memory)
            modified = copy.deepcopy(plan)
            modified["imports"].append(modified["imports"][0])
            with self.assertRaisesRegex(PEFormatError, "duplicates"):
                validate_review_plan(modified, capture, memory)

    def test_unrecorded_range_and_bad_oep_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            memory, capture, plan = evidence_fixture(Path(temporary))
            modified = copy.deepcopy(plan)
            modified["iat_ranges"] = [{"rva": 0x3100, "size": 12}]
            with self.assertRaisesRegex(PEFormatError, "recorded"):
                validate_review_plan(modified, capture, memory)
            for oep in (0x400000, 0x3000, -1):
                modified = copy.deepcopy(plan)
                modified["oep_rva"] = oep
                with self.assertRaisesRegex(PEFormatError, "OEP"):
                    validate_review_plan(modified, capture, memory)

    def test_wrong_architecture_base_and_unstable_process_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            memory, capture, plan = evidence_fixture(Path(temporary))
            for field, value in (("is64", True), ("loaded_base", 0x500000)):
                modified = copy.deepcopy(plan)
                modified[field] = value
                with self.assertRaises(PEFormatError):
                    validate_review_plan(modified, capture, memory)
            capture["process"]["identity_stable"] = False
            with self.assertRaisesRegex(PEFormatError, "stable"):
                validate_review_plan(plan, capture, memory)

    def test_missing_required_bytes_cannot_be_hidden_by_complete_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            memory, capture, plan = evidence_fixture(Path(temporary))
            capture["memory"]["missing_ranges"] = [{"rva": 0x1000, "size": 16}]
            with self.assertRaisesRegex(PEFormatError, "missing required"):
                validate_review_plan(plan, capture, memory)
            info = parse_pe(memory)
            self.assertEqual(missing_required_ranges(info, [{"rva": 0x500, "size": 16}]), [])

    def test_existing_output_and_hardlink_alias_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = directory / "existing.bin"
            original.write_bytes(b"preserved")
            with self.assertRaises(FileExistsError):
                atomic_publish(original, b"replacement")
            self.assertEqual(original.read_bytes(), b"preserved")
            with self.assertRaises(FileExistsError):
                preflight_paths([original], [])
            self.assertFalse(list(directory.glob(".rea-capture-*")))

    def test_output_cannot_replace_source_capture_or_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, _, plan = evidence_fixture(directory)
            plan_path = directory / "imports.json"
            plan_path.write_bytes(json_bytes(plan))
            for name in ("source.exe", "capture.memory.bin", "capture.json", "imports.json"):
                with self.subTest(name=name), self.assertRaises(FileExistsError):
                    rebuild_from_plan(plan_path, directory / name)

    def test_source_lookup_table_must_validate_before_it_becomes_a_hint(self) -> None:
        source = bytearray(make_image([]))
        struct.pack_into("<II", source, 0x98 + 96 + 8, 0x2100, 40)
        struct.pack_into("<IIIII", source, 0x2100, 0x2200, 0, 0, 0x2300, 0x3000)
        source[0x2300:0x230D] = b"kernel32.dll\0"
        struct.pack_into("<II", source, 0x2200, 0x2320, 0)
        struct.pack_into("<II", source, 0x3000, 0x2320, 0)
        source[0x2320:0x232E] = b"\0\0CreateFileW\0"
        valid = bytes(source)
        ranges, hints, _ = source_import_hints(valid, parse_pe(valid, "file"))
        self.assertEqual(ranges, [(0x3000, 8)])
        self.assertEqual(hints, {0x3000: "kernel32.dll"})
        struct.pack_into("<I", source, 0x2200, 0x76BF2310)
        invalid = bytes(source)
        ranges, hints, notes = source_import_hints(invalid, parse_pe(invalid, "file"))
        self.assertEqual((ranges, hints), ([], {}))
        self.assertIn("rejected", notes[0])


if __name__ == "__main__":
    unittest.main()
