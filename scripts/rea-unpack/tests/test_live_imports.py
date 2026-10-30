"""Byte-image parser tests and optional real current-process Win32 checks.

The image collection reads complete PE fixture bytes; it is not a simulated
debugger or a substitute for the separate live Windows integration checks.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from live_imports import (  # noqa: E402
    ModuleInfo,
    addressable_modules,
    bounded_memory_reader,
    build_export_index,
    enumerate_modules,
    process_creation_time,
    recommend_iat_ranges,
    resolve_iat,
)
from pe_rebuild import PEFormatError, parse_pe  # noqa: E402


def make_image(
    exports: list[tuple[str | None, int | str]], *, is64: bool = False,
    ordinal_base: int = 1,
) -> bytes:
    """Build a format-valid mapped PE with specified export-table entries."""
    image = bytearray(0x4000)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if is64 else 224
    struct.pack_into("<HHIIIHH", image, 0x84,
                     0x8664 if is64 else 0x14C, 3, 0x12345678, 0, 0,
                     optional_size, 0x2022 if is64 else 0x2102)
    opt = 0x98
    struct.pack_into("<H", image, opt, 0x20B if is64 else 0x10B)
    struct.pack_into("<I", image, opt + 16, 0x1000)
    if is64:
        struct.pack_into("<Q", image, opt + 24, 0x140000000)
    else:
        struct.pack_into("<I", image, opt + 28, 0x400000)
    struct.pack_into("<II", image, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, opt + 56, len(image), 0x200)
    struct.pack_into("<H", image, opt + 68, 3)
    directory_offset = opt + (112 if is64 else 96)
    struct.pack_into("<I", image, directory_offset - 4, 16)
    sections = (
        (b".text", 0x1000, 0x60000020),
        (b".edata", 0x2000, 0x40000040),
        (b".idata", 0x3000, 0xC0000040),
    )
    for position, (name, rva, flags) in enumerate(sections):
        header = opt + optional_size + position * 40
        image[header:header + len(name)] = name
        struct.pack_into("<IIII", image, header + 8, 0x1000, rva, 0x1000, rva)
        struct.pack_into("<I", image, header + 36, flags)
    image[0x1000] = 0xC3
    if not exports:
        return bytes(image)
    struct.pack_into("<II", image, directory_offset, 0x2000, 0x1000)
    named = [(index, name) for index, (name, _) in enumerate(exports) if name is not None]
    count = len(exports)
    address_rva = 0x2040
    name_rva = address_rva + count * 4
    ordinal_rva = name_rva + len(named) * 4
    string_rva = ordinal_rva + len(named) * 2
    struct.pack_into("<IIIIII", image, 0x2010,
                     ordinal_base, count, len(named), address_rva, name_rva, ordinal_rva)
    for index, (_, target) in enumerate(exports):
        if isinstance(target, str):
            encoded = target.encode("ascii") + b"\0"
            target_rva = string_rva
            image[string_rva:string_rva + len(encoded)] = encoded
            string_rva += len(encoded)
        else:
            target_rva = target
        struct.pack_into("<I", image, address_rva + index * 4, target_rva)
    for position, (index, export_name) in enumerate(named):
        assert export_name is not None
        encoded = export_name.encode("ascii") + b"\0"
        struct.pack_into("<I", image, name_rva + position * 4, string_rva)
        struct.pack_into("<H", image, ordinal_rva + position * 2, index)
        image[string_rva:string_rva + len(encoded)] = encoded
        string_rva += len(encoded)
    return bytes(image)


class ImageCollection:
    """A bounded address-space view of the actual byte fixtures above."""

    def __init__(self, entries: list[tuple[ModuleInfo, bytes]]) -> None:
        self.entries = entries
        self.reads: list[tuple[int, int]] = []

    def read(self, address: int, size: int) -> bytes:
        self.reads.append((address, size))
        for module, data in self.entries:
            if module.base <= address and address + size <= module.base + len(data):
                start = address - module.base
                return data[start:start + size]
        raise PEFormatError("The requested range is absent from the image collection.")


def target_with_slots(addresses: list[int], *, is64: bool = False) -> bytes:
    image = bytearray(make_image([], is64=is64))
    width, format_code = (8, "<Q") if is64 else (4, "<I")
    for position, address in enumerate(addresses):
        struct.pack_into(format_code, image, 0x3000 + position * width, address)
    return bytes(image)


class LiveExportByteTests(unittest.TestCase):
    def test_module_addressability_excludes_native_wow64_modules_from_x32(self) -> None:
        wow64 = ModuleInfo("ntdll.dll", "", 0x77000000, 0x4000)
        native = ModuleInfo("ntdll.dll", "", 0x7FFB00000000, 0x4000)
        crosses_boundary = ModuleInfo("crosses.dll", "", 0xFFFFF000, 0x2000)
        kept, skipped = addressable_modules([wow64, native, crosses_boundary], 4)
        self.assertEqual(kept, [wow64])
        self.assertEqual([item["base"] for item in skipped], [native.base, crosses_boundary.base])
        self.assertTrue(all(item["kind"] == "module_not_addressable_by_debugger" for item in skipped))
        kept, skipped = addressable_modules([wow64, native, crosses_boundary], 8)
        self.assertEqual(kept, [wow64, native, crosses_boundary])
        self.assertEqual(skipped, [])

    def test_bounded_reader_accepts_last_address_and_blocks_invalid_requests_before_read(self) -> None:
        for pointer_size in (4, 8):
            with self.subTest(pointer_size=pointer_size):
                limit = 1 << (pointer_size * 8)
                module = ModuleInfo("boundary.bin", "", limit - 4, 4)
                collection = ImageCollection([(module, b"abcd")])
                read = bounded_memory_reader(collection.read, pointer_size)
                self.assertEqual(read(limit - 1, 1), b"d")
                self.assertEqual(read(limit - 4, 4), b"abcd")
                valid_reads = list(collection.reads)
                for address, size in ((limit, 1), (-1, 1), (limit - 1, 2),
                                      (0, 0), (0, -1), (0, limit), (True, 1), (0, True)):
                    with self.subTest(address=address, size=size), self.assertRaises(PEFormatError):
                        read(address, size)
                self.assertEqual(collection.reads, valid_reads)

    def test_address_guards_reject_unsupported_pointer_width(self) -> None:
        collection = ImageCollection([])
        for width in (0, 1, 2, 16):
            with self.subTest(width=width):
                with self.assertRaises(PEFormatError):
                    addressable_modules([], width)
                with self.assertRaises(PEFormatError):
                    bounded_memory_reader(collection.read, width)
        self.assertEqual(collection.reads, [])

    def test_named_and_ordinal_exports_both_architectures(self) -> None:
        for is64 in (False, True):
            with self.subTest(is64=is64):
                base = 0x180000000 if is64 else 0x76000000
                module = ModuleInfo("HOST.dll", "", base, 0x4000)
                data = make_image([("First", 0x1100), (None, 0x1120)], is64=is64)
                collection = ImageCollection([(module, data)])
                index = build_export_index([module], collection.read)
                self.assertFalse(index.diagnostics)
                image = target_with_slots([base + 0x1100, base + 0x1120, 0], is64=is64)
                info = parse_pe(image)
                report, slots = resolve_iat(image, info, index, [(0x3000, 3 * info.pointer_size)])
                self.assertTrue(report["ok"])
                self.assertEqual(slots[0].symbol.name, "First")
                self.assertEqual(slots[1].symbol.ordinal, 2)
                self.assertEqual(slots[0].symbol.dll, "host.dll")
                self.assertEqual(len(collection.reads), len(set(collection.reads)))
                self.assertLessEqual(len(collection.reads), 3)

    def test_forwarders_preserve_public_alias_and_hint(self) -> None:
        host = ModuleInfo("host.dll", "", 0x76000000, 0x4000)
        facade = ModuleInfo("facade.dll", "", 0x77000000, 0x4000)
        collection = ImageCollection([
            (host, make_image([("First", 0x1100), (None, 0x1120)])),
            (facade, make_image([("PublicFirst", "host.First"), ("PublicSecond", "host.#2")])),
        ])
        index = build_export_index([host, facade], collection.read)
        self.assertFalse(index.diagnostics)
        image = target_with_slots([host.base + 0x1100, host.base + 0x1120, 0])
        info = parse_pe(image)
        report, slots = resolve_iat(image, info, index, [(0x3000, 12)], dll_hints={0x3000: "FACADE.dll"})
        self.assertTrue(report["ok"])
        self.assertEqual([item.symbol.name for item in slots], ["PublicFirst", "PublicSecond"])
        self.assertEqual(slots[0].symbol.dll, "facade.dll")
        self.assertTrue(any(candidate["forwarder_chain"] for candidate in report["slots"][0]["candidates"]))

    def test_duplicate_exact_names_are_ambiguous_and_interior_pointer_unresolved(self) -> None:
        module = ModuleInfo("host.dll", "", 0x76000000, 0x4000)
        collection = ImageCollection([(module, make_image([("First", 0x1100), ("Alias", 0x1100)]))])
        index = build_export_index([module], collection.read)
        image = target_with_slots([module.base + 0x1100, module.base + 0x1101, 0])
        report, slots = resolve_iat(image, parse_pe(image), index, [(0x3000, 12)])
        self.assertFalse(report["ok"])
        self.assertEqual(report["ambiguous_count"], 1)
        self.assertEqual(report["unresolved_count"], 1)
        self.assertEqual(slots, [])

    def test_wow64_forwarder_uses_matching_architecture_with_duplicate_dll_names(self) -> None:
        native_ntdll = ModuleInfo("ntdll.dll", "", 0x180000000, 0x4000)
        wow_ntdll = ModuleInfo("ntdll.dll", "", 0x76000000, 0x4000)
        wow_kernel32 = ModuleInfo("kernel32.dll", "", 0x77000000, 0x4000)
        collection = ImageCollection([
            (native_ntdll, make_image([("NtClose", 0x1100)], is64=True)),
            (wow_ntdll, make_image([("NtClose", 0x1100)])),
            (wow_kernel32, make_image([("CloseHandle", "ntdll.NtClose")])),
        ])
        index = build_export_index([native_ntdll, wow_ntdll, wow_kernel32], collection.read)
        self.assertFalse(index.diagnostics)
        wow_candidates = index.by_address[wow_ntdll.base + 0x1100]
        self.assertTrue(all(candidate.machine == 0x14C for candidate in wow_candidates))
        self.assertTrue(any(candidate.symbol.dll == "kernel32.dll" for candidate in wow_candidates))
        native_candidates = index.by_address[native_ntdll.base + 0x1100]
        self.assertTrue(all(candidate.machine == 0x8664 for candidate in native_candidates))
        self.assertFalse(any(candidate.symbol.dll == "kernel32.dll" for candidate in native_candidates))
        image = target_with_slots([wow_ntdll.base + 0x1100, 0])
        report, slots = resolve_iat(image, parse_pe(image), index, [(0x3000, 8)],
                                    dll_hints={0x3000: "kernel32.dll"})
        self.assertTrue(report["ok"])
        self.assertEqual(slots[0].symbol.name, "CloseHandle")
        self.assertEqual(report["slots"][0]["candidates"][0]["machine"], 0x14C)

    def test_low_address_x64_export_is_not_an_x86_import(self) -> None:
        native = ModuleInfo("ntdll.dll", "", 0x75000000, 0x4000)
        collection = ImageCollection([(native, make_image([("First", 0x1100)], is64=True))])
        index = build_export_index([native], collection.read)
        image = target_with_slots([native.base + 0x1100, native.base + 0x1100, 0])
        report, slots = resolve_iat(image, parse_pe(image), index, [(0x3000, 12)])
        self.assertFalse(report["ok"])
        self.assertEqual(report["unresolved_count"], 2)
        self.assertEqual(slots, [])
        self.assertEqual(recommend_iat_ranges(image, parse_pe(image), index), [])

    def test_x86_module_cannot_claim_export_above_32_bit_address_space(self) -> None:
        impossible = ModuleInfo("wrong.dll", "", 0x180000000, 0x4000)
        collection = ImageCollection([(impossible, make_image([("First", 0x1100)]))])
        index = build_export_index([impossible], collection.read)
        self.assertFalse(index.by_address)
        self.assertEqual(index.modules[0]["export_status"], "failed")
        self.assertIn("address space", index.diagnostics[0]["error"])

    def test_recursive_forwarder_cycle_and_unmapped_api_set_are_reported(self) -> None:
        first = ModuleInfo("first.dll", "", 0x76000000, 0x4000)
        second = ModuleInfo("second.dll", "", 0x77000000, 0x4000)
        collection = ImageCollection([
            (first, make_image([("Loop", "second.Loop"), ("Api", "api-ms-win-missing.Test")])),
            (second, make_image([("Loop", "first.Loop")])),
        ])
        index = build_export_index([first, second], collection.read)
        self.assertFalse(index.by_address)
        messages = [item["error"] for item in index.diagnostics]
        self.assertTrue(any("cycle" in item for item in messages))
        self.assertTrue(any("API-set" in item for item in messages))

    def test_failed_module_is_not_a_partial_success(self) -> None:
        module = ModuleInfo("truncated.dll", "", 0x76000000, 0x4000)
        collection = ImageCollection([(module, make_image([("First", 0x1100)])[:0x100])])
        index = build_export_index([module], collection.read)
        self.assertFalse(index.by_address)
        self.assertEqual(index.modules[0]["export_status"], "failed")
        self.assertEqual(index.diagnostics[0]["kind"], "module_export_read_failed")

    def test_corrupt_export_arrays_are_not_indexed(self) -> None:
        module = ModuleInfo("corrupt.dll", "", 0x76000000, 0x4000)
        data = bytearray(make_image([("First", 0x1100)]))
        struct.pack_into("<I", data, 0x201C, 0x3FFF)  # AddressOfFunctions overflows.
        collection = ImageCollection([(module, bytes(data))])
        index = build_export_index([module], collection.read)
        self.assertFalse(index.by_address)
        self.assertEqual(index.modules[0]["export_status"], "failed")

    def test_file_hash_is_separate_from_memory_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "host.dll"
            data = make_image([("First", 0x1100)])
            path.write_bytes(data)
            module = ModuleInfo("host.dll", str(path), 0x76000000, len(data))
            collection = ImageCollection([(module, data)])
            index = build_export_index([module], collection.read)
            evidence = index.modules[0]
            self.assertEqual(evidence["file_sha256"], hashlib.sha256(data).hexdigest())
            self.assertTrue(evidence["file_header_matches_live"])
            self.assertFalse(evidence["file_memory_equality_proven"])

    def test_range_errors_no_terminator_and_zero_only(self) -> None:
        module = ModuleInfo("host.dll", "", 0x76000000, 0x4000)
        collection = ImageCollection([(module, make_image([("First", 0x1100)]))])
        index = build_export_index([module], collection.read)
        image = target_with_slots([module.base + 0x1100, 0])
        info = parse_pe(image)
        for ranges in ([(0x3001, 8)], [(0x3000, 8), (0x3004, 8)], [(0x3FFC, 8)]):
            with self.subTest(ranges=ranges), self.assertRaises(PEFormatError):
                resolve_iat(image, info, index, ranges)
        report, _ = resolve_iat(image, info, index, [(0x3000, 4)])
        self.assertFalse(report["ok"])
        self.assertTrue(report["layout_errors"])
        report, slots = resolve_iat(image, info, index, [(0x3004, 4)])
        self.assertFalse(report["ok"])
        self.assertEqual(slots, [])

    def test_unknown_hint_cannot_invent_identity(self) -> None:
        module = ModuleInfo("host.dll", "", 0x76000000, 0x4000)
        collection = ImageCollection([(module, make_image([("First", 0x1100)]))])
        index = build_export_index([module], collection.read)
        image = target_with_slots([module.base + 0x1100, 0])
        report, slots = resolve_iat(image, parse_pe(image), index, [(0x3000, 8)],
                                    dll_hints={0x3000: "invented.dll"})
        self.assertFalse(report["ok"])
        self.assertEqual(report["ambiguous_count"], 1)
        self.assertEqual(slots, [])
        with self.assertRaises(PEFormatError):
            resolve_iat(image, parse_pe(image), index, [(0x3000, 8)], dll_hints={0x3004: "host.dll"})

    def test_mixed_modules_without_null_boundary_are_reported(self) -> None:
        first = ModuleInfo("first.dll", "", 0x76000000, 0x4000)
        second = ModuleInfo("second.dll", "", 0x77000000, 0x4000)
        collection = ImageCollection([
            (first, make_image([("First", 0x1100)])),
            (second, make_image([("Second", 0x1100)])),
        ])
        index = build_export_index([first, second], collection.read)
        image = target_with_slots([first.base + 0x1100, second.base + 0x1100, 0])
        report, _ = resolve_iat(image, parse_pe(image), index, [(0x3000, 12)])
        self.assertEqual(report["resolved_count"], 2)
        self.assertFalse(report["ok"])
        self.assertTrue(report["layout_errors"])

    def test_candidate_ranges_require_review_and_have_null_boundary(self) -> None:
        module = ModuleInfo("host.dll", "", 0x76000000, 0x4000)
        collection = ImageCollection([(module, make_image([("First", 0x1100), ("Second", 0x1120)]))])
        index = build_export_index([module], collection.read)
        image = target_with_slots([module.base + 0x1100, module.base + 0x1120, 0])
        candidates = recommend_iat_ranges(image, parse_pe(image), index)
        self.assertEqual(len(candidates), 1)
        self.assertEqual((candidates[0]["rva"], candidates[0]["size"]), (0x3000, 12))
        self.assertTrue(candidates[0]["requires_review"])
        self.assertFalse(candidates[0]["authoritative"])

    @unittest.skipUnless(os.name == "nt", "Real Win32 API check requires Windows")
    def test_actual_current_process_module_snapshot_and_creation_time(self) -> None:
        modules = enumerate_modules(os.getpid())
        self.assertTrue(modules)
        self.assertTrue(any(item.name.casefold() == "kernel32.dll" for item in modules))
        created = process_creation_time(os.getpid())
        self.assertGreater(created, 0)
        self.assertEqual(created, process_creation_time(os.getpid()))


if __name__ == "__main__":
    unittest.main()
