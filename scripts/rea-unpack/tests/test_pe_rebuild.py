"""Structural tests use bounded source-created PE bytes, not debugger mocks."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pe_rebuild import (  # noqa: E402
    ImportSlot,
    ImportSymbol,
    PEFormatError,
    directory_status,
    mapped_to_file,
    parse_pe,
    read_imports,
    rebuild_imports,
)


def fixture(is64: bool = False, relocations: bool = False) -> tuple[bytes, list[ImportSlot]]:
    """Build a small, deterministic mapped image with genuine PE structures."""
    image = bytearray(0x9000)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if is64 else 224
    struct.pack_into("<HHIIIHH", image, 0x84,
                     0x8664 if is64 else 0x14C, 4, 0, 0, 0, optional_size,
                     0x22 if relocations else 0x23)
    opt = 0x98
    struct.pack_into("<H", image, opt, 0x20B if is64 else 0x10B)
    struct.pack_into("<I", image, opt + 16, 0x362F)
    base = 0x140000000 if is64 else 0x400000
    struct.pack_into("<Q" if is64 else "<I", image, opt + (24 if is64 else 28), base)
    struct.pack_into("<II", image, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHH", image, opt + 40, 6, 1, 2, 3)
    struct.pack_into("<II", image, opt + 56, 0x9000, 0x400)
    struct.pack_into("<H", image, opt + 68, 3)
    struct.pack_into("<H", image, opt + 70, 0x140)
    directory_offset = opt + (112 if is64 else 96)
    struct.pack_into("<I", image, directory_offset - 4, 16)
    # Deliberately broken old import metadata must be entirely replaced.
    struct.pack_into("<II", image, directory_offset + 8, 0x7400, 40)
    struct.pack_into("<II", image, directory_offset + 2 * 8, 0x7000, 0x200)
    struct.pack_into("<II", image, directory_offset + 4 * 8, 0xD000, 128)
    struct.pack_into("<II", image, directory_offset + 11 * 8, 0x6400, 32)
    section_table = opt + optional_size
    sections = (
        (b".text", 0x5000, 0x1000, 0x5000, 0x400, 0x60000020),
        (b".rdata", 0x1000, 0x6000, 0x1000, 0x5400, 0x40000040),
        (b".rsrc", 0x1000, 0x7000, 0x1000, 0x6400, 0x40000040),
        (b".reloc", 0x1000, 0x8000, 0x1000, 0x7400, 0x42000040),
    )
    for index, (name, virtual_size, rva, raw_size, raw_offset, flags) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", image, section_table + index * 40,
                         name, virtual_size, rva, raw_size, raw_offset, 0, 0, 0, 0, flags)
    image[0x5252:0x5258] = b"\x55\x8b\xec\x81\xc4\x00"
    image[0x7000:0x7200] = bytes(range(256)) * 2
    image[0x7400:0x7428] = b"@" * 40
    width = 8 if is64 else 4
    addresses = (0x7FF812341010, 0x7FF812342020, 0x7FF923453030) if is64 else (0x76BF2310, 0x76BF3330, 0x75AF4560)
    slots = [
        ImportSlot(0x6100, addresses[0], ImportSymbol("KERNEL32.dll", "ExitProcess")),
        ImportSlot(0x6100 + width, addresses[1], ImportSymbol("KERNEL32.dll", ordinal=7)),
        ImportSlot(0x6140, addresses[2], ImportSymbol("USER32.dll", "MessageBoxW")),
    ]
    for slot in slots:
        struct.pack_into("<Q" if is64 else "<I", image, slot.rva, slot.address)
    if relocations:
        struct.pack_into("<II", image, directory_offset + 5 * 8, 0x8000, 12)
        struct.pack_into("<IIHH", image, 0x8000, 0x1000, 12,
                         ((10 if is64 else 3) << 12) | 0x100, 0)
        struct.pack_into("<Q" if is64 else "<I", image, 0x1100, base + 0x5252)
    return bytes(image), slots


class PERebuildTests(unittest.TestCase):
    def test_pe32_import_names_ordinals_oep_and_resource_bytes(self) -> None:
        image, slots = fixture()
        output, report = rebuild_imports(image, slots, oep_rva=0x5252, loaded_base=0x400000)
        info = parse_pe(output, "file")
        actual = read_imports(output)
        self.assertEqual(info.entry_rva, 0x5252)
        self.assertEqual([(slot.rva, slot.symbol) for slot in actual],
                         [(slot.rva, slot.symbol) for slot in slots])
        self.assertEqual(report["import_count"], 3)
        self.assertEqual(report["import_descriptor_count"], 2)
        self.assertTrue(report["import_table_validated"])
        self.assertFalse(report["portable_verified"])
        self.assertFalse(report["runtime_verified"])
        self.assertEqual(report["relocation_mode"], "fixed_base_required")
        resource_offset = info.rva_to_offset(0x7000, 0x200)
        self.assertEqual(output[resource_offset:resource_offset + 0x200], image[0x7000:0x7200])
        self.assertTrue(report["resource_directory_bytes_preserved"])
        self.assertEqual(info.directory(11).rva, 0)
        self.assertEqual(info.directory(4).rva, 0)
        self.assertEqual(struct.unpack_from("<HHHH", output, info.optional_offset + 40), (6, 1, 2, 3))
        self.assertEqual(info.file_alignment, 0x200)
        self.assertEqual(info.section_alignment, 0x1000)
        self.assertEqual(info.sections[1].characteristics, 0x40000040)

    def test_pe64_names_and_ordinal_high_bit(self) -> None:
        image, slots = fixture(True)
        output, report = rebuild_imports(image, slots, oep_rva=0x5252, loaded_base=0x140000000)
        info = parse_pe(output, "file")
        self.assertTrue(info.is64)
        self.assertEqual(info.pointer_size, 8)
        self.assertEqual(read_imports(output)[1].address, 0x8000000000000007)
        self.assertEqual(report["import_count"], 3)
        for slot in slots:
            offset = info.rva_to_offset(slot.rva, 8)
            self.assertNotEqual(struct.unpack_from("<Q", output, offset)[0], slot.address)

    def test_rebased_capture_records_actual_base_without_invented_relocations(self) -> None:
        image, slots = fixture()
        output, report = rebuild_imports(image, slots, oep_rva=0x5252, loaded_base=0x500000)
        self.assertEqual(parse_pe(output, "file").image_base, 0x500000)
        self.assertEqual(report["original_image_base"], 0x400000)
        self.assertEqual(report["captured_image_base"], 0x500000)
        self.assertEqual(report["directories"]["relocations"]["status"], "absent_in_capture")
        self.assertEqual(parse_pe(output, "file").dll_characteristics, 0x140)

    def test_valid_relocations_preserved_but_not_semantically_claimed(self) -> None:
        for is64 in (False, True):
            with self.subTest(is64=is64):
                image, slots = fixture(is64, True)
                output, report = rebuild_imports(image, slots, oep_rva=0x5252,
                                                loaded_base=parse_pe(image).image_base)
                self.assertEqual(report["relocation_mode"], "preserved_unverified")
                self.assertEqual(report["directories"]["relocations"]["relocation_entries"], 1)
                info = parse_pe(output, "file")
                offset = info.rva_to_offset(0x8000, 12)
                self.assertEqual(output[offset:offset + 12], image[0x8000:0x800C])

    def test_relocation_overlapping_rewritten_iat_is_rejected(self) -> None:
        for is64 in (False, True):
            width = 8 if is64 else 4
            for relative in (0x100, 0xFF, 0x100 + 2 * width):
                with self.subTest(is64=is64, relative=relative):
                    image, slots = fixture(is64, True)
                    captured = bytearray(image)
                    struct.pack_into("<IIHH", captured, 0x8000, 0x6000, 12,
                                     ((10 if is64 else 3) << 12) | relative, 0)
                    with self.assertRaisesRegex(PEFormatError, "base relocation overlaps"):
                        rebuild_imports(bytes(captured), slots, oep_rva=0x5252,
                                        loaded_base=parse_pe(image).image_base)

    def test_stale_slot_pointer_is_rejected(self) -> None:
        image, slots = fixture()
        slots[0] = ImportSlot(slots[0].rva, slots[0].address + 1, slots[0].symbol)
        with self.assertRaisesRegex(PEFormatError, "does not match"):
            rebuild_imports(image, slots, oep_rva=0x5252, loaded_base=0x400000)

    def test_interleaved_dlls_without_a_null_slot_are_rejected(self) -> None:
        image, slots = fixture()
        slots[1] = ImportSlot(slots[1].rva, slots[1].address, ImportSymbol("USER32.dll", "MessageBoxA"))
        with self.assertRaisesRegex(PEFormatError, "null terminator"):
            rebuild_imports(image, slots, oep_rva=0x5252, loaded_base=0x400000)

    def test_omitted_import_does_not_turn_into_a_terminator(self) -> None:
        image, slots = fixture()
        with self.assertRaisesRegex(PEFormatError, "null terminator"):
            rebuild_imports(image, [slots[0], slots[2]], oep_rva=0x5252, loaded_base=0x400000)

    def test_duplicate_slots_are_rejected(self) -> None:
        image, slots = fixture()
        with self.assertRaisesRegex(PEFormatError, "Duplicate"):
            rebuild_imports(image, slots + [slots[0]], oep_rva=0x5252, loaded_base=0x400000)

    def test_invalid_entrypoints_never_mask_to_32_bits(self) -> None:
        image, slots = fixture()
        for oep in (0, -1, 0x6100, 0x405252, 0x100005252):
            with self.subTest(oep=oep), self.assertRaisesRegex(PEFormatError, "OEP"):
                rebuild_imports(image, slots, oep_rva=oep, loaded_base=0x400000)

    def test_truncated_header_and_image_are_rejected(self) -> None:
        image, _ = fixture()
        for cut in (0, 63, 0x9A, 0x3FF, 0x8FFF):
            with self.subTest(cut=cut), self.assertRaises(PEFormatError):
                parse_pe(image[:cut])

    def test_overlapping_sections_are_rejected(self) -> None:
        image, _ = fixture()
        broken = bytearray(image)
        info = parse_pe(image)
        struct.pack_into("<I", broken, info.sections[1].header_offset + 12, 0x5000)
        with self.assertRaisesRegex(PEFormatError, "overlap"):
            parse_pe(bytes(broken))

    def test_occupied_section_header_padding_is_rejected(self) -> None:
        image, slots = fixture()
        info = parse_pe(image)
        broken = bytearray(image)
        broken[info.section_table_offset + len(info.sections) * 40] = 0x41
        with self.assertRaisesRegex(PEFormatError, "section-header space"):
            rebuild_imports(bytes(broken), slots, oep_rva=0x5252, loaded_base=0x400000)

    def test_import_map_cannot_overwrite_resource_directory(self) -> None:
        image, _ = fixture()
        broken = bytearray(image)
        struct.pack_into("<II", broken, 0x7000, 0x76BF2310, 0)
        slot = ImportSlot(0x7000, 0x76BF2310, ImportSymbol("KERNEL32.dll", "ExitProcess"))
        with self.assertRaisesRegex(PEFormatError, "unrelated PE data directory"):
            rebuild_imports(bytes(broken), [slot], oep_rva=0x5252, loaded_base=0x400000)

    def test_malformed_metadata_is_reported_not_fabricated(self) -> None:
        image, slots = fixture()
        info = parse_pe(image)
        broken = bytearray(image)
        struct.pack_into("<II", broken, info.directory_offset + 9 * 8, 0x6500, 4)
        struct.pack_into("<II", broken, info.directory_offset + 10 * 8, 0x6600, 32)
        struct.pack_into("<I", broken, 0x6600, 64)
        struct.pack_into("<II", broken, info.directory_offset + 5 * 8, 0x8000, 10)
        struct.pack_into("<IIH", broken, 0x8000, 0x1000, 7, 0)
        _, report = rebuild_imports(bytes(broken), slots, oep_rva=0x5252, loaded_base=0x400000)
        for name in ("tls", "load_config", "relocations"):
            self.assertEqual(report["directories"][name]["status"], "invalid")

    def test_debug_pointer_is_remapped_to_new_disk_layout(self) -> None:
        image, slots = fixture()
        info = parse_pe(image)
        captured = bytearray(image)
        struct.pack_into("<II", captured, info.directory_offset + 6 * 8, 0x6500, 28)
        struct.pack_into("<IIHHIIII", captured, 0x6500, 0, 0, 0, 0, 2, 8, 0x6600, 0x6600)
        captured[0x6600:0x6608] = b"RSDSdata"
        output, report = rebuild_imports(bytes(captured), slots, oep_rva=0x5252, loaded_base=0x400000)
        disk = parse_pe(output, "file")
        offset = disk.rva_to_offset(0x6500, 28)
        self.assertEqual(struct.unpack_from("<I", output, offset + 24)[0], disk.rva_to_offset(0x6600, 8))
        self.assertEqual(report["directories"]["debug"]["status"], "raw_offsets_remapped")

    def test_unmapped_debug_payload_is_disclosed_and_reference_removed(self) -> None:
        image, slots = fixture()
        info = parse_pe(image)
        captured = bytearray(image)
        struct.pack_into("<II", captured, info.directory_offset + 6 * 8, 0x6500, 28)
        struct.pack_into("<IIHHIIII", captured, 0x6500, 0, 0, 0, 0, 2, 8, 0, 0xD000)
        output, report = rebuild_imports(bytes(captured), slots, oep_rva=0x5252, loaded_base=0x400000)
        self.assertEqual(parse_pe(output, "file").directory(6).rva, 0)
        self.assertEqual(report["directories"]["debug"]["status"], "not_reconstructed")

    def test_analysis_dump_preserves_missing_oep_uncertainty(self) -> None:
        image, _ = fixture()
        output, report = mapped_to_file(image)
        self.assertEqual(parse_pe(output, "file").entry_rva, 0x362F)
        self.assertFalse(report["entry_point_written"])
        self.assertFalse(report["import_table_validated"])
        self.assertFalse(report["runtime_verified"])

    def test_invalid_symbol_identity_is_rejected(self) -> None:
        image, slots = fixture()
        invalid = (
            ImportSymbol("../kernel32.dll", "ExitProcess"),
            ImportSymbol("kernel32.dll", "ExitProcess\0Injected"),
            ImportSymbol("kernel32.dll", "ExitProcess", 2),
            ImportSymbol("kernel32.dll"),
            ImportSymbol("kernel32.dll", ordinal=65536),
        )
        for symbol in invalid:
            with self.subTest(symbol=symbol), self.assertRaises(PEFormatError):
                rebuild_imports(image, [ImportSlot(slots[0].rva, slots[0].address, symbol)] + slots[1:],
                                oep_rva=0x5252, loaded_base=0x400000)

    def test_directory_range_validation_uses_section_bounds(self) -> None:
        image, _ = fixture()
        info = parse_pe(image)
        broken = bytearray(image)
        struct.pack_into("<II", broken, info.directory_offset + 9 * 8, 0x8FF0, 40)
        self.assertEqual(directory_status(bytes(broken))["tls"]["status"], "invalid")

    def test_iat_spanning_sections_is_rejected(self) -> None:
        image, slots = fixture()
        captured = bytearray(image)
        struct.pack_into("<II", captured, 0x7500, 0x77AB3456, 0)
        slots.append(ImportSlot(0x7500, 0x77AB3456, ImportSymbol("ADVAPI32.dll", "RegCloseKey")))
        with self.assertRaisesRegex(PEFormatError, "multiple sections"):
            rebuild_imports(bytes(captured), slots, oep_rva=0x5252, loaded_base=0x400000)

    def test_low_alignment_preserves_file_offset_equals_rva(self) -> None:
        image, slots = fixture()
        info = parse_pe(image)
        captured = bytearray(image)
        struct.pack_into("<I", captured, info.optional_offset + 32, 0x200)
        output, report = rebuild_imports(bytes(captured), slots, oep_rva=0x5252, loaded_base=0x400000)
        disk = parse_pe(output, "file")
        self.assertTrue(all(section.raw_offset == section.virtual_address for section in disk.sections))
        self.assertTrue(report["import_table_validated"])

    def test_truncated_emitted_file_is_rejected(self) -> None:
        image, slots = fixture()
        output, _ = rebuild_imports(image, slots, oep_rva=0x5252, loaded_base=0x400000)
        with self.assertRaises(PEFormatError):
            parse_pe(output[:-1], "file")

    def test_duplicate_dll_can_use_separate_terminated_runs(self) -> None:
        image, slots = fixture()
        slots[2] = ImportSlot(slots[2].rva, slots[2].address, ImportSymbol("KERNEL32.dll", "GetCurrentProcessId"))
        output, report = rebuild_imports(image, slots, oep_rva=0x5252, loaded_base=0x400000)
        self.assertEqual(report["import_descriptor_count"], 2)
        self.assertEqual([slot.rva for slot in read_imports(output)], [slot.rva for slot in slots])

    def test_dll_alias_case_does_not_reorder_original_iat(self) -> None:
        image, slots = fixture()
        slots[1] = ImportSlot(slots[1].rva, slots[1].address, ImportSymbol("kernel32.DLL", ordinal=7))
        output, report = rebuild_imports(image, slots, oep_rva=0x5252, loaded_base=0x400000)
        self.assertEqual(report["import_descriptor_count"], 2)
        self.assertEqual([slot.rva for slot in read_imports(output)], [slot.rva for slot in slots])


if __name__ == "__main__":
    unittest.main()
