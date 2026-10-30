"""Bounded PE32/PE32+ import reconstruction from a captured mapped image.

Only explicit, resolved import slots are accepted. This module does not guess
symbols, run the target, recover missing bytes, or establish runtime equivalence.
The on-disk format follows Microsoft's PE/COFF specification:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
"""

from __future__ import annotations

import struct
from bisect import bisect_left
from dataclasses import dataclass
from typing import Any, Literal

MAX_IMAGE_SIZE = 512 * 1024 * 1024
MAX_IMPORTS = 65536
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
DIRECTORY_NAMES = (
    "exports", "imports", "resources", "exceptions", "security", "relocations",
    "debug", "architecture", "global_pointer", "tls", "load_config",
    "bound_imports", "iat", "delay_imports", "clr", "reserved",
)


class PEFormatError(ValueError):
    """The image or requested reconstruction cannot be represented safely."""


def _range(offset: int, size: int, limit: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        raise PEFormatError(f"{label} is outside the available bytes")


def _u16(data: bytes | bytearray, offset: int) -> int:
    _range(offset, 2, len(data), "16-bit field")
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes | bytearray, offset: int) -> int:
    _range(offset, 4, len(data), "32-bit field")
    return int(struct.unpack_from("<I", data, offset)[0])


def _u64(data: bytes | bytearray, offset: int) -> int:
    _range(offset, 8, len(data), "64-bit field")
    return int(struct.unpack_from("<Q", data, offset)[0])


def _align(value: int, alignment: int) -> int:
    result = (value + alignment - 1) & ~(alignment - 1)
    if result > 0xFFFFFFFF:
        raise PEFormatError("Aligned PE field exceeds the 32-bit RVA space")
    return result


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


@dataclass(frozen=True)
class DataDirectory:
    rva: int
    size: int


@dataclass(frozen=True)
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    header_offset: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)


@dataclass(frozen=True)
class PEInfo:
    is64: bool
    pointer_size: int
    image_base: int
    entry_rva: int
    size_image: int
    size_headers: int
    section_alignment: int
    file_alignment: int
    sections: tuple[PESection, ...]
    data_directories: tuple[DataDirectory, ...]
    pe_offset: int
    optional_offset: int
    section_table_offset: int
    directory_offset: int
    num_directories: int
    machine: int
    characteristics: int
    dll_characteristics: int
    data_length: int
    layout: Literal["mapped", "file"]

    def directory(self, index: int) -> DataDirectory:
        if not 0 <= index < 16:
            raise PEFormatError("Invalid data-directory index")
        if index >= len(self.data_directories):
            return DataDirectory(0, 0)
        return self.data_directories[index]

    def section_at(self, rva: int, size: int = 1) -> PESection | None:
        if rva < 0 or size <= 0:
            return None
        for section in self.sections:
            relative = rva - section.virtual_address
            if 0 <= relative and size <= section.mapped_size - relative:
                return section
        return None

    def executable_rva(self, rva: int) -> bool:
        section = self.section_at(rva)
        return section is not None and bool(section.characteristics & IMAGE_SCN_MEM_EXECUTE)

    def rva_to_offset(self, rva: int, size: int = 1) -> int:
        if size <= 0:
            raise PEFormatError("RVA range must have positive size")
        _range(rva, size, self.size_image, "RVA range")
        if rva < self.size_headers:
            _range(rva, size, self.size_headers, "Header RVA range")
            _range(rva, size, self.data_length, "Header bytes")
            return rva
        section = self.section_at(rva, size)
        if section is None:
            raise PEFormatError(f"RVA range {rva:#x}+{size:#x} is not in one section")
        if self.layout == "mapped":
            _range(rva, size, self.data_length, "Mapped section bytes")
            return rva
        relative = rva - section.virtual_address
        _range(relative, size, section.raw_size, "File-backed section range")
        offset = section.raw_offset + relative
        _range(offset, size, self.data_length, "File-backed section bytes")
        return offset


@dataclass(frozen=True)
class ImportSymbol:
    dll: str
    name: str | None = None
    ordinal: int | None = None


@dataclass(frozen=True)
class ImportSlot:
    rva: int
    address: int
    symbol: ImportSymbol


def parse_pe(data: bytes, layout: Literal["mapped", "file"] = "mapped") -> PEInfo:
    """Parse a complete mapped image or disk file with bounded section ranges."""
    if layout not in ("mapped", "file"):
        raise PEFormatError("PE layout must be 'mapped' or 'file'")
    _range(0, 64, len(data), "DOS header")
    if data[:2] != b"MZ":
        raise PEFormatError("Missing DOS MZ signature")
    pe = _u32(data, 0x3C)
    if pe < 64:
        raise PEFormatError("PE header overlaps the DOS header")
    _range(pe, 24, len(data), "PE/COFF header")
    if data[pe:pe + 4] != b"PE\0\0":
        raise PEFormatError("Missing PE signature")
    machine = _u16(data, pe + 4)
    count = _u16(data, pe + 6)
    size_optional = _u16(data, pe + 20)
    if not 1 <= count <= 96:
        raise PEFormatError("Windows PE must contain 1 to 96 sections")
    opt = pe + 24
    _range(opt, size_optional, len(data), "Optional header")
    magic = _u16(data, opt)
    if magic not in (0x10B, 0x20B):
        raise PEFormatError("Only PE32 and PE32+ images are supported")
    is64 = magic == 0x20B
    if machine != (0x8664 if is64 else 0x14C):
        raise PEFormatError("Only matching x86 PE32 / x64 PE32+ images are supported")
    directory_delta = 112 if is64 else 96
    if size_optional < directory_delta:
        raise PEFormatError("Truncated optional header")
    count_directories = _u32(data, opt + directory_delta - 4)
    if count_directories > 16 or directory_delta + count_directories * 8 > size_optional:
        raise PEFormatError("Data directories exceed the optional header")
    section_alignment = _u32(data, opt + 32)
    file_alignment = _u32(data, opt + 36)
    if not _power_of_two(section_alignment) or not _power_of_two(file_alignment):
        raise PEFormatError("PE alignments must be nonzero powers of two")
    if section_alignment < file_alignment or file_alignment > 65536:
        raise PEFormatError("Invalid section/file alignment relationship")
    if section_alignment < 4096:
        if file_alignment != section_alignment:
            raise PEFormatError("Low-alignment images need equal file and section alignment")
    elif file_alignment < 512:
        raise PEFormatError("FileAlignment must be at least 512 for normal PE images")
    size_image = _u32(data, opt + 56)
    size_headers = _u32(data, opt + 60)
    if not 0 < size_image <= MAX_IMAGE_SIZE or size_image % section_alignment:
        raise PEFormatError("Invalid, unaligned, or excessive SizeOfImage")
    section_table = opt + size_optional
    if not size_headers or size_headers % file_alignment:
        raise PEFormatError("Invalid or unaligned SizeOfHeaders")
    _range(section_table, count * 40, size_headers, "Section table in headers")
    _range(0, size_headers, len(data), "Complete PE headers")
    if size_headers > size_image:
        raise PEFormatError("Headers exceed SizeOfImage")
    if layout == "mapped":
        _range(0, size_image, len(data), "Complete captured image")
    sections: list[PESection] = []
    raw_intervals: list[tuple[int, int]] = []
    previous_end = size_headers
    for index in range(count):
        offset = section_table + index * 40
        raw_name = data[offset:offset + 8].split(b"\0", 1)[0]
        section = PESection(
            name=raw_name.decode("ascii", errors="replace"),
            virtual_size=_u32(data, offset + 8),
            virtual_address=_u32(data, offset + 12),
            raw_size=_u32(data, offset + 16),
            raw_offset=_u32(data, offset + 20),
            characteristics=_u32(data, offset + 36),
            header_offset=offset,
        )
        if section.virtual_address % section_alignment:
            raise PEFormatError(f"Section {section.name} has an unaligned RVA")
        if section.virtual_address < previous_end:
            raise PEFormatError("Sections overlap or are not ordered by RVA")
        _range(section.virtual_address, section.mapped_size, size_image, "Section in image")
        previous_end = _align(section.virtual_address + section.mapped_size, section_alignment)
        if section.raw_size and layout == "file":
            if section.raw_size % file_alignment or section.raw_offset % file_alignment:
                raise PEFormatError("Section file offset/size is not aligned")
            if section_alignment < 4096 and section.raw_offset != section.virtual_address:
                raise PEFormatError("Low-alignment PE sections require identical file offsets and RVAs")
            if section.raw_offset < size_headers:
                raise PEFormatError("Section raw bytes overlap PE headers")
            _range(section.raw_offset, section.raw_size, len(data), "Complete raw section")
            interval = (section.raw_offset, section.raw_offset + section.raw_size)
            if any(interval[0] < end and start < interval[1] for start, end in raw_intervals):
                raise PEFormatError("Raw section ranges overlap")
            raw_intervals.append(interval)
        sections.append(section)
    if previous_end > size_image:
        raise PEFormatError("Aligned sections exceed SizeOfImage")
    directories = tuple(
        DataDirectory(_u32(data, opt + directory_delta + index * 8),
                      _u32(data, opt + directory_delta + index * 8 + 4))
        for index in range(count_directories)
    )
    return PEInfo(
        is64=is64, pointer_size=8 if is64 else 4,
        image_base=_u64(data, opt + 24) if is64 else _u32(data, opt + 28),
        entry_rva=_u32(data, opt + 16), size_image=size_image,
        size_headers=size_headers, section_alignment=section_alignment,
        file_alignment=file_alignment, sections=tuple(sections),
        data_directories=directories, pe_offset=pe, optional_offset=opt,
        section_table_offset=section_table, directory_offset=opt + directory_delta,
        num_directories=count_directories, machine=machine,
        characteristics=_u16(data, pe + 22),
        dll_characteristics=_u16(data, opt + 70), data_length=len(data), layout=layout,
    )


def _set_directory(data: bytearray, info: PEInfo, index: int, rva: int, size: int) -> None:
    if index >= info.num_directories:
        if rva or size:
            raise PEFormatError("Optional header has no room for a required directory")
        return
    struct.pack_into("<II", data, info.directory_offset + index * 8, rva, size)


def _read_pointer(data: bytes | bytearray, offset: int, width: int) -> int:
    return _u64(data, offset) if width == 8 else _u32(data, offset)


def _write_pointer(data: bytearray, offset: int, value: int, width: int) -> None:
    if not 0 <= value < 1 << (width * 8):
        raise PEFormatError("Pointer value exceeds target architecture")
    struct.pack_into("<Q" if width == 8 else "<I", data, offset, value)


def _ascii_z(value: str, label: str, maximum: int) -> bytes:
    if not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        raise PEFormatError(f"Invalid {label}")
    try:
        return value.encode("ascii") + b"\0"
    except UnicodeEncodeError as exc:
        raise PEFormatError(f"{label} must contain exact ASCII bytes") from exc


def _validate_symbol(symbol: ImportSymbol) -> None:
    _ascii_z(symbol.dll, "DLL basename", 255)
    if any(char in symbol.dll for char in '/\\:<>"|?*') or symbol.dll in (".", ".."):
        raise PEFormatError("DLL import must be a basename without a path")
    if (symbol.name is None) == (symbol.ordinal is None):
        raise PEFormatError("An import needs exactly one name or ordinal")
    if symbol.name is not None:
        _ascii_z(symbol.name, "export name", 4096)
    if symbol.ordinal is not None and not 0 <= symbol.ordinal <= 65535:
        raise PEFormatError("Import ordinal does not fit the 16-bit PE ordinal field")


def _relocation_status(data: bytes, info: PEInfo) -> dict[str, Any]:
    directory = info.directory(5)
    if not directory.rva and not directory.size:
        return {"status": "absent_in_capture", "relocation_entries": 0}
    if not directory.rva or not directory.size:
        return {"status": "invalid", "reason": "Incomplete relocation directory"}
    try:
        offset = info.rva_to_offset(directory.rva, directory.size)
        end = offset + directory.size
        count = 0
        while offset < end:
            _range(offset, 8, end, "Relocation block header")
            page = _u32(data, offset)
            block_size = _u32(data, offset + 4)
            if block_size < 8 or block_size % 2 or page % 4096:
                raise PEFormatError("Malformed relocation block")
            _range(offset, block_size, end, "Relocation block")
            for position in range(offset + 8, offset + block_size, 2):
                entry = _u16(data, position)
                kind, relative = entry >> 12, entry & 0xFFF
                if not kind:
                    continue
                if kind != (10 if info.is64 else 3):
                    return {"status": "unsupported", "reason": f"Relocation type {kind}"}
                info.rva_to_offset(page + relative, info.pointer_size)
                count += 1
            offset += block_size
        return {"status": "structurally_valid", "relocation_entries": count,
                "semantics_verified": False}
    except PEFormatError as exc:
        return {"status": "invalid", "reason": str(exc)}


def directory_status(data: bytes, info: PEInfo | None = None) -> dict[str, dict[str, Any]]:
    """Describe captured ranges; range validity is not semantic reconstruction."""
    pe = info if info is not None else parse_pe(data)
    result: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(DIRECTORY_NAMES):
        directory = pe.directory(index)
        status: dict[str, Any] = {"rva": directory.rva, "size": directory.size}
        if not directory.rva and not directory.size:
            status["status"] = "absent_in_capture"
        elif index == 4:
            status.update(status="not_mapped", reason="Certificates use disk offsets, not RVAs")
        elif not directory.rva or not directory.size:
            status.update(status="invalid", reason="Incomplete RVA/size pair")
        else:
            try:
                pe.rva_to_offset(directory.rva, directory.size)
                status.update(status="range_preserved", semantics_verified=False)
                if index == 9:
                    if directory.size < (40 if pe.is64 else 24):
                        raise PEFormatError("TLS directory is too short")
                    status["reason"] = "TLS pointers/callback state are not reconstructed"
                elif index == 10:
                    declared = _u32(data, pe.rva_to_offset(directory.rva, 4))
                    if declared < 4 or declared > directory.size:
                        raise PEFormatError("Load Config size exceeds captured directory")
                    status["reason"] = "CFG, SafeSEH and security-cookie semantics are unverified"
                elif index == 13:
                    status["reason"] = "Delay imports are preserved but not reconstructed"
            except PEFormatError as exc:
                status.update(status="invalid", reason=str(exc))
        result[name] = status
    result["relocations"].update(_relocation_status(data, pe))
    return result


def _base_report(data: bytes, info: PEInfo, loaded_base: int) -> dict[str, Any]:
    directories = directory_status(data, info)
    relocation = directories["relocations"]
    relocations_usable = (relocation["status"] == "structurally_valid"
                          and relocation.get("relocation_entries", 0) > 0
                          and not info.characteristics & 1)
    limitations = [
        "A memory snapshot does not recover the original initial data state or code/data boundaries.",
        "The selected entry point is caller-supplied; executable-section membership is not OEP proof.",
        "Runtime behavior and cross-machine compatibility require separate controlled execution tests.",
    ]
    if not relocations_usable:
        limitations.append("Relocation support is absent/unverified; the captured image base is required.")
    for name in ("tls", "load_config", "delay_imports"):
        if directories[name]["status"] != "absent_in_capture":
            limitations.append(f"{name} was captured but its initialization semantics remain unverified.")
    return {
        "artifact_kind": "analysis_pe", "runtime_verified": False, "portable_verified": False,
        "original_image_base": info.image_base, "captured_image_base": loaded_base,
        "output_image_base": loaded_base,
        "relocation_mode": "preserved_unverified" if relocations_usable else "fixed_base_required",
        "directories": directories, "limitations": limitations,
        "signature_preserved": False, "initial_state_recovered": False,
    }


def _validate_base(info: PEInfo, loaded_base: int) -> None:
    if loaded_base <= 0 or loaded_base % 65536:
        raise PEFormatError("Captured image base must be a positive 64 KiB-aligned address")
    if loaded_base + info.size_image > 1 << (info.pointer_size * 8):
        raise PEFormatError("Captured image exceeds target address space")


def _fix_debug_offsets(out: bytearray, info: PEInfo, report: dict[str, Any]) -> None:
    directory = info.directory(6)
    if not directory.rva and not directory.size:
        return
    try:
        if not directory.rva or not directory.size or directory.size % 28:
            raise PEFormatError("Malformed debug-directory array")
        offset = info.rva_to_offset(directory.rva, directory.size)
        for position in range(offset, offset + directory.size, 28):
            size = _u32(out, position + 16)
            payload_rva = _u32(out, position + 20)
            if not size:
                struct.pack_into("<I", out, position + 24, 0)
            elif payload_rva:
                raw_offset = info.rva_to_offset(payload_rva, size)
                struct.pack_into("<I", out, position + 24, raw_offset)
            else:
                raise PEFormatError("Debug payload exists only at an original disk offset")
        report["directories"]["debug"].update(status="raw_offsets_remapped", semantics_verified=False)
    except PEFormatError as exc:
        # Keep the captured bytes for analysis, but remove the invalid loader-facing
        # reference. The report records that the debug data could not be restored.
        _set_directory(out, info, 6, 0, 0)
        report["directories"]["debug"].update(status="not_reconstructed", reason=str(exc))
        report["limitations"].append("Debug directory reference removed because its payload was not fully captured.")


def _emit_file(image: bytes, info: PEInfo, *, oep_rva: int | None,
               loaded_base: int) -> tuple[bytes, dict[str, Any]]:
    _validate_base(info, loaded_base)
    if oep_rva is not None and not info.executable_rva(oep_rva):
        raise PEFormatError("Selected OEP RVA is outside captured executable section bytes")
    out = bytearray(image[:info.size_headers])
    report = _base_report(image, info, loaded_base)
    cursor = info.size_headers
    size_code = 0
    size_initialized = 0
    for section in info.sections:
        amount = section.mapped_size
        raw_size = _align(amount, info.file_alignment) if amount else 0
        raw_offset = (section.virtual_address if info.section_alignment < 4096 else cursor) if raw_size else 0
        if raw_size:
            if raw_offset < len(out):
                raise PEFormatError("Realigned section would overlap preceding file bytes")
            out.extend(b"\0" * (raw_offset - len(out)))
            out.extend(image[section.virtual_address:section.virtual_address + amount])
            out.extend(b"\0" * (raw_size - amount))
            cursor = raw_offset + raw_size
        struct.pack_into("<II", out, section.header_offset + 16, raw_size, raw_offset)
        if section.characteristics & 0x20:
            size_code += raw_size
        if section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA:
            size_initialized += raw_size
        # COFF relocation/line-number records are file-layout metadata absent from
        # a normal mapped image, not the separate PE base-relocation directory.
        struct.pack_into("<IIHH", out, section.header_offset + 24, 0, 0, 0, 0)
    struct.pack_into("<II", out, info.optional_offset + 4, size_code, size_initialized)
    struct.pack_into("<I", out, info.optional_offset + 64, 0)  # CheckSum
    struct.pack_into("<II", out, info.pe_offset + 12, 0, 0)  # COFF symbol table
    if info.is64:
        struct.pack_into("<Q", out, info.optional_offset + 24, loaded_base)
    else:
        struct.pack_into("<I", out, info.optional_offset + 28, loaded_base)
    if oep_rva is not None:
        struct.pack_into("<I", out, info.optional_offset + 16, oep_rva)
    _set_directory(out, info, 4, 0, 0)
    report["directories"]["security"].update(status="not_preserved", reason="Rewriting invalidates Authenticode; certificates are not mapped")
    emitted_info = parse_pe(bytes(out), layout="file")
    _fix_debug_offsets(out, emitted_info, report)
    report.update(entry_point_rva=emitted_info.entry_rva,
                  entry_point_written=oep_rva is not None,
                  output_size=len(out), import_table_validated=False)
    return bytes(out), report


def mapped_to_file(image: bytes, *, oep_rva: int | None = None,
                   loaded_base: int | None = None) -> tuple[bytes, dict[str, Any]]:
    """Realign captured sections for analysis, without claiming import repair."""
    info = parse_pe(image)
    return _emit_file(image, info, oep_rva=oep_rva,
                      loaded_base=info.image_base if loaded_base is None else loaded_base)


def _import_groups(image: bytes, info: PEInfo, slots: list[ImportSlot]) -> list[list[ImportSlot]]:
    if not slots or len(slots) > MAX_IMPORTS:
        raise PEFormatError(f"Import count must be between 1 and {MAX_IMPORTS}")
    ordered = sorted(slots, key=lambda slot: slot.rva)
    groups: list[list[ImportSlot]] = []
    current: list[ImportSlot] = []
    previous_rva = -1
    for slot in ordered:
        _validate_symbol(slot.symbol)
        if slot.rva % info.pointer_size:
            raise PEFormatError("IAT slot is not pointer-aligned")
        if slot.rva == previous_rva:
            raise PEFormatError("Duplicate IAT slot RVA")
        if info.section_at(slot.rva, info.pointer_size) is None:
            raise PEFormatError("IAT slots must be captured section bytes")
        for index, directory in enumerate(info.data_directories):
            if index in (1, 4, 11, 12) or not directory.rva or not directory.size:
                continue
            if slot.rva < directory.rva + directory.size and directory.rva < slot.rva + info.pointer_size:
                raise PEFormatError("IAT slot overlaps an unrelated PE data directory")
        offset = info.rva_to_offset(slot.rva, info.pointer_size)
        if not slot.address or _read_pointer(image, offset, info.pointer_size) != slot.address:
            raise PEFormatError("Import-map address does not match the captured IAT slot")
        if current and (slot.rva != current[-1].rva + info.pointer_size
                        or slot.symbol.dll.casefold() != current[0].symbol.dll.casefold()):
            groups.append(current)
            current = []
        current.append(slot)
        previous_rva = slot.rva
    groups.append(current)
    for group in groups:
        end_rva = group[-1].rva + info.pointer_size
        end_offset = info.rva_to_offset(end_rva, info.pointer_size)
        if _read_pointer(image, end_offset, info.pointer_size):
            raise PEFormatError(
                "Each same-DLL IAT run requires an existing null terminator; "
                "interleaved DLLs or omitted nonzero slots need explicit reference relocation"
            )
    start = groups[0][0].rva
    end = groups[-1][-1].rva + 2 * info.pointer_size
    if info.section_at(start, end - start) is None:
        raise PEFormatError("A rebuilt IAT spanning multiple sections is not supported")
    return groups


def _new_section_space(image: bytes, info: PEInfo) -> int:
    if len(info.sections) >= 96:
        raise PEFormatError("No additional PE section is permitted")
    offset = info.section_table_offset + len(info.sections) * 40
    _range(offset, 40, info.size_headers, "New section header")
    if any(image[offset:offset + 40]):
        raise PEFormatError("No unused zero-filled section-header space is available")
    for index, directory in enumerate(info.data_directories):
        if index == 4 or not directory.rva or not directory.size:
            continue
        if directory.rva < offset + 40 and offset < directory.rva + directory.size:
            raise PEFormatError("New section header would overlap a data directory")
    if any(section.name == ".reaiat" for section in info.sections):
        raise PEFormatError("Image already contains a .reaiat rebuild section")
    return offset


def _reject_relocated_iat(image: bytes, info: PEInfo, slots: list[ImportSlot]) -> None:
    """Do not leave base relocations that would corrupt new unbound IAT RVAs."""
    if info.characteristics & 1 or _relocation_status(image, info)["status"] != "structurally_valid":
        return
    directory = info.directory(5)
    offset = info.rva_to_offset(directory.rva, directory.size)
    end = offset + directory.size
    width = info.pointer_size
    # Include each run's existing terminator: relocating a null entry would
    # also destroy the table's required shape. Adjacent selected slots dedupe.
    slot_rvas = sorted({rva for slot in slots for rva in (slot.rva, slot.rva + width)})
    while offset < end:
        page = _u32(image, offset)
        block_size = _u32(image, offset + 4)
        for position in range(offset + 8, offset + block_size, 2):
            entry = _u16(image, position)
            if not entry >> 12:
                continue
            target = page + (entry & 0xFFF)
            insertion = bisect_left(slot_rvas, target)
            adjacent = slot_rvas[max(0, insertion - 1):insertion + 1]
            if any(target < rva + width and rva < target + width for rva in adjacent):
                raise PEFormatError(
                    "A base relocation overlaps a rewritten IAT slot or terminator; "
                    "preserving it would corrupt the new name/ordinal thunk"
                )
        offset += block_size


def _read_c_string(data: bytes, info: PEInfo, rva: int, maximum: int = 4096) -> str:
    result = bytearray()
    for index in range(maximum + 1):
        value = data[info.rva_to_offset(rva + index)]
        if not value:
            try:
                return result.decode("ascii")
            except UnicodeDecodeError as exc:
                raise PEFormatError("Import string contains non-ASCII bytes") from exc
        result.append(value)
    raise PEFormatError("Unterminated import string")


def read_imports(data: bytes, info: PEInfo | None = None) -> list[ImportSlot]:
    """Read unbound named/ordinal imports from a disk file for verification."""
    pe = info if info is not None else parse_pe(data, layout="file")
    directory = pe.directory(1)
    if not directory.rva or directory.size < 20:
        raise PEFormatError("Missing or truncated import directory")
    offset = pe.rva_to_offset(directory.rva, directory.size)
    result: list[ImportSlot] = []
    ordinal_flag = 1 << (pe.pointer_size * 8 - 1)
    for relative in range(0, directory.size - 19, 20):
        fields = struct.unpack_from("<IIIII", data, offset + relative)
        if not any(fields):
            return result
        original_thunk, stamp, forwarder, dll_rva, first_thunk = fields
        if not original_thunk or not dll_rva or not first_thunk or stamp or forwarder:
            raise PEFormatError("Invalid rebuilt import descriptor")
        dll = _read_c_string(data, pe, dll_rva, 255)
        for index in range(MAX_IMPORTS + 1):
            lookup_offset = pe.rva_to_offset(original_thunk + index * pe.pointer_size, pe.pointer_size)
            slot_rva = first_thunk + index * pe.pointer_size
            slot_offset = pe.rva_to_offset(slot_rva, pe.pointer_size)
            value = _read_pointer(data, lookup_offset, pe.pointer_size)
            actual = _read_pointer(data, slot_offset, pe.pointer_size)
            if actual != value:
                raise PEFormatError("Rebuilt lookup and IAT thunks differ")
            if not value:
                break
            if len(result) >= MAX_IMPORTS:
                raise PEFormatError("Import table exceeds the configured bound")
            if value & ordinal_flag:
                if value & ~(ordinal_flag | 0xFFFF):
                    raise PEFormatError("Reserved ordinal thunk bits are nonzero")
                symbol = ImportSymbol(dll=dll, ordinal=value & 0xFFFF)
            else:
                if value > 0xFFFFFFFF:
                    raise PEFormatError("Name thunk is not a 32-bit RVA")
                pe.rva_to_offset(value, 2)
                symbol = ImportSymbol(dll=dll, name=_read_c_string(data, pe, value + 2))
            _validate_symbol(symbol)
            result.append(ImportSlot(rva=slot_rva, address=value, symbol=symbol))
        else:
            raise PEFormatError("Unterminated import lookup table")
    raise PEFormatError("Import descriptors have no null terminator")


def rebuild_imports(image: bytes, slots: list[ImportSlot], *, oep_rva: int,
                    loaded_base: int) -> tuple[bytes, dict[str, Any]]:
    """Write a new import directory while preserving all supplied IAT slot RVAs.

    Each contiguous DLL run must already have a captured null terminator. A
    scattered/interleaved table that would overwrite neighboring data is refused.
    The caller must bind the import map to the capture's hash and provenance.
    """
    info = parse_pe(image)
    _validate_base(info, loaded_base)
    if not info.executable_rva(oep_rva):
        raise PEFormatError("Selected OEP RVA is outside captured executable section bytes")
    if info.num_directories < 13:
        raise PEFormatError("Optional header has no IAT data-directory field")
    groups = _import_groups(image, info, slots)
    _reject_relocated_iat(image, info, slots)
    header_offset = _new_section_space(image, info)
    new_rva = _align(info.size_image, info.section_alignment)
    payload = bytearray(20 * (len(groups) + 1))
    replacements: list[tuple[int, int]] = []
    for group_index, group in enumerate(groups):
        dll_offset = len(payload)
        payload.extend(_ascii_z(group[0].symbol.dll, "DLL basename", 255))
        payload.extend(b"\0" * (-len(payload) % info.pointer_size))
        lookup_offset = len(payload)
        payload.extend(b"\0" * ((len(group) + 1) * info.pointer_size))
        for symbol_index, slot in enumerate(group):
            symbol = slot.symbol
            if symbol.ordinal is not None:
                value = (1 << (info.pointer_size * 8 - 1)) | symbol.ordinal
            else:
                payload.extend(b"\0" * (len(payload) % 2))
                value = new_rva + len(payload)
                payload.extend(b"\0\0")  # zero is a valid non-binding import hint
                assert symbol.name is not None
                payload.extend(_ascii_z(symbol.name, "export name", 4096))
            _write_pointer(payload, lookup_offset + symbol_index * info.pointer_size, value, info.pointer_size)
            replacements.append((slot.rva, value))
        struct.pack_into("<IIIII", payload, group_index * 20,
                         new_rva + lookup_offset, 0, 0, new_rva + dll_offset, group[0].rva)
    new_size = _align(new_rva + len(payload), info.section_alignment)
    if new_size > MAX_IMAGE_SIZE:
        raise PEFormatError("Rebuilt image exceeds the configured size bound")
    mapped = bytearray(image[:info.size_image])
    mapped.extend(b"\0" * (new_size - len(mapped)))
    mapped[new_rva:new_rva + len(payload)] = payload
    struct.pack_into("<8sIIIIIIHHI", mapped, header_offset, b".reaiat\0",
                     len(payload), new_rva, len(payload), 0, 0, 0, 0, 0,
                     IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ)
    struct.pack_into("<H", mapped, info.pe_offset + 6, len(info.sections) + 1)
    struct.pack_into("<I", mapped, info.optional_offset + 56, new_size)
    _set_directory(mapped, info, 1, new_rva, 20 * (len(groups) + 1))
    _set_directory(mapped, info, 11, 0, 0)
    iat_start = groups[0][0].rva
    iat_end = groups[-1][-1].rva + 2 * info.pointer_size
    _set_directory(mapped, info, 12, iat_start, iat_end - iat_start)
    for rva, value in replacements:
        _write_pointer(mapped, rva, value, info.pointer_size)
    # Keep the original section protections. The loader handles an IAT in a
    # read-only section; making an executable section writable is unnecessary.
    iat_section = info.section_at(iat_start, iat_end - iat_start)
    assert iat_section is not None
    expanded = parse_pe(bytes(mapped))
    output, report = _emit_file(bytes(mapped), expanded, oep_rva=oep_rva, loaded_base=loaded_base)
    parsed = parse_pe(output, layout="file")
    verified = read_imports(output, parsed)
    expected = [(slot.rva, slot.symbol.dll.casefold(), slot.symbol.name, slot.symbol.ordinal)
                for slot in sorted(slots, key=lambda item: item.rva)]
    actual = [(slot.rva, slot.symbol.dll.casefold(), slot.symbol.name, slot.symbol.ordinal)
              for slot in verified]
    if actual != expected or parsed.entry_rva != oep_rva:
        raise PEFormatError("Independent output traversal did not reproduce the requested imports/OEP")
    resource = info.directory(2)
    resource_preserved: bool | None = None
    if resource.rva and resource.size:
        try:
            old_offset = info.rva_to_offset(resource.rva, resource.size)
            new_offset = parsed.rva_to_offset(resource.rva, resource.size)
            resource_preserved = image[old_offset:old_offset + resource.size] == output[new_offset:new_offset + resource.size]
        except PEFormatError:
            resource_preserved = False
    report.update(
        artifact_kind="import_rebuilt_analysis_pe", import_table_validated=True,
        import_count=len(verified), import_descriptor_count=len(groups),
        iat_slots_preserved=True, resource_directory_bytes_preserved=resource_preserved,
        original_image_base=info.image_base,
        original_section_protections_preserved=True,
    )
    report["directories"]["imports"].update(status="rebuilt_and_validated", semantics_verified=True)
    report["directories"]["iat"].update(status="rebuilt_and_validated", semantics_verified=True)
    report["directories"]["bound_imports"].update(status="cleared_stale_bindings")
    return output, report
