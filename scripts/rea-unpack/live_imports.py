"""Exact live-export evidence for import reconstruction.

The caller must pause the debuggee and keep the same process alive for the
whole capture. This module never loads a DLL, calls a target export, or writes
target memory. A pointer scan only proposes ranges for review.

Format/API references:
https://learn.microsoft.com/windows/win32/debug/pe-format
https://learn.microsoft.com/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
https://learn.microsoft.com/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32w
https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pe_rebuild import ImportSlot, ImportSymbol, PEFormatError, PEInfo

ReadMemory = Callable[[int, int], bytes]
MAX_EXPORTS = 1_000_000
MAX_STRING = 4096
MAX_MODULE_SIZE = 1024 * 1024 * 1024
MAX_IAT_SLOTS = 1_000_000
MAX_FORWARD_DEPTH = 32


@dataclass(frozen=True)
class ModuleInfo:
    """One loaded module from a single paused-process snapshot."""

    name: str
    path: str
    base: int
    size: int


def _address_limit(pointer_size: int) -> int:
    if not isinstance(pointer_size, int) or pointer_size not in (4, 8):
        raise PEFormatError("A debugger pointer size must be 4 or 8 bytes.")
    return 1 << (pointer_size * 8)


def _validate_address_range(address: int, size: int, limit: int) -> None:
    if (not isinstance(address, int) or isinstance(address, bool)
            or not isinstance(size, int) or isinstance(size, bool)):
        raise PEFormatError("A bridge memory address and byte count must be integers.")
    if address < 0 or address >= limit:
        raise PEFormatError("The memory address exceeds the target debugger's pointer width.")
    if size <= 0 or size >= limit:
        raise PEFormatError("The memory byte count must be positive and fit the target debugger's pointer width.")
    if size > limit - address:
        raise PEFormatError("The memory range extends beyond the target debugger's address space.")


def addressable_modules(
    modules: list[ModuleInfo], pointer_size: int,
) -> tuple[list[ModuleInfo], list[dict[str, Any]]]:
    """Exclude module extents the target debugger cannot address.

    A 64-bit Toolhelp caller can see native 64-bit modules in a WOW64 process.
    Those module addresses must never be serialized into a 32-bit debugger's
    native memory-read request, even though Python itself can represent them.
    """
    limit = _address_limit(pointer_size)
    kept: list[ModuleInfo] = []
    skipped: list[dict[str, Any]] = []
    for module in modules:
        try:
            _validate_address_range(module.base, module.size, limit)
        except PEFormatError as error:
            skipped.append({
                "kind": "module_not_addressable_by_debugger",
                "name": module.name, "path": module.path,
                "base": module.base, "size": module.size,
                "pointer_size": pointer_size, "address_bits": pointer_size * 8,
                "reason": str(error),
            })
        else:
            kept.append(module)
    return kept, skipped


def bounded_memory_reader(read_memory: ReadMemory, pointer_size: int) -> ReadMemory:
    """Reject unrepresentable address/count arguments before invoking a bridge."""
    limit = _address_limit(pointer_size)

    def read(address: int, size: int) -> bytes:
        _validate_address_range(address, size, limit)
        return read_memory(address, size)

    return read


@dataclass(frozen=True)
class ExportCandidate:
    """One exact export identity; forwarders retain their public identity."""

    symbol: ImportSymbol
    module_base: int
    export_rva: int
    export_ordinal: int
    machine: int
    direct: bool = True
    forwarder_chain: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return the complete serializable evidence for this candidate."""
        return {
            **symbol_dict(self.symbol),
            "module_base": self.module_base,
            "export_rva": self.export_rva,
            "export_ordinal": self.export_ordinal,
            "machine": self.machine,
            "architecture": "x64" if self.machine == 0x8664 else "x86",
            "direct": self.direct,
            "forwarder_chain": list(self.forwarder_chain),
        }


@dataclass
class ExportIndex:
    """Index by exact live address, with module provenance and read errors."""

    by_address: dict[int, list[ExportCandidate]] = field(default_factory=dict)
    modules: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        """Return metadata without duplicating every export candidate."""
        return {
            "address_count": len(self.by_address),
            "candidate_count": sum(len(items) for items in self.by_address.values()),
            "modules": self.modules,
            "diagnostics": self.diagnostics,
            "resolution_basis": "exact exports read from the captured live modules",
            "original_import_identity_proven": False,
            "cross_windows_version_compatibility_proven": False,
        }


@dataclass(frozen=True)
class _Definition:
    module: ModuleInfo
    machine: int
    ordinal: int
    name: str | None
    rva: int
    forwarder: str | None


class _ModuleEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("th32ModuleID", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("GlblcntUsage", ctypes.c_uint32),
        ("ProccntUsage", ctypes.c_uint32),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", ctypes.c_uint32),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


def _kernel32() -> Any:
    if os.name != "nt":
        raise OSError("Live process enumeration requires Windows.")
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.CloseHandle.argtypes = [ctypes.c_void_p]
    library.CloseHandle.restype = ctypes.c_int
    return library


def enumerate_modules(pid: int) -> list[ModuleInfo]:
    """Enumerate native and WOW64 modules using documented Toolhelp APIs.

    A 64-bit Python process can enumerate both architectures. A 32-bit Python
    process cannot enumerate a 64-bit target; Windows' failure is surfaced.
    """
    if isinstance(pid, bool) or not 0 < pid <= 0xFFFFFFFF:
        raise ValueError("A positive 32-bit process ID is required.")
    kernel = _kernel32()
    kernel.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    kernel.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    for name in ("Module32FirstW", "Module32NextW"):
        function = getattr(kernel, name)
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ModuleEntry32W)]
        function.restype = ctypes.c_int
    invalid_handle = ctypes.c_void_p(-1).value
    snapshot = invalid_handle
    for attempt in range(5):
        snapshot = kernel.CreateToolhelp32Snapshot(0x00000008 | 0x00000010, pid)
        if snapshot != invalid_handle:
            break
        error = ctypes.get_last_error()
        if error != 24 or attempt == 4:  # ERROR_BAD_LENGTH can be transient.
            raise ctypes.WinError(error)
        time.sleep(0.01)
    if snapshot is None or snapshot == invalid_handle:
        raise OSError("Toolhelp returned an invalid snapshot handle.")
    modules: list[ModuleInfo] = []
    try:
        entry = _ModuleEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        success = kernel.Module32FirstW(snapshot, ctypes.byref(entry))
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())
        while success:
            base = int(entry.modBaseAddr or 0)
            size = int(entry.modBaseSize)
            if not base or not 0 < size <= MAX_MODULE_SIZE:
                raise PEFormatError("Toolhelp returned an invalid module extent.")
            modules.append(ModuleInfo(str(entry.szModule), str(entry.szExePath), base, size))
            if len(modules) > 4096:
                raise PEFormatError("Module count exceeds the capture limit.")
            entry.dwSize = ctypes.sizeof(entry)
            success = kernel.Module32NextW(snapshot, ctypes.byref(entry))
        error = ctypes.get_last_error()
        if error != 18:  # ERROR_NO_MORE_FILES is the only normal end condition.
            raise ctypes.WinError(error)
    finally:
        kernel.CloseHandle(snapshot)
    return sorted(modules, key=lambda item: item.base)


def process_creation_time(pid: int) -> int:
    """Return creation FILETIME (100 ns since 1601), distinguishing reused PIDs."""
    if isinstance(pid, bool) or not 0 < pid <= 0xFFFFFFFF:
        raise ValueError("A positive 32-bit process ID is required.")
    kernel = _kernel32()
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(_FileTime)] * 4
    kernel.GetProcessTimes.restype = ctypes.c_int
    handle = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        created, exited, system, user = (_FileTime() for _ in range(4))
        if not kernel.GetProcessTimes(
            handle, ctypes.byref(created), ctypes.byref(exited),
            ctypes.byref(system), ctypes.byref(user),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return (int(created.high) << 32) | int(created.low)
    finally:
        kernel.CloseHandle(handle)


def symbol_dict(symbol: ImportSymbol) -> dict[str, Any]:
    """Serialize the import identity without conflating ordinal and hint."""
    return {"dll": symbol.dll, "name": symbol.name, "ordinal": symbol.ordinal}


def _module_key(name: str) -> str:
    key = name.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if not key or any(ord(char) < 32 or ord(char) > 126 for char in key):
        raise PEFormatError("A module import name must be a nonempty ASCII basename.")
    return key if key.endswith((".dll", ".exe")) else key + ".dll"


class _ModuleReader:
    def __init__(self, module: ModuleInfo, read_memory: ReadMemory) -> None:
        self.module = module
        self.read_memory = read_memory
        self.pages: dict[int, bytes] = {}

    def read(self, rva: int, size: int) -> bytes:
        if rva < 0 or size < 0 or rva + size > self.module.size:
            raise PEFormatError("An export read lies outside its loaded module.")
        chunks: list[bytes] = []
        end = rva + size
        while rva < end:
            page_rva = rva & ~0xFFF
            page_size = min(0x1000, self.module.size - page_rva)
            if page_rva not in self.pages:
                data = self.read_memory(self.module.base + page_rva, page_size)
                if not isinstance(data, bytes) or len(data) != page_size:
                    raise PEFormatError(
                        f"Incomplete export page at {self.module.base + page_rva:#x}: "
                        f"expected {page_size} bytes."
                    )
                self.pages[page_rva] = data
            count = min(end - rva, page_size - (rva - page_rva))
            start = rva - page_rva
            chunks.append(self.pages[page_rva][start:start + count])
            rva += count
        return b"".join(chunks)

    def cstring(self, rva: int, *, limit: int = MAX_STRING) -> str:
        if rva <= 0 or rva >= self.module.size:
            raise PEFormatError("An export string has an invalid RVA.")
        chunks: list[bytes] = []
        end = min(self.module.size, rva + limit)
        while rva < end:
            size = min(end - rva, 0x1000 - (rva & 0xFFF))
            data = self.read(rva, size)
            terminator = data.find(b"\0")
            if terminator >= 0:
                chunks.append(data[:terminator])
                result = b"".join(chunks)
                if not result or any(byte < 32 or byte > 126 for byte in result):
                    raise PEFormatError("An export string is not nonempty printable ASCII.")
                return result.decode("ascii")
            chunks.append(data)
            rva += size
        raise PEFormatError("An export string has no bounded terminator.")


def _header_identity(reader: _ModuleReader) -> dict[str, Any]:
    dos = reader.read(0, 64)
    if dos[:2] != b"MZ":
        raise PEFormatError("Loaded module has no DOS header.")
    pe_offset = struct.unpack_from("<I", dos, 60)[0]
    if pe_offset < 64 or pe_offset > 1024 * 1024:
        raise PEFormatError("Loaded module PE header offset is invalid.")
    coff = reader.read(pe_offset, 24)
    if coff[:4] != b"PE\0\0":
        raise PEFormatError("Loaded module has no PE signature.")
    machine, sections, timestamp = struct.unpack_from("<HHI", coff, 4)
    optional_size = struct.unpack_from("<H", coff, 20)[0]
    if sections == 0 or sections > 96 or optional_size > 4096:
        raise PEFormatError("Loaded module header has invalid section/optional-header sizes.")
    optional = reader.read(pe_offset + 24, optional_size)
    if len(optional) < 2:
        raise PEFormatError("Loaded module optional header is truncated.")
    magic = struct.unpack_from("<H", optional)[0]
    directory_offset = 112 if magic == 0x20B else 96
    if magic not in (0x10B, 0x20B) or len(optional) < directory_offset:
        raise PEFormatError("Loaded module has an unsupported or truncated optional header.")
    if (magic == 0x20B and machine != 0x8664) or (magic == 0x10B and machine != 0x14C):
        raise PEFormatError("Export capture supports x86 and x64 module images only.")
    if reader.module.base + reader.module.size > 1 << (64 if magic == 0x20B else 32):
        raise PEFormatError("Loaded module extent exceeds its architecture's address space.")
    size_image = struct.unpack_from("<I", optional, 56)[0]
    directory_count = struct.unpack_from("<I", optional, directory_offset - 4)[0]
    if size_image != reader.module.size:
        raise PEFormatError("Live header SizeOfImage differs from the captured module extent.")
    if directory_count > (len(optional) - directory_offset) // 8:
        raise PEFormatError("Loaded module data directories exceed the optional header.")
    export_rva, export_size = (
        struct.unpack_from("<II", optional, directory_offset)
        if directory_count else (0, 0)
    )
    section_table = reader.read(pe_offset + 24 + optional_size, sections * 40)
    return {
        "machine": machine,
        "timestamp": timestamp,
        "size_image": size_image,
        "is64": magic == 0x20B,
        "export_rva": export_rva,
        "export_size": export_size,
        "live_header_sha256": hashlib.sha256(dos + coff + optional + section_table).hexdigest(),
    }


def _file_evidence(path: str, identity: dict[str, Any]) -> dict[str, Any]:
    if not path:
        return {"file_hash_status": "not_available", "file_header_matches_live": None}
    try:
        with Path(path).open("rb") as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > 512 * 1024 * 1024:
                return {"file_hash_status": "over_size_limit", "file_header_matches_live": None}
            digest = hashlib.sha256()
            header = stream.read(min(before.st_size, 1024 * 1024 + 8192))
            digest.update(header)
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            return {"file_hash_status": "changed_while_reading", "file_header_matches_live": None}
        matches = False
        if len(header) >= 64 and header[:2] == b"MZ":
            pe = struct.unpack_from("<I", header, 60)[0]
            if pe + 84 <= len(header) and header[pe:pe + 4] == b"PE\0\0":
                matches = (
                    struct.unpack_from("<H", header, pe + 4)[0] == identity["machine"]
                    and struct.unpack_from("<I", header, pe + 8)[0] == identity["timestamp"]
                    and struct.unpack_from("<I", header, pe + 24 + 56)[0] == identity["size_image"]
                )
        return {
            "file_sha256": digest.hexdigest(),
            "file_size": before.st_size,
            "file_hash_status": "observed_stable_file",
            "file_header_matches_live": matches,
            "file_memory_equality_proven": False,
        }
    except (OSError, ValueError) as error:
        return {
            "file_hash_status": "unreadable",
            "file_hash_error": str(error),
            "file_header_matches_live": None,
        }


def _read_exports(
    module: ModuleInfo, read_memory: ReadMemory,
) -> tuple[list[_Definition], dict[str, Any]]:
    reader = _ModuleReader(module, read_memory)
    identity = _header_identity(reader)
    evidence = {
        "name": module.name, "path": module.path, "base": module.base,
        "size": module.size, **identity, **_file_evidence(module.path, identity),
    }
    rva, size = int(identity["export_rva"]), int(identity["export_size"])
    if not rva and not size:
        return [], {**evidence, "export_status": "absent", "export_count": 0}
    if rva <= 0 or size < 40 or rva + size > module.size:
        raise PEFormatError("Loaded module has an invalid export-directory extent.")
    directory = reader.read(rva, 40)
    ordinal_base, functions, names, address_rva, name_rva, ordinal_rva = struct.unpack_from(
        "<IIIIII", directory, 16,
    )
    if functions > MAX_EXPORTS or names > MAX_EXPORTS or names > functions * 32:
        raise PEFormatError("Loaded module export table exceeds capture bounds.")
    if not functions:
        if names:
            raise PEFormatError("An empty export address table has name entries.")
        return [], {**evidence, "export_status": "empty", "export_count": 0}
    if not address_rva or (names and (not name_rva or not ordinal_rva)):
        raise PEFormatError("An export table has a zero array RVA.")
    addresses = reader.read(address_rva, functions * 4)
    name_pointers = reader.read(name_rva, names * 4)
    ordinals = reader.read(ordinal_rva, names * 2)
    by_index: dict[int, list[str]] = {}
    seen_names: set[str] = set()
    for index in range(names):
        function_index = struct.unpack_from("<H", ordinals, index * 2)[0]
        if function_index >= functions:
            raise PEFormatError("An export name ordinal exceeds the address table.")
        name = reader.cstring(struct.unpack_from("<I", name_pointers, index * 4)[0])
        if name in seen_names:
            raise PEFormatError("The live export table contains duplicate export names.")
        seen_names.add(name)
        by_index.setdefault(function_index, []).append(name)
    definitions: list[_Definition] = []
    for index in range(functions):
        function_rva = struct.unpack_from("<I", addresses, index * 4)[0]
        if not function_rva:
            continue  # A hole is not an exported address.
        if function_rva >= module.size:
            raise PEFormatError("An exported address lies outside its loaded module.")
        ordinal = ordinal_base + index
        if ordinal > 0xFFFFFFFF:
            raise PEFormatError("An export ordinal overflows its format field.")
        forwarder = (
            reader.cstring(function_rva, limit=min(MAX_STRING, rva + size - function_rva))
            if rva <= function_rva < rva + size else None
        )
        export_names: list[str | None] = list(by_index.get(index, [])) or [None]
        for export_name in export_names:
            definitions.append(_Definition(
                module, int(identity["machine"]), ordinal, export_name, function_rva, forwarder,
            ))
    return definitions, {
        **evidence, "export_status": "read", "export_count": len(definitions),
        "export_pages_sha256": hashlib.sha256(b"".join(
            struct.pack("<I", offset) + reader.pages[offset] for offset in sorted(reader.pages)
        )).hexdigest(),
    }


def build_export_index(modules: list[ModuleInfo], read_memory: ReadMemory) -> ExportIndex:
    """Index live exports and resolvable forwarders without loading module files.

    A failed module is recorded and contributes no partially read exports.
    API-set contracts absent from the module list are explicitly unresolved;
    concrete host exports remain available as separate evidence.
    """
    ordered = sorted(modules, key=lambda item: item.base)
    for position, module in enumerate(ordered):
        if module.base <= 0 or not 0 < module.size <= MAX_MODULE_SIZE:
            raise PEFormatError("A module has an invalid base or image size.")
        if position and ordered[position - 1].base + ordered[position - 1].size > module.base:
            raise PEFormatError("Captured module extents overlap.")
    index = ExportIndex()
    definitions: list[_Definition] = []
    for module in ordered:
        try:
            _module_key(module.name)
            found, evidence = _read_exports(module, read_memory)
            definitions.extend(found)
            index.modules.append(evidence)
        except Exception as error:
            index.modules.append({
                "name": module.name, "path": module.path, "base": module.base,
                "size": module.size, "export_status": "failed", "error": str(error),
            })
            index.diagnostics.append({
                "kind": "module_export_read_failed", "module": module.name,
                "base": module.base, "error": str(error),
            })
    # A WOW64 snapshot can contain both native and x86 ntdll.dll. Forwarder
    # lookup must retain the source architecture, not conflate equal basenames.
    by_name: dict[tuple[int, str, str], list[_Definition]] = {}
    by_ordinal: dict[tuple[int, str, int], list[_Definition]] = {}
    for definition in definitions:
        key = _module_key(definition.module.name)
        if definition.name is not None:
            by_name.setdefault((definition.machine, key, definition.name), []).append(definition)
        by_ordinal.setdefault((definition.machine, key, definition.ordinal), []).append(definition)

    def destination(
        definition: _Definition, visited: frozenset[tuple[int, int]],
    ) -> tuple[int, tuple[str, ...]]:
        node = (definition.module.base, definition.ordinal)
        if node in visited or len(visited) >= MAX_FORWARD_DEPTH:
            raise PEFormatError("Export forwarder cycle or depth limit.")
        if definition.forwarder is None:
            return definition.module.base + definition.rva, ()
        forwarder_module, separator, target = definition.forwarder.rpartition(".")
        if not separator or not forwarder_module or not target:
            raise PEFormatError("Malformed export forwarder.")
        key = _module_key(forwarder_module)
        if target.startswith("#"):
            if not target[1:].isdigit() or not 0 < int(target[1:]) <= 0xFFFFFFFF:
                raise PEFormatError("Malformed ordinal forwarder.")
            targets = by_ordinal.get((definition.machine, key, int(target[1:])), [])
        else:
            targets = by_name.get((definition.machine, key, target), [])
        if not targets:
            detail = "API-set contract" if key.startswith(("api-", "ext-")) else "module/export"
            raise PEFormatError(f"Forwarded {detail} not resolved in this capture: {definition.forwarder}")
        identities = {(item.module.base, item.ordinal, item.rva, item.forwarder) for item in targets}
        if len(identities) != 1:
            raise PEFormatError("Forwarder target has multiple loaded export identities.")
        address, chain = destination(targets[0], visited | {node})
        return address, (definition.forwarder,) + chain

    for definition in definitions:
        if definition.name is None and not 0 < definition.ordinal <= 0xFFFF:
            index.diagnostics.append({
                "kind": "ordinal_not_importable", "module": definition.module.name,
                "ordinal": definition.ordinal,
            })
            continue
        try:
            address, chain = destination(definition, frozenset())
        except PEFormatError as error:
            index.diagnostics.append({
                "kind": "forwarder_unresolved", "module": definition.module.name,
                "name": definition.name, "ordinal": definition.ordinal,
                "forwarder": definition.forwarder, "error": str(error),
            })
            continue
        symbol = ImportSymbol(
            dll=_module_key(definition.module.name), name=definition.name,
            ordinal=definition.ordinal if definition.name is None else None,
        )
        candidate = ExportCandidate(
            symbol, definition.module.base, definition.rva, definition.ordinal,
            machine=definition.machine,
            direct=definition.forwarder is None, forwarder_chain=chain,
        )
        existing = index.by_address.setdefault(address, [])
        if candidate not in existing:
            existing.append(candidate)
    return index


def _compatible_candidates(index: ExportIndex, address: int, machine: int) -> list[ExportCandidate]:
    return [candidate for candidate in index.by_address.get(address, [])
            if candidate.machine == machine]


def _choices(candidates: list[ExportCandidate], *, direct_only: bool = False) -> dict[str, list[ImportSymbol]]:
    by_dll: dict[str, list[ImportSymbol]] = {}
    for candidate in candidates:
        if direct_only and not candidate.direct:
            continue
        symbols = by_dll.setdefault(candidate.symbol.dll.casefold(), [])
        if candidate.symbol not in symbols:
            symbols.append(candidate.symbol)
    for dll, symbols in by_dll.items():
        named = [symbol for symbol in symbols if symbol.name is not None]
        by_dll[dll] = named or symbols
    return by_dll


def resolve_iat(
    image: bytes, info: PEInfo, index: ExportIndex, ranges: list[tuple[int, int]],
    *, dll_hints: dict[int, str] | None = None,
) -> tuple[dict[str, Any], list[ImportSlot]]:
    """Resolve only supplied (RVA, byte size) ranges, including null terminators.

    Hints select an exact DLL identity already supported by the live evidence;
    they never manufacture a name or match a nearest export. Each hint names
    the first non-null slot of a contiguous IAT run.
    """
    width = info.pointer_size
    if width not in (4, 8) or len(image) < info.size_image:
        raise PEFormatError("IAT resolution requires a complete mapped PE image.")
    extent = min(len(image), info.size_image)
    ordered = sorted(ranges)
    total = 0
    previous_end = -1
    for rva, size in ordered:
        if (isinstance(rva, bool) or isinstance(size, bool)
                or rva < info.size_headers or size <= 0
                or rva % width or size % width or rva + size > extent):
            raise PEFormatError("An IAT range is misaligned, empty, or outside captured sections.")
        if rva < previous_end:
            raise PEFormatError("IAT ranges overlap.")
        previous_end = rva + size
        total += size // width
    if total > MAX_IAT_SLOTS:
        raise PEFormatError("IAT ranges exceed the slot limit.")
    hints = dll_hints or {}
    entries: list[dict[str, Any]] = []
    runs: list[list[dict[str, Any]]] = []
    layout_errors: list[str] = []
    format_code = "<Q" if width == 8 else "<I"
    for rva, size in ordered:
        run: list[dict[str, Any]] = []
        for slot_rva in range(rva, rva + size, width):
            info.rva_to_offset(slot_rva, width)
            address = struct.unpack_from(format_code, image, slot_rva)[0]
            candidates = _compatible_candidates(index, address, info.machine) if address else []
            entry: dict[str, Any] = {
                "rva": slot_rva, "address": address,
                "status": "unresolved" if address else "empty",
                "candidates": [candidate.to_dict() for candidate in candidates],
                "selected": None, "selection": None,
            }
            entries.append(entry)
            if address:
                run.append(entry)
            elif run:
                runs.append(run)
                run = []
        if run:
            runs.append(run)
            layout_errors.append(f"IAT range {rva:#x} does not include a null terminator.")
    starts = {int(run[0]["rva"]) for run in runs}
    for hint_rva in hints:
        if hint_rva not in starts:
            raise PEFormatError(f"DLL hint {hint_rva:#x} is not the start of an IAT run.")
    resolved: list[ImportSlot] = []
    for run in runs:
        run_start = int(run[0]["rva"])
        options = [_choices(_compatible_candidates(index, int(entry["address"]), info.machine))
                   for entry in run]
        direct_options = [
            _choices(_compatible_candidates(index, int(entry["address"]), info.machine), direct_only=True)
            for entry in run
        ]
        hint = hints.get(run_start)
        selected_dll: str | None = None
        selection = "exact_direct_export"
        if hint is not None:
            selected_dll = _module_key(hint)
            selection = "explicit_dll_hint_verified_against_exports"
        elif options:
            direct_common = set.intersection(*(set(item) for item in direct_options))
            common = set.intersection(*(set(item) for item in options))
            if len(direct_common) == 1:
                selected_dll = next(iter(direct_common))
            elif len(common) == 1:
                selected_dll = next(iter(common))
                selection = "unique_common_exporting_dll"
        run_dlls: set[str] = set()
        for entry, choices, direct in zip(run, options, direct_options, strict=True):
            candidate_symbols: list[ImportSymbol]
            if selected_dll is not None:
                candidate_symbols = choices.get(selected_dll, [])
            else:
                candidate_symbols = [symbol for group in direct.values() for symbol in group]
            if len(candidate_symbols) == 1:
                symbol = candidate_symbols[0]
                entry["status"] = "resolved"
                entry["selected"] = symbol_dict(symbol)
                entry["selection"] = selection
                run_dlls.add(symbol.dll.casefold())
                resolved.append(ImportSlot(int(entry["rva"]), int(entry["address"]), symbol))
            elif candidate_symbols or choices:
                entry["status"] = "ambiguous"
                if hint is not None and not candidate_symbols:
                    entry["selection"] = "dll_hint_has_no_matching_export"
            else:
                entry["status"] = "unresolved"
        if len(run_dlls) > 1:
            layout_errors.append(
                f"IAT run {run_start:#x} mixes DLLs without null separators; "
                "preserving its slots needs a different reviewed layout."
            )
    unresolved_count = sum(entry["status"] == "unresolved" for entry in entries)
    ambiguous_count = sum(entry["status"] == "ambiguous" for entry in entries)
    report = {
        "ok": bool(resolved) and not unresolved_count and not ambiguous_count and not layout_errors,
        "ranges": [{"rva": rva, "size": size} for rva, size in ordered],
        "slots": entries,
        "resolved_count": len(resolved), "unresolved_count": unresolved_count,
        "ambiguous_count": ambiguous_count,
        "empty_count": sum(entry["status"] == "empty" for entry in entries),
        "layout_errors": layout_errors,
        "original_import_identity_proven": False,
    }
    return report, resolved


def recommend_iat_ranges(
    image: bytes, info: PEInfo, index: ExportIndex,
) -> list[dict[str, Any]]:
    """Propose null-terminated export-pointer runs for human review only.

    Pointer-looking data is not proof of an IAT. No proposed range is
    authoritative, even when every address has an exact export match.
    """
    if len(image) < info.size_image:
        raise PEFormatError("Candidate scanning requires a complete mapped image.")
    width = info.pointer_size
    format_code = "<Q" if width == 8 else "<I"
    recommendations: list[dict[str, Any]] = []
    for section in info.sections:
        lo = (section.virtual_address + width - 1) // width * width
        hi = min(section.virtual_address + section.mapped_size, info.size_image, len(image))
        start: int | None = None
        count = 0
        for rva in range(lo, hi - width + 1, width):
            value = struct.unpack_from(format_code, image, rva)[0]
            if value and _compatible_candidates(index, value, info.machine):
                if start is None:
                    start = rva
                count += 1
                continue
            if start is not None and count >= 2 and value == 0:
                recommendations.append({
                    "rva": start, "size": rva + width - start,
                    "pointer_count": count, "section": section.name,
                    "requires_review": True, "authoritative": False,
                    "reason": "Consecutive exact export pointers followed by null; data may look identical.",
                })
                if len(recommendations) >= 4096:
                    return recommendations
            start, count = None, 0
    return recommendations
