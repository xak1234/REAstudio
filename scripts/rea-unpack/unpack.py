#!/usr/bin/env python3
"""Capture a trusted live PE and rebuild reviewed imports from exact evidence.

Live use executes the selected EXE in a dedicated x64dbg session and requires
--trusted. Offline --rebuild-plan never executes an image. Pointer scans and
function prologues are review suggestions, never proof of an IAT or real OEP.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

from live_imports import (
    ModuleInfo,
    ReadMemory,
    addressable_modules,
    bounded_memory_reader,
    build_export_index,
    enumerate_modules,
    process_creation_time,
    recommend_iat_ranges,
    resolve_iat,
)
from pe_rebuild import (
    MAX_IMAGE_SIZE,
    ImportSlot,
    ImportSymbol,
    PEFormatError,
    PEInfo,
    mapped_to_file,
    parse_pe,
    rebuild_imports,
)

SCHEMA_VERSION = 1
MAX_JSON_SIZE = 64 * 1024 * 1024


def log(message: str) -> None:
    """Keep normal stdout reserved for the machine-readable final result."""
    print(f"[rea-unpack] {message}", file=sys.stderr, flush=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise PEFormatError(f"{label} must be an integer, not a boolean.")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise PEFormatError(f"{label} is not a decimal or 0x-prefixed integer.") from error
    raise PEFormatError(f"{label} must be an integer.")


def parse_range(value: str) -> tuple[int, int]:
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("Use RVA:SIZE, for example 0x2000:0x40.")
    try:
        return integer(parts[0], "IAT RVA"), integer(parts[1], "IAT size")
    except PEFormatError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def parse_dll_hint(value: str) -> tuple[int, str]:
    parts = value.split(":", 1)
    if len(parts) != 2 or not parts[1].strip():
        raise argparse.ArgumentTypeError("Use RVA:DLL, for example 0x2000:kernel32.dll.")
    try:
        return integer(parts[0], "DLL hint RVA"), parts[1].strip()
    except PEFormatError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    count = len(data)
    return round(-sum((n / count) * math.log2(n / count) for n in Counter(data).values()), 3)


def same_path(first: Path, second: Path) -> bool:
    try:
        return os.path.samefile(first, second)
    except OSError:
        return os.path.normcase(str(first.resolve())) == os.path.normcase(str(second.resolve()))


def artifact_paths(output: Path) -> dict[str, Path]:
    return {
        "output": output,
        "memory": Path(str(output) + ".memory.bin"),
        "capture": Path(str(output) + ".capture.json"),
        "plan": Path(str(output) + ".imports.json"),
        "report": Path(str(output) + ".report.json"),
    }


def preflight_paths(paths: list[Path], protected: list[Path]) -> None:
    """Refuse collisions and existing outputs before any target is launched."""
    for position, path in enumerate(paths):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"Refusing to overwrite an existing output: {path}")
        if any(same_path(path, item) for item in protected + paths[:position]):
            raise PEFormatError(f"Output collides with a source or capture artifact: {path}")
        if not path.parent.is_dir():
            raise FileNotFoundError(f"Output directory does not exist: {path.parent}")


def atomic_publish(path: Path, data: bytes) -> None:
    """Publish a new file atomically without any overwrite race."""
    descriptor, temporary_name = tempfile.mkstemp(prefix=".rea-capture-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.stat().st_size > MAX_JSON_SIZE:
        raise PEFormatError(f"JSON artifact exceeds {MAX_JSON_SIZE} bytes: {path}")
    raw = path.read_bytes()
    if len(raw) > MAX_JSON_SIZE:
        raise PEFormatError("JSON artifact grew beyond its allowed size.")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise PEFormatError("Capture/plan JSON must contain an object.")
    return value, raw


def _rva_string(data: bytes, info: PEInfo, rva: int) -> str:
    result = bytearray()
    for offset in range(4096):
        position = info.rva_to_offset(rva + offset)
        byte = data[position]
        if byte == 0:
            if not result or any(value < 32 or value > 126 for value in result):
                raise PEFormatError("An import string is not nonempty printable ASCII.")
            return result.decode("ascii")
        result.append(byte)
    raise PEFormatError("An import string has no bounded terminator.")


def source_import_hints(
    source: bytes, info: PEInfo,
) -> tuple[list[tuple[int, int]], dict[int, str], list[str]]:
    """Validate the complete source descriptor/lookup table before suggesting it.

    A packer's valid stub imports still do not establish coverage of the real
    program. These extents are suggestions, never automatic rebuild authority.
    """
    directory = info.directory(1)
    if not directory.rva and not directory.size:
        return [], {}, ["Source import directory is absent."]
    ranges: list[tuple[int, int]] = []
    hints: dict[int, str] = {}
    width = info.pointer_size
    format_code = "<Q" if width == 8 else "<I"
    ordinal_flag = 1 << (width * 8 - 1)
    try:
        if directory.size < 20 or directory.size > MAX_JSON_SIZE:
            raise PEFormatError("Invalid source import-directory size.")
        terminated = False
        total = 0
        for relative in range(0, min(directory.size, 20 * 4096) - 19, 20):
            offset = info.rva_to_offset(directory.rva + relative, 20)
            original, timestamp, forwarder, name_rva, first = struct.unpack_from("<IIIII", source, offset)
            if not any((original, timestamp, forwarder, name_rva, first)):
                terminated = True
                break
            if not first or first % width or (original and original % width):
                raise PEFormatError("Misaligned or absent source import thunks.")
            dll = _rva_string(source, info, name_rva)
            if "/" in dll or "\\" in dll or ":" in dll or dll in (".", ".."):
                raise PEFormatError("Source DLL import is not a basename.")
            lookup = original or first
            count = 0
            while count <= 65536:
                entry = struct.unpack_from(format_code, source, info.rva_to_offset(lookup + count * width, width))[0]
                info.rva_to_offset(first + count * width, width)
                if entry == 0:
                    break
                if entry & ordinal_flag:
                    if entry & ~(ordinal_flag | 0xFFFF) or not entry & 0xFFFF:
                        raise PEFormatError("Source ordinal thunk has invalid reserved bits.")
                else:
                    if entry > 0x7FFFFFFF:
                        raise PEFormatError("Source import thunk is not an unbound name RVA.")
                    info.rva_to_offset(entry, 2)
                    _rva_string(source, info, entry + 2)
                count += 1
                total += 1
                if total > 65536:
                    raise PEFormatError("Source import count exceeds the bound.")
            if count == 0 or count > 65536:
                raise PEFormatError("Source import run is empty or unterminated.")
            size = (count + 1) * width
            if any(first < rva + previous_size and rva < first + size for rva, previous_size in ranges):
                raise PEFormatError("Source IAT runs overlap.")
            ranges.append((first, size))
            hints[first] = dll
        if not terminated:
            raise PEFormatError("Source import descriptors have no bounded null terminator.")
    except (PEFormatError, struct.error) as error:
        return [], {}, [f"Source import hints rejected: {error}"]
    return ranges, hints, ["Validated source imports may describe only the packer stub."]


def missing_required_ranges(info: PEInfo, missing: list[dict[str, Any]]) -> list[dict[str, Any]]:
    required = [(0, info.size_headers)] + [
        (section.virtual_address, section.mapped_size) for section in info.sections if section.mapped_size
    ]
    blocked: list[dict[str, Any]] = []
    for item in missing:
        start, size = integer(item.get("rva"), "missing RVA"), integer(item.get("size"), "missing size")
        if start < 0 or size <= 0 or start + size > info.size_image:
            raise PEFormatError("Unreadable-range evidence is outside the captured image.")
        if any(start < rva + length and rva < start + size for rva, length in required):
            blocked.append(item)
    return blocked


def _symbol(value: dict[str, Any]) -> ImportSymbol:
    dll = value.get("dll")
    name = value.get("name")
    ordinal = value.get("ordinal")
    if not isinstance(dll, str) or not dll:
        raise PEFormatError("Every reviewed import requires an evidenced DLL name.")
    if name is not None and (not isinstance(name, str) or not name):
        raise PEFormatError("An import name must be a nonempty string or null.")
    if ordinal is not None:
        ordinal = integer(ordinal, "import ordinal")
    if (name is None) == (ordinal is None):
        raise PEFormatError("An import requires exactly one name or ordinal.")
    return ImportSymbol(dll.casefold(), name, ordinal)


def make_review_plan(capture: dict[str, Any], capture_path: Path, capture_hash: str) -> dict[str, Any]:
    imports = []
    for entry in capture["iat"]["slots"]:
        if not entry["address"]:
            continue
        selected = entry.get("selected") or {"dll": None, "name": None, "ordinal": None}
        imports.append({
            "rva": entry["rva"], "address": entry["address"], **selected,
            "status": entry["status"], "candidates": entry["candidates"],
        })
    return {
        "schema_version": SCHEMA_VERSION, "kind": "rea-import-review", "reviewed": False,
        "capture_path": str(capture_path), "capture_sha256": capture_hash,
        "memory_sha256": capture["memory"]["sha256"],
        "source_sha256": capture["source"]["sha256"],
        "is64": capture["source"]["is64"], "loaded_base": capture["process"]["loaded_base"],
        "oep_rva": capture["oep"].get("rva"),
        "iat_ranges": capture["iat"]["ranges"], "imports": imports,
        "review_note": (
            "Review the OEP and complete IAT coverage, choose only recorded exact candidates, "
            "then set reviewed=true. Runtime equivalence and cross-version compatibility remain unverified."
        ),
    }


def _resolve_artifact_path(value: Any, owner: Path, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise PEFormatError(f"Missing {label} path.")
    path = Path(value)
    return (path if path.is_absolute() else owner.parent / path).resolve()


def validate_review_plan(
    plan: dict[str, Any], capture: dict[str, Any], memory: bytes,
) -> tuple[PEInfo, list[ImportSlot], int, int]:
    """Validate an offline plan against capture metadata and every selected slot."""
    if plan.get("schema_version") != SCHEMA_VERSION or plan.get("kind") != "rea-import-review":
        raise PEFormatError("Unsupported import-review schema.")
    if capture.get("schema_version") != SCHEMA_VERSION or capture.get("kind") != "rea-memory-capture":
        raise PEFormatError("Unsupported capture schema.")
    if plan.get("reviewed") is not True:
        raise PEFormatError("The import plan requires reviewed=true after an explicit review.")
    if not isinstance(capture.get("memory"), dict) or not isinstance(capture.get("source"), dict):
        raise PEFormatError("Capture identity metadata is missing.")
    digest = sha256(memory)
    if digest != plan.get("memory_sha256") or digest != capture["memory"].get("sha256"):
        raise PEFormatError("Captured memory SHA-256 does not match the plan/capture.")
    source_hash = capture["source"].get("sha256")
    if (not isinstance(source_hash, str) or len(source_hash) != 64
            or any(char not in "0123456789abcdef" for char in source_hash)):
        raise PEFormatError("Capture has no valid source SHA-256 identity.")
    if plan.get("source_sha256") != source_hash:
        raise PEFormatError("Source identity differs between the plan and capture.")
    info = parse_pe(memory)
    if len(memory) != info.size_image or len(memory) != capture["memory"].get("size"):
        raise PEFormatError("Captured memory size differs from its PE headers or evidence.")
    if (not isinstance(plan.get("is64"), bool) or not isinstance(capture["source"].get("is64"), bool)
            or plan["is64"] != info.is64 or capture["source"]["is64"] != info.is64):
        raise PEFormatError("Capture and plan architectures do not match the image.")
    loaded_base = integer(plan.get("loaded_base"), "loaded image base")
    process = capture.get("process")
    if not isinstance(process, dict):
        raise PEFormatError("Capture has no process identity metadata.")
    if loaded_base != process.get("loaded_base"):
        raise PEFormatError("Loaded image base differs from the capture.")
    if (process.get("identity_stable") is not True
            or integer(process.get("pid"), "capture process ID") <= 0
            or integer(process.get("creation_filetime"), "capture process creation time") <= 0):
        raise PEFormatError("The capture did not verify stable process/module identity.")
    missing = capture["memory"].get("missing_ranges", [])
    if not isinstance(missing, list) or not all(isinstance(item, dict) for item in missing):
        raise PEFormatError("Invalid unreadable-range evidence.")
    if capture["memory"].get("complete") is not True or missing_required_ranges(info, missing):
        raise PEFormatError("The capture is missing required header or section bytes.")
    oep_rva = integer(plan.get("oep_rva"), "reviewed OEP RVA")
    if not info.executable_rva(oep_rva):
        raise PEFormatError("Reviewed OEP is not inside a captured executable section.")
    recorded_iat = capture.get("iat")
    if not isinstance(recorded_iat, dict):
        raise PEFormatError("Capture has no import evidence.")
    raw_ranges = plan.get("iat_ranges")
    if not isinstance(raw_ranges, list) or not raw_ranges:
        raise PEFormatError("At least one captured IAT range must be reviewed.")
    available = {
        (integer(item.get("rva"), "captured range RVA"), integer(item.get("size"), "captured range size"))
        for item in recorded_iat.get("ranges", []) if isinstance(item, dict)
    }
    ranges: list[tuple[int, int]] = []
    for item in raw_ranges:
        if not isinstance(item, dict):
            raise PEFormatError("Each reviewed IAT range must be an object.")
        extent = (integer(item.get("rva"), "range RVA"), integer(item.get("size"), "range size"))
        if extent not in available or extent in ranges:
            raise PEFormatError("Reviewed IAT ranges must be distinct ranges recorded by this capture.")
        ranges.append(extent)
    entries: dict[int, dict[str, Any]] = {}
    for entry in recorded_iat.get("slots", []):
        if not isinstance(entry, dict):
            raise PEFormatError("Invalid captured slot evidence.")
        rva = integer(entry.get("rva"), "captured slot RVA")
        if rva in entries:
            raise PEFormatError("Capture contains duplicate slot evidence.")
        entries[rva] = entry
    width = info.pointer_size
    format_code = "<Q" if info.is64 else "<I"
    required: dict[int, int] = {}
    last_end = -1
    for rva, size in sorted(ranges):
        if rva < last_end or rva % width or size <= 0 or size % width or rva < info.size_headers:
            raise PEFormatError("Reviewed IAT ranges overlap or are invalid.")
        last_end = rva + size
        for slot_rva in range(rva, rva + size, width):
            info.rva_to_offset(slot_rva, width)
            address = struct.unpack_from(format_code, memory, slot_rva)[0]
            entry = entries.get(slot_rva)
            if entry is None or integer(entry.get("address"), "captured pointer") != address:
                raise PEFormatError("Captured slot evidence does not match every reviewed memory slot.")
            if address:
                required[slot_rva] = address
        if struct.unpack_from(format_code, memory, rva + size - width)[0] != 0:
            raise PEFormatError("A reviewed IAT range does not include its null terminator.")
    raw_imports = plan.get("imports")
    if not isinstance(raw_imports, list) or not raw_imports:
        raise PEFormatError("No reviewed imports were supplied.")
    selected: dict[int, ImportSlot] = {}
    for item in raw_imports:
        if not isinstance(item, dict):
            raise PEFormatError("Each reviewed import must be an object.")
        rva = integer(item.get("rva"), "import RVA")
        address = integer(item.get("address"), "captured import address")
        if rva in selected or required.get(rva) != address:
            raise PEFormatError("Reviewed import duplicates a slot or differs from the selected captured ranges.")
        symbol = _symbol(item)
        candidates = entries[rva].get("candidates", [])
        if not isinstance(candidates, list) or not any(
            isinstance(candidate, dict) and _symbol(candidate) == symbol for candidate in candidates
        ):
            raise PEFormatError(f"Import at {rva:#x} is not an exact candidate recorded for that live pointer.")
        selected[rva] = ImportSlot(rva, address, symbol)
    if set(selected) != set(required):
        raise PEFormatError("The reviewed plan drops nonzero slots or leaves unresolved imports.")
    return info, [selected[rva] for rva in sorted(selected)], oep_rva, loaded_base


def rebuild_from_plan(plan_path: Path, output: Path) -> dict[str, Any]:
    plan, _ = _read_json(plan_path)
    capture_path = _resolve_artifact_path(plan.get("capture_path"), plan_path, "capture")
    capture, capture_raw = _read_json(capture_path)
    if sha256(capture_raw) != plan.get("capture_sha256"):
        raise PEFormatError("Capture JSON SHA-256 differs from the reviewed plan.")
    memory_path = _resolve_artifact_path(capture.get("memory", {}).get("path"), capture_path, "memory")
    if memory_path.stat().st_size > MAX_IMAGE_SIZE:
        raise PEFormatError("Captured memory exceeds the supported image size.")
    source_path = _resolve_artifact_path(capture.get("source", {}).get("path"), capture_path, "source")
    report_path = artifact_paths(output)["report"]
    preflight_paths([output, report_path], [plan_path, capture_path, memory_path, source_path])
    memory = memory_path.read_bytes()
    _, slots, oep_rva, loaded_base = validate_review_plan(plan, capture, memory)
    rebuilt, details = rebuild_imports(memory, slots, oep_rva=oep_rva, loaded_base=loaded_base)
    result = {
        "ok": True, "imports_rebuilt": True, "status": "imports_rebuilt",
        "mode": "offline_reviewed_rebuild", "output": str(output),
        "output_sha256": sha256(rebuilt), "output_size": len(rebuilt),
        "entry_rva": oep_rva, "import_count": len(slots), "details": details,
        "capture": str(capture_path), "capture_sha256": sha256(capture_raw),
        "reviewed_plan": str(plan_path), "report": str(report_path),
        "oep_provenance": "explicitly reviewed RVA; startup semantics not independently proven",
        "runtime_verified": False, "portable_verified": False,
    }
    atomic_publish(output, rebuilt)
    atomic_publish(report_path, json_bytes(result))
    return result


def find_dbg(root: Path, is64: bool) -> Path:
    name = "x64dbg.exe" if is64 else "x32dbg.exe"
    preferred = [root / "release" / ("x64" if is64 else "x32") / name,
                 root / ("x64" if is64 else "x32") / name, root / name]
    for path in preferred:
        if path.is_file():
            return path
    matches = sorted(root.rglob(name)) if root.is_dir() else []
    if not matches:
        raise FileNotFoundError(f"{name} not found under {root}")
    return matches[0]


def looks_like_prologue(data: bytes) -> bool:
    return data.startswith((b"\x55\x8b\xec", b"\x55\x89\xe5", b"\x53", b"\x83\xec",
                            b"\x48\x89", b"\x40\x53", b"\x48\x83\xec"))


def _capture_memory(read_memory: ReadMemory, base: int, size: int) -> tuple[bytes, list[dict[str, Any]]]:
    if not 0 < size <= MAX_IMAGE_SIZE:
        raise PEFormatError("The actual mapped module exceeds the supported image size.")
    image = bytearray(size)
    missing: list[dict[str, Any]] = []
    for rva in range(0, size, 0x1000):
        count = min(0x1000, size - rva)
        try:
            data = read_memory(base + rva, count)
            if not isinstance(data, bytes) or len(data) != count:
                raise PEFormatError(f"Short read: expected exactly {count} bytes.")
            image[rva:rva + count] = data
        except Exception as error:
            missing.append({"rva": rva, "size": count, "error": str(error)})
    return bytes(image), missing


def _same_modules(first: list[ModuleInfo], second: list[ModuleInfo]) -> bool:
    def keys(items: list[ModuleInfo]) -> set[tuple[str, str, int, int]]:
        return {(item.name.casefold(), os.path.normcase(item.path), item.base, item.size) for item in items}
    return keys(first) == keys(second)


def _terminate_owned_process(process: subprocess.Popen[Any]) -> str:
    """Bounded fallback for the exact process handle owned by this driver."""
    code = process.poll()
    if code is not None:
        return f"Owned debugger PID {process.pid} was already stopped (exit code {code})."
    process.terminate()
    try:
        code = process.wait(timeout=5)
        return f"Terminated owned debugger PID {process.pid} (exit code {code})."
    except subprocess.TimeoutExpired:
        process.kill()
        code = process.wait(timeout=5)
        return f"Killed owned debugger PID {process.pid} after termination timed out (exit code {code})."


def _stop_owned_session(client: Any) -> str | None:
    # terminate_session()/detach_session() clear client.proc. Keep the original
    # Popen handle so cleanup never relies on a PID lookup or targets another app.
    process = getattr(client, "proc", None)
    notes: list[str] = []
    try:
        if process is None:
            notes.append("No owned debugger process handle was available; skipped shutdown RPC.")
        elif (code := process.poll()) is not None:
            notes.append(f"Owned debugger had already exited (code {code}); skipped shutdown RPC.")
        else:
            try:
                client.terminate_session()
            except Exception as error:
                notes.append(f"Debugger shutdown RPC/session cleanup failed: {type(error).__name__}: {error}")
    finally:
        # A failed shutdown RPC does not close x64dbg-automate's event thread.
        # Its public detach path closes the local connection and joins that
        # thread even after the debugger/plugin process has died.
        try:
            client.detach_session()
        except Exception as error:
            notes.append(f"Local debugger-client detach failed: {type(error).__name__}: {error}")
        if process is not None:
            try:
                if process.poll() is None:
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        notes.append(_terminate_owned_process(process))
            except Exception as error:
                notes.append(f"Owned debugger process cleanup failed: {type(error).__name__}: {error}")
    return " ".join(notes) or None


def _wait_for_entry(
    client: Any, info: PEInfo, base: int, oep_rva: int | None,
    timeout: float, max_rounds: int, read_memory: ReadMemory,
) -> dict[str, Any]:
    target = base + oep_rva if oep_rva is not None else None
    register = "rip" if info.is64 else "eip"
    result: dict[str, Any] = {
        "rva": oep_rva, "va": target, "explicit": target is not None,
        "reached": False, "semantics_verified": False, "candidate": None,
    }
    if oep_rva is not None:
        if not 0 <= oep_rva < info.size_image:
            raise PEFormatError("Explicit OEP lies outside the loaded main image.")
        if not client.set_hardware_breakpoint(target, bp_type="x", size=1):
            raise RuntimeError("Could not set the dedicated OEP hardware breakpoint.")
    else:
        installed = 0
        for section in info.sections:
            if section.characteristics & 0x20000000 and section.mapped_size:
                if client.set_memory_breakpoint(base + section.virtual_address, bp_type="x", singleshoot=False):
                    installed += 1
        if not installed:
            raise RuntimeError("Could not set an executable-section observation breakpoint.")
    deadline = time.monotonic() + timeout
    for round_number in range(max_rounds):
        if not client.is_debugging():
            result["note"] = "process exited before capture"
            return result
        if not client.is_running():
            ip = int(client.get_reg(register))
            if target is not None and ip == target:
                result.update(reached=True, rounds=round_number)
                return result
            candidate = ip - base
            if target is None and info.executable_rva(candidate) and abs(candidate - info.entry_rva) > 0x40:
                try:
                    prologue = read_memory(ip, 8)
                except Exception:
                    prologue = b""
                if looks_like_prologue(prologue):
                    result.update(rva=candidate, va=ip, candidate=candidate, rounds=round_number,
                                  note="Heuristic prologue candidate requires explicit OEP review.")
                    return result
        if time.monotonic() >= deadline:
            break
        if not client.is_running() and not client.go(pass_exceptions=True):
            raise RuntimeError("Debugger refused to continue the owned target.")
        client.wait_until_stopped(timeout=max(1, min(2, math.ceil(deadline - time.monotonic()))))
    if client.is_debugging() and client.is_running():
        if not client.pause() or not client.wait_until_stopped(timeout=5):
            raise RuntimeError("Could not pause the owned process for a consistent capture.")
    result["note"] = "OEP was not reached before the time/round limit."
    return result


def _proposed_ranges(
    source_ranges: list[tuple[int, int]], suggestions: list[dict[str, Any]],
) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for rva, size in source_ranges + [(item["rva"], item["size"]) for item in suggestions]:
        if not any(rva < start + length and start < rva + size for start, length in result):
            result.append((rva, size))
    return sorted(result)


def unpack_live(args: argparse.Namespace) -> dict[str, Any]:
    source_path = Path(args.input).resolve()
    output = Path(args.output).resolve() if args.output else source_path.with_name(source_path.stem + "_unpacked.exe")
    paths = artifact_paths(output)
    preflight_paths(list(paths.values()), [source_path])
    if source_path.stat().st_size > MAX_IMAGE_SIZE:
        raise PEFormatError("The input file exceeds the supported capture size.")
    source = source_path.read_bytes()
    info = parse_pe(source, "file")
    if info.characteristics & 0x2000:
        raise PEFormatError("Live capture currently accepts native EXE targets, not DLL launch targets.")
    if not args.trusted:
        raise PEFormatError("Live capture executes the selected EXE; pass --trusted after reviewing it.")
    if not 0 < args.timeout <= 3600 or not 1 <= args.max_rounds <= 100000:
        raise PEFormatError("Timeout must be 0–3600 seconds and max-rounds must be 1–100000.")
    source_ranges, source_hints, source_notes = source_import_hints(source, info)
    explicit_ranges = list(args.iat_range)
    previous_end = -1
    for start, length in sorted(explicit_ranges):
        if (start < previous_end or start < info.size_headers or length <= 0
                or start % info.pointer_size or length % info.pointer_size
                or start + length > info.size_image or info.section_at(start, length) is None):
            raise PEFormatError("An explicit IAT range overlaps or lies outside an aligned section extent.")
        previous_end = start + length
    if len({rva for rva, _ in args.iat_dll}) != len(args.iat_dll):
        raise PEFormatError("Duplicate DLL hint RVAs are not permitted.")
    explicit_hints = dict(args.iat_dll)
    debugger = find_dbg(Path(args.x64dbg_root), info.is64)
    from x64dbg_automate import X64DbgClient

    client: Any = X64DbgClient(x64dbg_path=str(debugger))
    capture: dict[str, Any] = {}
    memory = b""
    cleanup_note: str | None = None
    try:
        debugger_pid = client.start_session(str(source_path))
        if not client.wait_until_debugging(timeout=20) or not client.wait_until_stopped(timeout=20):
            raise RuntimeError("The dedicated debugger did not reach a stopped target.")
        base, valid = client.eval_sync("mod.main()")
        if not valid or not base:
            raise RuntimeError("x64dbg did not identify the actual loaded main module base.")
        base = int(base)
        pid = client.debugee_pid()
        if pid is None:
            raise RuntimeError("The dedicated debugger did not identify its target process.")
        pid = int(pid)
        created = process_creation_time(pid)
        initial_modules = enumerate_modules(pid)
        main = next((module for module in initial_modules if module.base == base), None)
        if main is None or not same_path(Path(main.path), source_path):
            raise PEFormatError("The debugger main module path does not match the selected input.")
        oep_rva = args.oep_rva
        if args.oep_va is not None:
            oep_rva = args.oep_va - base
        read_memory = bounded_memory_reader(client.read_memory, info.pointer_size)
        oep = _wait_for_entry(client, info, base, oep_rva, args.timeout, args.max_rounds, read_memory)
        if not client.is_debugging() or client.is_running():
            raise RuntimeError("No paused live target remains to capture.")
        modules_before = enumerate_modules(pid)
        main_before = next((module for module in modules_before if module.base == base), None)
        if main_before is None or not same_path(Path(main_before.path), source_path):
            raise PEFormatError("Main module identity changed before the capture.")
        log(f"Capturing {main_before.size} bytes at the actual base {base:#x}.")
        memory, missing = _capture_memory(read_memory, base, main_before.size)
        live_info = parse_pe(memory)
        if live_info.is64 != info.is64 or live_info.size_image != main_before.size:
            raise PEFormatError("Captured PE identity differs from the loaded source module.")
        blocked = missing_required_ranges(live_info, missing)
        # Toolhelp can include native 64-bit modules in a WOW64 snapshot. The
        # x32 bridge accepts native-width addresses, so filter before any RPC.
        modules_for_exports, skipped_modules = addressable_modules(
            [module for module in modules_before if module.base != base], live_info.pointer_size,
        )
        index = build_export_index(modules_for_exports, read_memory)
        index.diagnostics.extend(skipped_modules)
        suggestions = recommend_iat_ranges(memory, live_info, index)
        ranges = explicit_ranges or _proposed_ranges(source_ranges, suggestions)
        hints = {rva: dll for rva, dll in source_hints.items() if any(start == rva for start, _ in ranges)}
        hints.update(explicit_hints)
        try:
            iat_report, slots = resolve_iat(memory, live_info, index, ranges, dll_hints=hints)
        except PEFormatError as error:
            iat_report = {
                "ok": False, "ranges": [], "slots": [], "resolved_count": 0,
                "unresolved_count": 0, "ambiguous_count": 0, "empty_count": 0,
                "layout_errors": [str(error)],
            }
            slots = []
        modules_after = enumerate_modules(pid)
        identity_stable = (
            not client.is_running() and client.is_debugging()
            and client.debugee_pid() == pid and process_creation_time(pid) == created
            and _same_modules(modules_before, modules_after)
            and sha256(source_path.read_bytes()) == sha256(source)
        )
        capture = {
            "schema_version": SCHEMA_VERSION, "kind": "rea-memory-capture",
            "captured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": {"path": str(source_path), "sha256": sha256(source), "is64": info.is64,
                       "preferred_image_base": info.image_base, "entry_rva": info.entry_rva},
            "process": {"pid": pid, "creation_filetime": created, "loaded_base": base,
                        "identity_stable": identity_stable, "debugger_pid": debugger_pid,
                        "debugger": str(debugger)},
            "memory": {"path": str(paths["memory"]), "sha256": sha256(memory), "size": len(memory),
                       "complete": not blocked, "all_pages_read": not missing,
                       "missing_ranges": missing, "missing_required_ranges": blocked},
            "oep": oep, "iat": iat_report,
            "iat_selection": "explicit_ranges" if explicit_ranges else "proposed_ranges_require_review",
            "dll_hints": {str(rva): dll for rva, dll in hints.items()},
            "proposed_ranges": suggestions, "source_import_notes": source_notes,
            "source_import_ranges": [{"rva": rva, "size": size} for rva, size in source_ranges],
            "exports": index.summary(), "runtime_verified": False, "portable_verified": False,
        }
        review_reasons: list[str] = []
        if args.analysis_only:
            review_reasons.append("Analysis-only capture was requested.")
        if not explicit_ranges:
            review_reasons.append("IAT ranges require explicit review; source/scan candidates were not applied.")
        if not oep["explicit"] or not oep["reached"]:
            review_reasons.append("An explicitly selected OEP was not reached.")
        if oep["rva"] is None or not live_info.executable_rva(integer(oep["rva"], "OEP RVA")):
            review_reasons.append("The selected entry is not inside captured executable bytes.")
        if blocked:
            review_reasons.append("Required header or section bytes could not be captured.")
        if not identity_stable:
            review_reasons.append("Process, module, or source identity changed during capture.")
        if not iat_report["ok"]:
            review_reasons.append("IAT symbols or layout remain unresolved; inspect the capture report.")
        rebuilt: bytes | None = None
        details: dict[str, Any] = {}
        if not review_reasons:
            try:
                rebuilt, details = rebuild_imports(memory, slots, oep_rva=oep["rva"], loaded_base=base)
            except PEFormatError as error:
                review_reasons.append(f"Import rebuild requires review: {error}")
        imports_rebuilt = rebuilt is not None
        if rebuilt is None:
            try:
                candidate = oep["rva"] if oep["rva"] is not None and live_info.executable_rva(oep["rva"]) else None
                rebuilt, details = mapped_to_file(memory, oep_rva=candidate, loaded_base=base)
            except PEFormatError as error:
                review_reasons.append(f"No disk PE emitted: {error}")
        result = {
            "ok": imports_rebuilt, "imports_rebuilt": imports_rebuilt,
            "status": "imports_rebuilt" if imports_rebuilt else "review_required",
            "mode": "live_capture", "input": str(source_path), "input_sha256": sha256(source),
            "arch": "x64" if info.is64 else "x86", "image_base": hex(base),
            "entry_rva": oep["rva"], "oep": hex(oep["va"]) if oep["va"] is not None else None,
            "oep_found": bool(oep["explicit"] and oep["reached"]), "oep_evidence": oep,
            "output": str(output) if rebuilt is not None else None,
            "output_sha256": sha256(rebuilt) if rebuilt is not None else None,
            "output_size": len(rebuilt) if rebuilt is not None else 0,
            "analysis_only": not imports_rebuilt, "import_count": len(slots),
            "iat": iat_report, "details": details, "review_reasons": review_reasons,
            "memory": str(paths["memory"]), "capture": str(paths["capture"]),
            "review_plan": str(paths["plan"]), "report": str(paths["report"]),
            "runtime_verified": False, "portable_verified": False,
        }
    except Exception as error:
        if not memory:
            raise
        capture = {
            "schema_version": SCHEMA_VERSION, "kind": "rea-memory-capture",
            "captured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": {"path": str(source_path), "sha256": sha256(source), "is64": info.is64,
                       "preferred_image_base": info.image_base, "entry_rva": info.entry_rva},
            "process": {"pid": pid, "creation_filetime": created, "loaded_base": base,
                        "identity_stable": False, "debugger_pid": debugger_pid,
                        "debugger": str(debugger)},
            "memory": {"path": str(paths["memory"]), "sha256": sha256(memory), "size": len(memory),
                       "complete": False, "all_pages_read": not missing, "missing_ranges": missing},
            "oep": oep,
            "iat": {"ok": False, "ranges": [], "slots": [], "resolved_count": 0,
                    "unresolved_count": 0, "ambiguous_count": 0, "layout_errors": [str(error)]},
            "capture_error": f"{type(error).__name__}: {error}",
            "runtime_verified": False, "portable_verified": False,
        }
        rebuilt = None
        result = {
            "ok": False, "imports_rebuilt": False, "status": "review_required", "mode": "live_capture",
            "input": str(source_path), "input_sha256": sha256(source), "analysis_only": True,
            "output": None, "review_reasons": [f"Capture validation failed: {error}"],
            "memory": str(paths["memory"]), "capture": str(paths["capture"]),
            "review_plan": str(paths["plan"]), "report": str(paths["report"]),
            "runtime_verified": False, "portable_verified": False,
        }
    finally:
        cleanup_note = _stop_owned_session(client)
    if cleanup_note:
        capture["cleanup_note"] = cleanup_note
        result["cleanup_note"] = cleanup_note
    capture_raw = json_bytes(capture)
    plan = make_review_plan(capture, paths["capture"], sha256(capture_raw))
    atomic_publish(paths["memory"], memory)
    atomic_publish(paths["capture"], capture_raw)
    atomic_publish(paths["plan"], json_bytes(plan))
    if rebuilt is not None:
        atomic_publish(output, rebuilt)
    atomic_publish(paths["report"], json_bytes(result))
    return result


def default_debugger_root() -> str:
    configured = os.environ.get("REA_X64DBG_ROOT")
    if configured:
        return configured
    here = Path(__file__).resolve().parent
    for parent in (here, *here.parents[:3]):
        candidate = parent / "resources" / "toolchain" / "x64dbg"
        if candidate.is_dir():
            return str(candidate)
    return str(here / "resources" / "toolchain" / "x64dbg")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture a trusted live PE and rebuild reviewed imports.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input", help="Native EXE to execute in a dedicated debugger.")
    mode.add_argument("--rebuild-plan", help="Reviewed capture plan; rebuilds offline without execution.")
    parser.add_argument("--output", default="")
    parser.add_argument("--x64dbg-root", default=default_debugger_root())
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--max-rounds", type=int, default=2000)
    parser.add_argument("--trusted", action="store_true", help="Acknowledge execution of the selected EXE.")
    parser.add_argument("--analysis-only", action="store_true", help="Capture evidence without applying imports.")
    oep = parser.add_mutually_exclusive_group()
    oep.add_argument("--oep-rva", type=lambda value: integer(value, "OEP RVA"))
    oep.add_argument("--oep-va", type=lambda value: integer(value, "OEP VA"))
    parser.add_argument("--iat-range", type=parse_range, action="append", default=[], metavar="RVA:SIZE")
    parser.add_argument("--iat-dll", type=parse_dll_hint, action="append", default=[], metavar="RVA:DLL")
    args = parser.parse_args(argv)
    try:
        if args.rebuild_plan:
            if not args.output:
                raise PEFormatError("Offline rebuilding requires --output with a new file path.")
            if (args.input or args.analysis_only or args.oep_rva is not None
                    or args.oep_va is not None or args.iat_range or args.iat_dll):
                raise PEFormatError("Offline import/OEP choices belong in the reviewed plan.")
            result = rebuild_from_plan(Path(args.rebuild_plan).resolve(), Path(args.output).resolve())
        else:
            result = unpack_live(args)
    except Exception as error:
        result = {
            "ok": False, "imports_rebuilt": False, "status": "failed",
            "error": f"{type(error).__name__}: {error}",
            "runtime_verified": False, "portable_verified": False,
        }
    print(json.dumps(result, indent=2))
    if result.get("ok"):
        return 0
    return 3 if result.get("status") == "review_required" else 1


if __name__ == "__main__":
    raise SystemExit(main())
