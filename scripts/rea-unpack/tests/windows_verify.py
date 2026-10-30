#!/usr/bin/env python3
"""Independently inspect and run the source-owned Windows IAT probe fixtures.

This verifier deliberately does not import the production PE parser or writer.
It uses Python 3.10+ standard-library APIs and runs a fixture only when the
explicit ``--execute-owned-fixtures`` flag is supplied to ``verify``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

EXPECTED_NAMES = {"ExitProcess", "GetStdHandle", "WriteFile"}
EXPECTED_OUTPUT = b"REA_IAT_OK=42\r\n"
RESOURCE_MARKER = b"REA_IAT_RESOURCE_V1"


def require(condition: bool, message: str) -> None:
    """Raise a meaningful verification failure, including under python -O."""
    if not condition:
        raise ValueError(message)


class FixturePE:
    """Small bounded PE reader for independently checking compiler fixtures."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve(strict=True)
        self.data = self.path.read_bytes()
        require(self.data[:2] == b"MZ", "Missing DOS signature")
        pe = self.u32(0x3C)
        require(self.read(pe, 4) == b"PE\0\0", "Missing PE signature")
        self.machine = self.u16(pe + 4)
        section_count = self.u16(pe + 6)
        require(0 < section_count <= 96, "Invalid section count")
        optional_size = self.u16(pe + 20)
        optional = pe + 24
        magic = self.u16(optional)
        require(magic in (0x10B, 0x20B), "Unsupported optional header")
        self.is64 = magic == 0x20B
        require(
            self.machine == (0x8664 if self.is64 else 0x14C),
            "Fixture architecture disagrees with optional header",
        )
        self.pointer_size = 8 if self.is64 else 4
        directory_offset = 112 if self.is64 else 96
        require(optional_size >= directory_offset, "Truncated optional header")
        self.read(optional, optional_size)
        self.entry_rva = self.u32(optional + 16)
        self.image_base = (
            self.u64(optional + 24) if self.is64 else self.u32(optional + 28)
        )
        self.size_image = self.u32(optional + 56)
        self.size_headers = self.u32(optional + 60)
        require(
            0 < self.size_headers <= len(self.data), "Invalid header extent"
        )
        directory_count = self.u32(optional + directory_offset - 4)
        require(
            directory_count <= (optional_size - directory_offset) // 8,
            "Data directories exceed optional header",
        )
        self.directories = [
            (
                self.u32(optional + directory_offset + index * 8),
                self.u32(optional + directory_offset + index * 8 + 4),
            )
            for index in range(directory_count)
        ]
        section_table = optional + optional_size
        self.sections: list[dict[str, int | str]] = []
        for index in range(section_count):
            offset = section_table + index * 40
            self.read(offset, 40)
            section: dict[str, int | str] = {
                "name": self.read(offset, 8).split(b"\0", 1)[0].decode("ascii"),
                "virtual_size": self.u32(offset + 8),
                "rva": self.u32(offset + 12),
                "raw_size": self.u32(offset + 16),
                "raw_offset": self.u32(offset + 20),
                "characteristics": self.u32(offset + 36),
            }
            self.sections.append(section)
        executable_entry = any(
            int(section["rva"]) <= self.entry_rva
            < int(section["rva"]) + int(section["virtual_size"])
            and int(section["characteristics"]) & 0x20000000
            for section in self.sections
        )
        require(executable_entry, "Entry RVA is not in executable section data")
        self.rva_offset(self.entry_rva, 1)

    def read(self, offset: int, size: int) -> bytes:
        require(
            0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset,
            f"Out-of-file read at {offset:#x} ({size} bytes)",
        )
        return self.data[offset : offset + size]

    def u16(self, offset: int) -> int:
        return int(struct.unpack("<H", self.read(offset, 2))[0])

    def u32(self, offset: int) -> int:
        return int(struct.unpack("<I", self.read(offset, 4))[0])

    def u64(self, offset: int) -> int:
        return int(struct.unpack("<Q", self.read(offset, 8))[0])

    def rva_offset(self, rva: int, size: int) -> int:
        require(0 <= rva < self.size_image, f"RVA outside image: {rva:#x}")
        require(0 <= size <= self.size_image - rva, "RVA range overflows image")
        candidates: list[int] = []
        if rva < self.size_headers and size <= self.size_headers - rva:
            candidates.append(rva)
        for section in self.sections:
            start = int(section["rva"])
            relative = rva - start
            if 0 <= relative and size <= int(section["raw_size"]) - relative:
                candidates.append(int(section["raw_offset"]) + relative)
        require(len(candidates) == 1, f"RVA is not uniquely file-backed: {rva:#x}")
        self.read(candidates[0], size)
        return candidates[0]

    def rva_bytes(self, rva: int, size: int) -> bytes:
        return self.read(self.rva_offset(rva, size), size)

    def ascii_z(self, rva: int) -> str:
        value = bytearray()
        for index in range(4096):
            byte = self.rva_bytes(rva + index, 1)
            if byte == b"\0":
                require(bool(value), "Empty import name")
                return value.decode("ascii")
            value.extend(byte)
        raise ValueError("Unterminated import name")

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def imports(self) -> tuple[list[dict[str, Any]], list[dict[str, int]]]:
        directory_rva, directory_size = self.directory(1)
        require(directory_rva != 0 and directory_size >= 20, "No import directory")
        imports: list[dict[str, Any]] = []
        ranges: list[dict[str, int]] = []
        terminated = False
        ordinal_mask = 1 << (self.pointer_size * 8 - 1)
        for index in range(min(directory_size // 20, 4096)):
            descriptor = struct.unpack(
                "<IIIII", self.rva_bytes(directory_rva + index * 20, 20)
            )
            if not any(descriptor):
                terminated = True
                break
            lookup_rva, stamp, _forwarder, name_rva, iat_rva = descriptor
            require(stamp == 0, "Fixture import descriptor must be unbound")
            require(iat_rva != 0, "Import descriptor has no FirstThunk")
            dll = self.ascii_z(name_rva)
            lookup_rva = lookup_rva or iat_rva
            for slot_index in range(4096):
                displacement = slot_index * self.pointer_size
                raw = self.rva_bytes(lookup_rva + displacement, self.pointer_size)
                value = int.from_bytes(raw, "little")
                iat = self.rva_bytes(iat_rva + displacement, self.pointer_size)
                require(raw == iat, "IAT is not restored to unbound thunk values")
                if value == 0:
                    require(slot_index > 0, "Empty import descriptor")
                    ranges.append(
                        {"rva": iat_rva, "size": (slot_index + 1) * self.pointer_size}
                    )
                    break
                item: dict[str, Any] = {
                    "dll": dll,
                    "iat_rva": iat_rva + displacement,
                    "name": None,
                    "ordinal": None,
                }
                if value & ordinal_mask:
                    require(
                        value & ~(ordinal_mask | 0xFFFF) == 0,
                        "Invalid ordinal thunk",
                    )
                    item["ordinal"] = value & 0xFFFF
                else:
                    require(value <= 0x7FFFFFFF, "Invalid hint/name RVA")
                    self.rva_bytes(value, 2)
                    item["name"] = self.ascii_z(value + 2)
                imports.append(item)
            else:
                raise ValueError("Unterminated import thunk table")
        require(terminated, "Import directory has no terminating descriptor")
        slots = [item["iat_rva"] for item in imports]
        require(len(set(slots)) == len(slots), "Overlapping import slots")
        return sorted(imports, key=lambda item: item["iat_rva"]), ranges

    def describe(self) -> dict[str, Any]:
        imports, ranges = self.imports()
        resource_rva, resource_size = self.directory(2)
        require(resource_rva != 0 and resource_size > 0, "Fixture resource is missing")
        resources = self.rva_bytes(resource_rva, resource_size)
        require(RESOURCE_MARKER in resources, "Owned fixture resource marker is missing")
        return {
            "path": str(self.path),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "arch": "x64" if self.is64 else "x86",
            "entry_rva": self.entry_rva,
            "image_base": self.image_base,
            "imports": imports,
            "iat_ranges": ranges,
            "resources": {
                "rva": resource_rva,
                "size": resource_size,
                "sha256": hashlib.sha256(resources).hexdigest(),
            },
        }


def read_json(path: Path) -> dict[str, Any]:
    value: Any = json.loads(path.read_text(encoding="utf-8-sig"))
    require(isinstance(value, dict), f"Expected JSON object: {path}")
    return dict(value)


def run_fixture(path: Path) -> dict[str, Any]:
    require(os.name == "nt", "Runtime verification requires Windows")
    completed = subprocess.run(
        [str(path.resolve(strict=True))],
        cwd=path.parent,
        capture_output=True,
        check=False,
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    require(completed.returncode == 0, f"Fixture exited {completed.returncode}: {path}")
    require(completed.stdout == EXPECTED_OUTPUT, f"Unexpected fixture stdout: {path}")
    require(completed.stderr == b"", f"Unexpected fixture stderr: {path}")
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode("ascii"),
        "stderr": completed.stderr.decode("ascii"),
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    original_path = Path(args.original)
    rebuilt_path = Path(args.rebuilt)
    baseline = read_json(Path(args.baseline))
    report = read_json(Path(args.driver_report))
    require(report.get("ok") is True, "Driver did not report ok=true")
    require(report.get("imports_rebuilt") is True, "Driver did not rebuild imports")
    original = FixturePE(original_path).describe()
    rebuilt = FixturePE(rebuilt_path).describe()
    require(original == baseline, "Original fixture changed after baseline capture")
    require(original["arch"] == rebuilt["arch"], "Rebuilt architecture changed")
    require(original["image_base"] == rebuilt["image_base"], "Fixture base changed")
    require(original["entry_rva"] == rebuilt["entry_rva"], "Rebuilt OEP differs")
    require(original["resources"] == rebuilt["resources"], "Resource bytes or RVA changed")
    require(
        {item["name"] for item in original["imports"]} == EXPECTED_NAMES
        and len(original["imports"]) == len(EXPECTED_NAMES),
        "Compiled fixture does not have exactly the declared three imports",
    )
    require(
        len(original["imports"]) == len(rebuilt["imports"]), "Import count changed"
    )
    remappings: list[dict[str, Any]] = []
    for old, new in zip(original["imports"], rebuilt["imports"], strict=True):
        for key in ("iat_rva", "name", "ordinal"):
            require(old[key] == new[key], f"Import {key} changed: {old} -> {new}")
        if old["dll"].casefold() != new["dll"].casefold():
            require(
                old["dll"].casefold() == "kernel32.dll"
                and new["dll"].casefold() in {"kernelbase.dll", "ntdll.dll"},
                f"Unexpected import DLL remapping: {old} -> {new}",
            )
            remappings.append({"original": old, "rebuilt": new})
    if report.get("output_sha256") is not None:
        require(
            report["output_sha256"] == rebuilt["sha256"],
            "Driver output hash disagrees with emitted file",
        )
    result: dict[str, Any] = {
        "passed": True,
        "arch": original["arch"],
        "input_sha256": original["sha256"],
        "rebuilt_sha256": rebuilt["sha256"],
        "entry_rva": original["entry_rva"],
        "imports": rebuilt["imports"],
        "dll_remappings": remappings,
        "resources": rebuilt["resources"],
        "input_unchanged": True,
        "iat_slots_preserved": True,
        "runtime_verified": False,
        "limitations": [
            "Owned fixed-base fixture only; does not establish arbitrary packed-app recovery.",
            "Does not establish ASLR, TLS, Load Config, or behavioural equivalence for other binaries.",
        ],
    }
    if args.execute_owned_fixtures:
        result["original_runtime"] = run_fixture(original_path)
        result["rebuilt_runtime"] = run_fixture(rebuilt_path)
        result["runtime_verified"] = True
        require(
            hashlib.sha256(original_path.read_bytes()).hexdigest() == baseline["sha256"],
            "Input fixture changed during runtime checks",
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subcommands.add_parser("inspect")
    inspect_parser.add_argument("input")
    verify_parser = subcommands.add_parser("verify")
    verify_parser.add_argument("--original", required=True)
    verify_parser.add_argument("--rebuilt", required=True)
    verify_parser.add_argument("--baseline", required=True)
    verify_parser.add_argument("--driver-report", required=True)
    verify_parser.add_argument("--execute-owned-fixtures", action="store_true")
    args = parser.parse_args()
    try:
        result = (
            FixturePE(Path(args.input)).describe()
            if args.command == "inspect"
            else verify(args)
        )
        print(json.dumps(result, indent=2))
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        struct.error,
        subprocess.SubprocessError,
    ) as error:
        print(json.dumps({"passed": False, "error": f"{type(error).__name__}: {error}"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
