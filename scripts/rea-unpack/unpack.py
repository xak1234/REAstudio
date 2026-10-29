#!/usr/bin/env python3
"""rea-unpack: reusable live-dump unpacker for packed Windows PE binaries.

Drives x64dbg (via x64dbg-automate) to run a packed executable until its loader
stub has decompressed the real image into memory, then dumps and rebuilds a
static PE that a disassembler can analyse fully. Handles x86 and x64, admin-
manifest targets (when run elevated), and SEH-based packers (PECompact, etc.)
by passing exceptions through to the target.

SAFETY: this EXECUTES the target. Only point it at binaries the user trusts.
Pass --trusted to acknowledge. Output is one JSON object on stdout.

Usage:
  python unpack.py --input C:\\path\\app.exe [--output out.exe] [--trusted]
                   [--x64dbg-root <dir>] [--timeout 90] [--verify-ida]
"""
from __future__ import annotations
import argparse, json, math, os, struct, sys, time, hashlib, collections, traceback

def log(*a): print("[rea-unpack]", *a, file=sys.stderr, flush=True)

def pe_info(data: bytes) -> dict:
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    opt = pe + 24
    return {
        "pe": pe, "machine": machine, "is64": machine == 0x8664,
        "entry_rva": struct.unpack_from("<I", data, opt + 16)[0],
        "image_base": (struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20b
                       else struct.unpack_from("<I", data, opt + 28)[0]),
        "size_image": struct.unpack_from("<I", data, opt + 56)[0],
        "num_sec": struct.unpack_from("<H", data, pe + 6)[0],
        "size_opt": struct.unpack_from("<H", data, pe + 20)[0],
    }

def entropy(b: bytes) -> float:
    if not b: return 0.0
    c = collections.Counter(b); L = len(b); e = 0.0
    for v in c.values():
        p = v / L; e -= p * math.log2(p)
    return round(e, 3)

def find_dbg(root: str, is64: bool) -> str:
    """Locate x32dbg.exe / x64dbg.exe under the portable x64dbg root."""
    want = "x64dbg.exe" if is64 else "x32dbg.exe"
    for dirpath, _dirs, files in os.walk(root):
        if want in files:
            return os.path.join(dirpath, want)
    raise FileNotFoundError(f"{want} not found under {root}")

def rebuild_pe(image: bytes, info: dict, oep_rva: int | None) -> bytes:
    """Realign a memory image to a disk PE: raw offset == VA, raw size == vsize."""
    out = bytearray(image)
    pe, opt = info["pe"], info["pe"] + 24
    sec_tab = opt + info["size_opt"]
    for i in range(info["num_sec"]):
        s = sec_tab + i * 40
        vsize = struct.unpack_from("<I", out, s + 8)[0]
        vaddr = struct.unpack_from("<I", out, s + 12)[0]
        aligned = (vsize + 0xFFF) & ~0xFFF
        struct.pack_into("<I", out, s + 16, aligned)   # SizeOfRawData
        struct.pack_into("<I", out, s + 20, vaddr)     # PointerToRawData
    struct.pack_into("<I", out, opt + 36, 0x1000)      # SectionAlignment
    struct.pack_into("<I", out, opt + 40, 0x1000)      # FileAlignment
    if oep_rva is not None:
        struct.pack_into("<I", out, opt + 16, oep_rva & 0xFFFFFFFF)
    return bytes(out)

def looks_like_prologue(b: bytes) -> bool:
    return (b[:3] in (b"\x55\x8b\xec", b"\x55\x89\xe5")
            or b[:1] == b"\x53" or b[:2] == b"\x83\xec"
            or b[:2] == b"\x48\x89" or b[:2] == b"\x40\x53"
            or b[:3] == b"\x48\x83\xec")

def unpack(input_path: str, output_path: str, x64dbg_root: str,
           timeout_s: float, max_rounds: int) -> dict:
    from x64dbg_automate import X64DbgClient
    with open(input_path, "rb") as f:
        src = f.read()
    info = pe_info(src)
    res = {"input": input_path, "input_sha256": hashlib.sha256(src).hexdigest(),
           "arch": "x64" if info["is64"] else "x86",
           "image_base": hex(info["image_base"]),
           "packed_entropy": entropy(src[0x400:0x400 + 0x20000])}
    dbg = find_dbg(x64dbg_root, info["is64"])
    res["debugger"] = dbg

    base = info["image_base"]
    text_lo = base + 0x1000
    text_hi = base + min(info["size_image"], 0x26000)
    entry_va = base + info["entry_rva"]

    c = X64DbgClient(x64dbg_path=dbg)
    try:
        c.start_session(input_path)
        c.wait_until_debugging(20)
        res["elevated"] = c.debugger_is_elevated()
        c.hide_debugger_peb()
        # exec bp on image .text catches when code runs there; keep passing
        # exceptions so SEH-based decompressors complete. The stub also lives in
        # .text, so we step past it until a real prologue well away from entry.
        c.set_memory_breakpoint(text_lo, bp_type="x", singleshoot=False)
        oep = None
        deadline = time.time() + timeout_s
        for rnd in range(max_rounds):
            if time.time() > deadline:
                res["note"] = "timeout before OEP latch"; break
            c.go(pass_exceptions=True)
            if not c.wait_until_stopped(15) or not c.is_debugging():
                if not c.is_debugging():
                    res["note"] = "process exited"; break
                continue
            ip = c.get_reg("eip" if not info["is64"] else "rip")
            if text_lo <= ip < text_hi and abs(ip - entry_va) > 0x40:
                b = c.read_memory(ip, 4) or b""
                if looks_like_prologue(b):
                    oep = ip; res["oep"] = hex(ip); res["rounds"] = rnd; break
        res["oep_found"] = oep is not None

        if c.is_debugging():
            hdr = c.read_memory(base, 0x400)
            live = pe_info(hdr)
            size_image = live["size_image"] or info["size_image"]
            data = bytearray()
            cur, end = base, base + size_image
            while cur < end:
                n = min(0x1000, end - cur)
                chunk = c.read_memory(cur, n)
                data += chunk if chunk else b"\x00" * n
                cur += n
            oep_rva = (oep - base) if oep else None
            rebuilt = rebuild_pe(bytes(data), info, oep_rva)
            with open(output_path, "wb") as f:
                f.write(rebuilt)
            res.update(ok=True, output=output_path, output_size=len(rebuilt),
                       output_sha256=hashlib.sha256(rebuilt).hexdigest(),
                       unpacked_entropy=entropy(bytes(data[0x1000:0x21000])))
        else:
            res["ok"] = False
    finally:
        try: c.terminate_session()
        except Exception: pass
    return res

DEFAULT_X64DBG_ROOT = os.environ.get("REA_X64DBG_ROOT", r"E:\tools\REA-Studio\resources\toolchain\x64dbg")

def main() -> int:
    ap = argparse.ArgumentParser(description="rea-unpack: live-dump PE unpacker")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", default="")
    ap.add_argument("--x64dbg-root", default=DEFAULT_X64DBG_ROOT)
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--max-rounds", type=int, default=2000)
    ap.add_argument("--trusted", action="store_true",
                    help="acknowledge that the target will be EXECUTED")
    args = ap.parse_args()

    res = {"ok": False, "input": args.input}
    if not args.trusted:
        res["error"] = "refused: unpacking EXECUTES the target; pass --trusted"
        print(json.dumps(res)); return 2
    if not os.path.isfile(args.input):
        res["error"] = f"input not found: {args.input}"
        print(json.dumps(res)); return 2
    out = args.output or os.path.splitext(args.input)[0] + "_unpacked.exe"
    try:
        res = unpack(args.input, out, args.x64dbg_root, args.timeout, args.max_rounds)
    except Exception as e:
        res = {"ok": False, "input": args.input,
               "error": f"{type(e).__name__}: {e}", "tb": traceback.format_exc()}
    print(json.dumps(res, indent=2))
    return 0 if res.get("ok") else 1

if __name__ == "__main__":
    sys.exit(main())

