#!/usr/bin/env python3
"""
Independent model of the version.dll patch, used to verify the fingerprints
and the resulting code against the real Bandizip.exe.

  python3 tools/verify_patch.py [Bandizip.exe]

Performs exactly what src/version.c does at runtime:
  * locate  C7 86 20 01 00 00 98 00 00 00          (unique, executable sections)
  * locate  48 8D 15 ?? ?? ?? ?? 48 8D 88 C0 00 00 00 (unique)
  * verify the lea source literal really is L"STD"
  * locate the single L"PRO" wide literal
  * rewrite the lea displacement onto L"PRO" and the store immediate to 980
then re-reads the patched file and prints the new bytes.
"""

import re
import struct
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path

PAT_STORE = bytes.fromhex("c7862001000098000000")
PAT_LEA = re.compile(rb"\x48\x8d\x15(....)\x48\x8d\x88\xc0\x00\x00\x00", re.S)
W_STD = "STD".encode("utf-16le") + b"\x00\x00"
W_PRO = "PRO".encode("utf-16le") + b"\x00\x00"


def decode(edition: int) -> int:
    """Bandizip's inline edition decode, applied at every edition test."""
    return (((edition & 0xD5555555) << 1) | ((edition >> 1) & 0x55555555)) & 0xFFFFFFFF


class Image:
    def __init__(self, path: Path):
        self.path = path
        self.data = bytearray(path.read_bytes())
        e = struct.unpack_from("<I", self.data, 0x3C)[0]
        assert self.data[e:e + 4] == b"PE\0\0"
        coff = e + 4
        (machine, nsec, _ts, _ps, _ns, opt_size, _ch) = struct.unpack_from("<HHIIIHH", self.data, coff)
        assert machine == 0x8664, "not x86-64"
        self.opt = e + 24
        self.image_base = struct.unpack_from("<Q", self.data, self.opt + 24)[0]
        self.image_size = struct.unpack_from("<I", self.data, self.opt + 56)[0]
        self.sections = []
        sh = self.opt + opt_size
        for i in range(nsec):
            name, vsize, vaddr, rsize, roff = struct.unpack_from("<8sIIII", self.data, sh + i * 40)
            chars = struct.unpack_from("<I", self.data, sh + i * 40 + 36)[0]
            self.sections.append((name.rstrip(b"\0").decode(), vsize, vaddr, rsize, roff, chars))

    def rva_to_off(self, rva: int) -> int:
        for _n, vsize, vaddr, rsize, roff, _c in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return roff + (rva - vaddr)
        raise KeyError(hex(rva))

    def off_to_va(self, off: int) -> int:
        for _n, vsize, vaddr, rsize, roff, _c in self.sections:
            if roff <= off < roff + rsize:
                return self.image_base + vaddr + (off - roff)
        raise KeyError(hex(off))

    def code_span(self):
        for name, vsize, vaddr, rsize, roff, chars in self.sections:
            if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                yield name, roff, min(vsize or rsize, rsize)


def find_unique(buf, pat, what):
    hits = [m.start() for m in re.finditer(re.escape(pat), buf)]
    if len(hits) != 1:
        sys.exit(f"FAIL: {what}: expected 1 occurrence, found {len(hits)}")
    return hits[0]


def patch_image(img: "Image", apply=True):
    """
    Locate the Bandizip 7.4.6 fingerprints in an image and (optionally) apply
    the same rewrite src/version.c performs at runtime.  Returns the offsets.
    """
    store_off = lea_off = None
    for name, roff, size in img.code_span():
        chunk = bytes(img.data[roff:roff + size])
        hits = [m.start() for m in re.finditer(re.escape(PAT_STORE), chunk)]
        if len(hits) == 1:
            store_off = roff + hits[0]
        elif len(hits) > 1:
            sys.exit(f"FAIL: edition store ambiguous in {name}: {len(hits)}")
        ms = list(re.finditer(PAT_LEA.pattern, chunk, re.S))
        if len(ms) == 1:
            lea_off = roff + ms[0].start()
        elif len(ms) > 1:
            sys.exit(f"FAIL: lea pair ambiguous in {name}: {len(ms)}")
    if store_off is None or lea_off is None:
        sys.exit("FAIL: fingerprints not found")
    if store_off - lea_off != 0x13:
        sys.exit("FAIL: unexpected code layout")

    lea_va = img.off_to_va(lea_off)
    disp = struct.unpack_from("<i", img.data, lea_off + 3)[0]
    src_va = lea_va + 7 + disp
    src_off = img.rva_to_off(src_va - img.image_base)
    if bytes(img.data[src_off:src_off + 8]) != W_STD:
        sys.exit("FAIL: lea source is not L\"STD\"")

    pro_hits = [m.start() for m in re.finditer(re.escape(W_PRO), bytes(img.data))]
    if len(pro_hits) != 1:
        sys.exit(f"FAIL: L\"PRO\" not unique: {len(pro_hits)}")
    pro_off = pro_hits[0]
    pro_va = img.off_to_va(pro_off)

    if apply:
        new_disp = pro_va - (lea_va + 7)
        if not -0x80000000 <= new_disp <= 0x7FFFFFFF:
            sys.exit("FAIL: PRO literal out of rel32 range")
        struct.pack_into("<i", img.data, lea_off + 3, new_disp)
        struct.pack_into("<I", img.data, store_off + 6, 980)

    return dict(store_off=store_off, lea_off=lea_off, lea_va=lea_va,
                src_off=src_off, src_va=src_va, pro_off=pro_off, pro_va=pro_va)


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "Bandizip.exe")
    img = Image(src)
    print(f"image        : {src}  base={img.image_base:#x} size={img.image_size:#x}")

    info = patch_image(img)
    store_off, lea_off = info["store_off"], info["lea_off"]
    lea_va, src_va, pro_va = info["lea_va"], info["src_va"], info["pro_va"]
    print(f"store        : file off {store_off:#x}  va {img.off_to_va(store_off):#x}")
    print(f"lea pair     : file off {lea_off:#x}  va {lea_va:#x}")
    print(f"lea source   : {src_va:#x} -> {bytes(img.data[info['src_off']:info['src_off'] + 8])!r}")
    print(f"PRO literal  : {pro_va:#x} (file off {info['pro_off']:#x})")

    print(f"edition      : {152} -> decoded {decode(152)}   (STD)")
    print(f"patch target : 980 -> decoded {decode(980)}   (PRO)")

    out = Path(tempfile.gettempdir()) / ("patched_" + src.name)
    out.write_bytes(img.data)
    print(f"patched copy : {out}")

    again = Image(out)
    disp2 = struct.unpack_from("<i", again.data, lea_off + 3)[0]
    imm2 = struct.unpack_from("<I", again.data, store_off + 6)[0]
    src2_va = lea_va + 7 + disp2
    src2_off = again.rva_to_off(src2_va - again.image_base)
    print(f"verify       : lea -> {src2_va:#x} = {bytes(again.data[src2_off:src2_off + 8])!r}"
          f"   store imm = {imm2} (decoded {decode(imm2)})")
    assert src2_va == pro_va and imm2 == 980

    dis = subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn",
                          f"--start-address={lea_va - 0x20:#x}",
                          f"--stop-address={lea_va + 0x40:#x}", str(out)],
                         capture_output=True, text=True)
    print("\n--- patched code ---")
    print(dis.stdout.strip() or dis.stderr.strip())


if __name__ == "__main__":
    main()
