#!/usr/bin/env python3
"""
Differential emulation of Bandizip 7.4.6's edition decision.

sub_1401316C0 (RVA 0x1316C0) maps the stored licence state to
appinfo.edition (offset 0x120) and to the app object's edition string
(appobj+0xC0).  This script executes that function twice - on the pristine
image and on the version.dll-patched image - for the state "no licence
present", with its five helper calls stubbed, and reports what it stored.

Expected:
    pristine : edition 152 -> decode 100  (Standard)  string "STD"
    patched  : edition 980 -> decode 1000 (Professional) string "PRO"

Usage: python3 tools/emulate_edition.py [Bandizip.exe]        (needs: pip install unicorn)
"""

import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RCX,
                               UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_RAX,
                               UC_X86_REG_RDI)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_patch import Image, patch_image, decode  # noqa: E402

FN_EDITION = 0x1401316C0

HLP_LICENCE_OBJ = 0x1400CF570   # returns the licence object
HLP_LICENCE_CHK = 0x1400D0370   # validates/resets it
HLP_APP_OBJ = 0x140167890       # returns the application object
HLP_STR_ASSIGN = 0x140018F50    # dest string object, source, char count
HLP_STR_CLEAR = 0x140018CB0     # clears a string object (tail call: end)

SCRATCH = 0x300000000
APPINFO = SCRATCH + 0x1000      # app info struct, edition at +0x120
APPOBJ = SCRATCH + 0x2000       # application object, edition string at +0xC0
LICOBJ = SCRATCH + 0x4000       # licence object: +0x60 status, +0x28 edition
STR_POOL = SCRATCH + 0x6000
STACK = SCRATCH + 0x10000
STACK_TOP = STACK + 0x10000


class Emu:
    def __init__(self, img: Image):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.img = img
        self.mu.mem_map(img.image_base, (img.image_size + 0xFFFF) & ~0xFFFF, UC_PROT_ALL)
        self.mu.mem_write(img.image_base, bytes(img.data[:0x1000]))
        for _n, vsize, vaddr, rsize, roff, _c in img.sections:
            if rsize:
                self.mu.mem_write(img.image_base + vaddr, bytes(img.data[roff:roff + rsize]))
        self.mu.mem_map(SCRATCH, 0x20000, UC_PROT_ALL)

        # "no licence present": both licence strings exist but are empty
        empty = STR_POOL
        self.mu.mem_write(empty, b"\0\0\0\0")
        self.mu.mem_write(LICOBJ + 0x60 - 0x10, struct.pack("<I", 0))  # status len 0
        self.mu.mem_write(LICOBJ + 0x60, struct.pack("<Q", empty))
        self.mu.mem_write(LICOBJ + 0x28, struct.pack("<Q", empty))
        self.str_next = STR_POOL + 0x100

        self.result = None
        self.hook_stub(HLP_LICENCE_OBJ, self._licence_obj)
        self.hook_stub(HLP_LICENCE_CHK, lambda mu: set_rax(mu, 0))
        self.hook_stub(HLP_APP_OBJ, lambda mu: set_rax(mu, APPOBJ))
        self.hook_stub(HLP_STR_ASSIGN, self._str_assign)
        self.hook_stub(HLP_STR_CLEAR, self._finish)

    # -- hooks ----------------------------------------------------------
    def hook_stub(self, addr, fn):
        def cb(mu, _address, _size, _user):
            fn(mu)
            ret = struct.unpack("<Q", mu.mem_read(mu.reg_read(UC_X86_REG_RSP), 8))[0]
            mu.reg_write(UC_X86_REG_RSP, mu.reg_read(UC_X86_REG_RSP) + 8)
            mu.reg_write(UC_X86_REG_RIP, ret)
        self.mu.hook_add(UC_HOOK_CODE, cb, begin=addr, end=addr)

    def _licence_obj(self, mu):
        set_rax(mu, LICOBJ)

    def _str_assign(self, mu):
        dest = mu.reg_read(UC_X86_REG_RCX)
        src = mu.reg_read(UC_X86_REG_RDX)
        n = mu.reg_read(UC_X86_REG_R8)
        buf = self.str_next
        self.str_next += 0x100
        data = bytes(mu.mem_read(src, 2 * n)) if (src and n) else b""
        mu.mem_write(buf, data + b"\0\0")
        mu.mem_write(dest, struct.pack("<Q", buf))
        mu.mem_write(dest - 0x10, struct.pack("<I", n))
        set_rax(mu, buf)

    def _finish(self, mu):
        self.result = (mu.reg_read(UC_X86_REG_RCX))
        mu.emu_stop()
        self._stopped = True
        # emulate the return from the hooked call as well

    # -- run ------------------------------------------------------------
    def run(self):
        mu = self.mu
        mu.reg_write(UC_X86_REG_RSP, STACK_TOP - 0x100)
        mu.mem_write(STACK_TOP - 0x100, b"\0" * 8)          # fake return address
        mu.reg_write(UC_X86_REG_RCX, APPINFO)
        self._stopped = False
        try:
            mu.emu_start(FN_EDITION, 0, timeout=10 * 1000 * 1000, count=100000)
        except Exception as exc:                            # noqa: BLE001
            import traceback; traceback.print_exc()
            return f"emulation error: {exc}"

        edition = struct.unpack("<I", mu.mem_read(APPINFO + 0x120, 4))[0]
        strptr = struct.unpack("<Q", mu.mem_read(APPOBJ + 0xC0, 8))[0]
        text = ""
        if strptr:
            raw = bytes(mu.mem_read(strptr, 16))
            text = raw.decode("utf-16le").split("\0")[0]
        return edition, text


def set_rax(mu, value):
    mu.reg_write(UC_X86_REG_RAX, value)


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "Bandizip.exe")

    pristine = Image(src)
    patched = Image(src)
    info = patch_image(patched)

    print(f"image: {src}  base={pristine.image_base:#x}")
    print(f"fingerprints: store {info['store_off']:#x}  lea {info['lea_off']:#x}  "
          f"PRO literal {info['pro_off']:#x}\n")

    rc = 0
    for label, img in (("pristine", pristine), ("patched ", patched)):
        res = Emu(img).run()
        if isinstance(res, str):
            print(f"{label}: {res}")
            rc = 1
            continue
        edition, text = res
        public = decode(edition)
        name = {100: "Standard", 1000: "Professional", 10000: "Enterprise"}.get(public, "?")
        print(f"{label}: edition={edition:<5} decode={public:<5} ({name})  editionStr={text!r}")
        expected = (152, "STD") if label == "pristine" else (980, "PRO")
        if (edition, text) != expected:
            print(f"          FAIL: expected {expected}")
            rc = 1
        else:
            print("          OK")

    print("\nPASS" if rc == 0 else "\nFAIL")
    return rc


if __name__ == "__main__":
    sys.exit(main())
