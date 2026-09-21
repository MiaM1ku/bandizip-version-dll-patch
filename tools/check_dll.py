#!/usr/bin/env python3
"""
Structural validation of the built version.dll.  Used as the build gate
locally (`make check`) and in CI.

Checks what a proxy DLL must get right:
  * PE32+ x86-64, Windows subsystem >= 6.0, non-zero entry point in code
  * exactly the 17 exports of the real version.dll, same ordinals
  * KERNEL32.dll as the only import, including every API the patch needs
  * the runtime fingerprints for Bandizip 7.4.6 are present in the code

Usage: python3 tools/check_dll.py [dist/version.dll]
"""

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_patch import Image  # noqa: E402

EXPECTED_EXPORTS = [
    "GetFileVersionInfoA",
    "GetFileVersionInfoByHandle",
    "GetFileVersionInfoExA",
    "GetFileVersionInfoExW",
    "GetFileVersionInfoSizeA",
    "GetFileVersionInfoSizeExA",
    "GetFileVersionInfoSizeExW",
    "GetFileVersionInfoSizeW",
    "GetFileVersionInfoW",
    "VerFindFileA",
    "VerFindFileW",
    "VerInstallFileA",
    "VerInstallFileW",
    "VerLanguageNameA",
    "VerLanguageNameW",
    "VerQueryValueA",
    "VerQueryValueW",
]

REQUIRED_IMPORTS = {
    "DisableThreadLibraryCalls", "InitializeCriticalSectionAndSpinCount",
    "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
    "GetModuleHandleW", "VirtualProtect", "FlushInstructionCache",
    "GetEnvironmentVariableW", "CreateFileW", "WriteFile", "CloseHandle",
    "GetSystemDirectoryW", "GetTempPathW", "CopyFileW", "GetFileAttributesW",
    "LoadLibraryW", "GetProcAddress", "FreeLibrary", "GetCurrentProcess",
    "GetCurrentProcessId",
}

# literals the runtime needs (wide ones must be searched as UTF-16LE)
REQUIRED_LITERALS = {
    'wide L"STD"': "STD".encode("utf-16le") + b"\0\0",
    'wide L"PRO"': "PRO".encode("utf-16le") + b"\0\0",
    'wide L"BZPATCH_LOG"': "BZPATCH_LOG".encode("utf-16le"),
}


def data_dir(img, index):
    return struct.unpack_from("<II", img.data, img.opt + 112 + index * 8)


def exports_of(img):
    rva, _size = data_dir(img, 0)
    off = img.rva_to_off(rva)
    (_flags, _ts, _maj, _min, _name, base, nfunc, nname, eat, npt, ot) = \
        struct.unpack_from("<IIHHIIIIIII", img.data, off)
    names = {}
    for i in range(nname):
        ordinal = struct.unpack_from("<H", img.data, img.rva_to_off(ot) + i * 2)[0]
        nrva = struct.unpack_from("<I", img.data, img.rva_to_off(npt) + i * 4)[0]
        noff = img.rva_to_off(nrva)
        name = img.data[noff:img.data.index(0, noff)].decode()
        names[ordinal + base] = name
    return base, nfunc, names


def imports_of(img):
    rva, _size = data_dir(img, 1)
    off = img.rva_to_off(rva)
    out = {}
    i = 0
    while True:
        oft, _ts, _fwd, name_rva, iat = struct.unpack_from("<IIIII", img.data, off + i * 20)
        if name_rva == 0:
            break
        noff = img.rva_to_off(name_rva)
        dll = img.data[noff:img.data.index(0, noff)].decode()
        funcs = set()
        t = oft or iat
        j = 0
        while True:
            value = struct.unpack_from("<Q", img.data, img.rva_to_off(t) + j * 8)[0]
            if value == 0:
                break
            if value & (1 << 63):
                funcs.add("ordinal#%d" % (value & 0xFFFF))
            else:
                foff = img.rva_to_off(value + 2)
                funcs.add(img.data[foff:img.data.index(0, foff)].decode())
            j += 1
        out[dll] = funcs
        i += 1
    return out


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "dist/version.dll")
    img = Image(path)
    data = bytes(img.data)
    results = []

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail))

    nt = img.opt - 24
    opt_magic = struct.unpack_from("<H", img.data, img.opt)[0]
    subsystem = struct.unpack_from("<H", img.data, img.opt + 68)[0]
    subsys_major = struct.unpack_from("<H", img.data, img.opt + 48)[0]
    entry = struct.unpack_from("<I", img.data, img.opt + 16)[0]
    entry_off = None
    for _n, _vs, vaddr, rsize, roff, chars in img.sections:
        if rsize and (chars & 0x20000000) and vaddr <= entry < vaddr + rsize:
            entry_off = roff + entry - vaddr

    check("PE32+ image", opt_magic == 0x20B, f"magic {opt_magic:#x}")
    check("x86-64", struct.unpack_from("<H", img.data, nt + 4)[0] == 0x8664)
    check("windows subsystem 6.0+", subsystem == 2 and subsys_major >= 6,
          f"subsystem {subsystem}, version {subsys_major}")
    check("entry point in code", entry_off is not None, f"entry {entry:#x}")

    base, nfunc, names = exports_of(img)
    got = [names.get(i) for i in range(base, base + nfunc)]
    check("17 exports, canonical order", got == EXPECTED_EXPORTS,
          f"base {base}, {nfunc} funcs")

    imports = imports_of(img)
    check("imports KERNEL32 only", list(imports) == ["KERNEL32.dll"], ", ".join(imports))
    missing = REQUIRED_IMPORTS - imports.get("KERNEL32.dll", set())
    check("all required KERNEL32 APIs", not missing, "missing: " + ", ".join(sorted(missing)))

    for label, literal in REQUIRED_LITERALS.items():
        check(f"literal present ({label})", data.count(literal) >= 1)

    digest = hashlib.sha256(data).hexdigest()
    print(f"{path}: {len(data)} bytes  sha256 {digest}\n")
    failed = 0
    for name, ok, detail in results:
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
        failed += not ok
    print("\nPASS" if not failed else f"\nFAIL: {failed} check(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
