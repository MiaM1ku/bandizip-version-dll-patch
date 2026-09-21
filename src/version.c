/*
 * version.dll  -  pass-through proxy for the system version.dll that also
 *                 unlocks the Professional edition of Bandizip 7.4.6
 *                 (Bandizip.exe 7.46.0.1 / BuildNo 71822, x86-64).
 *
 * Why it works
 * ------------
 * Bandizip.exe statically imports VERSION.dll (GetFileVersionInfoSizeW,
 * GetFileVersionInfoW, VerQueryValueW).  version.dll is not a KnownDLL, so
 * the loader resolves it from the application directory first: a version.dll
 * next to Bandizip.exe runs in-process before the EXE entry point, and before
 * any of Bandizip's own code (including its integrity checks) executes.
 *
 * What is patched
 * ---------------
 * The edition ("appEditionStrEn") is decided by one basic block of
 * sub_1401316C0:
 *
 *     1401317d7  call  sub_140167890
 *     1401317dc  mov   r8d, 3
 *     1401317e2  lea   rdx, [rip+disp]            ; L"STD"
 *     1401317e9  lea   rcx, [rax+0C0h]            ; appobj->editionStr
 *     1401317f0  call  sub_140018F50              ; copy 3 wchars
 *     1401317f5  mov   dword ptr [rsi+120h], 98h  ; edition = 152 (STD)
 *
 * Every edition test in the image is the same inline expression
 * decode(appinfo+0x120), with
 *     decode(x) = ((x & 0xD5555555) << 1) | ((x >> 1) & 0x55555555)
 * compared against 100 (STD), 1000 (PRO) or 10000 (ENT):
 *     decode(152) = 100,  decode(980) = 1000,  decode(6944) = 10000.
 *
 * Both writes above are redirected:
 *     1401317e2  lea   rdx, [rip+disp]              ; L"PRO"
 *     1401317f5  mov   dword ptr [rsi+120h], 3D4h   ; edition = 980 (PRO)
 *
 * Consequently every "is this the free/standard edition?" gate (33 sites
 * testing 100) is bypassed, the Professional gate (testing 1000) succeeds,
 * and the edition string shown in the UI / used to pick the updater section
 * becomes "PRO".  Enterprise-only gates (testing 10000) stay locked.
 *
 * Safety
 * ------
 * The patch is applied only when the mapped image carries the exact 7.4.6
 * fingerprints, each unique in the image:
 *     48 8D 15 ?? ?? ?? ?? 48 8D 88 C0 00 00 00    lea/lea pair
 *     C7 86 20 01 00 00 98 00 00 00                mov [rsi+120h], 98h
 *     one single L"PRO\0" wide literal (the new string source)
 * plus the structural checks below.  On any other build nothing is written
 * and the DLL is a plain, fully transparent proxy.
 *
 * x86-64 only.  Linked without a CRT: its only import is KERNEL32.dll.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* ------------------------------------------------------------- logging */

static HANDLE g_log = INVALID_HANDLE_VALUE;

static void log_open(void)
{
    wchar_t path[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"BZPATCH_LOG", path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return;
    g_log = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void log_put(const char *s)
{
    DWORD written;
    const char *end = s;
    if (g_log == INVALID_HANDLE_VALUE)
        return;
    while (*end)
        end++;
    if (end != s)
        WriteFile(g_log, s, (DWORD)(end - s), &written, NULL);
}

static void log_hex(UINT64 v)
{
    static const char digits[] = "0123456789abcdef";
    char b[17];
    int i;
    for (i = 0; i < 16; i++)
        b[i] = digits[(v >> ((15 - i) * 4)) & 0xF];
    b[16] = 0;
    log_put("0x");
    log_put(b);
}

static void log_dec(unsigned v)
{
    char b[11];
    int i = 11;
    b[--i] = 0;
    if (v == 0)
        b[--i] = '0';
    while (v != 0) {
        b[--i] = (char)('0' + (v % 10));
        v /= 10;
    }
    log_put(b + i);
}

static void log_wstr(const wchar_t *s)
{
    char b[64];
    UINT i;
    if (!s) {
        log_put("(null)");
        return;
    }
    for (i = 0; i + 1 < sizeof b && s[i]; i++)
        b[i] = (char)(s[i] < 0x80 ? s[i] : '?');
    b[i] = 0;
    log_put(b);
}

static void log_close(void)
{
    if (g_log != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log);
        g_log = INVALID_HANDLE_VALUE;
    }
}

/* ---------------------------------------------------------- the patch */

/* mov dword ptr [rsi+120h], 98h  --  appinfo.edition = 152 (STD) */
static const BYTE PAT_STORE[10] = {0xC7, 0x86, 0x20, 0x01, 0x00, 0x00,
                                   0x98, 0x00, 0x00, 0x00};
/* lea rdx, [rip+disp32] ; lea rcx, [rax+0C0h]  --  edition string source */
static const BYTE PAT_LEA[3]      = {0x48, 0x8D, 0x15};
static const BYTE PAT_LEA_TAIL[7] = {0x48, 0x8D, 0x88, 0xC0, 0x00, 0x00, 0x00};

#define EDITION_STD 152u
#define EDITION_PRO 980u
#define GAP_STORE_TO_LEA 0x13

/* Bandizip 7.4.6 state observed by the diagnostic probe (see probe_edition) */
#define RVA_APPINFO_EDITION   0x31D8B0u   /* &unk_14031D790 + 0x120 */
#define RVA_APPOBJ_EDITIONSTR 0x31D9F0u   /* &qword_14031D930 + 0x0C0 */

/* every edition test derives 100/1000/10000 from the stored value */
static unsigned edition_to_public(unsigned e)
{
    return ((e & 0xD5555555u) << 1) | ((e >> 1) & 0x55555555u);
}

static BOOL bytes_eq(const BYTE *a, const BYTE *b, SIZE_T n)
{
    SIZE_T i;
    for (i = 0; i < n; i++)
        if (a[i] != b[i])
            return FALSE;
    return TRUE;
}


/* exact pattern; exactly one occurrence required, else NULL */
static BYTE *scan_unique(const BYTE *p, SIZE_T size, const BYTE *pat, SIZE_T n)
{
    BYTE *hit = NULL;
    SIZE_T i;
    if (size < n)
        return NULL;
    for (i = 0; i + n <= size; i++) {
        if (p[i] != pat[0] || !bytes_eq(p + i, pat, n))
            continue;
        if (hit)
            return NULL;                 /* ambiguous: refuse to patch */
        hit = (BYTE *)(p + i);
    }
    return hit;
}

/* 48 8D 15 <disp32> 48 8D 88 C0 00 00 00 ; exactly one occurrence */
static BYTE *scan_unique_lea(const BYTE *p, SIZE_T size)
{
    BYTE *hit = NULL;
    SIZE_T i;
    if (size < 14)
        return NULL;
    for (i = 0; i + 14 <= size; i++) {
        if (p[i] != PAT_LEA[0] || p[i + 1] != PAT_LEA[1] || p[i + 2] != PAT_LEA[2])
            continue;
        if (!bytes_eq(p + i + 7, PAT_LEA_TAIL, 7))
            continue;
        if (hit)
            return NULL;
        hit = (BYTE *)(p + i);
    }
    return hit;
}

static const char *g_status = "not started";

static int patch_license(void)
{
    const BYTE *mod = (const BYTE *)GetModuleHandleW(NULL);
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_SECTION_HEADER *sec;
    BYTE *store = NULL, *lea = NULL, *pro;
    const BYTE *src;
    SIZE_T image_size;
    INT64 disp;
    DWORD old_prot;
    WORD i, nsec;

    if (!mod) { g_status = "no main module"; return 0; }
    dos = (const IMAGE_DOS_HEADER *)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { g_status = "not a PE image"; return 0; }
    nt = (const IMAGE_NT_HEADERS64 *)(mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { g_status = "not a PE image"; return 0; }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) { g_status = "not x86-64"; return 0; }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { g_status = "not PE32+"; return 0; }

    image_size = nt->OptionalHeader.SizeOfImage;
    nsec = nt->FileHeader.NumberOfSections;
    sec = IMAGE_FIRST_SECTION(nt);

    /* code fingerprints live in executable sections */
    for (i = 0; i < nsec; i++) {
        const BYTE *p;
        SIZE_T sz, rva;
        rva = sec[i].VirtualAddress;
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) || rva >= image_size)
            continue;
        sz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (rva + sz > image_size)
            sz = image_size - rva;
        p = mod + rva;
        if (store == NULL)
            store = scan_unique(p, sz, PAT_STORE, sizeof PAT_STORE);
        if (lea == NULL)
            lea = scan_unique_lea(p, sz);
    }

    if (!store || !lea) { g_status = "build not recognised - not patched"; return 0; }
    if (store - lea != GAP_STORE_TO_LEA) { g_status = "unexpected code layout"; return 0; }

    src = lea + 7 + (INT64)*(const INT32 *)(lea + 3);
    if (src < mod || src + 8 > mod + image_size) { g_status = "literal out of image"; return 0; }
    if (!bytes_eq(src, (const BYTE *)L"STD", 8)) { g_status = "literal is not STD"; return 0; }

    /* replacement is the module's own unique L"PRO" literal */
    pro = scan_unique(mod, image_size, (const BYTE *)L"PRO", 8);
    if (!pro || pro == src) { g_status = "no unique PRO literal"; return 0; }

    disp = (INT64)(pro - (lea + 7));
    if (disp < -0x7FFFFFFFLL || disp > 0x7FFFFFFFLL) { g_status = "PRO literal out of range"; return 0; }

    if (!VirtualProtect(lea, 0x20, PAGE_EXECUTE_READWRITE, &old_prot)) {
        g_status = "VirtualProtect failed";
        return 0;
    }
    *(INT32 *)(lea + 3) = (INT32)disp;                  /* source literal: STD -> PRO */
    store[6] = (BYTE)(EDITION_PRO & 0xFF);              /* edition: 152 -> 980 (PRO)  */
    store[7] = (BYTE)((EDITION_PRO >> 8) & 0xFF);
    store[8] = 0;
    store[9] = 0;
    FlushInstructionCache(GetCurrentProcess(), lea, 0x20);
    VirtualProtect(lea, 0x20, old_prot, &old_prot);

    /* read back */
    if (*(const INT32 *)(lea + 3) != (INT32)disp || *(const DWORD *)(store + 6) != EDITION_PRO) {
        g_status = "read-back mismatch";
        return 0;
    }

    g_status = "patched";
    log_put("bandizip 7.4.6 edition patch: store=");
    log_hex((UINT64)(ULONG_PTR)store);
    log_put(" lea=");
    log_hex((UINT64)(ULONG_PTR)lea);
    log_put(" pro=");
    log_hex((UINT64)(ULONG_PTR)pro);
    log_put(" edition ");
    log_dec(EDITION_STD);
    log_put("(");
    log_dec(edition_to_public(EDITION_STD));
    log_put(") -> ");
    log_dec(EDITION_PRO);
    log_put("(");
    log_dec(edition_to_public(EDITION_PRO));
    log_put(")\r\n");
    return 1;
}

/* ------------------------------------------ runtime self-check (opt-in) */

/*
 * Enabled only when BZPATCH_LOG is set and the image was patched.  Bandizip
 * asks version.dll for its own version information in sub_140131820 right
 * after it has decided the edition, so the first forwarded call is a
 * dependency-free trigger to report what the application really ended up
 * with: the raw edition word, its decoded value (1000 = Professional) and the
 * edition string the application stored.
 */
static BOOL g_probe_pending;

static void probe_edition(void)
{
    const BYTE *base;
    DWORD edition;
    const wchar_t *str;

    if (!g_probe_pending)
        return;

    base = (const BYTE *)GetModuleHandleW(NULL);
    edition = *(const volatile DWORD *)(base + RVA_APPINFO_EDITION);
    if (edition == 0)
        return;                     /* the application has not decided yet */

    g_probe_pending = FALSE;
    str = *(const wchar_t *const *)(base + RVA_APPOBJ_EDITIONSTR);

    log_put("runtime: edition=");
    log_dec(edition);
    log_put(" decoded=");
    log_dec(edition_to_public(edition));
    log_put(" editionStr=");
    log_wstr(str);
    log_put("\r\n");
    log_close();
}

/* ------------------------------------- pass-through to the real version.dll */

static CRITICAL_SECTION g_lock;
static BOOL g_lock_ready;
static HMODULE g_real;

static UINT w_len(const wchar_t *s)
{
    UINT n = 0;
    while (s[n])
        n++;
    return n;
}

static BOOL w_cat(wchar_t *dst, const wchar_t *src, UINT cap)
{
    UINT n = w_len(dst);
    UINT i = 0;
    while (src[i]) {
        if (n + i + 1 >= cap)
            return FALSE;
        dst[n + i] = src[i];
        i++;
    }
    dst[n + i] = 0;
    return TRUE;
}

static void w_copy(wchar_t *dst, const wchar_t *src, UINT cap)
{
    UINT i = 0;
    while (src[i] && i + 1 < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

/*
 * The genuine version.dll is loaded under a different base name: the loader
 * matches loaded modules by base name, so LoadLibraryW("...\version.dll")
 * would return *this* module and every forward would recurse.
 */
static HMODULE load_real_version(void)
{
    wchar_t sys[MAX_PATH], dir[MAX_PATH], dst[MAX_PATH];
    wchar_t pid[16];
    UINT n, i, v;
    DWORD attr;
    HMODULE m;

    n = GetSystemDirectoryW(sys, MAX_PATH);
    if (n == 0 || n >= MAX_PATH - 16)
        return NULL;
    if (!w_cat(sys, L"\\version.dll", MAX_PATH))
        return NULL;

    if (GetTempPathW(MAX_PATH, dir) == 0 || w_len(dir) >= MAX_PATH - 32)
        return NULL;

    v = GetCurrentProcessId();
    for (i = 0; i < 5; i++) {
        static const DWORD scale[5] = {10000, 1000, 100, 10, 1};
        pid[i] = (wchar_t)('0' + (v / scale[i]) % 10);
    }
    pid[5] = 0;

    w_copy(dst, dir, MAX_PATH);
    if (!w_cat(dst, L"bz_version_", MAX_PATH) || !w_cat(dst, pid, MAX_PATH) ||
        !w_cat(dst, L".dll", MAX_PATH))
        return NULL;

    attr = GetFileAttributesW(dst);
    if (attr == INVALID_FILE_ATTRIBUTES)
        CopyFileW(sys, dst, FALSE);                  /* best effort */
    m = LoadLibraryW(dst);
    if (m)
        return m;

    /* last resort: a single shared copy */
    w_copy(dst, dir, MAX_PATH);
    if (!w_cat(dst, L"bz_version.dll", MAX_PATH))
        return NULL;
    if (GetFileAttributesW(dst) == INVALID_FILE_ATTRIBUTES)
        CopyFileW(sys, dst, FALSE);
    return LoadLibraryW(dst);
}

static FARPROC real_proc(const char *name)
{
    probe_edition();
    if (!g_real) {
        if (g_lock_ready)
            EnterCriticalSection(&g_lock);
        if (!g_real)
            g_real = load_real_version();
        if (g_lock_ready)
            LeaveCriticalSection(&g_lock);
    }
    return g_real ? GetProcAddress(g_real, name) : NULL;
}

#define FWD(fail_value, type, name, ...)             \
    do {                                             \
        type f_ = (type)real_proc(name);             \
        if (!f_)                                     \
            return fail_value;                       \
        return f_(__VA_ARGS__);                      \
    } while (0)

typedef BOOL  (WINAPI *F_GVI)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI *F_GVIH)(DWORD, HANDLE, LPVOID, DWORD);
typedef BOOL  (WINAPI *F_GVIExA)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI *F_GVIExW)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *F_GVISzA)(LPCSTR, LPDWORD);
typedef DWORD (WINAPI *F_GVISzExA)(DWORD, LPCSTR, LPDWORD);
typedef DWORD (WINAPI *F_GVISzExW)(DWORD, LPCWSTR, LPDWORD);
typedef DWORD (WINAPI *F_GVISzW)(LPCWSTR, LPDWORD);
typedef BOOL  (WINAPI *F_GVIW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *F_FFA)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD (WINAPI *F_FFW)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
typedef DWORD (WINAPI *F_IFA)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, PUINT);
typedef DWORD (WINAPI *F_IFW)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT);
typedef DWORD (WINAPI *F_LNA)(DWORD, LPSTR, DWORD);
typedef DWORD (WINAPI *F_LNW)(DWORD, LPWSTR, DWORD);
typedef BOOL  (WINAPI *F_QVA)(LPCVOID, LPCSTR, LPVOID *, PUINT);
typedef BOOL  (WINAPI *F_QVW)(LPCVOID, LPCWSTR, LPVOID *, PUINT);

BOOL WINAPI GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d)
{ FWD(FALSE, F_GVI, "GetFileVersionInfoA", a, b, c, d); }

BOOL WINAPI GetFileVersionInfoByHandle(DWORD a, HANDLE b, LPVOID c, DWORD d)
{ FWD(FALSE, F_GVIH, "GetFileVersionInfoByHandle", a, b, c, d); }

BOOL WINAPI GetFileVersionInfoExA(DWORD a, LPCSTR b, DWORD c, DWORD d, LPVOID e)
{ FWD(FALSE, F_GVIExA, "GetFileVersionInfoExA", a, b, c, d, e); }

BOOL WINAPI GetFileVersionInfoExW(DWORD a, LPCWSTR b, DWORD c, DWORD d, LPVOID e)
{ FWD(FALSE, F_GVIExW, "GetFileVersionInfoExW", a, b, c, d, e); }

DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b)
{ FWD(0, F_GVISzA, "GetFileVersionInfoSizeA", a, b); }

DWORD WINAPI GetFileVersionInfoSizeExA(DWORD a, LPCSTR b, LPDWORD c)
{ FWD(0, F_GVISzExA, "GetFileVersionInfoSizeExA", a, b, c); }

DWORD WINAPI GetFileVersionInfoSizeExW(DWORD a, LPCWSTR b, LPDWORD c)
{ FWD(0, F_GVISzExW, "GetFileVersionInfoSizeExW", a, b, c); }

DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b)
{ FWD(0, F_GVISzW, "GetFileVersionInfoSizeW", a, b); }

BOOL WINAPI GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d)
{ FWD(FALSE, F_GVIW, "GetFileVersionInfoW", a, b, c, d); }

DWORD WINAPI VerFindFileA(DWORD a, LPSTR b, LPSTR c, LPSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h)
{ FWD(0, F_FFA, "VerFindFileA", a, b, c, d, e, f, g, h); }

DWORD WINAPI VerFindFileW(DWORD a, LPWSTR b, LPWSTR c, LPWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h)
{ FWD(0, F_FFW, "VerFindFileW", a, b, c, d, e, f, g, h); }

DWORD WINAPI VerInstallFileA(DWORD a, LPSTR b, LPSTR c, LPSTR d, LPSTR e, LPSTR f, LPSTR g, PUINT h)
{ FWD(0, F_IFA, "VerInstallFileA", a, b, c, d, e, f, g, h); }

DWORD WINAPI VerInstallFileW(DWORD a, LPWSTR b, LPWSTR c, LPWSTR d, LPWSTR e, LPWSTR f, LPWSTR g, PUINT h)
{ FWD(0, F_IFW, "VerInstallFileW", a, b, c, d, e, f, g, h); }

DWORD WINAPI VerLanguageNameA(DWORD a, LPSTR b, DWORD c)
{ FWD(0, F_LNA, "VerLanguageNameA", a, b, c); }

DWORD WINAPI VerLanguageNameW(DWORD a, LPWSTR b, DWORD c)
{ FWD(0, F_LNW, "VerLanguageNameW", a, b, c); }

BOOL WINAPI VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID *c, PUINT d)
{ FWD(FALSE, F_QVA, "VerQueryValueA", a, b, c, d); }

BOOL WINAPI VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID *c, PUINT d)
{ FWD(FALSE, F_QVW, "VerQueryValueW", a, b, c, d); }

/* ------------------------------------------------------------- DllMain */

static BOOL WINAPI bz_dll_main(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        int patched;
        DisableThreadLibraryCalls(inst);
        if (InitializeCriticalSectionAndSpinCount(&g_lock, 0x400))
            g_lock_ready = TRUE;
        log_open();
        patched = patch_license();
        if (g_log != INVALID_HANDLE_VALUE) {
            log_put("status=");
            log_put(g_status);
            log_put("\r\n");
            if (patched) {
                /* reported on the first forwarded version.dll call */
                g_probe_pending = TRUE;
            } else {
                log_close();
            }
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        log_close();
        if (g_lock_ready)
            DeleteCriticalSection(&g_lock);
        g_lock_ready = FALSE;
        if (g_real) {
            FreeLibrary(g_real);
            g_real = NULL;
        }
    }
    return TRUE;
}

/* entry point (linked with -nostartfiles); the loader honours the returned
   BOOL for DLL_PROCESS_ATTACH, so pass it through unchanged */
BOOL WINAPI DllMainCRTStartup(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    return bz_dll_main(inst, reason, reserved);
}
