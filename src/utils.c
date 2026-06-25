#include <hookchain.h>
#include <winternl.h>

PVOID GetNtdllBase(VOID) {
    static PVOID base = NULL;
    if (base) return base;
    
    base = GetModuleHandleA("ntdll.dll");
    return base;
}

PVOID GetKernel32Base(VOID) {
    static PVOID base = NULL;
    if (base) return base;
    
    base = GetModuleHandleA("kernel32.dll");
    return base;
}

PVOID GetFunctionAddress(LPCSTR module_name, LPCSTR func_name) {
    if (!module_name || !func_name) return NULL;
    
    HMODULE hModule = GetModuleHandleA(module_name);
    if (!hModule) return NULL;
    
    return GetProcAddress(hModule, func_name);
}

VOID DebugPrint(LPCSTR format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

VOID SleepPrecise(DWORD milliseconds) {
    Sleep(milliseconds);
}

DWORD GetCurrentProcessIdEx(VOID) {
    return GetCurrentProcessId();
}

BOOL IsProcessElevated(VOID) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return FALSE;
    }
    
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);
    BOOL result = GetTokenInformation(hToken, TokenElevation, &elevation, size, &size);
    CloseHandle(hToken);
    
    return result && elevation.TokenIsElevated;
}

BOOL IsDebuggerPresentEx(VOID) {
    // Simple debugger check
    return IsDebuggerPresent();
}

VOID AntiDebug(VOID) {
    if (IsDebuggerPresentEx()) {
        DebugPrint("[!] Debugger detected, exiting...");
        ExitProcess(0);
    }
}

DWORD GetWindowsBuildNumber(VOID) {
    static DWORD build = 0;
    if (build) return build;
    
    // Use GetVersionEx
    OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    
    // RtlGetVersion is more reliable
    typedef LONG (WINAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
    if (RtlGetVersion) {
        RTL_OSVERSIONINFOW rtl_osvi = {0};
        rtl_osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
        if (RtlGetVersion(&rtl_osvi) == 0) {
            build = rtl_osvi.dwBuildNumber;
            return build;
        }
    }
    
    // Fallback to GetVersionEx
    if (GetVersionExW(&osvi)) {
        build = osvi.dwBuildNumber;
    }
    
    return build;
}

BOOL IsWindows10(VOID) {
    DWORD build = GetWindowsBuildNumber();
    return build >= 10240 && build < 22000;
}

BOOL IsWindows11(VOID) {
    DWORD build = GetWindowsBuildNumber();
    return build >= 22000;
}

VOID RandomDelay(DWORD min_ms, DWORD max_ms) {
    if (min_ms >= max_ms) {
        Sleep(min_ms);
        return;
    }
    
    DWORD delay = (DWORD)(rand() % (max_ms - min_ms + 1)) + min_ms;
    Sleep(delay);
}

DWORD HashString(LPCSTR str) {
    if (!str) return 0;
    
    DWORD hash = 0;
    while (*str) {
        hash = (hash * 33) + *str;
        str++;
    }
    return hash;
}

BOOL CompareBytes(PBYTE bytes1, PBYTE bytes2, SIZE_T size) {
    if (!bytes1 || !bytes2 || size == 0) return FALSE;
    return memcmp(bytes1, bytes2, size) == 0;
}

PVOID FindPattern(PVOID start, SIZE_T size, PBYTE pattern, SIZE_T pattern_size) {
    if (!start || !pattern || pattern_size == 0) return NULL;
    
    PBYTE end = (PBYTE)start + size - pattern_size;
    for (PBYTE ptr = (PBYTE)start; ptr <= end; ptr++) {
        if (memcmp(ptr, pattern, pattern_size) == 0) {
            return ptr;
        }
    }
    return NULL;
}

VOID HexDump(PBYTE data, DWORD size) {
    if (!data || size == 0) return;
    
    for (DWORD i = 0; i < size; i++) {
        if (i % 16 == 0) {
            printf("\n%08lx: ", (unsigned long)i);
        }
        printf("%02x ", data[i]);
    }
    printf("\n");
}