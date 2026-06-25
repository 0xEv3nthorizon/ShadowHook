#include <ssn_resolver.h>
#include <hookchain.h>

PSSN_ENTRY g_ssn_table = NULL;
DWORD g_ssn_count = 0;

static DWORD SSN_GetNtVersion(VOID) {
    static DWORD version = 0;
    if (version) return version;
    
    RTL_OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    
    typedef LONG (WINAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!RtlGetVersion) return 0;
    
    if (RtlGetVersion(&osvi) == 0) {
        version = (DWORD)osvi.dwMajorVersion << 16 | osvi.dwMinorVersion;
    }
    
    return version;
}

PVOID SSN_GetNtdllBase(VOID) {
    static PVOID base = NULL;
    if (base) return base;
    
    base = GetModuleHandleA("ntdll.dll");
    return base;
}

IMAGE_EXPORT_DIRECTORY_EXT* SSN_GetExportDirectory(PVOID module_base) {
    if (!module_base) return NULL;
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_rva) return NULL;
    
    return (IMAGE_EXPORT_DIRECTORY_EXT*)((PBYTE)module_base + export_rva);
}

DWORD SSN_ExtractFromFunction(PVOID func_addr) {
    if (!func_addr) return 0;
    
    PBYTE bytes = (PBYTE)func_addr;
    DWORD ssn = 0;
    
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0xB8) {
            ssn = *(DWORD*)(bytes + i + 1);
            if (ssn > 0 && ssn < 0x1000) {
                return ssn;
            }
        }
    }
    
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0xBA) {
            ssn = *(DWORD*)(bytes + i + 1);
            if (ssn > 0 && ssn < 0x1000) {
                return ssn;
            }
        }
    }
    
    return 0;
}

DWORD SSN_ExtractFromFunctionEx(PVOID func_addr, BOOL use_fallback) {
    DWORD ssn = SSN_ExtractFromFunction(func_addr);
    if (ssn > 0) return ssn;
    
    if (use_fallback) {
        PBYTE bytes = (PBYTE)func_addr;
        for (int i = 0; i < 64; i++) {
            if (bytes[i] == 0x0F && bytes[i+1] == 0x05) {
                for (int j = i - 1; j >= 0 && j > i - 20; j--) {
                    if (bytes[j] == 0xB8) {
                        ssn = *(DWORD*)(bytes + j + 1);
                        if (ssn > 0 && ssn < 0x1000) {
                            return ssn;
                        }
                    }
                }
            }
        }
    }
    
    return 0;
}

DWORD SSN_ResolveByName(LPCSTR func_name) {
    if (!func_name) return 0;
    
    // ============================================
    // HARDCODED SSNs for Windows 10 (Fallback)
    // Only essential functions for HookChain
    // ============================================
    if (strcmp(func_name, "NtCreateFile") == 0) return 0x55;
    if (strcmp(func_name, "NtWriteFile") == 0) return 0x52;
    if (strcmp(func_name, "NtReadFile") == 0) return 0x3F;
    if (strcmp(func_name, "NtAllocateVirtualMemory") == 0) return 0x18;
    if (strcmp(func_name, "NtOpenProcess") == 0) return 0x26;
    if (strcmp(func_name, "NtCreateThreadEx") == 0) return 0x6D;
    if (strcmp(func_name, "NtClose") == 0) return 0x0F;
    if (strcmp(func_name, "NtFreeVirtualMemory") == 0) return 0x66;
    if (strcmp(func_name, "NtQueryInformationProcess") == 0) return 0x1A;
    if (strcmp(func_name, "NtQuerySystemInformation") == 0) return 0x36;
    if (strcmp(func_name, "NtOpenThread") == 0) return 0xA1;
    if (strcmp(func_name, "NtSuspendThread") == 0) return 0x41;
    if (strcmp(func_name, "NtResumeThread") == 0) return 0x42;
    if (strcmp(func_name, "NtWaitForSingleObject") == 0) return 0x04;
    if (strcmp(func_name, "NtDelayExecution") == 0) return 0x49;
    
    // Dynamic Resolution (Original Code)
    
    if (g_ssn_table) {
        for (DWORD i = 0; i < g_ssn_count; i++) {
            if (strcmp(g_ssn_table[i].func_name, func_name) == 0) {
                return g_ssn_table[i].ssn;
            }
        }
    }
    
    PVOID ntdll_base = SSN_GetNtdllBase();
    if (!ntdll_base) return 0;
    
    IMAGE_EXPORT_DIRECTORY_EXT* export_dir = SSN_GetExportDirectory(ntdll_base);
    if (!export_dir) return 0;
    
    PDWORD functions = (PDWORD)((PBYTE)ntdll_base + export_dir->AddressOfFunctions);
    PDWORD names = (PDWORD)((PBYTE)ntdll_base + export_dir->AddressOfNames);
    PWORD ordinals = (PWORD)((PBYTE)ntdll_base + export_dir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        LPCSTR current_name = (LPCSTR)((PBYTE)ntdll_base + names[i]);
        if (strcmp(current_name, func_name) == 0) {
            WORD ordinal = ordinals[i];
            DWORD func_rva = functions[ordinal];
            PVOID func_addr = (PVOID)((PBYTE)ntdll_base + func_rva);
            
            DWORD ssn = SSN_ExtractFromFunctionEx(func_addr, TRUE);
            if (ssn > 0) {
                g_ssn_table = realloc(g_ssn_table, (g_ssn_count + 1) * sizeof(SSN_ENTRY));
                if (g_ssn_table) {
                    g_ssn_table[g_ssn_count].func_name = _strdup(func_name);
                    g_ssn_table[g_ssn_count].ssn = ssn;
                    g_ssn_table[g_ssn_count].func_addr = func_addr;
                    g_ssn_table[g_ssn_count].ordinal = ordinal;
                    g_ssn_count++;
                }
                return ssn;
            }
            
            return (DWORD)ordinal;
        }
    }
    
    return 0;
}

DWORD SSN_ResolveByOrdinal(WORD ordinal) {
    PVOID ntdll_base = SSN_GetNtdllBase();
    if (!ntdll_base) return 0;
    
    IMAGE_EXPORT_DIRECTORY_EXT* export_dir = SSN_GetExportDirectory(ntdll_base);
    if (!export_dir) return 0;
    
    PDWORD functions = (PDWORD)((PBYTE)ntdll_base + export_dir->AddressOfFunctions);
    DWORD func_rva = functions[ordinal];
    PVOID func_addr = (PVOID)((PBYTE)ntdll_base + func_rva);
    
    return SSN_ExtractFromFunctionEx(func_addr, TRUE);
}

DWORD SSN_ResolveFromAddress(PVOID func_addr) {
    if (!func_addr) return 0;
    
    PVOID ntdll_base = SSN_GetNtdllBase();
    if (!ntdll_base) return 0;
    
    IMAGE_EXPORT_DIRECTORY_EXT* export_dir = SSN_GetExportDirectory(ntdll_base);
    if (!export_dir) return 0;
    
    PDWORD functions = (PDWORD)((PBYTE)ntdll_base + export_dir->AddressOfFunctions);
    PDWORD names = (PDWORD)((PBYTE)ntdll_base + export_dir->AddressOfNames);
    PWORD ordinals = (PWORD)((PBYTE)ntdll_base + export_dir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        WORD ordinal = ordinals[i];
        DWORD func_rva = functions[ordinal];
        PVOID current_addr = (PVOID)((PBYTE)ntdll_base + func_rva);
        
        if (current_addr == func_addr) {
            return SSN_ExtractFromFunctionEx(func_addr, TRUE);
        }
    }
    
    return 0;
}

DWORD* SSN_GetAll(DWORD *count) {
    if (!count) return NULL;
    
    PVOID ntdll_base = SSN_GetNtdllBase();
    if (!ntdll_base) return NULL;
    
    IMAGE_EXPORT_DIRECTORY_EXT* export_dir = SSN_GetExportDirectory(ntdll_base);
    if (!export_dir) return NULL;
    
    DWORD num_funcs = export_dir->NumberOfFunctions;
    DWORD* ssn_array = (DWORD*)malloc(num_funcs * sizeof(DWORD));
    if (!ssn_array) return NULL;
    
    PDWORD functions = (PDWORD)((PBYTE)ntdll_base + export_dir->AddressOfFunctions);
    
    for (DWORD i = 0; i < num_funcs; i++) {
        DWORD func_rva = functions[i];
        PVOID func_addr = (PVOID)((PBYTE)ntdll_base + func_rva);
        ssn_array[i] = SSN_ExtractFromFunctionEx(func_addr, TRUE);
    }
    
    *count = num_funcs;
    return ssn_array;
}

BOOL SSN_IsValid(DWORD ssn) {
    return (ssn > 0 && ssn < 0x1000);
}

LPCSTR SSN_GetNameBySSN(DWORD ssn) {
    if (g_ssn_table) {
        for (DWORD i = 0; i < g_ssn_count; i++) {
            if (g_ssn_table[i].ssn == ssn) {
                return g_ssn_table[i].func_name;
            }
        }
    }
    return NULL;
}

BOOL SSN_ResolveAll(PVOID *ssn_table, DWORD *count) {
    if (!ssn_table || !count) return FALSE;
    
    PVOID ntdll_base = SSN_GetNtdllBase();
    if (!ntdll_base) return FALSE;
    
    IMAGE_EXPORT_DIRECTORY_EXT* export_dir = SSN_GetExportDirectory(ntdll_base);
    if (!export_dir) return FALSE;
    
    *count = export_dir->NumberOfFunctions;
    *ssn_table = malloc(*count * sizeof(DWORD));
    if (!*ssn_table) return FALSE;
    
    PDWORD functions = (PDWORD)((PBYTE)ntdll_base + export_dir->AddressOfFunctions);
    DWORD* table = (DWORD*)*ssn_table;
    
    for (DWORD i = 0; i < *count; i++) {
        DWORD func_rva = functions[i];
        PVOID func_addr = (PVOID)((PBYTE)ntdll_base + func_rva);
        table[i] = SSN_ExtractFromFunctionEx(func_addr, TRUE);
    }
    
    return TRUE;
}

DWORD SSN_GetNtMajorVersion(VOID) {
    DWORD version = SSN_GetNtVersion();
    return (version >> 16) & 0xFFFF;
}

DWORD SSN_GetNtMinorVersion(VOID) {
    DWORD version = SSN_GetNtVersion();
    return version & 0xFFFF;
}

DWORD SSN_GetBuildNumber(VOID) {
    static DWORD build = 0;
    if (build) return build;
    
    RTL_OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    
    typedef LONG (WINAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!RtlGetVersion) return 0;
    
    if (RtlGetVersion(&osvi) == 0) {
        build = osvi.dwBuildNumber;
    }
    
    return build;
}

BOOL SSN_IsWow64(VOID) {
    static BOOL is_wow64 = FALSE;
    static BOOL checked = FALSE;
    
    if (checked) return is_wow64;
    
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        typedef BOOL (WINAPI *pIsWow64Process)(HANDLE, PBOOL);
        pIsWow64Process IsWow64Process = (pIsWow64Process)GetProcAddress(hKernel32, "IsWow64Process");
        if (IsWow64Process) {
            IsWow64Process(GetCurrentProcess(), &is_wow64);
        }
    }
    
    checked = TRUE;
    return is_wow64;
}

BOOL SSN_InitializeTable(VOID) {
    if (g_ssn_table) return TRUE;
    
    PVOID ntdll_base = SSN_GetNtdllBase();
    if (!ntdll_base) return FALSE;
    
    IMAGE_EXPORT_DIRECTORY_EXT* export_dir = SSN_GetExportDirectory(ntdll_base);
    if (!export_dir) return FALSE;
    
    DWORD num_funcs = export_dir->NumberOfNames;
    g_ssn_table = (PSSN_ENTRY)malloc(num_funcs * sizeof(SSN_ENTRY));
    if (!g_ssn_table) return FALSE;
    
    PDWORD functions = (PDWORD)((PBYTE)ntdll_base + export_dir->AddressOfFunctions);
    PDWORD names = (PDWORD)((PBYTE)ntdll_base + export_dir->AddressOfNames);
    PWORD ordinals = (PWORD)((PBYTE)ntdll_base + export_dir->AddressOfNameOrdinals);
    
    g_ssn_count = 0;
    for (DWORD i = 0; i < num_funcs; i++) {
        LPCSTR current_name = (LPCSTR)((PBYTE)ntdll_base + names[i]);
        WORD ordinal = ordinals[i];
        DWORD func_rva = functions[ordinal];
        PVOID func_addr = (PVOID)((PBYTE)ntdll_base + func_rva);
        
        DWORD ssn = SSN_ExtractFromFunctionEx(func_addr, TRUE);
        if (ssn > 0) {
            g_ssn_table[g_ssn_count].func_name = _strdup(current_name);
            g_ssn_table[g_ssn_count].ssn = ssn;
            g_ssn_table[g_ssn_count].func_addr = func_addr;
            g_ssn_table[g_ssn_count].ordinal = ordinal;
            g_ssn_count++;
        }
    }
    
    DebugPrint("[+] SSN table initialized: %d entries", g_ssn_count);
    return TRUE;
}

VOID SSN_CleanupTable(VOID) {
    if (g_ssn_table) {
        for (DWORD i = 0; i < g_ssn_count; i++) {
            if (g_ssn_table[i].func_name) {
                free((void*)g_ssn_table[i].func_name);
            }
        }
        free(g_ssn_table);
        g_ssn_table = NULL;
        g_ssn_count = 0;
    }
}