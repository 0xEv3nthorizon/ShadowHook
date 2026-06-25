#include <iat_hook.h>
#include <hookchain.h>

IAT_HOOK_LIST g_iat_list = {0};

static BOOL IAT_IsValidPointer(PVOID ptr) {
    return ptr != NULL && !IsBadReadPtr(ptr, sizeof(PVOID));
}

BOOL IAT_InitializeList(PIAT_HOOK_LIST list, DWORD capacity) {
    if (!list || capacity == 0) return FALSE;
    
    ZeroMemory(list, sizeof(IAT_HOOK_LIST));
    
    list->entries = (PIAT_ENTRY)calloc(capacity, sizeof(IAT_ENTRY));
    if (!list->entries) {
        DebugPrint("[-] Failed to allocate IAT entries");
        return FALSE;
    }
    
    list->capacity = capacity;
    list->count = 0;
    list->initialized = TRUE;
    InitializeCriticalSection(&list->lock);
    
    DebugPrint("[+] IAT list initialized (capacity: %d)", capacity);
    return TRUE;
}

PIMAGE_IMPORT_DESCRIPTOR IAT_GetDescriptor(PVOID module_base) {
    if (!IAT_IsValidPointer(module_base)) return NULL;
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        DebugPrint("[-] Invalid DOS header");
        return NULL;
    }
    
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        DebugPrint("[-] Invalid NT header");
        return NULL;
    }
    
    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!import_rva) {
        return NULL;
    }
    
    return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)module_base + import_rva);
}

PIMAGE_THUNK_DATA IAT_FindFunction(PIMAGE_IMPORT_DESCRIPTOR descriptor, LPCSTR func_name) {
    if (!descriptor || !func_name) return NULL;
    
    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)descriptor + descriptor->FirstThunk);
    PIMAGE_THUNK_DATA original_thunk = (PIMAGE_THUNK_DATA)((PBYTE)descriptor + descriptor->OriginalFirstThunk);
    
    if (!IAT_IsValidPointer(thunk) || !IAT_IsValidPointer(original_thunk)) {
        return NULL;
    }
    
    while (thunk->u1.Function) {
        if (!IAT_IsValidPointer(&thunk->u1.Function)) {
            break;
        }
        
        if (IMAGE_SNAP_BY_ORDINAL(original_thunk->u1.Ordinal)) {
            WORD ordinal = IMAGE_ORDINAL(original_thunk->u1.Ordinal);
            if ((DWORD)ordinal == (DWORD)func_name) {
                return thunk;
            }
        } else {
            PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)((PBYTE)descriptor + original_thunk->u1.AddressOfData);
            if (IAT_IsValidPointer(import_name)) {
                if (strcmp(import_name->Name, func_name) == 0) {
                    return thunk;
                }
            }
        }
        thunk++;
        original_thunk++;
    }
    return NULL;
}

PIMAGE_THUNK_DATA IAT_FindFunctionByOrdinal(PIMAGE_IMPORT_DESCRIPTOR descriptor, WORD ordinal) {
    if (!descriptor) return NULL;
    
    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)descriptor + descriptor->FirstThunk);
    PIMAGE_THUNK_DATA original_thunk = (PIMAGE_THUNK_DATA)((PBYTE)descriptor + descriptor->OriginalFirstThunk);
    
    while (thunk->u1.Function) {
        if (IMAGE_SNAP_BY_ORDINAL(original_thunk->u1.Ordinal)) {
            if (IMAGE_ORDINAL(original_thunk->u1.Ordinal) == ordinal) {
                return thunk;
            }
        }
        thunk++;
        original_thunk++;
    }
    return NULL;
}

BOOL IAT_ReplaceThunk(PIMAGE_THUNK_DATA thunk, PVOID new_addr, PVOID *old_addr) {
    if (!IAT_IsValidPointer(thunk)) return FALSE;
    
    DWORD old_protect;
    SIZE_T size = sizeof(PVOID);
    
    if (!VirtualProtect(&thunk->u1.Function, size, PAGE_READWRITE, &old_protect)) {
        DebugPrint("[-] Failed to change memory protection");
        return FALSE;
    }
    
    if (old_addr) {
        *old_addr = (PVOID)thunk->u1.Function;
    }
    
    thunk->u1.Function = (ULONGLONG)new_addr;
    
    if (!VirtualProtect(&thunk->u1.Function, size, old_protect, &old_protect)) {
        DebugPrint("[-] Failed to restore memory protection");
        return FALSE;
    }
    
    DebugPrint("[+] Thunk replaced: 0x%p -> 0x%p", old_addr ? *old_addr : NULL, new_addr);
    return TRUE;
}

BOOL IAT_RestoreThunk(PIMAGE_THUNK_DATA thunk, PVOID original_addr) {
    if (!IAT_IsValidPointer(thunk)) return FALSE;
    return IAT_ReplaceThunk(thunk, original_addr, NULL);
}

PVOID IAT_GetModuleBase(LPCSTR module_name) {
    return GetModuleHandleA(module_name);
}

BOOL IAT_IsValidModule(LPCSTR module_name) {
    HMODULE hModule = GetModuleHandleA(module_name);
    return hModule != NULL;
}

BOOL IAT_HookFunction(LPCSTR module_name, LPCSTR func_name, PVOID hook_func, PVOID *original_func) {
    if (!module_name || !func_name || !hook_func) {
        DebugPrint("[-] Invalid parameters for IAT_HookFunction");
        return FALSE;
    }
    
    HMODULE hModule = GetModuleHandleA(module_name);
    if (!hModule) {
        DebugPrint("[-] Module not loaded: %s", module_name);
        return FALSE;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR descriptor = IAT_GetDescriptor(hModule);
    if (!descriptor) {
        DebugPrint("[-] No import descriptor for: %s", module_name);
        return FALSE;
    }
    
    PIMAGE_THUNK_DATA thunk = IAT_FindFunction(descriptor, func_name);
    if (!thunk) {
        DebugPrint("[-] Function not in import table: %s", func_name);
        return FALSE;
    }
    
    if (original_func) {
        *original_func = (PVOID)thunk->u1.Function;
    }
    
    return IAT_ReplaceThunk(thunk, hook_func, NULL);
}

BOOL IAT_UnhookFunction(LPCSTR module_name, LPCSTR func_name) {
    if (!module_name || !func_name) {
        DebugPrint("[-] Invalid parameters for IAT_UnhookFunction");
        return FALSE;
    }
    
    HMODULE hModule = GetModuleHandleA(module_name);
    if (!hModule) {
        DebugPrint("[-] Module not loaded: %s", module_name);
        return FALSE;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR descriptor = IAT_GetDescriptor(hModule);
    if (!descriptor) {
        DebugPrint("[-] No import descriptor for: %s", module_name);
        return FALSE;
    }
    
    PIMAGE_THUNK_DATA thunk = IAT_FindFunction(descriptor, func_name);
    if (!thunk) {
        DebugPrint("[-] Function not in import table: %s", func_name);
        return FALSE;
    }
    
    PVOID original_addr = GetProcAddress(hModule, func_name);
    if (!original_addr) {
        DebugPrint("[-] Failed to get original address for: %s", func_name);
        return FALSE;
    }
    
    return IAT_RestoreThunk(thunk, original_addr);
}

BOOL IAT_AddHook(PIAT_HOOK_LIST list, LPCSTR module_name, LPCSTR func_name, PVOID hook_func) {
    if (!list || !module_name || !func_name || !hook_func) {
        return FALSE;
    }
    
    if (list->count >= list->capacity) {
        DebugPrint("[-] IAT list is full");
        return FALSE;
    }
    
    EnterCriticalSection(&list->lock);
    
    PIAT_ENTRY entry = &list->entries[list->count];
    ZeroMemory(entry, sizeof(IAT_ENTRY));
    
    strncpy(entry->module_name, module_name, sizeof(entry->module_name) - 1);
    strncpy(entry->func_name, func_name, sizeof(entry->func_name) - 1);
    entry->hook_addr = hook_func;
    entry->by_name = TRUE;
    entry->is_hooked = FALSE;
    
    HMODULE hModule = GetModuleHandleA(module_name);
    if (hModule) {
        entry->original_addr = GetProcAddress(hModule, func_name);
    }
    
    list->count++;
    
    LeaveCriticalSection(&list->lock);
    DebugPrint("[+] IAT hook added: %s!%s", module_name, func_name);
    return TRUE;
}

BOOL IAT_AddHookByOrdinal(PIAT_HOOK_LIST list, LPCSTR module_name, WORD ordinal, PVOID hook_func) {
    if (!list || !module_name || !hook_func) {
        return FALSE;
    }
    
    if (list->count >= list->capacity) {
        DebugPrint("[-] IAT list is full");
        return FALSE;
    }
    
    EnterCriticalSection(&list->lock);
    
    PIAT_ENTRY entry = &list->entries[list->count];
    ZeroMemory(entry, sizeof(IAT_ENTRY));
    
    strncpy(entry->module_name, module_name, sizeof(entry->module_name) - 1);
    entry->ordinal = ordinal;
    entry->hook_addr = hook_func;
    entry->by_name = FALSE;
    entry->is_hooked = FALSE;
    
    HMODULE hModule = GetModuleHandleA(module_name);
    if (hModule) {
        entry->original_addr = GetProcAddress(hModule, MAKEINTRESOURCEA(ordinal));
    }
    
    list->count++;
    
    LeaveCriticalSection(&list->lock);
    DebugPrint("[+] IAT hook added: %s!#%d", module_name, ordinal);
    return TRUE;
}

BOOL IAT_ApplyHooks(PIAT_HOOK_LIST list) {
    if (!list || !list->initialized) return FALSE;
    
    EnterCriticalSection(&list->lock);
    
    DWORD success_count = 0;
    for (DWORD i = 0; i < list->count; i++) {
        PIAT_ENTRY entry = &list->entries[i];
        if (!entry->is_hooked) {
            if (IAT_HookFunction(entry->module_name, entry->func_name, entry->hook_addr, &entry->original_addr)) {
                entry->is_hooked = TRUE;
                success_count++;
                DebugPrint("[+] IAT hook applied: %s!%s", entry->module_name, entry->func_name);
            }
        }
    }
    
    LeaveCriticalSection(&list->lock);
    return success_count > 0;
}

BOOL IAT_ApplyHook(PIAT_HOOK_LIST list, LPCSTR func_name) {
    if (!list || !func_name) return FALSE;
    
    EnterCriticalSection(&list->lock);
    
    for (DWORD i = 0; i < list->count; i++) {
        PIAT_ENTRY entry = &list->entries[i];
        if (strcmp(entry->func_name, func_name) == 0 && !entry->is_hooked) {
            if (IAT_HookFunction(entry->module_name, entry->func_name, entry->hook_addr, &entry->original_addr)) {
                entry->is_hooked = TRUE;
                LeaveCriticalSection(&list->lock);
                return TRUE;
            }
        }
    }
    
    LeaveCriticalSection(&list->lock);
    return FALSE;
}

BOOL IAT_RemoveHooks(PIAT_HOOK_LIST list) {
    if (!list || !list->initialized) return FALSE;
    
    EnterCriticalSection(&list->lock);
    
    DWORD success_count = 0;
    for (DWORD i = 0; i < list->count; i++) {
        PIAT_ENTRY entry = &list->entries[i];
        if (entry->is_hooked) {
            if (IAT_UnhookFunction(entry->module_name, entry->func_name)) {
                entry->is_hooked = FALSE;
                success_count++;
                DebugPrint("[+] IAT hook removed: %s!%s", entry->module_name, entry->func_name);
            }
        }
    }
    
    LeaveCriticalSection(&list->lock);
    return success_count > 0;
}

BOOL IAT_RemoveHookSingle(PIAT_HOOK_LIST list, LPCSTR func_name) {
    if (!list || !func_name) return FALSE;
    
    EnterCriticalSection(&list->lock);
    
    for (DWORD i = 0; i < list->count; i++) {
        PIAT_ENTRY entry = &list->entries[i];
        if (strcmp(entry->func_name, func_name) == 0 && entry->is_hooked) {
            if (IAT_UnhookFunction(entry->module_name, entry->func_name)) {
                entry->is_hooked = FALSE;
                LeaveCriticalSection(&list->lock);
                return TRUE;
            }
        }
    }
    
    LeaveCriticalSection(&list->lock);
    return FALSE;
}

PVOID IAT_GetOriginal(PIAT_HOOK_LIST list, LPCSTR func_name) {
    if (!list || !func_name) return NULL;
    
    EnterCriticalSection(&list->lock);
    
    for (DWORD i = 0; i < list->count; i++) {
        if (strcmp(list->entries[i].func_name, func_name) == 0) {
            PVOID result = list->entries[i].original_addr;
            LeaveCriticalSection(&list->lock);
            return result;
        }
    }
    
    LeaveCriticalSection(&list->lock);
    return NULL;
}


BOOL IAT_IsHooked(LPCSTR module_name, LPCSTR func_name) {
    if (!module_name || !func_name) return FALSE;
    
    EnterCriticalSection(&g_iat_list.lock);
    
    for (DWORD i = 0; i < g_iat_list.count; i++) {
        if (strcmp(g_iat_list.entries[i].module_name, module_name) == 0 &&
            strcmp(g_iat_list.entries[i].func_name, func_name) == 0) {
            BOOL result = g_iat_list.entries[i].is_hooked;
            LeaveCriticalSection(&g_iat_list.lock);
            return result;
        }
    }
    
    LeaveCriticalSection(&g_iat_list.lock);
    return FALSE;
}

DWORD IAT_GetHookCount(LPCSTR module_name) {
    if (!module_name) return 0;
    
    EnterCriticalSection(&g_iat_list.lock);
    
    DWORD count = 0;
    for (DWORD i = 0; i < g_iat_list.count; i++) {
        if (strcmp(g_iat_list.entries[i].module_name, module_name) == 0) {
            count++;
        }
    }
    
    LeaveCriticalSection(&g_iat_list.lock);
    return count;
}

VOID IAT_DumpHooks(VOID) {
    DebugPrint("[+] IAT Hooks Dump");
    DebugPrint("[+] ===============");
    
    EnterCriticalSection(&g_iat_list.lock);
    
    for (DWORD i = 0; i < g_iat_list.count; i++) {
        PIAT_ENTRY entry = &g_iat_list.entries[i];
        DebugPrint("[%d] %s!%s: hooked=%d, orig=0x%p, hook=0x%p",
            i, entry->module_name, entry->func_name,
            entry->is_hooked, entry->original_addr, entry->hook_addr);
    }
    
    LeaveCriticalSection(&g_iat_list.lock);
}

VOID IAT_Cleanup(VOID) {
    IAT_RemoveHooks(&g_iat_list);
    
    if (g_iat_list.entries) {
        free(g_iat_list.entries);
        g_iat_list.entries = NULL;
    }
    
    DeleteCriticalSection(&g_iat_list.lock);
    ZeroMemory(&g_iat_list, sizeof(IAT_HOOK_LIST));
}