#include <hookchain.h>

static BOOL HookChain_VerifyChain(PHOOK_CHAIN chain) {
    if (!chain || !chain->entries || chain->capacity == 0) {
        return FALSE;
    }
    return TRUE;
}

static PHOOK_ENTRY HookChain_FindEntry(PHOOK_CHAIN chain, LPCSTR func_name) {
    if (!chain || !func_name) return NULL;
    
    for (DWORD i = 0; i < chain->count; i++) {
        if (strcmp(chain->entries[i].func_name, func_name) == 0) {
            return &chain->entries[i];
        }
    }
    return NULL;
}

static BOOL HookChain_ValidateHook(PHOOK_ENTRY entry) {
    if (!entry) return FALSE;
    if (!entry->hook_func) return FALSE;
    if (strlen(entry->func_name) == 0) return FALSE;
    if (entry->ssn == 0 && entry->type == HOOK_TYPE_SYSCALL) return FALSE;
    return TRUE;
}

BOOL HookChain_Initialize(PHOOK_CHAIN chain, DWORD capacity) {
    if (!chain) return FALSE;
    
    ZeroMemory(chain, sizeof(HOOK_CHAIN));
    
    chain->entries = (PHOOK_ENTRY)calloc(capacity, sizeof(HOOK_ENTRY));
    if (!chain->entries) {
        DebugPrint("[-] Failed to allocate hook entries");
        return FALSE;
    }
    
    chain->capacity = capacity;
    chain->count = 0;
    chain->ntdll_base = GetNtdllBase();
    chain->syscall_gadget = Syscall_FindGadget(chain->ntdll_base);
    chain->wow64_gadget = Syscall_GetWow64Gadget();
    
    InitializeCriticalSection(&chain->lock);
    
    DebugPrint("[+] HookChain initialized");
    DebugPrint("[+] Capacity: %d", capacity);
    DebugPrint("[+] ntdll base: 0x%p", chain->ntdll_base);
    DebugPrint("[+] syscall gadget: 0x%p", chain->syscall_gadget);
    
    return TRUE;
}

BOOL HookChain_AddHook(PHOOK_CHAIN chain, LPCSTR func_name, PVOID hook_func, HOOK_TYPE type) {
    return HookChain_AddHookEx(chain, func_name, hook_func, type, 0);
}

BOOL HookChain_AddHookEx(PHOOK_CHAIN chain, LPCSTR func_name, PVOID hook_func, HOOK_TYPE type, DWORD flags) {
    (void)flags;
    
    if (!chain || !func_name || !hook_func) {
        DebugPrint("[-] Invalid parameters for HookChain_AddHookEx");
        return FALSE;
    }
    
    if (chain->count >= chain->capacity) {
        DebugPrint("[-] Hook chain is full (max: %d)", chain->capacity);
        return FALSE;
    }
    
    EnterCriticalSection(&chain->lock);
    
    PHOOK_ENTRY entry = &chain->entries[chain->count];
    ZeroMemory(entry, sizeof(HOOK_ENTRY));
    
    strncpy(entry->func_name, func_name, MAX_FUNC_NAME - 1);
    entry->hook_func = hook_func;
    entry->type = type;
    entry->enabled = FALSE;
    entry->hook_count = 0;
    GetSystemTimeAsFileTime((PFILETIME)&entry->timestamp);
    
    if (type & HOOK_TYPE_SYSCALL) {
        entry->ssn = SSN_ResolveByName(func_name);
        entry->syscall_addr = GetFunctionAddress("ntdll.dll", func_name);
    }
    
    if (type & HOOK_TYPE_IAT) {
        entry->original_func = GetFunctionAddress("ntdll.dll", func_name);
    }
    
    chain->count++;
    DebugPrint("[+] Hook added: %s (type: 0x%x, ssn: 0x%x)", func_name, type, entry->ssn);
    
    LeaveCriticalSection(&chain->lock);
    return TRUE;
}

BOOL HookChain_EnableHooks(PHOOK_CHAIN chain) {
    if (!HookChain_VerifyChain(chain)) return FALSE;
    
    EnterCriticalSection(&chain->lock);
    
    DWORD success_count = 0;
    for (DWORD i = 0; i < chain->count; i++) {
        PHOOK_ENTRY entry = &chain->entries[i];
        if (!entry->enabled && HookChain_ValidateHook(entry)) {
            // Just mark as enabled - we'll call hooks directly from ExecuteSyscall
            entry->enabled = TRUE;
            entry->hook_count++;
            success_count++;
            DebugPrint("[+] Hook enabled: %s (SSN: 0x%x)", entry->func_name, entry->ssn);
        }
    }
    
    LeaveCriticalSection(&chain->lock);
    
    DebugPrint("[+] Enabled %d hooks", success_count);
    return success_count > 0;
}

BOOL HookChain_EnableHook(PHOOK_CHAIN chain, LPCSTR func_name) {
    if (!chain || !func_name) return FALSE;
    
    EnterCriticalSection(&chain->lock);
    
    PHOOK_ENTRY entry = HookChain_FindEntry(chain, func_name);
    if (!entry || entry->enabled) {
        LeaveCriticalSection(&chain->lock);
        return FALSE;
    }
    
    entry->enabled = TRUE;
    entry->hook_count++;
    DebugPrint("[+] Hook enabled: %s", func_name);
    
    LeaveCriticalSection(&chain->lock);
    return TRUE;
}

BOOL HookChain_DisableHooks(PHOOK_CHAIN chain) {
    if (!HookChain_VerifyChain(chain)) return FALSE;
    
    EnterCriticalSection(&chain->lock);
    
    DWORD success_count = 0;
    for (DWORD i = 0; i < chain->count; i++) {
        PHOOK_ENTRY entry = &chain->entries[i];
        if (entry->enabled) {
            entry->enabled = FALSE;
            success_count++;
            DebugPrint("[+] Hook disabled: %s", entry->func_name);
        }
    }
    
    LeaveCriticalSection(&chain->lock);
    
    DebugPrint("[+] Disabled %d hooks", success_count);
    return TRUE;
}

BOOL HookChain_DisableHook(PHOOK_CHAIN chain, LPCSTR func_name) {
    if (!chain || !func_name) return FALSE;
    
    EnterCriticalSection(&chain->lock);
    
    PHOOK_ENTRY entry = HookChain_FindEntry(chain, func_name);
    if (!entry || !entry->enabled) {
        LeaveCriticalSection(&chain->lock);
        return FALSE;
    }
    
    entry->enabled = FALSE;
    DebugPrint("[+] Hook disabled: %s", func_name);
    
    LeaveCriticalSection(&chain->lock);
    return TRUE;
}

BOOL HookChain_RemoveHook(PHOOK_CHAIN chain, LPCSTR func_name) {
    if (!chain || !func_name) return FALSE;
    
    EnterCriticalSection(&chain->lock);
    
    PHOOK_ENTRY entry = HookChain_FindEntry(chain, func_name);
    if (!entry) {
        LeaveCriticalSection(&chain->lock);
        return FALSE;
    }
    
    ZeroMemory(entry, sizeof(HOOK_ENTRY));
    chain->count--;
    
    LeaveCriticalSection(&chain->lock);
    DebugPrint("[+] Hook removed: %s", func_name);
    return TRUE;
}

PVOID HookChain_ExecuteSyscall(PHOOK_CHAIN chain, DWORD ssn, ...) {
    if (!chain) return NULL;
    
    va_list args;
    va_start(args, ssn);
    
    PVOID arg_array[SYSCALL_MAX_ARGS] = {0};
    for (int i = 0; i < SYSCALL_MAX_ARGS; i++) {
        arg_array[i] = va_arg(args, PVOID);
    }
    va_end(args);
    
    return HookChain_ExecuteSyscallEx(chain, ssn, arg_array, SYSCALL_MAX_ARGS);
}

PVOID HookChain_ExecuteSyscallEx(PHOOK_CHAIN chain, DWORD ssn, PVOID *args, DWORD arg_count) {
    (void)arg_count;
    
    if (!chain || !args) return NULL;
    
    DebugPrint("[+] Syscall: SSN=0x%x", ssn);
    
    // Check if we have a hook for this SSN
    for (DWORD i = 0; i < chain->count; i++) {
        PHOOK_ENTRY entry = &chain->entries[i];
        if (entry->ssn == ssn && entry->enabled && entry->hook_func) {
            DebugPrint("[+] Calling hook function for SSN 0x%x: %s", ssn, entry->func_name);
            
            // Cast hook_func to a function pointer with 6 arguments
            typedef PVOID (NTAPI *HOOK_FUNC)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
            HOOK_FUNC hook = (HOOK_FUNC)entry->hook_func;
            
            // Call the hook function with arguments
            return hook(
                args[0], args[1], args[2], args[3], args[4], args[5]
            );
        }
    }
    
    // If no hook found, use indirect syscall
    if (chain->syscall_gadget) {
        DebugPrint("[+] Using indirect syscall with gadget: 0x%p", chain->syscall_gadget);
        DWORD result = Syscall_Indirect(ssn, chain->syscall_gadget,
            args[0], args[1], args[2], args[3], args[4], args[5]);
        DebugPrint("[+] Indirect syscall result: 0x%08x", result);
        return (PVOID)(ULONG_PTR)result;
    }
    
    // Fallback to direct syscall
    DebugPrint("[+] Using direct syscall");
    DWORD result = Syscall_Direct(ssn,
        args[0], args[1], args[2], args[3], args[4], args[5]);
    DebugPrint("[+] Direct syscall result: 0x%08x", result);
    
    return (PVOID)(ULONG_PTR)result;
}

DWORD HookChain_GetHookCount(PHOOK_CHAIN chain) {
    if (!chain) return 0;
    return chain->count;
}

PHOOK_ENTRY HookChain_GetHookEntry(PHOOK_CHAIN chain, LPCSTR func_name) {
    return HookChain_FindEntry(chain, func_name);
}

VOID HookChain_DumpHooks(PHOOK_CHAIN chain) {
    if (!chain) return;
    
    DebugPrint("[+] Hook Chain Dump");
    DebugPrint("[+] ================");
    DebugPrint("[+] Total hooks: %d", chain->count);
    
    for (DWORD i = 0; i < chain->count; i++) {
        PHOOK_ENTRY entry = &chain->entries[i];
        DebugPrint("[%d] %s: ssn=0x%x, type=0x%x, enabled=%d, calls=%d",
            i, entry->func_name, entry->ssn, entry->type, entry->enabled, entry->hook_count);
    }
}

VOID HookChain_Cleanup(PHOOK_CHAIN chain) {
    if (!chain) return;
    
    HookChain_DisableHooks(chain);
    
    if (chain->entries) {
        free(chain->entries);
        chain->entries = NULL;
    }
    
    DeleteCriticalSection(&chain->lock);
    
    ZeroMemory(chain, sizeof(HOOK_CHAIN));
    DebugPrint("[+] HookChain cleaned up");
}