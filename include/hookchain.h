#ifndef HOOKCHAIN_H
#define HOOKCHAIN_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
// IAT functions are defined in iat_hook.h
#include "iat_hook.h"

#define HOOKCHAIN_VERSION "2.0.0"
#define MAX_HOOKS 64
#define MAX_FUNC_NAME 128
#define SYSCALL_MAX_ARGS 6

typedef enum {
    HOOK_TYPE_IAT = 0x01,
    HOOK_TYPE_INLINE = 0x02,
    HOOK_TYPE_SYSCALL = 0x04,
    HOOK_TYPE_ALL = 0xFF
} HOOK_TYPE;

typedef struct {
    DWORD ssn;
    PVOID syscall_addr;
    PVOID original_func;
    PVOID hook_func;
    CHAR func_name[MAX_FUNC_NAME];
    BOOL enabled;
    HOOK_TYPE type;
    DWORD hook_count;
    LARGE_INTEGER timestamp;
} HOOK_ENTRY, *PHOOK_ENTRY;

typedef struct {
    PHOOK_ENTRY entries;
    DWORD count;
    DWORD capacity;
    PVOID ntdll_base;
    PVOID syscall_gadget;
    PVOID wow64_gadget;
    DWORD flags;
    CRITICAL_SECTION lock;
} HOOK_CHAIN, *PHOOK_CHAIN;

typedef struct {
    PVOID original_addr;
    PVOID hook_addr;
    BYTE original_bytes[16];
    BYTE hook_bytes[16];
    SIZE_T hook_size;
    BOOL is_hooked;
} INLINE_HOOK, *PINLINE_HOOK;

typedef struct {
    DWORD pid;
    HANDLE hProcess;
    PVOID allocated_addr;
    SIZE_T alloc_size;
    BOOL is_remote;
} PROCESS_CTX, *PPROCESS_CTX;

extern HOOK_CHAIN g_chain;
extern PROCESS_CTX g_process_ctx;

BOOL HookChain_Initialize(PHOOK_CHAIN chain, DWORD capacity);
BOOL HookChain_AddHook(PHOOK_CHAIN chain, LPCSTR func_name, PVOID hook_func, HOOK_TYPE type);
BOOL HookChain_AddHookEx(PHOOK_CHAIN chain, LPCSTR func_name, PVOID hook_func, HOOK_TYPE type, DWORD flags);
BOOL HookChain_EnableHooks(PHOOK_CHAIN chain);
BOOL HookChain_EnableHook(PHOOK_CHAIN chain, LPCSTR func_name);
BOOL HookChain_DisableHooks(PHOOK_CHAIN chain);
BOOL HookChain_DisableHook(PHOOK_CHAIN chain, LPCSTR func_name);
BOOL HookChain_RemoveHook(PHOOK_CHAIN chain, LPCSTR func_name);
PVOID HookChain_ExecuteSyscall(PHOOK_CHAIN chain, DWORD ssn, ...);
PVOID HookChain_ExecuteSyscallEx(PHOOK_CHAIN chain, DWORD ssn, PVOID *args, DWORD arg_count);
DWORD HookChain_GetHookCount(PHOOK_CHAIN chain);
PHOOK_ENTRY HookChain_GetHookEntry(PHOOK_CHAIN chain, LPCSTR func_name);
VOID HookChain_DumpHooks(PHOOK_CHAIN chain);
VOID HookChain_Cleanup(PHOOK_CHAIN chain);

BOOL IAT_HookFunction(LPCSTR module_name, LPCSTR func_name, PVOID hook_func, PVOID *original_func);
BOOL IAT_UnhookFunction(LPCSTR module_name, LPCSTR func_name);
BOOL IAT_HookModule(LPCSTR module_name, LPCSTR *func_names, PVOID *hook_funcs, DWORD count);
BOOL IAT_UnhookModule(LPCSTR module_name);
BOOL IAT_GetOriginalFunction(LPCSTR module_name, LPCSTR func_name, PVOID *original_func);
//BOOL IAT_IsHooked(PIAT_HOOK_LIST list, LPCSTR func_name);
//DWORD IAT_GetHookCount(PIAT_HOOK_LIST list);

BOOL INLINE_HookFunction(PVOID target_func, PVOID hook_func, PINLINE_HOOK hook_ctx);
BOOL INLINE_UnhookFunction(PINLINE_HOOK hook_ctx);
BOOL INLINE_IsHooked(PVOID target_func);
BOOL INLINE_GetOriginalBytes(PVOID target_func, PBYTE bytes, SIZE_T *size);
BOOL INLINE_InstallTrampoline(PVOID target_func, PVOID hook_func, PBYTE trampoline, SIZE_T trampoline_size);

DWORD SSN_ResolveByName(LPCSTR func_name);
DWORD SSN_ResolveByOrdinal(WORD ordinal);
DWORD SSN_ResolveFromAddress(PVOID func_addr);
DWORD* SSN_GetAll(DWORD *count);
BOOL SSN_IsValid(DWORD ssn);
LPCSTR SSN_GetNameBySSN(DWORD ssn);
BOOL SSN_ResolveAll(PVOID *ssn_table, DWORD *count);
DWORD SSN_GetNtMajorVersion(VOID);
DWORD SSN_GetNtMinorVersion(VOID);

DWORD Syscall_Direct(DWORD ssn, ...);
DWORD Syscall_Indirect(DWORD ssn, PVOID gadget, ...);
PVOID Syscall_FindGadget(PVOID ntdll_base);
PVOID Syscall_FindGadgetEx(PVOID ntdll_base, BOOL use_wow64);
BOOL Syscall_IsWow64(VOID);
PVOID Syscall_GetWow64Gadget(VOID);
DWORD Syscall_ExecuteWithArgs(DWORD ssn, PVOID *args, DWORD arg_count);
BOOL Syscall_VerifyGadget(PVOID gadget);

PVOID Shellcode_Execute(PBYTE shellcode, DWORD size);
PVOID Shellcode_ExecuteEx(PBYTE shellcode, DWORD size, PVOID arg1, PVOID arg2);
BOOL Shellcode_ExecuteRemote(HANDLE hProcess, PBYTE shellcode, DWORD size);
PVOID Shellcode_AllocateMemory(DWORD size, DWORD protection);
BOOL Shellcode_FreeMemory(PVOID addr, DWORD size);
BOOL Shellcode_LoadFromFile(LPCSTR filename, PBYTE *data, DWORD *size);
BOOL Shellcode_SaveToFile(LPCSTR filename, PBYTE data, DWORD size);
VOID Shellcode_XOR(PBYTE data, DWORD size, BYTE key);
VOID Shellcode_XOR_Extended(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_AES_Encrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_AES_Decrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_RC4_Encrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_RC4_Decrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_ProtectMemory(PVOID addr, DWORD size, DWORD protection, DWORD *old_protection);
BOOL Shellcode_ChangeProtection(PVOID addr, DWORD size, DWORD new_protection);
BOOL Shellcode_Validate(PBYTE data, DWORD size);
PVOID Shellcode_GetEntryPoint(PBYTE data, DWORD size);
BOOL Shellcode_IsValidPE(PBYTE data, DWORD size);

PVOID GetNtdllBase(VOID);
PVOID GetKernel32Base(VOID);
PVOID GetFunctionAddress(LPCSTR module_name, LPCSTR func_name);
PVOID GetFunctionAddressEx(LPCSTR module_name, LPCSTR func_name, BOOL use_peb);
VOID DebugPrint(LPCSTR format, ...);
VOID DebugPrintEx(DWORD level, LPCSTR format, ...);
VOID SleepPrecise(DWORD milliseconds);
DWORD GetCurrentProcessIdEx(VOID);
BOOL IsProcessElevated(VOID);
BOOL IsDebuggerPresentEx(VOID);
VOID AntiDebug(VOID);
DWORD GetWindowsBuildNumber(VOID);
BOOL IsWindows10(VOID);
BOOL IsWindows11(VOID);
VOID RandomDelay(DWORD min_ms, DWORD max_ms);
DWORD HashString(LPCSTR str);
BOOL CompareBytes(PBYTE bytes1, PBYTE bytes2, SIZE_T size);
PVOID FindPattern(PVOID start, SIZE_T size, PBYTE pattern, SIZE_T pattern_size);
VOID HexDump(PBYTE data, DWORD size);

#endif