#ifndef IAT_HOOK_H
#define IAT_HOOK_H

#include <windows.h>

#define MAX_IAT_HOOKS 128

typedef struct {
    PIMAGE_IMPORT_DESCRIPTOR descriptor;
    PIMAGE_THUNK_DATA original_thunk;
    PIMAGE_THUNK_DATA hook_thunk;
    CHAR module_name[64];
    CHAR func_name[64];
    PVOID original_addr;
    PVOID hook_addr;
    DWORD ordinal;
    BOOL by_name;
    BOOL is_hooked;
    LARGE_INTEGER hook_time;
} IAT_ENTRY, *PIAT_ENTRY;

typedef struct {
    PIAT_ENTRY entries;
    DWORD count;
    DWORD capacity;
    CRITICAL_SECTION lock;
    BOOL initialized;
} IAT_HOOK_LIST, *PIAT_HOOK_LIST;

extern IAT_HOOK_LIST g_iat_list;

BOOL IAT_InitializeList(PIAT_HOOK_LIST list, DWORD capacity);
BOOL IAT_AddHook(PIAT_HOOK_LIST list, LPCSTR module_name, LPCSTR func_name, PVOID hook_func);
BOOL IAT_AddHookByOrdinal(PIAT_HOOK_LIST list, LPCSTR module_name, WORD ordinal, PVOID hook_func);
BOOL IAT_RemoveHook(PIAT_HOOK_LIST list, LPCSTR func_name);
BOOL IAT_ApplyHooks(PIAT_HOOK_LIST list);
BOOL IAT_ApplyHook(PIAT_HOOK_LIST list, LPCSTR func_name);
BOOL IAT_RemoveHooks(PIAT_HOOK_LIST list);
BOOL IAT_RemoveHookSingle(PIAT_HOOK_LIST list, LPCSTR func_name);
PVOID IAT_GetOriginal(PIAT_HOOK_LIST list, LPCSTR func_name);

// These functions use the global list
BOOL IAT_IsHooked(LPCSTR module_name, LPCSTR func_name);
DWORD IAT_GetHookCount(LPCSTR module_name);

VOID IAT_DumpHooks(VOID);
VOID IAT_Cleanup(VOID);

// Internal functions
PIMAGE_IMPORT_DESCRIPTOR IAT_GetDescriptor(PVOID module_base);
PIMAGE_THUNK_DATA IAT_FindFunction(PIMAGE_IMPORT_DESCRIPTOR descriptor, LPCSTR func_name);
PIMAGE_THUNK_DATA IAT_FindFunctionByOrdinal(PIMAGE_IMPORT_DESCRIPTOR descriptor, WORD ordinal);
BOOL IAT_ReplaceThunk(PIMAGE_THUNK_DATA thunk, PVOID new_addr, PVOID *old_addr);
BOOL IAT_RestoreThunk(PIMAGE_THUNK_DATA thunk, PVOID original_addr);
PVOID IAT_GetModuleBase(LPCSTR module_name);

#endif