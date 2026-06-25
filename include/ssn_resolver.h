#ifndef SSN_RESOLVER_H
#define SSN_RESOLVER_H

#include <windows.h>

#define MAX_SSN_TABLE 4096
#define SSN_VERSION_WIN10 0x0A
#define SSN_VERSION_WIN11 0x0B

typedef struct {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER_EXT;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY_EXT;

typedef struct {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_EXT DataDirectory[16];
} IMAGE_OPTIONAL_HEADER_EXT;

typedef struct {
    DWORD Signature;
    IMAGE_FILE_HEADER_EXT FileHeader;
    IMAGE_OPTIONAL_HEADER_EXT OptionalHeader;
} IMAGE_NT_HEADERS_EXT;

typedef struct {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY_EXT;

typedef struct {
    LPCSTR func_name;
    DWORD ssn;
    PVOID func_addr;
    WORD ordinal;
} SSN_ENTRY, *PSSN_ENTRY;

extern PSSN_ENTRY g_ssn_table;
extern DWORD g_ssn_count;

BOOL SSN_InitializeTable(VOID);
VOID SSN_CleanupTable(VOID);
DWORD SSN_ResolveByName(LPCSTR func_name);
DWORD SSN_ResolveByOrdinal(WORD ordinal);
DWORD SSN_ResolveFromAddress(PVOID func_addr);
DWORD* SSN_GetAll(DWORD *count);
BOOL SSN_IsValid(DWORD ssn);
LPCSTR SSN_GetNameBySSN(DWORD ssn);
BOOL SSN_ResolveAll(PVOID *ssn_table, DWORD *count);
DWORD SSN_GetNtMajorVersion(VOID);
DWORD SSN_GetNtMinorVersion(VOID);
DWORD SSN_GetBuildNumber(VOID);
BOOL SSN_IsWow64(VOID);

PVOID SSN_GetNtdllBase(VOID);
IMAGE_EXPORT_DIRECTORY_EXT* SSN_GetExportDirectory(PVOID module_base);
DWORD SSN_ExtractFromFunction(PVOID func_addr);
DWORD SSN_ExtractFromFunctionEx(PVOID func_addr, BOOL use_fallback);
BOOL SSN_ParseFunctionCode(PVOID func_addr, DWORD *ssn, DWORD *ordinal);
PVOID SSN_GetFunctionBySSN(DWORD ssn);
LPCSTR SSN_GetFunctionName(PVOID func_addr);
BOOL SSN_IsSyscallInstruction(PBYTE code, SIZE_T size);
DWORD SSN_GetSyscallNumber(PBYTE code, SIZE_T size);

#endif