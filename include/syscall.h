#ifndef SYSCALL_H
#define SYSCALL_H

#include <windows.h>

#define SSN_NT_ALLOCATE_VIRTUAL_MEMORY 0x18
#define SSN_NT_CREATE_FILE 0x55
#define SSN_NT_WRITE_FILE 0x52
#define SSN_NT_READ_FILE 0x3F
#define SSN_NT_CLOSE 0x0F
#define SSN_NT_OPEN_PROCESS 0x26
#define SSN_NT_TERMINATE_PROCESS 0x2C
#define SSN_NT_CREATE_THREAD 0x6D
#define SSN_NT_CREATE_THREAD_EX 0x7A
#define SSN_NT_QUERY_INFORMATION_PROCESS 0x1A
#define SSN_NT_SET_INFORMATION_PROCESS 0x1F
#define SSN_NT_QUERY_SYSTEM_INFORMATION 0x36
#define SSN_NT_OPEN_THREAD 0x2D
#define SSN_NT_SUSPEND_THREAD 0x41
#define SSN_NT_RESUME_THREAD 0x42
#define SSN_NT_WAIT_FOR_SINGLE_OBJECT 0x04
#define SSN_NT_DELETE_FILE 0x56
#define SSN_NT_RENAME_FILE 0x58
#define SSN_NT_SET_INFORMATION_FILE 0x5A
#define SSN_NT_QUERY_INFORMATION_FILE 0x5B
#define SSN_NT_DEVICE_IO_CONTROL_FILE 0x5C
#define SSN_NT_LOAD_DRIVER 0x3A
#define SSN_NT_UNLOAD_DRIVER 0x3B
#define SSN_NT_OPEN_KEY 0x79
#define SSN_NT_CREATE_KEY 0x7B
#define SSN_NT_DELETE_KEY 0x7C
#define SSN_NT_ENUM_KEY 0x7D
#define SSN_NT_QUERY_VALUE_KEY 0x7E
#define SSN_NT_SET_VALUE_KEY 0x7F
#define SSN_NT_REGISTER_THREAD_TERMINATE_PORT 0x6E

#define SYSCALL_STATUS_SUCCESS 0x00000000
#define SYSCALL_STATUS_ACCESS_DENIED 0xC0000022
#define SYSCALL_STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define SYSCALL_STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A
#define SYSCALL_STATUS_INVALID_HANDLE 0xC0000008
#define SYSCALL_STATUS_NO_MEMORY 0xC0000017
#define SYSCALL_STATUS_ACCESS_VIOLATION 0xC0000005
#define SYSCALL_STATUS_PRIVILEGE_NOT_HELD 0xC0000061

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *pNtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
   ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

typedef NTSTATUS (NTAPI *pNtWriteFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

typedef NTSTATUS (NTAPI *pNtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

typedef NTSTATUS (NTAPI *pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

#endif