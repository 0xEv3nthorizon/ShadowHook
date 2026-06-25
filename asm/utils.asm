BITS 64

section .text

global Utils_GetProcAddress
global Utils_GetModuleHandle
global Utils_DebugPrint
global Utils_SleepPrecise
global Utils_GetTickCount

; Utils_GetProcAddress - Get procedure address
; Parameters: module (rcx), func_name (rdx)
; Returns: function address
Utils_GetProcAddress:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    
    ; Use standard GetProcAddress
    mov rax, [rel g_GetProcAddress]
    test rax, rax
    jz .error
    
    call rax
    jmp .done

.error:
    xor rax, rax

.done:
    pop rsi
    pop rbx
    pop rbp
    ret

; Utils_GetModuleHandle - Get module handle
; Parameters: module_name (rcx)
; Returns: module handle
Utils_GetModuleHandle:
    push rbp
    mov rbp, rsp
    
    ; Use standard GetModuleHandle
    mov rax, [rel g_GetModuleHandle]
    test rax, rax
    jz .error
    
    call rax
    jmp .done

.error:
    xor rax, rax

.done:
    pop rbp
    ret

; Utils_DebugPrint - Print debug message
; Parameters: format (rcx), ...
Utils_DebugPrint:
    push rbp
    mov rbp, rsp
    
    sub rsp, 32
    
    ; Save registers
    push rbx
    push rsi
    push rdi
    
    ; Call printf
    mov rax, [rel g_printf]
    test rax, rax
    jz .done
    
    ; Pass arguments
    mov rdx, rsi
    mov r8, rdx
    mov r9, rcx
    call rax

.done:
    pop rdi
    pop rsi
    pop rbx
    
    add rsp, 32
    pop rbp
    ret

; Utils_SleepPrecise - Sleep with high resolution
; Parameters: milliseconds (rcx)
Utils_SleepPrecise:
    push rbp
    mov rbp, rsp
    
    ; Use Sleep
    mov rax, [rel g_Sleep]
    test rax, rax
    jz .done
    
    call rax

.done:
    pop rbp
    ret

; Utils_GetTickCount - Get tick count
; Returns: tick count in rax
Utils_GetTickCount:
    push rbp
    mov rbp, rsp
    
    ; Use GetTickCount
    mov rax, [rel g_GetTickCount]
    test rax, rax
    jz .error
    
    call rax
    jmp .done

.error:
    xor rax, rax

.done:
    pop rbp
    ret

section .data
g_GetProcAddress dq 0
g_GetModuleHandle dq 0
g_printf dq 0
g_Sleep dq 0
g_GetTickCount dq 0