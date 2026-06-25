BITS 64

section .text

global Syscall_Direct
global Syscall_Indirect
global Syscall_FindGadget
global Syscall_FindGadgetEx
global Syscall_GetWow64Gadget
global Syscall_ExecuteWithArgs
global Syscall_VerifyGadget

; ============================================
; Syscall_Direct - Execute direct syscall
; Parameters: ssn (rcx), arg1 (rdx), arg2 (r8), arg3 (r9), arg4 (stack), arg5 (stack), arg6 (stack)
; Returns: result in rax
; ============================================
Syscall_Direct:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    push r12
    
    ; Move SSN to rax
    mov rax, rcx
    
    ; Load arguments from stack
    ; arg1 = rdx, arg2 = r8, arg3 = r9
    ; arg4 = [rbp+40], arg5 = [rbp+48], arg6 = [rbp+56]
    mov rcx, rdx     ; arg1
    mov rdx, r8      ; arg2
    mov r8, r9       ; arg3
    mov r9, [rbp+40] ; arg4
    
    ; Push args 5 and 6 (reverse order)
    push [rbp+56]    ; arg6
    push [rbp+48]    ; arg5
    
    ; Execute syscall
    syscall
    
    ; Cleanup stack
    add rsp, 16
    
    pop r12
    pop rdi
    pop rsi
    pop rbx
    
    pop rbp
    ret

; ============================================
; Syscall_Indirect - Execute indirect syscall
; Parameters: ssn (rcx), gadget (rdx), arg1 (r8), arg2 (r9), arg3 (stack), arg4 (stack), arg5 (stack), arg6 (stack)
; Returns: result in rax
; ============================================
Syscall_Indirect:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    ; Save SSN in r10
    mov r10, rcx
    
    ; Save gadget in r11
    mov r11, rdx
    
    ; Load arguments
    ; arg1 = r8, arg2 = r9
    ; arg3 = [rbp+40], arg4 = [rbp+48]
    ; arg5 = [rbp+56], arg6 = [rbp+64]
    mov rcx, r8      ; arg1
    mov rdx, r9      ; arg2
    mov r8, [rbp+40] ; arg3
    mov r9, [rbp+48] ; arg4
    
    ; Push args 5 and 6 (reverse order)
    push [rbp+64]    ; arg6
    push [rbp+56]    ; arg5
    
    ; Move SSN to rax
    mov rax, r10
    
    ; Call gadget (executes syscall)
    call r11
    
    ; Cleanup stack
    add rsp, 16
    
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    
    pop rbp
    ret

; ============================================
; Syscall_FindGadget - Find syscall gadget in ntdll
; Parameters: ntdll_base (rcx)
; Returns: address of syscall; ret gadget
; ============================================
Syscall_FindGadget:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    
    mov rbx, rcx
    
    ; Store ntdll base
    mov [rel g_ntdll_base], rbx
    
    ; Search for syscall; ret (0F 05 C3)
    mov rsi, rbx
    add rsi, 0x100000
    
    mov rdi, rbx
    and rdi, ~0xF
    
.search:
    cmp rdi, rsi
    jge .not_found
    
    ; Check for 0F 05 C3 (syscall; ret)
    cmp byte [rdi], 0x0F
    jne .continue
    cmp byte [rdi+1], 0x05
    jne .continue
    cmp byte [rdi+2], 0xC3
    je .found
    
    ; Check for 0F 05 C3 90 (syscall; ret; nop)
    cmp byte [rdi], 0x0F
    jne .continue
    cmp byte [rdi+1], 0x05
    jne .continue
    cmp byte [rdi+2], 0xC3
    jne .continue
    cmp byte [rdi+3], 0x90
    je .found
    
.continue:
    inc rdi
    jmp .search

.found:
    mov rax, rdi
    jmp .done

.not_found:
    xor rax, rax

.done:
    pop rdi
    pop rsi
    pop rbx
    
    pop rbp
    ret

; ============================================
; Syscall_FindGadgetEx - Find syscall gadget with custom size
; ============================================
Syscall_FindGadgetEx:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    push r12
    
    mov rbx, rcx
    mov r12, rdx
    
    mov rsi, rbx
    add rsi, r12
    
    mov rdi, rbx
    and rdi, ~0xF
    
.search_ext:
    cmp rdi, rsi
    jge .not_found_ext
    
    cmp byte [rdi], 0x0F
    jne .continue_ext
    cmp byte [rdi+1], 0x05
    jne .continue_ext
    cmp byte [rdi+2], 0xC3
    je .found_ext
    
    cmp byte [rdi], 0x0F
    jne .continue_ext
    cmp byte [rdi+1], 0x05
    jne .continue_ext
    cmp byte [rdi+2], 0xC3
    jne .continue_ext
    cmp byte [rdi+3], 0x90
    je .found_ext
    
.continue_ext:
    inc rdi
    jmp .search_ext

.found_ext:
    mov rax, rdi
    jmp .done_ext

.not_found_ext:
    xor rax, rax

.done_ext:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    
    pop rbp
    ret

; ============================================
; Syscall_GetWow64Gadget - Get Wow64 syscall gadget
; ============================================
Syscall_GetWow64Gadget:
    push rbp
    mov rbp, rsp
    
    mov rax, gs:[0x60]
    test rax, rax
    jz .not_wow64
    
    mov rax, [rax + 0xC0]
    test rax, rax
    jz .not_wow64
    
    mov rax, 0x7ffe0300
    jmp .done

.not_wow64:
    xor rax, rax

.done:
    pop rbp
    ret

; ============================================
; Syscall_ExecuteWithArgs - Execute syscall with array of args
; ============================================
Syscall_ExecuteWithArgs:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    push r12
    
    mov rbx, rcx
    mov rsi, rdx
    mov rcx, r8
    
    cmp rcx, 6
    jg .too_many
    
    mov rax, rbx
    
    cmp rcx, 0
    je .exec
    mov rdi, [rsi]
    mov rcx, rdi
    
    cmp rcx, 1
    je .exec
    mov rdi, [rsi+8]
    mov rdx, rdi
    
    cmp rcx, 2
    je .exec
    mov rdi, [rsi+16]
    mov r8, rdi
    
    cmp rcx, 3
    je .exec
    mov rdi, [rsi+24]
    mov r9, rdi
    
    cmp rcx, 4
    je .exec
    mov rdi, [rsi+32]
    push rdi
    
    cmp rcx, 5
    je .exec
    mov rdi, [rsi+40]
    push rdi

.too_many:
    mov rcx, 6

.exec:
    syscall
    
    cmp rcx, 4
    jge .cleanup4
    cmp rcx, 5
    jge .cleanup5
    
.cleanup4:
    add rsp, 8
.cleanup5:
    add rsp, 8

.done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    
    pop rbp
    ret

; ============================================
; Syscall_VerifyGadget - Verify if address is a valid gadget
; ============================================
Syscall_VerifyGadget:
    push rbp
    mov rbp, rsp
    
    mov rax, rcx
    test rax, rax
    jz .invalid
    
    cmp byte [rax], 0x0F
    jne .invalid
    cmp byte [rax+1], 0x05
    jne .invalid
    cmp byte [rax+2], 0xC3
    je .valid
    
    cmp byte [rax], 0x0F
    jne .invalid
    cmp byte [rax+1], 0x05
    jne .invalid
    cmp byte [rax+2], 0xC3
    jne .invalid
    cmp byte [rax+3], 0x90
    je .valid
    
.valid:
    mov rax, 1
    jmp .done

.invalid:
    xor rax, rax

.done:
    pop rbp
    ret

section .data
g_ntdll_base dq 0