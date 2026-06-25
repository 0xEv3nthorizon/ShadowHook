BITS 64

section .text

global HookEngine_Install
global HookEngine_Remove
global HookEngine_IsInstalled
global HookEngine_GetHookCount
global HookEngine_GetHookEntry

; HookEngine_Install - Install hook engine
; Parameters: hook_table (rcx), hook_count (rdx)
; Returns: BOOL (rax)
HookEngine_Install:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    
    ; Check parameters
    test rcx, rcx
    jz .error
    test rdx, rdx
    jz .error
    
    ; Store hook table
    mov [rel g_hook_table], rcx
    mov [rel g_hook_count], rdx
    
    ; Install each hook
    mov rsi, rcx
    mov rcx, rdx
    xor rbx, rbx
    
.install_loop:
    cmp rbx, rcx
    jge .done
    
    ; Install hook at index rbx
    push rcx
    push rbx
    
    ; Get hook entry
    mov rax, [rsi + rbx*8]
    test rax, rax
    jz .skip
    
    ; Install the hook
    ; ... hook installation code ...
    
.skip:
    pop rbx
    pop rcx
    inc rbx
    jmp .install_loop

.done:
    mov rax, 1
    jmp .finish

.error:
    xor rax, rax

.finish:
    pop rdi
    pop rsi
    pop rbx
    
    pop rbp
    ret

; HookEngine_Remove - Remove hook engine
HookEngine_Remove:
    push rbp
    mov rbp, rsp
    
    ; Remove all hooks
    mov rcx, [rel g_hook_count]
    test rcx, rcx
    jz .done
    
    mov rsi, [rel g_hook_table]
    xor rbx, rbx
    
.remove_loop:
    cmp rbx, rcx
    jge .done
    
    ; Remove hook at index rbx
    ; ... hook removal code ...
    
    inc rbx
    jmp .remove_loop

.done:
    mov rax, 1
    
    pop rbp
    ret

; HookEngine_IsInstalled - Check if hooks are installed
HookEngine_IsInstalled:
    mov rax, [rel g_hook_count]
    test rax, rax
    setnz al
    movzx rax, al
    ret

; HookEngine_GetHookCount - Get number of hooks
HookEngine_GetHookCount:
    mov rax, [rel g_hook_count]
    ret

; HookEngine_GetHookEntry - Get hook entry by index
; Parameters: index (rcx)
; Returns: hook entry address
HookEngine_GetHookEntry:
    mov rdx, [rel g_hook_table]
    test rdx, rdx
    jz .error
    
    mov rax, [rdx + rcx*8]
    ret

.error:
    xor rax, rax
    ret

section .data
g_hook_table dq 0
g_hook_count dq 0