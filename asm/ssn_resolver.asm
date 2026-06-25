BITS 64

section .text

global SSN_ResolveAsm
global SSN_ExtractAsm
global SSN_GetNtdllBaseAsm
global SSN_GetExportDirAsm
global SSN_FindFunctionAsm

; SSN_ResolveAsm - Resolve SSN using assembly
; Parameters: func_name (rcx), ntdll_base (rdx)
; Returns: SSN in rax
SSN_ResolveAsm:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    ; Store parameters
    mov rbx, rcx    ; func_name
    mov r12, rdx    ; ntdll_base
    
    ; Get export directory
    mov rcx, r12
    call SSN_GetExportDirAsm
    test rax, rax
    jz .not_found
    
    mov r13, rax    ; export_dir
    
    ; Get export directory fields
    mov rsi, [r13 + 0x20]   ; AddressOfNames
    add rsi, r12
    mov rdi, [r13 + 0x24]   ; AddressOfNameOrdinals
    add rdi, r12
    mov rdx, [r13 + 0x1C]   ; AddressOfFunctions
    add rdx, r12
    
    push rdx
    
    ; Number of names
    mov rcx, [r13 + 0x18]   ; NumberOfNames
    xor r8, r8
    
.search_loop:
    cmp r8, rcx
    jge .not_found
    
    ; Get function name
    mov rax, [rsi + r8*4]
    add rax, r12
    mov r9, rax
    
    ; Compare names
    push rcx
    push r8
    push rdi
    
    mov rcx, r9
    mov rdx, rbx
    call _strcmp
    test rax, rax
    
    pop rdi
    pop r8
    pop rcx
    
    je .found
    
    inc r8
    jmp .search_loop

.found:
    ; Get ordinal
    movzx rax, word [rdi + r8*2]
    pop rdx
    
    ; Get function address
    mov rcx, [rdx + rax*4]
    add rcx, r12
    
    ; Extract SSN
    call SSN_ExtractAsm
    jmp .done

.not_found:
    pop rdx
    xor rax, rax

.done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    
    pop rbp
    ret

; SSN_ExtractAsm - Extract SSN from function code
; Parameters: func_addr (rcx)
; Returns: SSN in rax
SSN_ExtractAsm:
    push rbp
    mov rbp, rsp
    
    push rbx
    
    mov rbx, rcx
    
    ; Search for MOV EAX, SSN (B8 XX XX XX XX)
    mov rcx, 0
.search_mov:
    cmp rcx, 32
    jge .search_ba
    
    ; Check for 0xB8 (MOV EAX, imm32)
    cmp byte [rbx + rcx], 0xB8
    jne .next_mov
    
    ; Extract SSN
    mov eax, [rbx + rcx + 1]
    test eax, eax
    jz .next_mov
    cmp eax, 0x1000
    jge .next_mov
    
    jmp .done

.next_mov:
    inc rcx
    jmp .search_mov

.search_ba:
    ; Search for MOV EAX, SSN (BA XX XX XX XX)
    mov rcx, 0
.search_ba_loop:
    cmp rcx, 32
    jge .not_found
    
    ; Check for 0xBA (MOV EDX, imm32)
    cmp byte [rbx + rcx], 0xBA
    jne .next_ba
    
    ; Extract SSN
    mov eax, [rbx + rcx + 1]
    test eax, eax
    jz .next_ba
    cmp eax, 0x1000
    jge .next_ba
    
    jmp .done

.next_ba:
    inc rcx
    jmp .search_ba_loop

.not_found:
    xor rax, rax

.done:
    pop rbx
    pop rbp
    ret

; SSN_GetNtdllBaseAsm - Get ntdll base address
SSN_GetNtdllBaseAsm:
    push rbp
    mov rbp, rsp
    
    ; Get PEB
    mov rax, gs:[0x60]
    test rax, rax
    jz .error
    
    ; Get LDR
    mov rax, [rax + 0x18]
    test rax, rax
    jz .error
    
    ; Get InMemoryOrderModuleList
    mov rax, [rax + 0x20]
    test rax, rax
    jz .error
    
    ; Get first module (ntdll)
    mov rax, [rax]
    mov rax, [rax + 0x20]   ; BaseAddress
    test rax, rax
    jz .error
    
    jmp .done

.error:
    xor rax, rax

.done:
    pop rbp
    ret

; SSN_GetExportDirAsm - Get export directory
; Parameters: module_base (rcx)
; Returns: export directory address
SSN_GetExportDirAsm:
    push rbp
    mov rbp, rsp
    
    push rbx
    
    mov rbx, rcx
    
    ; Check DOS header
    cmp word [rbx], 0x5A4D
    jne .error
    
    ; Get NT headers
    mov eax, [rbx + 0x3C]
    add rax, rbx
    cmp dword [rax], 0x00004550
    jne .error
    
    ; Get export directory
    mov eax, [rax + 0x88]   ; Export directory RVA
    test eax, eax
    jz .error
    
    add rax, rbx
    jmp .done

.error:
    xor rax, rax

.done:
    pop rbx
    pop rbp
    ret

; SSN_FindFunctionAsm - Find function in export directory
; Parameters: export_dir (rcx), func_name (rdx)
; Returns: function address
SSN_FindFunctionAsm:
    push rbp
    mov rbp, rsp
    
    push rbx
    push rsi
    push rdi
    
    mov rbx, rcx
    mov rsi, rdx
    
    ; Get AddressOfNames
    mov rdi, [rbx + 0x20]
    test rdi, rdi
    jz .not_found
    
    ; Get module base
    mov rcx, rbx
    sub rcx, [rbx + 0x1C]   ; Subtract AddressOfFunctions to get base
    
    ; Search names
    mov rdx, [rbx + 0x18]   ; NumberOfNames
    xor r8, r8
    
.search:
    cmp r8, rdx
    jge .not_found
    
    ; Get current name
    mov eax, [rdi + r8*4]
    add rax, rcx
    push r8
    
    ; Compare names
    mov rcx, rax
    mov rdx, rsi
    call _strcmp
    test rax, rax
    
    pop r8
    je .found
    
    inc r8
    jmp .search

.found:
    ; Get ordinal
    mov rdx, [rbx + 0x24]   ; AddressOfNameOrdinals
    movzx rax, word [rdx + r8*2]
    
    ; Get function address
    mov rdx, [rbx + 0x1C]   ; AddressOfFunctions
    mov eax, [rdx + rax*4]
    add rax, rcx
    
    jmp .done

.not_found:
    xor rax, rax

.done:
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

; Internal: strcmp implementation
_strcmp:
    push rbp
    mov rbp, rsp
    
    xor rax, rax
    
.compare:
    mov dl, byte [rcx]
    mov dh, byte [rdx]
    
    test dl, dl
    jz .check_dh
    test dh, dh
    jz .done
    
    cmp dl, dh
    jne .done
    
    inc rcx
    inc rdx
    jmp .compare

.check_dh:
    test dh, dh
    jne .done
    xor rax, rax
    jmp .finish

.done:
    movzx rax, dl
    sub rax, rdx

.finish:
    pop rbp
    ret