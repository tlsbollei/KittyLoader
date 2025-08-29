.code

public hijack_entry_point
public initialize_early_execution

hijack_entry_point proc
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    
    call initialize_early_execution
    
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    
    mov rsp, rbp
    pop rbp
    ret
hijack_entry_point endp

initialize_early_execution proc
  
    push rbx
    mov rbx, gs:[60h]      ; PEB
    movzx eax, byte ptr [rbx+2] ; BeingDebugged
    test al, al
    jnz debugger_detected
    
    mov eax, dword ptr [rbx+68h]
    and eax, 70h
    test eax, eax
    jnz debugger_detected
    
    pop rbx
    ret
    
debugger_detected:
    mov ecx, 0
    call ExitProcess
    
initialize_early_execution endp

end