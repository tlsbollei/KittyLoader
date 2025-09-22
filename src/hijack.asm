.code

public jumpstart
public startup

jumpstart proc
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    
    call startup
    
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
jumpstart endp

startup proc
    push rbx
    mov rbx, gs:[60h]
    movzx eax, byte ptr [rbx+2]
    test al, al
    jnz gotcaught
    
    mov eax, dword ptr [rbx+68h]
    and eax, 70h
    test eax, eax
    jnz gotcaught
    
    pop rbx
    ret
    
gotcaught:
    mov ecx, 0
    call ExitProcess
    
startup endp

end
