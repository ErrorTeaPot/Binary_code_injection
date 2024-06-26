BITS 64

SECTION .text
global main

main:
    ; save context
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r11

    mov rax, 1
    mov rdi, 1
    mov rdx, 23
    lea rsi, [rel msg]
    syscall

    ; load context
    pop r11
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    ; return
    mov rax, 0x4022e0
    jmp rax

msg: db "je suis trop un hacker", 10, 0