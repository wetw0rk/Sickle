
global _start        ; Entry point, required for ld linker

section .text        ; Text segment, code resides here

_start:
    ; write(1, message, mlen)
    mov eax, 0x4
    mov ebx, 0x1
    mov ecx, message
    mov edx, mlen
    int 0x80
    
    ; exit(5)
    mov eax, 0x1
    mov ebx, 0x5
    int 0x80

section .data        ; Data segment

    message:    db "Fuck the world. And you.", 10
    mlen        equ     $-message

