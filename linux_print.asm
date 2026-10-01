bits 32

global _start               ; ELF standard entry point identifier (equivalent to _main)

section .data
    message     db "Hello World from a custom-linked Linux ELF binary!", 0x0A
    message_len equ $ - message

section .text
_start:
    ; 1. sys_write(stdout, message, message_len)
    mov     eax, 4          ; System call number 4 = sys_write
    mov     ebx, 1          ; File descriptor 1 = stdout
    mov     ecx, message    ; Absolute address pointer to our data section string
    mov     edx, message_len; Length of string payload
    int     0x80            ; Trigger kernel software interrupt vector

    ; 2. sys_exit(0)
    mov     eax, 1          ; System call number 1 = sys_exit
    mov     ebx, 0          ; Return status code 0
    int     0x80            ; Trigger kernel software interrupt vector
