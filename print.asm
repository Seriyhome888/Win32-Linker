bits 32

extern __imp__GetStdHandle@4
extern __imp__WriteFile@20
extern __imp__ExitProcess@4

global _main

section .data
    message        db  "Hello World! This binary was built by a custom linker.", 0x0D, 0x0A
    message_len    equ $ - message
    bytes_written  dd  0 ; Moved into .data to keep allocations fully aligned and simple

section .text
_main:
    ; 1. Get standard output handle
    push    -11
    call    [__imp__GetStdHandle@4]
    mov     ebx, eax

    ; 2. Call WriteFile(handle, buffer, len, &bytes_written, NULL)
    push    0
    push    bytes_written
    push    message_len
    push    message
    push    ebx
    call    [__imp__WriteFile@20]

    ; 3. Exit program successfully
    push    0
    call    [__imp__ExitProcess@4]