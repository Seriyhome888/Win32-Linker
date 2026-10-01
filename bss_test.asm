bits 32

extern __imp__MessageBoxA@16
extern __imp__ExitProcess@4

global _main

section .data
    title_text  db "Custom Linker Core", 0
    body_text   db "Hardened Multi-DLL Engine with .BSS Support!", 0

section .bss
    ; Reserve 64 Kilobytes of working uninitialized RAM buffer space.
    ; This will take up ZERO physical bytes inside the file on disk!
    large_buffer resb 65536 

section .text
_main:
    ; 1. Clear out or manipulate the first byte of our uninitialized buffer safely
    mov     byte [large_buffer], 0xAA

    ; 2. Spawn our desktop alert box
    push    0x00000040              ; MB_OK | MB_ICONINFORMATION
    push    title_text              ; lpCaption
    push    body_text               ; lpText
    push    0                       ; hWnd = NULL
    call    [__imp__MessageBoxA@16]

    ; 3. Exit gracefully
    push    0
    call    [__imp__ExitProcess@4]
