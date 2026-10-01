bits 32

extern __imp__MessageBoxA@16
global _SayHello@0

section .data
    title_text  db "Custom Linker DLL", 0
    body_text   db "Hello from a DLL compiled by a custom linker!", 0

section .text
_SayHello@0:
    ; Standard stdcall prologue
    push    ebp
    mov     ebp, esp

    ; MessageBoxA(NULL, body_text, title_text, MB_OK | MB_ICONINFORMATION)
    push    0x00000040              ; MB_ICONINFORMATION
    push    title_text
    push    body_text
    push    0                       ; hWnd = NULL
    call    [__imp__MessageBoxA@16]

    mov     esp, ebp
    pop     ebp
    ret     4                       ; Clean up stack arguments (stdcall)
