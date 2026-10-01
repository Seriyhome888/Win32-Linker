bits 32

extern __imp__GetConsoleWindow@0
extern __imp__MessageBoxA@16
extern __imp__ExitProcess@4

global _main

section .data
    title_text   db "Custom Linker Core", 0
    body_text    db "Multi-DLL Engine Working Flawlessly!", 0x0D, 0x0A
                 db "Brought to you by your own Linker.", 0

section .text
_main:
    ; 1. Fetch handle of current console window from kernel32.dll
    call    [__imp__GetConsoleWindow@0]
    mov     ebx, eax                ; Store hWnd window handle in ebx

    ; 2. Spawn a native desktop GUI popup box from user32.dll
    ; MessageBoxA(hWnd, lpText, lpCaption, uType)
    push    0x00000040              ; uType = MB_OK | MB_ICONINFORMATION
    push    title_text              ; lpCaption
    push    body_text               ; lpText
    push    ebx                     ; hWnd
    call    [__imp__MessageBoxA@16]

    ; 3. Exit gracefully
    push    0
    call    [__imp__ExitProcess@4]
