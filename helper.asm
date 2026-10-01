bits 32
global _my_exit_helper
extern __imp__ExitProcess@4

section .text
_my_exit_helper:
    push    ebp
    mov     ebp, esp
    
    push    dword [ebp+8]          ; Push the exit code passed from main
    call    [__imp__ExitProcess@4] ; Call the Windows API
    
    mov     esp, ebp
    pop     ebp
    ret
