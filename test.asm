bits 32

; Declare the implicit __imp__ prefix that linkers use for imported functions
extern __imp__ExitProcess@4

section .text
global _main
_main:
    push    42
    ; The brackets mean "call the address stored at this pointer"
    call    [__imp__ExitProcess@4] 
