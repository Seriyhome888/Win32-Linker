bits 32
global _main
extern _my_exit_helper ; Defined in helper.asm

section .text
_main:
    push    42              ; Pass exit code 42 as an argument
    call    _my_exit_helper ; Cross-module call!
