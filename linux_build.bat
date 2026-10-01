nasm -f elf32 linux_print.asm -o linux_print.o

cl elf_linker.c

elf_linker.exe linux_hello linux_print.o