del *.obj
del *.exe
del *.dll
del *.lib
del *.exp
del linux_hello

cl lib_parser.c

rem nasm -f win32 test.asm -o test.obj

nasm -f win32 main.asm -o main.obj
nasm -f win32 helper.asm -o helper.obj
nasm -f win32 print.asm -o print.obj

nasm -f win32 popup.asm -o popup.obj

nasm -f win32 bss_test.asm -o bss_test.obj

nasm -f win32 mylib.asm -o mylib.obj
cl dlltest.c

cl linker.c