linker.exe custom_multi.exe 2 "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\user32.lib" main.obj helper.obj
custom_multi.exe
echo %errorlevel%

linker.exe print_demo.exe 2 "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\user32.lib" print.obj
print_demo.exe

linker.exe multi_test.exe 2 "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\user32.lib" popup.obj
multi_test.exe

linker.exe bss_demo.exe 2 "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\user32.lib" bss_test.obj
bss_demo.exe

echo Second time to test Incremental Linker Engine
linker.exe bss_demo.exe 2 "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\user32.lib" bss_test.obj
bss_demo.exe

linker.exe mylib.dll _SayHello@0 2 "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\user32.lib" mylib.obj
dlltest.exe
cl staticlibtest.c mylib.lib
staticlibtest.exe

lib_parser.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x86\kernel32.lib" _ExitProcess@4