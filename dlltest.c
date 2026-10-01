#include <stdio.h>
#include <windows.h>

// Define a function pointer signature matching the stdcall exported function
typedef void(__stdcall* SayHelloFunc)();

int main() {
	printf("--- Native C Shared Module Test Client Starting ---\n");

	// 1. Explicitly load the custom-linked DLL into this process memory space
	printf("[Loading] Mounting mylib.dll...\n");
	HMODULE hLib = LoadLibraryA("mylib.dll");

	if (hLib == NULL) {
		printf("[Error] Failed to load mylib.dll. Error Code: %lu\n", GetLastError());
		return 1;
	}

	// 2. Query the DLL's Export Address Table (.edata) for the cleaned function string
	printf("[Executing] Invoking exported symbol 'SayHello' via GetProcAddress...\n");
	SayHelloFunc SayHello = (SayHelloFunc)GetProcAddress(hLib, "SayHello@0");

	if (SayHello == NULL) {
		printf("[Error] Failed to locate the exported 'SayHello' symbol inside .edata! Error Code: %lu\n", GetLastError());
		FreeLibrary(hLib);
		return 1;
	}

	// 3. Jump to the absolute virtual address space of the exported assembly code
	SayHello();

	// 4. Clean up process handles gracefully
	printf("[Success] Shared module method returned successfully!\n");
	FreeLibrary(hLib);
	return 0;
}
