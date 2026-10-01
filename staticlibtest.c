#include <stdio.h>

// Tell the compiler to expect this function to be resolved via an import thunk array
__declspec(dllimport) void __stdcall SayHello();

int main() {
	printf("--- Compile-Time Static Import C Client Starting ---\n");

	// Invoke the function directly as if it were a local function!
	printf("[Linking] Direct hardware call into mylib.lib descriptor table...\n");
	SayHello();

	printf("[Success] Static compile execution loop finished successfully!\n");
	return 0;
}
