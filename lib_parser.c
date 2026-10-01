#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Standard definitions for Unix 'ar' archive headers 
#define AR_MAGIC "!<arch>\n"
#define AR_MAGIC_LEN 8

typedef struct {
    char Name[16];      // File member name
    char Date[12];      // File modification date
    char UID[6];        // User ID
    char GID[6];        // Group ID
    char Mode[8];       // File mode (octal)
    char Size[10];      // File member size in ASCII bytes
    char EndMarker[2];  // Always contains `\x60\x0A`
} AR_HEADER;

// Official MS Short Import Header specification layout
typedef struct {
    WORD Sig1;          // Must be 0x0000
    WORD Sig2;          // Must be 0xFFFF
    WORD Version;
    WORD Machine;       // e.g. 0x014C for i386
    DWORD TimeDateStamp;
    DWORD SizeOfData;   // Length of the following string payloads
    WORD Ordinal_or_Hint;
    WORD TypeFlags;     // Format execution type definitions
} SHORT_IMPORT_HEADER;

// Routine to safely extract numeric length from fixed ASCII ar spacing headers
long parse_ar_size(const char* size_str) {
    char buf[12] = {0};
    memcpy(buf, size_str, 10);
    return strtol(buf, NULL, 10);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: lib_parser.exe <path_to_lib> <symbol_name>\n");
        printf("Example: lib_parser.exe kernel32.lib _ExitProcess@4\n");
        return 1;
    }

    const char* lib_path = argv[1];
    const char* target_symbol = argv[2];

    FILE* f = fopen(lib_path, "rb");
    if (!f) {
        printf("[Error] Failed to open library file path: %s\n", lib_path);
        return 1;
    }

    // 1. Verify standard global archive magic file marker
    char magic[AR_MAGIC_LEN];
    fread(magic, 1, AR_MAGIC_LEN, f);
    if (memcmp(magic, AR_MAGIC, AR_MAGIC_LEN) != 0) {
        printf("[Error] Invalid library signature. Not a standard MS format library archive.\n");
        fclose(f);
        return 1;
    }

    printf("[Parsing] Searching %s for symbol '%s'...\n", lib_path, target_symbol);

    AR_HEADER ar_hdr;
    // 2. Linear scan through the archive members blocks loop
    while (fread(&ar_hdr, 1, sizeof(AR_HEADER), f) == sizeof(AR_HEADER)) {
        long member_size = parse_ar_size(ar_hdr.Size);
        long next_member_pos = ftell(f) + member_size;
        
        // Archive entries must be aligned to even byte boundaries on disk
        next_member_pos = (next_member_pos + 1) & ~1;

        // Peak ahead to parse short import sub-structures
        if (member_size >= sizeof(SHORT_IMPORT_HEADER)) {
            long current_pos = ftell(f);
            SHORT_IMPORT_HEADER imp_hdr;
            fread(&imp_hdr, 1, sizeof(SHORT_IMPORT_HEADER), f);

            // Match structural Short Format markers (0xFFFF0000)
            if (imp_hdr.Sig1 == 0x0000 && imp_hdr.Sig2 == 0xFFFF) {
                // String blocks follow immediately after the header
                char* string_pool = malloc(imp_hdr.SizeOfData);
                fread(string_pool, 1, imp_hdr.SizeOfData, f);

                char* sym_name = string_pool;                        // First string
                char* dll_name = string_pool + strlen(sym_name) + 1; // Second string

                // Match against the compiler's decorated symbol signature
                // E.g., Matching either exact text or stdcall variations
                if (strstr(target_symbol, sym_name) != NULL) {
                    printf("\n🎉 [Match Found!]\n");
                    printf("  -> Symbol Name: %s\n", sym_name);
                    printf("  -> Hosted inside DLL: %s\n", dll_name);
                    printf("  -> Function Hint Index: %d\n", imp_hdr.Ordinal_or_Hint);
                    
                    free(string_pool);
                    fclose(f);
                    return 0; // Success exit
                }
                free(string_pool);
            }
            fseek(f, current_pos, SEEK_SET); // Rewind pointer
        }

        // Advance file context cursor stream directly to the next block frame
        fseek(f, next_member_pos, SEEK_SET);
    }

    printf("[Info] Scanned library completely. Symbol target mapping not discovered.\n");
    fclose(f);
    return 0;
}
