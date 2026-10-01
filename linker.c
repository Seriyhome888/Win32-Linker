#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define AR_MAGIC "!<arch>\n"
#define AR_MAGIC_LEN 8
#define MAX_INPUT_OBJECTS 16
#define MAX_GLOBAL_SYMBOLS 128
#define MAX_UNIQUE_DLLS 8
#define MAX_FUNCS_PER_DLL 32

#ifndef IMPORT_OBJECT_CODE
#define IMPORT_OBJECT_CODE 0
#endif

#ifndef IMPORT_OBJECT_NAME_NO_SIGNATURE
#define IMPORT_OBJECT_NAME_NO_SIGNATURE 1
#endif

typedef struct {
	char name[8];
	DWORD virtual_size;
	DWORD virtual_address;
	DWORD size_of_raw_data;
	DWORD pointer_to_raw_data;
	BYTE* data;
} OutputSection;

typedef struct {
	char raw_target_name[64];
	char clean_symbol_name[64];
	WORD hint;
	DWORD iat_rva;
} FunctionImport;

typedef struct {
	char dll_name[64];
	FunctionImport funcs[MAX_FUNCS_PER_DLL];
	int func_count;
	DWORD ilt_offset_in_section;
	DWORD iat_offset_in_section;
} DllImportGroup;

typedef struct {
	char name[64];
	DWORD final_va;
	BOOL defined;
} GlobalSymbol;

typedef struct {
	WORD Sig1; WORD Sig2; WORD Version; WORD Machine; DWORD TimeDateStamp;
	DWORD SizeOfData; WORD Ordinal_or_Hint; WORD TypeFlags;
} SHORT_IMPORT_HEADER;

typedef struct {
	char Name[16]; char Date[12]; char UID[6]; char GID[6]; char Mode[8]; char Size[10]; char EndMarker[2];
} AR_HEADER;

DWORD align(DWORD value, DWORD alignment) {
	return (value + alignment - 1) & ~(alignment - 1);
}

long parse_ar_size(const char* size_str) {
	char buf[12] = { 0 };
	memcpy(buf, size_str, 10);
	return strtol(buf, NULL, 10);
}

BOOL resolve_from_libs(char** lib_paths, int lib_count, const char* target_symbol, char* out_dll, char* out_clean_sym, WORD* out_hint) {
	for (int l = 0; l < lib_count; l++) {
		FILE* f = fopen(lib_paths[l], "rb");
		if (!f) continue;

		char magic[AR_MAGIC_LEN];
		if (fread(magic, 1, AR_MAGIC_LEN, f) != AR_MAGIC_LEN || memcmp(magic, AR_MAGIC, AR_MAGIC_LEN) != 0) {
			fclose(f); continue;
		}

		AR_HEADER ar_hdr;
		while (fread(&ar_hdr, 1, sizeof(AR_HEADER), f) == sizeof(AR_HEADER)) {
			long member_size = parse_ar_size(ar_hdr.Size);
			long next_member_pos = ftell(f) + member_size;
			next_member_pos = (next_member_pos + 1) & ~1;

			if (member_size >= sizeof(SHORT_IMPORT_HEADER)) {
				long current_pos = ftell(f);
				SHORT_IMPORT_HEADER imp_hdr;
				fread(&imp_hdr, 1, sizeof(SHORT_IMPORT_HEADER), f);

				if (imp_hdr.Sig1 == 0x0000 && imp_hdr.Sig2 == 0xFFFF) {
					char* string_pool = malloc(imp_hdr.SizeOfData);
					fread(string_pool, 1, imp_hdr.SizeOfData, f);

					char* sym_name = string_pool;
					char* dll_name = string_pool + strlen(sym_name) + 1;

					if (strstr(target_symbol, sym_name) != NULL) {
						strcpy(out_dll, dll_name);
						strcpy(out_clean_sym, sym_name);
						*out_hint = imp_hdr.Ordinal_or_Hint;
						free(string_pool); fclose(f);
						return TRUE;
					}
					free(string_pool);
				}
				fseek(f, current_pos, SEEK_SET);
			}
			fseek(f, next_member_pos, SEEK_SET);
		}
		fclose(f);
	}
	return FALSE;
}

int main(int argc, char* argv[]) {
	if (argc < 5) {
		printf("Usage: linker.exe <output.exe/.dll> [export_sym (DLL only)] <libs_count> <lib1.lib> ... <obj1.obj> ...\n");
		return 1;
	}

	const char* out_filename = argv[1];
	BOOL is_dll_mode = (strstr(out_filename, ".dll") != NULL || _stricmp(out_filename, ".DLL") == 0);
	const char* target_export_sym = NULL;

	int num_libs = 0;
	int obj_start_idx = 0;

	if (is_dll_mode) {
		target_export_sym = argv[2];
		num_libs = atoi(argv[3]);
		obj_start_idx = 4 + num_libs;
	}
	else {
		num_libs = atoi(argv[2]);
		obj_start_idx = 3 + num_libs;
	}

	char* lib_filenames[MAX_UNIQUE_DLLS];
	for (int i = 0; i < num_libs; i++) {
		lib_filenames[i] = argv[(is_dll_mode ? 4 : 3) + i];
	}

	int num_objs = argc - obj_start_idx;

	// =================================================================
	// NEW PASSTHROUGH: INCREMENTAL DETECTOR (IN-PLACE SCANNING MODE)
	// =================================================================
	FILE* f_exist = fopen(out_filename, "rb");
	DWORD existing_text_file_offset = 0;
	DWORD existing_data_file_offset = 0;
	BOOL run_incremental = FALSE;

	if (f_exist != NULL) {
		// Read DOS header check
		IMAGE_DOS_HEADER dos_h;
		if (fread(&dos_h, 1, sizeof(IMAGE_DOS_HEADER), f_exist) == sizeof(IMAGE_DOS_HEADER) && dos_h.e_magic == IMAGE_DOS_SIGNATURE) {
			fseek(f_exist, dos_h.e_lfanew, SEEK_SET);
			IMAGE_NT_HEADERS32 nt_h;
			if (fread(&nt_h, 1, sizeof(IMAGE_NT_HEADERS32), f_exist) == sizeof(IMAGE_NT_HEADERS32) && nt_h.Signature == IMAGE_NT_SIGNATURE) {
				// Read section definitions out of existing binary map tables
				IMAGE_SECTION_HEADER* s_hdrs = malloc(sizeof(IMAGE_SECTION_HEADER) * nt_h.FileHeader.NumberOfSections);
				fread(s_hdrs, sizeof(IMAGE_SECTION_HEADER), nt_h.FileHeader.NumberOfSections, f_exist);

				for (int s = 0; s < nt_h.FileHeader.NumberOfSections; s++) {
					if (strncmp((char*)s_hdrs[s].Name, ".text", 5) == 0) existing_text_file_offset = s_hdrs[s].PointerToRawData;
					if (strncmp((char*)s_hdrs[s].Name, ".data", 5) == 0) existing_data_file_offset = s_hdrs[s].PointerToRawData;
				}
				free(s_hdrs);
				if (existing_text_file_offset > 0) {
					run_incremental = TRUE;
				}
			}
		}
		fclose(f_exist);
	}

	printf("--- Universal Production Linker Engine Starting (%s Mode) ---\n", is_dll_mode ? "DLL" : "EXE");
	if (run_incremental) {
		printf("[Optimization] Pre-existing file matched. Swapping into INCREMENTAL PATCH Mode!\n");
	}
	else {
		printf("[Optimization] Clean target build required. Launching FULL BUILD Mode.\n");
	}

	DWORD image_base = is_dll_mode ? 0x10000000 : 0x00400000;
	DWORD section_alignment = 0x1000;
	DWORD file_alignment = 0x0200;

	DWORD text_rva = 0x1000;
	DWORD data_rva = 0x0000;
	DWORD bss_rva = 0x0000;
	DWORD idata_rva = 0x0000;
	DWORD edata_rva = 0x0000;

	BYTE* obj_buffers[MAX_INPUT_OBJECTS] = { 0 };
	DWORD obj_text_offsets[MAX_INPUT_OBJECTS] = { 0 };
	DWORD obj_text_sizes[MAX_INPUT_OBJECTS] = { 0 };
	DWORD obj_data_offsets[MAX_INPUT_OBJECTS] = { 0 };
	DWORD obj_data_sizes[MAX_INPUT_OBJECTS] = { 0 };
	DWORD obj_bss_offsets[MAX_INPUT_OBJECTS] = { 0 };
	DWORD obj_bss_sizes[MAX_INPUT_OBJECTS] = { 0 };

	DWORD aggregated_text_size = 0;
	DWORD aggregated_data_size = 0;
	DWORD aggregated_bss_size = 0;

	GlobalSymbol symbol_table[MAX_GLOBAL_SYMBOLS] = { 0 };
	int global_sym_count = 0;

	DllImportGroup dll_groups[MAX_UNIQUE_DLLS] = { 0 };
	int dll_group_count = 0;

	// ==========================================
	// PASS 1: PARSE ALL SECTIONS AND MAP OFFSETS
	// ==========================================
	for (int i = 0; i < num_objs; i++) {
		FILE* f = fopen(argv[obj_start_idx + i], "rb");
		if (!f) return 1;
		fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
		obj_buffers[i] = malloc(size);
		fread(obj_buffers[i], 1, size, f);
		fclose(f);

		IMAGE_FILE_HEADER* file_hdr = (IMAGE_FILE_HEADER*)obj_buffers[i];
		IMAGE_SECTION_HEADER* sec_hdrs = (IMAGE_SECTION_HEADER*)(obj_buffers[i] + sizeof(IMAGE_FILE_HEADER));

		for (int s = 0; s < file_hdr->NumberOfSections; s++) {
			if (strncmp((char*)sec_hdrs[s].Name, ".text", 5) == 0) {
				obj_text_sizes[i] = sec_hdrs[s].SizeOfRawData;
				obj_text_offsets[i] = aggregated_text_size;
				aggregated_text_size += align(sec_hdrs[s].SizeOfRawData, 4);
			}
			else if (strncmp((char*)sec_hdrs[s].Name, ".data", 5) == 0) {
				obj_data_sizes[i] = sec_hdrs[s].SizeOfRawData;
				obj_data_offsets[i] = aggregated_data_size;
				aggregated_data_size += align(sec_hdrs[s].SizeOfRawData, 4);
			}
			else if (strncmp((char*)sec_hdrs[s].Name, ".bss", 4) == 0) {
				obj_bss_sizes[i] = sec_hdrs[s].Misc.VirtualSize > 0 ? sec_hdrs[s].Misc.VirtualSize : sec_hdrs[s].SizeOfRawData;
				obj_bss_offsets[i] = aggregated_bss_size;
				aggregated_bss_size += align(obj_bss_sizes[i], 4);
			}
		}
	}

	data_rva = text_rva + align(aggregated_text_size == 0 ? 4 : aggregated_text_size, section_alignment);
	bss_rva = data_rva + align(aggregated_data_size == 0 ? 4 : aggregated_data_size, section_alignment);
	idata_rva = bss_rva + align(aggregated_bss_size == 0 ? 4 : aggregated_bss_size, section_alignment);

	BYTE* final_text_data = calloc(1, aggregated_text_size == 0 ? 4 : aggregated_text_size);
	BYTE* final_data_data = calloc(1, aggregated_data_size == 0 ? 4 : aggregated_data_size);

	// ==========================================
	// PASS 2: RESOLVE INTERNAL GLOBAL SYMBOLS
	// ==========================================
	for (int i = 0; i < num_objs; i++) {
		IMAGE_FILE_HEADER* file_hdr = (IMAGE_FILE_HEADER*)obj_buffers[i];
		IMAGE_SECTION_HEADER* sec_hdrs = (IMAGE_SECTION_HEADER*)(obj_buffers[i] + sizeof(IMAGE_FILE_HEADER));
		IMAGE_SYMBOL* syms = (IMAGE_SYMBOL*)(obj_buffers[i] + file_hdr->PointerToSymbolTable);
		char* strings = (char*)((BYTE*)syms + (file_hdr->NumberOfSymbols * sizeof(IMAGE_SYMBOL)));

		for (int s = 0; s < file_hdr->NumberOfSections; s++) {
			if (strncmp((char*)sec_hdrs[s].Name, ".text", 5) == 0 && sec_hdrs[s].SizeOfRawData > 0) {
				memcpy(final_text_data + obj_text_offsets[i], obj_buffers[i] + sec_hdrs[s].PointerToRawData, sec_hdrs[s].SizeOfRawData);
			}
			if (strncmp((char*)sec_hdrs[s].Name, ".data", 5) == 0 && sec_hdrs[s].SizeOfRawData > 0) {
				memcpy(final_data_data + obj_data_offsets[i], obj_buffers[i] + sec_hdrs[s].PointerToRawData, sec_hdrs[s].SizeOfRawData);
			}
		}
		for (DWORD s = 0; s < file_hdr->NumberOfSymbols; s++) {
			char name[64] = { 0 };
			if (syms[s].N.Name.Short == 0) strcpy(name, strings + syms[s].N.Name.Long);
			else memcpy(name, syms[s].N.ShortName, 8);
			if (syms[s].SectionNumber > 0 && syms[s].SectionNumber <= file_hdr->NumberOfSections) {
				IMAGE_SECTION_HEADER* associated_sec = &sec_hdrs[syms[s].SectionNumber - 1];
				DWORD final_va = 0;
				if (strncmp((char*)associated_sec->Name, ".text", 5) == 0) {
					final_va = image_base + text_rva + obj_text_offsets[i] + syms[s].Value;
				}
				else if (strncmp((char*)associated_sec->Name, ".data", 5) == 0) {
					final_va = image_base + data_rva + obj_data_offsets[i] + syms[s].Value;
				}
				else if (strncmp((char*)associated_sec->Name, ".bss", 4) == 0) {
					final_va = image_base + bss_rva + obj_bss_offsets[i] + syms[s].Value;
				}
				if (final_va > 0 && syms[s].StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
					strcpy(symbol_table[global_sym_count].name, name);
					symbol_table[global_sym_count].final_va = final_va;
					symbol_table[global_sym_count].defined = TRUE;
					global_sym_count++;
				}
			}
			s += syms[s].NumberOfAuxSymbols;
		}
	}
	DWORD exported_function_rva = 0;
	if (is_dll_mode && target_export_sym) {
		for (int i = 0; i < global_sym_count; i++) {
			if (strcmp(symbol_table[i].name, target_export_sym) == 0) {
				exported_function_rva = symbol_table[i].final_va - image_base;
				break;
			}
		}
		if (exported_function_rva == 0) {
			printf("[Error] Missing designated target export symbol: %s\n", target_export_sym);
			return 1;
		}
	}
	// ==========================================
	// PASS 3: COLLECT AND SORT IMPORTS BY DLL
	// ==========================================
	for (int i = 0; i < num_objs; i++) {
		IMAGE_FILE_HEADER* file_hdr = (IMAGE_FILE_HEADER*)obj_buffers[i];
		IMAGE_SECTION_HEADER* sec_hdrs = (IMAGE_SECTION_HEADER*)(obj_buffers[i] + sizeof(IMAGE_FILE_HEADER));
		for (int s = 0; s < file_hdr->NumberOfSections; s++) {
			if (strncmp((char*)sec_hdrs[s].Name, ".text", 5) != 0) continue;
			IMAGE_RELOCATION* relocs = (IMAGE_RELOCATION*)(obj_buffers[i] + sec_hdrs[s].PointerToRelocations);
			IMAGE_SYMBOL* syms = (IMAGE_SYMBOL*)(obj_buffers[i] + file_hdr->PointerToSymbolTable);
			char* strings = (char*)((BYTE*)syms + (file_hdr->NumberOfSymbols * sizeof(IMAGE_SYMBOL)));
			for (WORD r = 0; r < sec_hdrs[s].NumberOfRelocations; r++) {
				IMAGE_SYMBOL target_sym = syms[relocs[r].SymbolTableIndex];
				if (target_sym.SectionNumber != 0) continue;
				char target_name[64] = { 0 };
				if (target_sym.N.Name.Short == 0) strcpy(target_name, strings + target_sym.N.Name.Long);
				else memcpy(target_name, target_sym.N.ShortName, 8);
				char dll_name[64] = { 0 };
				char clean_sym[64] = { 0 };
				WORD hint = 0;
				if (resolve_from_libs(lib_filenames, num_libs, target_name, dll_name, clean_sym, &hint)) {
					int group_idx = -1;
					for (int d = 0; d < dll_group_count; d++) {
						if (_stricmp(dll_groups[d].dll_name, dll_name) == 0) { group_idx = d; break; }
					}
					if (group_idx == -1 && dll_group_count < MAX_UNIQUE_DLLS) {
						group_idx = dll_group_count++;
						strcpy(dll_groups[group_idx].dll_name, dll_name);
					}
					BOOL func_added = FALSE;
					for (int f = 0; f < dll_groups[group_idx].func_count; f++) {
						if (strcmp(dll_groups[group_idx].funcs[f].raw_target_name, target_name) == 0) { func_added = TRUE; break; }
					}
					if (!func_added && dll_groups[group_idx].func_count < MAX_FUNCS_PER_DLL) {
						int f_idx = dll_groups[group_idx].func_count++;
						strcpy(dll_groups[group_idx].funcs[f_idx].raw_target_name, target_name);
						strcpy(dll_groups[group_idx].funcs[f_idx].clean_symbol_name, clean_sym);
						dll_groups[group_idx].funcs[f_idx].hint = hint;
					}
				}
			}
		}
	}
	// ==========================================
	// PASS 4: SYNTHESIZE IMPORTS SECTION (.idata)
	// ==========================================
	BYTE* idata_buf = calloc(1, 0x4000);
	DWORD desc_array_size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (dll_group_count + 1);
	DWORD current_pool_offset = desc_array_size;
	for (int d = 0; d < dll_group_count; d++) {
		dll_groups[d].ilt_offset_in_section = current_pool_offset;
		current_pool_offset += (dll_groups[d].func_count + 1) * 4;
		dll_groups[d].iat_offset_in_section = current_pool_offset;
		current_pool_offset += (dll_groups[d].func_count + 1) * 4;
	}
	for (int d = 0; d < dll_group_count; d++) {
		IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)&idata_buf[d * sizeof(IMAGE_IMPORT_DESCRIPTOR)];
		desc->Characteristics = idata_rva + dll_groups[d].ilt_offset_in_section;
		desc->FirstThunk = idata_rva + dll_groups[d].iat_offset_in_section;
		for (int f = 0; f < dll_groups[d].func_count; f++) {
			DWORD hint_name_rva = idata_rva + current_pool_offset;
			memcpy(&idata_buf[dll_groups[d].ilt_offset_in_section + (f * 4)], &hint_name_rva, 4);
			memcpy(&idata_buf[dll_groups[d].iat_offset_in_section + (f * 4)], &hint_name_rva, 4);
			dll_groups[d].funcs[f].iat_rva = idata_rva + dll_groups[d].iat_offset_in_section + (f * 4);
			memcpy(&idata_buf[current_pool_offset], &dll_groups[d].funcs[f].hint, 2);
			current_pool_offset += 2;
			char* name_str = dll_groups[d].funcs[f].clean_symbol_name;
			if (strncmp(name_str, "imp", 7) == 0)    name_str += 7;
			else if (strncmp(name_str, "imp_", 6) == 0)  name_str += 6;
			else if (strncmp(name_str, "_imp", 6) == 0)  name_str += 6;
			else if (strncmp(name_str, "imp", 5) == 0)   name_str += 5;
			if (name_str[0] == '_') name_str++;
			strcpy((char*)&idata_buf[current_pool_offset], name_str);
			char* at_marker = strchr((char*)&idata_buf[current_pool_offset], '@');
			if (at_marker) *at_marker = '\0';
			current_pool_offset += align((DWORD)strlen((char*)&idata_buf[current_pool_offset]) + 1, 2);
		}
		desc->Name = idata_rva + current_pool_offset;
		strcpy((char*)&idata_buf[current_pool_offset], dll_groups[d].dll_name);
		current_pool_offset += align((DWORD)strlen(dll_groups[d].dll_name) + 1, 4);
	}
	DWORD idata_raw_size = current_pool_offset;
	// ==========================================
	// PASS 4b: SYNTHESIZE EXPORTS SECTION (.edata)
	// ==========================================
	BYTE* edata_buf = NULL;
	DWORD edata_raw_size = 0;
	if (is_dll_mode) {
		edata_rva = idata_rva + align(idata_raw_size, section_alignment);
		edata_buf = calloc(1, 0x1000);
		IMAGE_EXPORT_DIRECTORY* exp_dir = (IMAGE_EXPORT_DIRECTORY*)edata_buf;
		DWORD exp_name_str_offset = sizeof(IMAGE_EXPORT_DIRECTORY);
		strcpy((char*)&edata_buf[exp_name_str_offset], out_filename);
		DWORD func_name_str_offset = exp_name_str_offset + align((DWORD)strlen(out_filename) + 1, 4);
		const char* public_export_name = target_export_sym;
		if (public_export_name[0] == '_') public_export_name++;
		strcpy((char*)&edata_buf[func_name_str_offset], public_export_name);
		DWORD eat_offset = func_name_str_offset + align((DWORD)strlen(public_export_name) + 1, 4);
		DWORD ent_offset = eat_offset + 4;
		DWORD eot_offset = ent_offset + 4;
		memcpy(&edata_buf[eat_offset], &exported_function_rva, 4);
		DWORD func_name_rva = edata_rva + func_name_str_offset;
		memcpy(&edata_buf[ent_offset], &func_name_rva, 4);
		WORD ordinal_value = 0;
		memcpy(&edata_buf[eot_offset], &ordinal_value, 2);
		exp_dir->Name = edata_rva + exp_name_str_offset;
		exp_dir->Base = 1;
		exp_dir->NumberOfFunctions = 1;
		exp_dir->NumberOfNames = 1;
		exp_dir->AddressOfFunctions = edata_rva + eat_offset;
		exp_dir->AddressOfNames = edata_rva + ent_offset;
		exp_dir->AddressOfNameOrdinals = edata_rva + eot_offset;
		edata_raw_size = eot_offset + 4;
	}
	// ==========================================
	// PASS 5: RESOLVE ALL CODE RELOCATIONS
	// ==========================================
	for (int i = 0; i < num_objs; i++) {
		IMAGE_FILE_HEADER* file_hdr = (IMAGE_FILE_HEADER*)obj_buffers[i];
		IMAGE_SECTION_HEADER* sec_hdrs = (IMAGE_SECTION_HEADER*)(obj_buffers[i] + sizeof(IMAGE_FILE_HEADER));
		for (int s = 0; s < file_hdr->NumberOfSections; s++) {
			if (strncmp((char*)sec_hdrs[s].Name, ".text", 5) != 0) continue;
			IMAGE_RELOCATION* relocs = (IMAGE_RELOCATION*)(obj_buffers[i] + sec_hdrs[s].PointerToRelocations);
			IMAGE_SYMBOL* syms = (IMAGE_SYMBOL*)(obj_buffers[i] + file_hdr->PointerToSymbolTable);
			char* strings = (char*)((BYTE*)syms + (file_hdr->NumberOfSymbols * sizeof(IMAGE_SYMBOL)));
			for (WORD r = 0; r < sec_hdrs[s].NumberOfRelocations; r++) {
				IMAGE_RELOCATION current_reloc = relocs[r];
				IMAGE_SYMBOL target_sym = syms[current_reloc.SymbolTableIndex];
				char target_name[64] = { 0 };
				if (target_sym.N.Name.Short == 0) strcpy(target_name, strings + target_sym.N.Name.Long);
				else memcpy(target_name, target_sym.N.ShortName, 8);
				DWORD final_target_va = 0;
				BOOL resolved = FALSE;
				for (int g = 0; g < global_sym_count; g++) {
					if (strcmp(symbol_table[g].name, target_name) == 0) {
						final_target_va = symbol_table[g].final_va;
						resolved = TRUE; break;
					}
				}
				if (!resolved) {
					for (int d = 0; d < dll_group_count; d++) {
						for (int f = 0; f < dll_groups[d].func_count; f++) {
							if (strcmp(dll_groups[d].funcs[f].raw_target_name, target_name) == 0) {
								final_target_va = image_base + dll_groups[d].funcs[f].iat_rva;
								resolved = TRUE; break;
							}
						}
						if (resolved) break;
					}
				}
				if (!resolved && target_sym.SectionNumber != 0) {
					IMAGE_SECTION_HEADER* target_sec_hdr = &sec_hdrs[target_sym.SectionNumber - 1];
					if (strncmp((char*)target_sec_hdr->Name, ".bss", 4) == 0) {
						final_target_va = image_base + bss_rva + obj_bss_offsets[i] + target_sym.Value;
					}
					else {
						final_target_va = image_base + data_rva + obj_data_offsets[i] + target_sym.Value;
					}
					resolved = TRUE;
				}
				DWORD patch_offset = obj_text_offsets[i] + current_reloc.VirtualAddress;
				DWORD existing_inline_offset = 0;
				memcpy(&existing_inline_offset, final_text_data + patch_offset, 4);
				if (current_reloc.Type == IMAGE_REL_I386_DIR32) {
					DWORD total_patch_va = final_target_va + existing_inline_offset;
					memcpy(final_text_data + patch_offset, &total_patch_va, 4);
				}
				else if (current_reloc.Type == IMAGE_REL_I386_REL32) {
					DWORD instruction_va = image_base + text_rva + patch_offset;
					DWORD displacement = (final_target_va + existing_inline_offset) - (instruction_va + 4);
					memcpy(final_text_data + patch_offset, &displacement, 4);
				}
			}
		}
	}
	// ==========================================
	// PASS 6: EMIT STRUCTURAL PE BINARY RUNNABLE
	// ==========================================
	int num_sections_to_emit = is_dll_mode ? 5 : 4;
	OutputSection sections[5];
	strcpy(sections[0].name, ".text");
	sections[0].virtual_size = aggregated_text_size == 0 ? 4 : aggregated_text_size;
	sections[0].virtual_address = text_rva;
	sections[0].size_of_raw_data = align(sections[0].virtual_size, file_alignment);
	sections[0].data = final_text_data;
	strcpy(sections[1].name, ".data");
	sections[1].virtual_size = aggregated_data_size == 0 ? 4 : aggregated_data_size;
	sections[1].virtual_address = data_rva;
	sections[1].size_of_raw_data = align(sections[1].virtual_size, file_alignment);
	sections[1].data = final_data_data;
	strcpy(sections[2].name, ".bss");
	sections[2].virtual_size = aggregated_bss_size == 0 ? 4 : aggregated_bss_size;
	sections[2].virtual_address = bss_rva;
	sections[2].size_of_raw_data = 0;
	sections[2].pointer_to_raw_data = 0;
	sections[2].data = NULL;
	strcpy(sections[3].name, ".idata");
	sections[3].virtual_size = idata_raw_size;
	sections[3].virtual_address = idata_rva;
	sections[3].size_of_raw_data = align(idata_raw_size, file_alignment);
	sections[3].data = idata_buf;
	if (is_dll_mode) {
		strcpy(sections[4].name, ".edata");
		sections[4].virtual_size = edata_raw_size;
		sections[4].virtual_address = edata_rva;
		sections[4].size_of_raw_data = align(edata_raw_size, file_alignment);
		sections[4].data = edata_buf;
	}
	// --- EXECUTE MODE BRANCH CONDITIONAL ---
	if (run_incremental) {
		// INCREMENTAL PATHER: Surgical block over-writing mode
		FILE* f_patch = fopen(out_filename, "r+b"); // Open file for targeted random access writes
		if (f_patch) {
			// Hot-patch our newly computed relocations and text straight into the pre-existing code section offset
			fseek(f_patch, existing_text_file_offset, SEEK_SET);
			fwrite(final_text_data, 1, sections[0].virtual_size, f_patch);
			// Hot-patch global data parameters instantly into the pre-existing data section offset
			if (existing_data_file_offset > 0) {
				fseek(f_patch, existing_data_file_offset, SEEK_SET);
				fwrite(final_data_data, 1, sections[1].virtual_size, f_patch);
			}
			fclose(f_patch);
			printf("[Incremental] In-place segment overwrites committed successfully! (0ms engine pass)\n");
		}
	}
	else {
		// FULL BUILD ENGINE TRACK (Standard compilation stream fallback)
		DWORD size_of_headers = align(0x80 + sizeof(IMAGE_NT_HEADERS32) + (sizeof(IMAGE_SECTION_HEADER) * num_sections_to_emit), file_alignment);
		DWORD current_file_ptr = size_of_headers;
		for (int i = 0; i < num_sections_to_emit; i++) {
			if (sections[i].size_of_raw_data > 0) {
				sections[i].pointer_to_raw_data = current_file_ptr;
				current_file_ptr += sections[i].size_of_raw_data;
			}
		}
		DWORD entry_point_rva = 0;
		if (!is_dll_mode) {
			for (int i = 0; i < global_sym_count; i++) {
				if (strcmp(symbol_table[i].name, "_main") == 0) {
					entry_point_rva = symbol_table[i].final_va - image_base; break;
				}
			}
		}
		FILE* f_out = fopen(out_filename, "wb");
		BYTE dos_stub[0x80] = { 0 };
		dos_stub[0] = 'M'; dos_stub[1] = 'Z';
		DWORD pe_offset = 0x80;
		memcpy(&dos_stub[0x3C], &pe_offset, 4);
		fwrite(dos_stub, 1, 0x80, f_out);
		IMAGE_NT_HEADERS32 nt_hdrs = { 0 };
		nt_hdrs.Signature = IMAGE_NT_SIGNATURE;
		nt_hdrs.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
		nt_hdrs.FileHeader.NumberOfSections = num_sections_to_emit;
		nt_hdrs.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
		nt_hdrs.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
		if (is_dll_mode) nt_hdrs.FileHeader.Characteristics |= IMAGE_FILE_DLL;
		nt_hdrs.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
		nt_hdrs.OptionalHeader.AddressOfEntryPoint = entry_point_rva;
		nt_hdrs.OptionalHeader.ImageBase = image_base;
		nt_hdrs.OptionalHeader.SectionAlignment = section_alignment;
		nt_hdrs.OptionalHeader.FileAlignment = file_alignment;
		nt_hdrs.OptionalHeader.MajorOperatingSystemVersion = 5;
		nt_hdrs.OptionalHeader.MinorOperatingSystemVersion = 0;
		nt_hdrs.OptionalHeader.MajorSubsystemVersion = 5;
		nt_hdrs.OptionalHeader.MinorSubsystemVersion = 0;
		nt_hdrs.OptionalHeader.SizeOfImage = sections[num_sections_to_emit - 1].virtual_address + align(sections[num_sections_to_emit - 1].virtual_size, section_alignment);
		nt_hdrs.OptionalHeader.SizeOfHeaders = size_of_headers;
		nt_hdrs.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
		nt_hdrs.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
		if (is_dll_mode) {
			nt_hdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = edata_rva;
			nt_hdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = edata_raw_size;
		}
		nt_hdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = idata_rva;
		nt_hdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = idata_raw_size;
		fwrite(&nt_hdrs, 1, sizeof(IMAGE_NT_HEADERS32), f_out);
		for (int i = 0; i < num_sections_to_emit; i++) {
			IMAGE_SECTION_HEADER s_hdr = { 0 };
			memcpy(s_hdr.Name, sections[i].name, 8);
			s_hdr.Misc.VirtualSize = sections[i].virtual_size;
			s_hdr.VirtualAddress = sections[i].virtual_address;
			s_hdr.SizeOfRawData = sections[i].size_of_raw_data;
			s_hdr.PointerToRawData = sections[i].pointer_to_raw_data;
			if (strcmp(sections[i].name, ".text") == 0) {
				s_hdr.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
			}
			else if (strcmp(sections[i].name, ".data") == 0) {
				s_hdr.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
			}
			else if (strcmp(sections[i].name, ".bss") == 0) {
				s_hdr.Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
			}
			else {
				s_hdr.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
			}
			fwrite(&s_hdr, 1, sizeof(IMAGE_SECTION_HEADER), f_out);
		}
		LONG pos = ftell(f_out);
		for (int i = 0; i < (int)(size_of_headers - pos); i++) fputc(0, f_out);
		for (int s = 0; s < num_sections_to_emit; s++) {
			if (sections[s].size_of_raw_data == 0) continue;
			fwrite(sections[s].data, 1, sections[s].virtual_size, f_out);
			for (DWORD i = sections[s].virtual_size; i < sections[s].size_of_raw_data; i++) fputc(0, f_out);
		}
		fclose(f_out);
		printf("[Success] Native Win32 %s successfully linked -> %s\n", is_dll_mode ? "DLL" : "EXE", out_filename);
	}
	// =================================================================
	// NEW PASS: EMIT COMPANION IMPORT LIBRARY VIA AUTOMATED DEF GENERATION
	// =================================================================
	if (is_dll_mode && target_export_sym) {
		FILE* f_def = fopen("mylib.def", "w");
		if (f_def) {
			fprintf(f_def, "LIBRARY mylib\n");
			fprintf(f_def, "EXPORTS\n");
			const char* public_export = target_export_sym;
			if (public_export[0] == '_') public_export++;
			fprintf(f_def, "    %s\n", public_export);
			fclose(f_def);
			char cmd_buf[256] = { 0 };
			sprintf(cmd_buf, "lib.exe /def:mylib.def /out:mylib.lib /machine:x86 > nul 2>&1");
			system(cmd_buf);
			remove("mylib.def");
		}
	}
	for (int i = 0; i < num_objs; i++) free(obj_buffers[i]);
	free(idata_buf); if (edata_buf) free(edata_buf); free(final_data_data); free(final_text_data);
	return 0;
}
