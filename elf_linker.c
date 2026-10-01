#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_OBJECTS 16
#define MAX_GLOBAL_SYMBOLS 128

// =================================================================
// MANUAL LINUX ELF32 STRUCT DEFINITIONS (Cross-Compilation Layer)
// =================================================================
typedef struct {
    unsigned char e_ident[16];
    unsigned short e_type; unsigned short e_machine; unsigned int e_version;
    unsigned int e_entry; unsigned int e_phoff; unsigned int e_shoff;
    unsigned int e_flags; unsigned short e_ehsize; unsigned short e_phentsize;
    unsigned short e_phnum; unsigned short e_shentsize; unsigned short e_shnum;
    unsigned short e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    unsigned int sh_name; unsigned int sh_type; unsigned int sh_flags;
    unsigned int sh_addr; unsigned int sh_offset; unsigned int sh_size;
    unsigned int sh_link; unsigned int sh_info; unsigned int sh_addralign;
    unsigned int sh_entsize;
} Elf32_Shdr;

typedef struct {
    unsigned int st_name; unsigned int st_value; unsigned int st_size;
    unsigned char st_info; unsigned char st_other; unsigned short st_shndx;
} Elf32_Sym;

typedef struct {
    unsigned int r_offset; unsigned int r_info;
} Elf32_Rel;

typedef struct {
    unsigned int p_type; unsigned int p_offset; unsigned int p_vaddr;
    unsigned int p_paddr; unsigned int p_filesz; unsigned int p_memsz;
    unsigned int p_flags; unsigned int p_align;
} Elf32_Phdr;

// ELF Layout Calculation Helpers
#define ELF_SECTION_ALIGN(v, a) (((v) + (a) - 1) & ~((a) - 1))

typedef struct {
    char name[32];
    unsigned int virtual_address;
    unsigned int size;
    unsigned int file_offset;
    unsigned char* data;
} OutputSegment;

typedef struct {
    char name[64];
    unsigned int final_va;
    unsigned short source_sec_idx;
} ElfGlobalSymbol;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: elf_linker.exe <output_elf> <input_obj1.o> [input_obj2.o ...]\n");
        return 1;
    }

    const char* out_filename = argv[1];
    int num_objs = argc - 2;

    printf("--- Universal Cross-Platform ELF Linker Engine Starting ---\n");

    unsigned int target_image_base = 0x08048000; 
    unsigned int current_text_size = 0;
    unsigned int current_data_size = 0;

    unsigned char* obj_buffers[MAX_INPUT_OBJECTS] = {0};
    unsigned int obj_text_offsets[MAX_INPUT_OBJECTS] = {0};
    unsigned int obj_data_offsets[MAX_INPUT_OBJECTS] = {0};

    ElfGlobalSymbol symbol_table[MAX_GLOBAL_SYMBOLS] = {0};
    int global_sym_count = 0;

    // ==========================================
    // PASS 1: PARSE ALL ELF OBJECT SECTIONS
    // ==========================================
    for (int i = 0; i < num_objs; i++) {
        FILE* f = fopen(argv[2 + i], "rb");
        if (!f) { printf("[Error] Cannot open Linux object module: %s\n", argv[2 + i]); return 1; }
        fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
        obj_buffers[i] = malloc(size);
        fread(obj_buffers[i], 1, size, f);
        fclose(f);

        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)obj_buffers[i];
        if (memcmp(ehdr->e_ident, "\x7F\x45\x4C\x46", 4) != 0) {
            printf("[Error] Malformed Linux object signature inside: %s\n", argv[2 + i]);
            return 1;
        }

        Elf32_Shdr* shdrs = (Elf32_Shdr*)(obj_buffers[i] + ehdr->e_shoff);
        char* shstrtab = (char*)(obj_buffers[i] + shdrs[ehdr->e_shstrndx].sh_offset);

        for (int s = 0; s < ehdr->e_shnum; s++) {
            char* sec_name = shstrtab + shdrs[s].sh_name;
            if (strcmp(sec_name, ".text") == 0) {
                obj_text_offsets[i] = current_text_size;
                current_text_size += ELF_SECTION_ALIGN(shdrs[s].sh_size, 4);
            }
            else if (strcmp(sec_name, ".data") == 0) {
                obj_data_offsets[i] = current_data_size;
                current_data_size += ELF_SECTION_ALIGN(shdrs[s].sh_size, 4);
            }
        }
    }

    unsigned char* aggregated_text = calloc(1, current_text_size == 0 ? 4 : current_text_size);
    unsigned char* aggregated_data = calloc(1, current_data_size == 0 ? 4 : current_data_size);

    // ==========================================
    // PASS 2: CONSOLIDATE DATA CORES AND MAP SYMBOLS
    // ==========================================
    for (int i = 0; i < num_objs; i++) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)obj_buffers[i];
        Elf32_Shdr* shdrs = (Elf32_Shdr*)(obj_buffers[i] + ehdr->e_shoff);
        char* shstrtab = (char*)(obj_buffers[i] + shdrs[ehdr->e_shstrndx].sh_offset);

        unsigned int text_base_va = target_image_base + 0x1000; 
        unsigned int data_base_va = text_base_va + ELF_SECTION_ALIGN(current_text_size, 0x1000);

        for (int s = 0; s < ehdr->e_shnum; s++) {
            char* sec_name = shstrtab + shdrs[s].sh_name;
            if (strcmp(sec_name, ".text") == 0 && shdrs[s].sh_size > 0) {
                memcpy(aggregated_text + obj_text_offsets[i], obj_buffers[i] + shdrs[s].sh_offset, shdrs[s].sh_size);
            }
            if (strcmp(sec_name, ".data") == 0 && shdrs[s].sh_size > 0) {
                memcpy(aggregated_data + obj_data_offsets[i], obj_buffers[i] + shdrs[s].sh_offset, shdrs[s].sh_size);
            }
        }

        for (int s = 0; s < ehdr->e_shnum; s++) {
            if (shdrs[s].sh_type == 2) { 
                Elf32_Sym* syms = (Elf32_Sym*)(obj_buffers[i] + shdrs[s].sh_offset);
                int num_syms = shdrs[s].sh_size / sizeof(Elf32_Sym);
                char* strtab = (char*)(obj_buffers[i] + shdrs[shdrs[s].sh_link].sh_offset);

                for (int sym_idx = 0; sym_idx < num_syms; sym_idx++) {
                    if ((syms[sym_idx].st_info >> 4) == 1 || syms[sym_idx].st_name > 0) { 
                        char* sym_name = strtab + syms[sym_idx].st_name;
                        if (strlen(sym_name) == 0) continue;

                        unsigned int final_va = 0;
                        unsigned short shndx = syms[sym_idx].st_shndx;
                        
                        if (shndx < ehdr->e_shnum) {
                            char* target_sec_name = shstrtab + shdrs[shndx].sh_name;
                            if (strcmp(target_sec_name, ".text") == 0) {
                                final_va = text_base_va + obj_text_offsets[i] + syms[sym_idx].st_value;
                            } else if (strcmp(target_sec_name, ".data") == 0) {
                                final_va = data_base_va + obj_data_offsets[i] + syms[sym_idx].st_value;
                            }
                        }

                        if (final_va > 0 && global_sym_count < MAX_GLOBAL_SYMBOLS) {
                            strcpy(symbol_table[global_sym_count].name, sym_name);
                            symbol_table[global_sym_count].final_va = final_va;
                            symbol_table[global_sym_count].source_sec_idx = shndx;
                            global_sym_count++;
                        }
                    }
                }
            }
        }
    }

    // ==========================================
    // PASS 3: RESOLVE LINUX RELOCATION SYMBOLS
    // ==========================================
    for (int i = 0; i < num_objs; i++) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)obj_buffers[i];
        Elf32_Shdr* shdrs = (Elf32_Shdr*)(obj_buffers[i] + ehdr->e_shoff);
        char* shstrtab = (char*)(obj_buffers[i] + shdrs[ehdr->e_shstrndx].sh_offset);

        unsigned int text_base_va = target_image_base + 0x1000;
        unsigned int data_base_va = text_base_va + ELF_SECTION_ALIGN(current_text_size, 0x1000);

        for (int s = 0; s < ehdr->e_shnum; s++) {
            if (shdrs[s].sh_type == 9) {
                Elf32_Shdr* target_sec = &shdrs[shdrs[s].sh_info];
                if (strcmp(shstrtab + target_sec->sh_name, ".text") != 0) continue;

                Elf32_Rel* relocs = (Elf32_Rel*)(obj_buffers[i] + shdrs[s].sh_offset);
                int num_relocs = shdrs[s].sh_size / sizeof(Elf32_Rel);

                Elf32_Shdr* symtab_sec = &shdrs[shdrs[s].sh_link];
                Elf32_Sym* syms = (Elf32_Sym*)(obj_buffers[i] + symtab_sec->sh_offset);
                char* strtab = (char*)(obj_buffers[i] + shdrs[symtab_sec->sh_link].sh_offset);

                for (int r = 0; r < num_relocs; r++) {
                    int sym_idx = relocs[r].r_info >> 8;
                    int type = relocs[r].r_info & 0xFF;
                    char* sym_name = strtab + syms[sym_idx].st_name;

                    unsigned int target_va = 0;
                    int found = 0; // FIXED: Swapped BOOL for standard integer logic

                    for (int g = 0; g < global_sym_count; g++) {
                        if (strcmp(symbol_table[g].name, sym_name) == 0) {
                            target_va = symbol_table[g].final_va;
                            found = 1; break;
                        }
                    }

                    if (!found && syms[sym_idx].st_shndx < ehdr->e_shnum) {
                        char* local_sec = shstrtab + shdrs[syms[sym_idx].st_shndx].sh_name;
                        if (strcmp(local_sec, ".text") == 0) {
                            target_va = text_base_va + obj_text_offsets[i] + syms[sym_idx].st_value;
                        } else if (strcmp(local_sec, ".data") == 0) {
                            target_va = data_base_va + obj_data_offsets[i] + syms[sym_idx].st_value;
                        }
                    }

                    unsigned int patch_file_offset = obj_text_offsets[i] + relocs[r].r_offset;
                    
                    if (type == 1) { 
                        unsigned int base_addend = 0;
                        memcpy(&base_addend, aggregated_text + patch_file_offset, 4);
                        unsigned int final_patch_value = target_va + base_addend;
memcpy(aggregated_text + patch_file_offset, &final_patch_value, 4); // FIXED: Corrected destination identifier key name
}
else if (type == 2) {
unsigned int base_addend = 0;
memcpy(&base_addend, aggregated_text + patch_file_offset, 4);
unsigned int current_instruction_va = text_base_va + patch_file_offset;
unsigned int displacement = target_va + base_addend - current_instruction_va;
memcpy(aggregated_text + patch_file_offset, &displacement, 4);
}
}
}
}
}
// ==========================================
// PASS 4: EMIT COMPILED NATIVE LINUX ELF BINARY
// ==========================================
unsigned int text_rva = 0x1000;
unsigned int data_rva = text_rva + ELF_SECTION_ALIGN(current_text_size, 0x1000);
unsigned int size_of_elf_headers = sizeof(Elf32_Ehdr) + (sizeof(Elf32_Phdr) * 2);
unsigned int text_file_offset = ELF_SECTION_ALIGN(size_of_elf_headers, 0x1000);
unsigned int data_file_offset = text_file_offset + ELF_SECTION_ALIGN(current_text_size, 0x1000);
unsigned int entry_point_va = target_image_base + text_rva;
for (int i = 0; i < global_sym_count; i++) {
if (strcmp(symbol_table[i].name, "_start") == 0) {
entry_point_va = symbol_table[i].final_va; break;
}
}
FILE* f_out = fopen(out_filename, "wb");
if (!f_out) { printf("[Error] Cannot write output file.\n"); return 1; }
Elf32_Ehdr ehdr = {0};
memcpy(ehdr.e_ident, "\x7F\x45\x4C\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
ehdr.e_type = 2;
ehdr.e_machine = 3;
ehdr.e_version = 1;
ehdr.e_entry = entry_point_va;
ehdr.e_phoff = sizeof(Elf32_Ehdr);
ehdr.e_shoff = 0;
ehdr.e_ehsize = sizeof(Elf32_Ehdr);
ehdr.e_phentsize = sizeof(Elf32_Phdr);
ehdr.e_phnum = 2;
fwrite(&ehdr, 1, sizeof(Elf32_Ehdr), f_out);
Elf32_Phdr ph_text = {0};
ph_text.p_type = 1;
ph_text.p_offset = 0;
ph_text.p_vaddr = target_image_base;
ph_text.p_paddr = target_image_base;
ph_text.p_filesz = text_file_offset + current_text_size;
ph_text.p_memsz = ph_text.p_filesz;
ph_text.p_flags = 5;
ph_text.p_align = 0x1000;
fwrite(&ph_text, 1, sizeof(Elf32_Phdr), f_out);
Elf32_Phdr ph_data = {0};
ph_data.p_type = 1;
ph_data.p_offset = data_file_offset;
ph_data.p_vaddr = target_image_base + data_rva;
ph_data.p_paddr = ph_data.p_vaddr;
ph_data.p_filesz = current_data_size;
ph_data.p_memsz = ph_data.p_filesz;
ph_data.p_flags = 6;
ph_data.p_align = 0x1000;
fwrite(&ph_data, 1, sizeof(Elf32_Phdr), f_out);
long current_pos = ftell(f_out);
for (int i = 0; i < (int)(text_file_offset - current_pos); i++) fputc(0, f_out);
fwrite(aggregated_text, 1, current_text_size, f_out);
current_pos = ftell(f_out);
for (int i = 0; i < (int)(data_file_offset - current_pos); i++) fputc(0, f_out);
fwrite(aggregated_data, 1, current_data_size, f_out);
fclose(f_out);
printf("[Success] Native Linux ELF executable successfully cross-linked -> %s\n", out_filename);
for (int i = 0; i < num_objs; i++) free(obj_buffers[i]);
free(aggregated_data); free(aggregated_text);
return 0;
}
