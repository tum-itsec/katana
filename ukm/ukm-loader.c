/* Compile with
 *   gcc -I. -nostdlib -Wl,-e_start ukm-loader.c xz/xz.a -o loader
 * -nostdlib: turn this into a statically-compiled standalone binary
 * -Wl,-e_start: use _start as the entry point (default on x86, but not on MIPS)
 *
 * Build the kernel module before building this loader.
 * You may need to run ./fetch-deps.sh beforehand.
 *
 * Usage:
 *   ./loader [argument string] [reference module or search path]
 * The default argument string is just the empty string. If no reference module
 * is specified, this loader defaults to searching /lib/modules/$(uname -r).
 */

#include <ukm-arch.h>
#include <ukm-lib.c>
#include <ukm-shared.h>

#if !defined(DISABLE_XZ)
	#include <xz/xz.c> /* This works around an odd linker issue */
#endif
#if !defined(DISABLE_GZ)
	#pragma GCC message "GZIP support is not yet implemented, but not disabled."
#endif

/* Loader configuration */
#if !defined(KOBJECT)
	#define KOBJECT "ukm.ko"
#endif
#if !defined(MODULE_NAME)
	#define MODULE_NAME "ukm"
#endif
#if !defined(THIS_MODULE_EXTRA_SPACE)
	/* This should be larger than common sizes of struct module, otherwise
	 * the kernel will likely segfault during load
	 */
	#define THIS_MODULE_EXTRA_SPACE 1024
#endif
#if !defined(MODINFO_EXTRA_SPACE)
	#define MODINFO_EXTRA_SPACE 512
#endif
#if !defined(QUIET)
	#define println(message) do { print(message); write(2, "\n", 1); } while (0)
	#define print(message) write(2, message, __builtin_strlen(message))
#else
	#define println(message) do {} while (0)
	#define print(message) do {} while (0)
#endif

#define int_to_string(number, buffer, size) ({ \
	/* This is a macro only in order to support numbers of arbitrary type */ \
	char *num = (buffer); \
	typeof(size) sznum = (size); \
	__builtin_memset(num, 0, sznum); \
	typeof(number) copy, orig; \
	copy = orig = (number); \
	int index = sznum - 2; \
	if (copy < 0) \
		copy = -copy; \
	do { \
		num[index--] = (copy % 10) + '0'; \
		copy /= 10; \
	} while (index >= 1 && copy); \
	if (orig < ((typeof(number)) 0)) \
		num[index--] = '-'; \
	if (copy) \
		__builtin_memcpy(num, "Number too long", sizeof("Number too long")); \
	else if (index > -1) \
		__builtin_memmove(num, &num[index + 1], sznum - (index + 1)); \
	buffer; \
})

/* Stored kernel module with additional space */
asm (
	".section .data\n"
	".global data\n"
	".type data STT_OBJECT\n"
	"data:\n"
	"        .incbin \"" KOBJECT "\"\n"
	".p2align 6\n" /* Ensure proper alignment of this_module */
	".global extra_space\n"
	".type extra_space STT_OBJECT\n"
	"extra_space:\n"
	"        .skip " STRINGIFY(THIS_MODULE_EXTRA_SPACE) "\n"
	".p2align 2\n"
	".global modinfo_space\n"
	".type modinfo_space STT_OBJECT\n"
	"modinfo_space:\n"
	"        .skip " STRINGIFY(MODINFO_EXTRA_SPACE) "\n"
	".global length\n"
	".type length STT_OBJECT\n"
	"length:\n"
	"        .long (length - data)\n"
);
extern char data, extra_space, modinfo_space;
extern long length;

static char *image = &data;

/* Miscellaneous */
void put_zero_terminated_release(char *buffer, unsigned long max_length)
{
	struct utsname u = {0};
	int error = uname(&u);
	if (error != 0)
		die(error, "Failed to query uname");

	unsigned long length = __builtin_strlen(u.release);
	if (length >= UTS_ENTRY_SIZE || length >= max_length - 1)
		die(-28, "Release name is too large");

	__builtin_memcpy(buffer, u.release, length + 1);
}

/* A primitive ELF parser */
#define _READ_AT(ptr, index, otype, shift) (((otype) *(((const unsigned char *) (ptr)) + (index))) << (shift))
#define READ_ANY8(ptr) (_READ_AT(ptr, 0, unsigned char, 0))
#define READ_LE16(ptr) (_READ_AT(ptr, 0, uint16_t, 0) | _READ_AT(ptr, 1, uint16_t, 8))
#define READ_BE16(ptr) (_READ_AT(ptr, 0, uint16_t, 8) | _READ_AT(ptr, 1, uint16_t, 0))
#define READ_LE32(ptr) (_READ_AT(ptr, 0, uint32_t, 0) | _READ_AT(ptr, 1, uint32_t, 8) | _READ_AT(ptr, 2, uint32_t, 16) | _READ_AT(ptr, 3, uint32_t, 24))
#define READ_BE32(ptr) (_READ_AT(ptr, 0, uint32_t, 24) | _READ_AT(ptr, 1, uint32_t, 16) | _READ_AT(ptr, 2, uint32_t, 8) | _READ_AT(ptr, 3, uint32_t, 0))
#define READ_LE64(ptr) (_READ_AT(ptr, 0, uint64_t, 0) | _READ_AT(ptr, 1, uint64_t, 8) | _READ_AT(ptr, 2, uint64_t, 16) | _READ_AT(ptr, 3, uint64_t, 24) | _READ_AT(ptr, 4, uint64_t, 32) | _READ_AT(ptr, 5, uint64_t, 40) | _READ_AT(ptr, 6, uint64_t, 48) | _READ_AT(ptr, 7, uint64_t, 56))
#define READ_BE64(ptr) (_READ_AT(ptr, 0, uint64_t, 56) | _READ_AT(ptr, 1, uint64_t, 48) | _READ_AT(ptr, 2, uint64_t, 40) | _READ_AT(ptr, 3, uint64_t, 32) | _READ_AT(ptr, 4, uint64_t, 24) | _READ_AT(ptr, 5, uint64_t, 16) | _READ_AT(ptr, 6, uint64_t, 8) | _READ_AT(ptr, 7, uint64_t, 0))

#define _WRITE_AT(ptr, value, index, otype, shift) ({ *(((unsigned char *) (ptr)) + (index)) = (unsigned char) ((((otype) (value)) >> (shift)) & 0xFF); })
#define WRITE_LE16(ptr, value) ({ _WRITE_AT(ptr, value, 0, uint16_t, 0); _WRITE_AT(ptr, value, 1, uint16_t, 8); })
#define WRITE_BE16(ptr, value) ({ _WRITE_AT(ptr, value, 0, uint16_t, 8); _WRITE_AT(ptr, value, 1, uint16_t, 0); })
#define WRITE_LE32(ptr, value) ({ _WRITE_AT(ptr, value, 0, uint32_t, 0); _WRITE_AT(ptr, value, 1, uint32_t, 8); _WRITE_AT(ptr, value, 2, uint32_t, 16); _WRITE_AT(ptr, value, 3, uint32_t, 24); })
#define WRITE_BE32(ptr, value) ({ _WRITE_AT(ptr, value, 0, uint32_t, 24); _WRITE_AT(ptr, value, 1, uint32_t, 16); _WRITE_AT(ptr, value, 2, uint32_t, 8); _WRITE_AT(ptr, value, 3, uint32_t, 0); })
#define WRITE_LE64(ptr, value) ({ _WRITE_AT(ptr, value, 0, uint64_t, 0); _WRITE_AT(ptr, value, 1, uint64_t, 8); _WRITE_AT(ptr, value, 2, uint64_t, 16); _WRITE_AT(ptr, value, 3, uint64_t, 24); _WRITE_AT(ptr, value, 4, uint64_t, 32); _WRITE_AT(ptr, value, 5, uint64_t, 40); _WRITE_AT(ptr, value, 6, uint64_t, 48); _WRITE_AT(ptr, value, 7, uint64_t, 56); })
#define WRITE_BE64(ptr, value) ({ _WRITE_AT(ptr, value, 0, uint64_t, 56); _WRITE_AT(ptr, value, 1, uint64_t, 48); _WRITE_AT(ptr, value, 2, uint64_t, 40); _WRITE_AT(ptr, value, 3, uint64_t, 32); _WRITE_AT(ptr, value, 4, uint64_t, 24); _WRITE_AT(ptr, value, 5, uint64_t, 16); _WRITE_AT(ptr, value, 6, uint64_t, 8); _WRITE_AT(ptr, value, 7, uint64_t, 0); })

typedef enum { LE32, BE32, LE64, BE64 } elf_type_t;

elf_type_t elf_type(char *image)
{
	/* Determine whether this is a 32- or 64-bit ELF, and its endianness */
	switch (READ_BE16(&image[0x04])) {
		case 0x0101: return LE32;
		case 0x0102: return BE32;
		case 0x0201: return LE64;
		case 0x0202: return BE64;
		default: die(-ENOEXEC, "Invalid ELF file");
	}
}

typedef struct {
	unsigned long e_shoff;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
	uint16_t e_shentsize;
	unsigned long shstrtab_offset;
} elf_header_t;

void parse_elf_header(elf_header_t *into, char *image, elf_type_t type)
{
	/* Find section headers */
	switch (type) {
		case LE32:
			into->e_shoff = READ_LE32(&image[0x20]);
			into->e_shentsize = READ_LE16(&image[0x2e]);
			into->e_shnum = READ_LE16(&image[0x30]);
			into->e_shstrndx = READ_LE16(&image[0x32]);
			break;
		case BE32:
			into->e_shoff = READ_BE32(&image[0x20]);
			into->e_shentsize = READ_BE16(&image[0x2e]);
			into->e_shnum = READ_BE16(&image[0x30]);
			into->e_shstrndx = READ_BE16(&image[0x32]);
			break;
		case LE64:
			into->e_shoff = READ_LE64(&image[0x28]);
			into->e_shentsize = READ_LE16(&image[0x3a]);
			into->e_shnum = READ_LE16(&image[0x3c]);
			into->e_shstrndx = READ_LE16(&image[0x3e]);
			break;
		case BE64:
			into->e_shoff = READ_BE64(&image[0x28]);
			into->e_shentsize = READ_BE16(&image[0x3a]);
			into->e_shnum = READ_BE16(&image[0x3c]);
			into->e_shstrndx = READ_BE16(&image[0x3e]);
			break;
	}

	/* Find section names */
	switch (type) {
		case LE32: into->shstrtab_offset = READ_LE32(&image[into->e_shoff + into->e_shstrndx * into->e_shentsize + 0x10]); break;
		case BE32: into->shstrtab_offset = READ_BE32(&image[into->e_shoff + into->e_shstrndx * into->e_shentsize + 0x10]); break;
		case LE64: into->shstrtab_offset = READ_LE64(&image[into->e_shoff + into->e_shstrndx * into->e_shentsize + 0x18]); break;
		case BE64: into->shstrtab_offset = READ_BE64(&image[into->e_shoff + into->e_shstrndx * into->e_shentsize + 0x18]); break;
	}
}

typedef struct {
	char *raw;
	char *sh_name_ref;
	unsigned long sh_offset;
	unsigned long sh_size;
	uint32_t sh_type;
	uint32_t sh_info;
} elf_section_t;

static void load_section_fields(elf_section_t *into, char *sh, elf_type_t type)
{
	into->raw = sh;
	switch (type) {
		case LE32: into->sh_offset = READ_LE32(&sh[0x10]); into->sh_size = READ_LE32(&sh[0x14]); into->sh_info = READ_LE32(&sh[0x1c]); break;
		case BE32: into->sh_offset = READ_BE32(&sh[0x10]); into->sh_size = READ_BE32(&sh[0x14]); into->sh_info = READ_BE32(&sh[0x1c]); break;
		case LE64: into->sh_offset = READ_LE64(&sh[0x18]); into->sh_size = READ_LE64(&sh[0x20]); into->sh_info = READ_LE32(&sh[0x2c]); break;
		case BE64: into->sh_offset = READ_BE64(&sh[0x18]); into->sh_size = READ_BE64(&sh[0x20]); into->sh_info = READ_BE32(&sh[0x2c]); break;
	}
}

int find_elf_section(elf_section_t *into, const char *name, char *image, elf_type_t type, elf_header_t *header)
{
	int index = 0;
	for (char *sh = &image[header->e_shoff]; sh < &image[header->e_shoff + header->e_shnum * header->e_shentsize]; sh += header->e_shentsize, ++index) {
		uint32_t sh_name_offset = (type == LE32 || type == LE64) ? READ_LE32(sh) : READ_BE32(sh);
		char *sh_name = &image[header->shstrtab_offset + sh_name_offset];

		if (__builtin_strcmp(sh_name, name) == 0) {
			into->sh_type = (type == LE32 || type == LE64) ? READ_LE32(&sh[0x4]) : READ_BE32(&sh[0x4]);
			into->sh_name_ref = sh_name;
			load_section_fields(into, sh, type);
			return index;
		}
	}
	return -1;
}

#define SHT_RELA 4
#define SHT_REL  9
#define SHT_RELR 19 /* The kernel does not process SHT_RELR sections (see apply_relocations in module.c). SHT_RELA sections are hidden behind a config flag, but are possible. */
int find_elf_section_by_type(elf_section_t *into, uint32_t section_type, char *image, elf_type_t type, elf_header_t *header, int start_at)
{
	int index = start_at;
	for (char *sh = &image[header->e_shoff + start_at * header->e_shentsize]; sh < &image[header->e_shoff + header->e_shnum * header->e_shentsize]; sh += header->e_shentsize, ++index) {
		uint32_t sh_type = (type == LE32 || type == LE64) ? READ_LE32(&sh[0x4]) : READ_BE32(&sh[0x4]);

		if (sh_type == section_type) {
			uint32_t sh_name_offset = (type == LE32 || type == LE64) ? READ_LE32(sh) : READ_BE32(sh);
			into->sh_name_ref = &image[header->shstrtab_offset + sh_name_offset];
			load_section_fields(into, sh, type);
			return index;
		}
	}
	return -1;
}

typedef struct {
	char *raw;
	char *st_name_ref;
	unsigned long st_value;
	unsigned long st_size;
	unsigned char st_info;
} elf_symbol_t;

static void load_symbol_fields(elf_symbol_t *into, char *st, elf_type_t type)
{
	into->raw = st;
	switch (type) {
		case LE32: into->st_value = READ_LE32(&st[0x4]); into->st_size = READ_LE32(&st[0x8]); into->st_info = READ_ANY8(&st[0xc]); break;
		case BE32: into->st_value = READ_BE32(&st[0x4]); into->st_size = READ_BE32(&st[0x8]); into->st_info = READ_ANY8(&st[0xc]); break;
		case LE64: into->st_value = READ_LE64(&st[0x8]); into->st_size = READ_LE64(&st[0x10]); into->st_info = READ_ANY8(&st[0x4]); break;
		case BE64: into->st_value = READ_BE64(&st[0x8]); into->st_size = READ_BE64(&st[0x10]); into->st_info = READ_ANY8(&st[0x4]); break;
	}
}

int find_elf_symbol_value(elf_symbol_t *into, const char *name, char *image, elf_type_t type, elf_header_t *header)
{
	elf_section_t symtab, strtab;
	if (find_elf_section(&symtab, ".symtab", image, type, header) < 0)
		die(-ENOEXEC, "No .symtab section");
	if (find_elf_section(&strtab, ".strtab", image, type, header) < 0)
		die(-ENOEXEC, "No .strtab section");

	int index = 0;
	for (char *st = &image[symtab.sh_offset]; st < &image[symtab.sh_offset + symtab.sh_size]; st += (type == LE32 || type == BE32) ? 16 : 24, ++index) {
		uint32_t st_name = (type == LE32 || type == LE64) ? READ_LE32(st) : READ_BE32(st);
		char *st_name_ref = &image[strtab.sh_offset + st_name];

		if (__builtin_strcmp(st_name_ref, name) == 0) {
			into->st_name_ref = st_name_ref;
			load_symbol_fields(into, st, type);
			return index;
		}
	}
	return -1;
}

int find_elf_symbol_value_by_index(elf_symbol_t *into, int index, char *image, elf_type_t type, elf_header_t *header)
{
	elf_section_t symtab, strtab;
	if (find_elf_section(&symtab, ".symtab", image, type, header) < 0)
		die(-ENOEXEC, "No .symtab section");
	if (find_elf_section(&strtab, ".strtab", image, type, header) < 0)
		die(-ENOEXEC, "No .strtab section");

	unsigned long offset = index * ((type == LE32 || type == BE32) ? 16 : 24);
	if (offset > symtab.sh_size)
		return -1;

	char *st = &image[symtab.sh_offset + offset];
	uint32_t st_name = (type == LE32 || type == LE64) ? READ_LE32(st) : READ_BE32(st);
	into->st_name_ref = &image[strtab.sh_offset + st_name];
	load_symbol_fields(into, st, type);
	return index;
}


/* Fixup the kernel module for the current kernel version
 * We would love to use finit_module for this, but it is probably too new
 * Instead, crudely approximate what modprobe --force does (used to do?):
 *   - Rename the __versions section, if it exists
 *   - Replace the vermagic tag name in the .modinfo section
 * We also need to ensure that the .gnu.linkonce.this_module section is large
 * enough to match the kernel version, and that the init and exit function
 * pointers are correctly set after applying relocations.
 */
void fix_init_and_cleanup(elf_section_t *target_section, elf_section_t *relocations, unsigned long relocation_size, unsigned long init_offset, unsigned long cleanup_offset, char *image, elf_type_t type, elf_header_t *header)
{
	/* If there are multiple relocations, we are bound to screw something up... */
	unsigned long relocation_count = relocations->sh_size / relocation_size;

	/* Find relocations against init_module and exit_module */
	for (unsigned long index = 0; index < relocation_count; ++index) {
		uint32_t symbol_index;
		switch (type) {
			case LE32: symbol_index = READ_LE32(&image[relocations->sh_offset + index * relocation_size + 0x4]) >> 8; break;
			case BE32: symbol_index = READ_BE32(&image[relocations->sh_offset + index * relocation_size + 0x4]) >> 8; break;
			case LE64: symbol_index = READ_LE64(&image[relocations->sh_offset + index * relocation_size + 0x8]) >> 32; break;
			case BE64: symbol_index = READ_BE64(&image[relocations->sh_offset + index * relocation_size + 0x8]) >> 32; break;
		}

		elf_symbol_t target_symbol;
		if (find_elf_symbol_value_by_index(&target_symbol, symbol_index, image, type, header) < 0)
			die(-ENOEXEC, "Relocation against nonexistent symbol");

		unsigned long new_offset;
		if (__builtin_strcmp(target_symbol.st_name_ref, "init_module") == 0)
			new_offset = init_offset;
		else if (__builtin_strcmp(target_symbol.st_name_ref, "cleanup_module") == 0)
			new_offset = cleanup_offset;
		else
			continue;

		/* Retarget the relocation to the correct offset */
		switch (type) {
			case LE32: WRITE_LE32(&image[relocations->sh_offset + index * relocation_size], new_offset); break;
			case BE32: WRITE_BE32(&image[relocations->sh_offset + index * relocation_size], new_offset); break;
			case LE64: WRITE_LE64(&image[relocations->sh_offset + index * relocation_size], new_offset); break;
			case BE64: WRITE_BE64(&image[relocations->sh_offset + index * relocation_size], new_offset); break;
		}
	}
}

int patch_image(unsigned long init_offset, unsigned long cleanup_offset, const char *vermagic, const char *args)
{
	elf_type_t type;
	elf_header_t header;
	elf_section_t section, relocations;

	type = elf_type(image);
	parse_elf_header(&header, image, type);

	/* Rename __versions */
	println("Renaming __versions...");
	if (find_elf_section(&section, "__versions", image, type, &header) >= 0)
		__builtin_memset(section.sh_name_ref, '_', sizeof("__versions") - 1);

	/* Duplicate .modinfo */
	println("Finding .modinfo and vermagic...");
	if (find_elf_section(&section, ".modinfo", image, type, &header) >= 0) {
		unsigned long vermagic_begin = 0, vermagic_size = 0;
		for (unsigned long position = section.sh_offset; position < section.sh_offset + section.sh_size; position += __builtin_strlen(&image[position]) + 1) {
			if (__builtin_strncmp(&image[position], "vermagic=", sizeof("vermagic=") - 1) == 0) {
				/* Found vermagic */
				vermagic_begin = position - section.sh_offset;
				vermagic_size = __builtin_strlen(&image[position]) + 1;
				break;
			}
		}
		if (vermagic_size) {
			println("Patching vermagic...");
			unsigned long new_offset = &modinfo_space - image;
			unsigned long upto = vermagic_begin + sizeof("vermagic=") - 1;
			unsigned long new_length = __builtin_strlen(vermagic) + 1;
			unsigned long old_length = vermagic_size - (sizeof("vermagic=") - 1);
			long change = new_length - old_length;
			__builtin_memcpy(&image[new_offset], &image[section.sh_offset], upto); /* Copy up to and including "vermagic=" */
			__builtin_memcpy(&image[new_offset + upto], vermagic, new_length); /* Replace the value of vermagic with the correct one for this architecture */
			__builtin_memcpy(&image[new_offset + upto + new_length], &image[section.sh_offset + vermagic_begin + vermagic_size], section.sh_size - vermagic_begin - vermagic_size); /* Copy the rest */

			println("Replacing .modinfo...");
			switch (type) {
				case LE32: WRITE_LE32(&section.raw[0x10], new_offset); WRITE_LE32(&section.raw[0x14], section.sh_size + change); break;
				case BE32: WRITE_BE32(&section.raw[0x10], new_offset); WRITE_BE32(&section.raw[0x14], section.sh_size + change); break;
				case LE64: WRITE_LE64(&section.raw[0x18], new_offset); WRITE_LE64(&section.raw[0x20], section.sh_size + change); break;
				case BE64: WRITE_BE64(&section.raw[0x18], new_offset); WRITE_BE64(&section.raw[0x20], section.sh_size + change); break;
			}
		}
	}

	/* Duplicate and extend this_module */
	int this_module_index;
	if ((this_module_index = find_elf_section(&section, ".gnu.linkonce.this_module", image, type, &header)) >= 0) {
		println("Duplicating this_module...");
		unsigned long new_offset = &extra_space - image;
		__builtin_memcpy(&image[new_offset], &image[section.sh_offset], section.sh_size);
		switch (type) {
			case LE32: WRITE_LE32(&section.raw[0x10], new_offset); WRITE_LE32(&section.raw[0x14], THIS_MODULE_EXTRA_SPACE); break;
			case BE32: WRITE_BE32(&section.raw[0x10], new_offset); WRITE_BE32(&section.raw[0x14], THIS_MODULE_EXTRA_SPACE); break;
			case LE64: WRITE_LE64(&section.raw[0x18], new_offset); WRITE_LE64(&section.raw[0x20], THIS_MODULE_EXTRA_SPACE); break;
			case BE64: WRITE_BE64(&section.raw[0x18], new_offset); WRITE_BE64(&section.raw[0x20], THIS_MODULE_EXTRA_SPACE); break;
		}

		println("Finding relocations...");
		/* Find relocations for this_module */
		for (int section_index = -1; (section_index = find_elf_section_by_type(&relocations, SHT_REL, image, type, &header, section_index + 1)) >= 0;) {
			if (relocations.sh_info != this_module_index)
				continue;
			/* Found a .rel section for this section */
			println("Processing relocation section of type SHT_REL...");
			unsigned long relocation_size = ((type == LE32 || type == BE32) ? 8 : 16);
			fix_init_and_cleanup(&section, &relocations, relocation_size, init_offset, cleanup_offset, image, type, &header);
		}
		for (int section_index = -1; (section_index = find_elf_section_by_type(&relocations, SHT_RELA, image, type, &header, section_index + 1)) >= 0;) {
			if (relocations.sh_info != this_module_index)
				continue;
			/* Found a .rela section for this section */
			println("Processing relocation section of type SHT_RELA...");
			unsigned long relocation_size = ((type == LE32 || type == BE32) ? 12 : 24);
			fix_init_and_cleanup(&section, &relocations, relocation_size, init_offset, cleanup_offset, image, type, &header);
		}
	}

	/* Replace the special UKM argument section, if it is present. See ukm-shared.h for more detail. */
	if (find_elf_section(&section, UKM_ARG_SECTION, image, type, &header) >= 0) {
		unsigned long occurrences = section.sh_size / MAX_ARG_LENGTH;
		for (unsigned long pos = 0; pos + MAX_ARG_LENGTH <= section.sh_size; pos += MAX_ARG_LENGTH) {
			__builtin_memcpy(&image[section.sh_offset + pos], args, __builtin_strlen(args) + 1);
		}
	}

	/* Since there is no easy way to get the kernel version in the module (without relying on hardcoded
	 * offsets courtesy of kernel/version.c or include/linux/utsname.h), we also have a section for the
	 * kernel version if the module requests it.
	 */
	if (find_elf_section(&section, UKM_KERNEL_VERSION_SECTION, image, type, &header) >= 0) {
		char uname_buffer[UTS_ENTRY_SIZE];
		put_zero_terminated_release(uname_buffer, UTS_ENTRY_SIZE);
		uint32_t segments[3], current = 0;
		for (unsigned segment = 0, position = 0; segment < 3; ++position) {
			if (uname_buffer[position] < '0' || uname_buffer[position] > '9') {
				segments[segment++] = current;
				current = 0;
			} else {
				current *= 10;
				current += uname_buffer[position] - '0';
			}
			if (uname_buffer[position] == 0)
				break;
		}
		struct ukm_kernel_version version = { .major = segments[0], .minor = segments[1], .patch = segments[2] };
		char conv_buf[20];
		print("Detected kernel version ");
		print(int_to_string(version.major, conv_buf, sizeof(conv_buf)));
		print(".");
		print(int_to_string(version.minor, conv_buf, sizeof(conv_buf)));
		print(".");
		print(int_to_string(version.patch, conv_buf, sizeof(conv_buf)));
		print("\n");
		unsigned long occurrences = section.sh_size / UKM_KERNEL_VERSION_SPACE;
		for (unsigned long pos = 0; pos + UKM_KERNEL_VERSION_SPACE <= section.sh_size; pos += UKM_KERNEL_VERSION_SPACE) {
			__builtin_memcpy(&image[section.sh_offset + pos], &version, sizeof(struct ukm_kernel_version));
		}
	}
	return 0;
}

/* Detect settings for the fixup */
#define NO_OFFSET -1
void detect_init_and_cleanup(unsigned long *init_offset, unsigned long *cleanup_offset, elf_section_t *relocations, unsigned long relocation_size, char *image, elf_type_t type, elf_header_t *header)
{
	unsigned long relocation_count = relocations->sh_size / relocation_size;
	for (unsigned long index = 0; index < relocation_count; ++index) {
		uint32_t symbol_index;
		unsigned long offset;
		switch (type) {
			case LE32: symbol_index = READ_LE32(&image[relocations->sh_offset + index * relocation_size + 0x4]) >> 8;  offset = READ_LE32(&image[relocations->sh_offset + index * relocation_size]); break;
			case BE32: symbol_index = READ_BE32(&image[relocations->sh_offset + index * relocation_size + 0x4]) >> 8;  offset = READ_BE32(&image[relocations->sh_offset + index * relocation_size]); break;
			case LE64: symbol_index = READ_LE64(&image[relocations->sh_offset + index * relocation_size + 0x8]) >> 32; offset = READ_LE64(&image[relocations->sh_offset + index * relocation_size]); break;
			case BE64: symbol_index = READ_BE64(&image[relocations->sh_offset + index * relocation_size + 0x8]) >> 32; offset = READ_BE64(&image[relocations->sh_offset + index * relocation_size]); break;
		}

		elf_symbol_t target_symbol;
		if (find_elf_symbol_value_by_index(&target_symbol, symbol_index, image, type, header) < 0)
			die(-ENOEXEC, "Relocation against nonexistent symbol");

		unsigned long new_offset;
		if (__builtin_strcmp(target_symbol.st_name_ref, "init_module") == 0) {
			if (*init_offset != NO_OFFSET)
				die(-ENOEXEC, "Multiple relocations against init_module");
			*init_offset = offset;
		} else if (__builtin_strcmp(target_symbol.st_name_ref, "cleanup_module") == 0) {
			if (*cleanup_offset != NO_OFFSET)
				die(-ENOEXEC, "Multiple relocations against cleanup_module");
			*cleanup_offset = offset;
		}
	}
}

int is_directory(const char *path)
{
	int fd = openat(AT_FDCWD, path, O_RDONLY | O_DIRECTORY, 0);
	if (fd == -ENOTDIR)
		return 0;
	if (fd < 0)
		die(fd, "Failed to open file or directory");
	close(fd);
	return 1;
}

char *load_valid_module_from(int parent_fd, const char *path, char *(*callback)(int, const char *))
{
	char dent_buf[1024];
	struct linux_dirent64 *dir;
	char *result = 0;

	int fd = openat(parent_fd, path, O_RDONLY | O_DIRECTORY, 0);
	if (fd == -ENOTDIR)
		return result;
	if (fd < 0) {
		print("Failed reading ");
		print(path);
		print("\n");
		return result;
	}

	for (;;) {
		int bytes = getdents64(fd, (struct linux_dirent64 *) dent_buf, sizeof(dent_buf));
		if (bytes < 0)
			die(bytes, "Failed to read directory");
		if (bytes == 0)
			goto done;
		for (int pos = 0; pos < bytes;) {
			dir = (struct linux_dirent64 *) (dent_buf + pos);
			pos += dir->d_reclen;
			if (__builtin_strcmp(dir->d_name, ".") == 0 || __builtin_strcmp(dir->d_name, "..") == 0 || __builtin_strlen(dir->d_name) == 0)
				continue;
			if (dir->d_type == DT_DIR || dir->d_type == DT_UNKNOWN)
				if ((result = load_valid_module_from(fd, dir->d_name, callback)))
					goto done;
			if (dir->d_type == DT_REG || dir->d_type == DT_UNKNOWN)
				if ((result = callback(fd, dir->d_name)))
					goto done;
		}
	}

done:
	close(fd);
	return result;
}

char *load_module(int parent_fd, const char *filename)
{
	int fd = -1;

#define load_error(message) do { print("Failed to load module "); print(filename); print(": "); print(message); print("\n"); if (fd >= 0) close(fd); return 0; } while (0)

	/* Check the file extension */
	unsigned long length = __builtin_strlen(filename);
	enum { NONE, XZ, GZ } transform;
	if (!length)
		load_error("Invalid argument");
#if !defined(DISABLE_XZ)
	else if (length > 6 && __builtin_strcmp(&filename[length - 6], ".ko.xz") == 0)
		transform = XZ;
#endif
	else if (length > 3 && __builtin_strcmp(&filename[length - 3], ".ko") == 0)
		transform = NONE;
	else
		load_error("Not a recognized file format");

	/* Read the file at brk */
	fd = openat(parent_fd, filename, O_RDONLY, 0);
	if (fd < 0)
		load_error("Could not open module file");

	unsigned long begin = brk(0);
	unsigned long end = brk(begin + 1024);
	unsigned long available = 1024;
	char *current = (char *) begin;

	for (;;) {
		long bytes = read(fd, current, available);
		if (bytes < 0)
			load_error("Read failed");
		if (bytes == 0)
			break;
		available -= bytes;
		current += bytes;
		if (available == 0) {
			end = brk(end + 1024);
			available = 1024;
		}
	}

	print("Loaded ");
	print(filename);
	print("\n");

	close(fd);
	fd = -1;

	/* Uncompress the file if necessary */
	switch (transform) {
#if !defined(DISABLE_XZ)
		case XZ: {
			/* We don't know the real size of the file, so we need
			 * some carefully placed calls to brk to get memory.
			 * Make sure those happen after xz_dec_init, which calls
			 * brk itself. This is static, so we don't allocate twice.
			 */
			static struct xz_dec *dec = 0;
			if (dec == 0)
				dec = xz_dec_init(XZ_SINGLE, 0);
			unsigned long out_start = brk(0);
			unsigned long in_size = (unsigned long) current - begin;
			for (unsigned factor = 2;; ++factor) {
				unsigned long out_size = in_size * factor;
				unsigned long out_end = brk(out_start + out_size);
				if (out_end > (unsigned long) -4096)
					die(-ENOMEM, "Out of memory");

				struct xz_buf xzb = {
					.in = (const uint8_t *) begin,
					.in_pos = 0,
					.in_size = in_size,
					.out = (uint8_t *) out_start,
					.out_pos = 0,
					.out_size = out_size
				};
				enum xz_ret result = xz_dec_run(dec, &xzb);
				switch (result) {
					case XZ_STREAM_END:
						return (char *) out_start;
					case XZ_FORMAT_ERROR:
						load_error("Invalid format");
					case XZ_OPTIONS_ERROR:
						load_error("Format not supported");
					case XZ_DATA_ERROR:
						load_error("File is corrupt");
					case XZ_BUF_ERROR:
						/* Input buffer was too small, retry */
						continue;
					case XZ_OK:
					case XZ_MEM_ERROR:
					case XZ_MEMLIMIT_ERROR:
					case XZ_UNSUPPORTED_CHECK:
						load_error("xz_dec_run returned (allegedly impossible) status");
				}
			}

			load_error("Module is too large");
		}
#endif
		case NONE:
			return (char *) begin;
#if defined(DISABLE_XZ)
		default:
			load_error("Module uses an unimplemented compression scheme");
#endif
	}
}

int detect_settings(char *reference_image, unsigned long *init_offset, unsigned long *cleanup_offset, char *vermagic)
{

	elf_type_t type;
	elf_header_t header;
	elf_section_t section, relocations;

	type = elf_type(reference_image);
	parse_elf_header(&header, reference_image, type);

	/* Find relocation offsets for this_module */
	*init_offset = NO_OFFSET;
	*cleanup_offset = NO_OFFSET;

	int this_module_index;
	if ((this_module_index = find_elf_section(&section, ".gnu.linkonce.this_module", reference_image, type, &header)) >= 0) {
		for (int section_index = -1; (section_index = find_elf_section_by_type(&relocations, SHT_REL, reference_image, type, &header, section_index + 1)) >= 0;) {
			if (relocations.sh_info != this_module_index)
				continue;
			println("Processing relocation section of type SHT_REL...");
			unsigned long relocation_size = ((type == LE32 || type == BE32) ? 8 : 16);
			detect_init_and_cleanup(init_offset, cleanup_offset, &relocations, relocation_size, reference_image, type, &header);
		}
		for (int section_index = -1; (section_index = find_elf_section_by_type(&relocations, SHT_RELA, reference_image, type, &header, section_index + 1)) >= 0;) {
			if (relocations.sh_info != this_module_index)
				continue;
			println("Processing relocation section of type SHT_RELA...");
			unsigned long relocation_size = ((type == LE32 || type == BE32) ? 12 : 24);
			detect_init_and_cleanup(init_offset, cleanup_offset, &relocations, relocation_size, reference_image, type, &header);
		}
	} else {
		die(-ENOEXEC, "No .gnu.linkonce.this_module section");
	}
	if (*init_offset == NO_OFFSET)
		die(-ENOEXEC, "No this_module relocation against init_module");
	if (*cleanup_offset == NO_OFFSET)
		die(-ENOEXEC, "No this_module relocation against cleanup_module");

	/* Find vermagic */
	if (find_elf_section(&section, ".modinfo", reference_image, type, &header) >= 0) {
		unsigned long vermagic_position = -1;
		for (unsigned long position = section.sh_offset; position < section.sh_offset + section.sh_size; position += __builtin_strlen(&reference_image[position]) + 1) {
			if (__builtin_strncmp(&reference_image[position], "vermagic=", sizeof("vermagic=") - 1) == 0) {
				vermagic_position = position + sizeof("vermagic=") - 1;
				break;
			}
		}

		if (vermagic_position == -1)
			die(-ENOEXEC, "No vermagic found in .modinfo");

		__builtin_memcpy(vermagic, &reference_image[vermagic_position], __builtin_strlen(&reference_image[vermagic_position]));
	} else {
		die(-ENOEXEC, "No .modinfo section");
	}

	return 0;
}

/* Main */
typedef enum { EMPTY, OK, TRUNCATED } arg_state_t;
arg_state_t get_argv(char *buffer, unsigned long size, unsigned int index)
{
	/* Try to read the reference module path from /proc/self/cmdline. This avoids some magic foo with %rsp / $sp in _start to read the arguments because we have no libc. */
	int cmdline_fd = openat(AT_FDCWD, "/proc/self/cmdline", O_RDONLY, 0);
	if (cmdline_fd < 0)
		die(cmdline_fd, "Failed to open /proc/self/cmdline");

	/* argv[0] goes up to the first NUL */
	__builtin_memset(buffer, 0, size);

	long cmdline_bytes = read(cmdline_fd, buffer, size - 1);
	if (cmdline_bytes < 0)
		die(cmdline_bytes, "Failed to read /proc/self/cmdline");
	if (cmdline_bytes == 0) {
		close(cmdline_fd);
		return EMPTY; /* No such argument */
	}

	/* See if we already have the start of the argument */
	unsigned long next_size;
	for (unsigned int arg = 0; arg <= index; ++arg) {
retry:
		next_size = __builtin_strlen(buffer);
		if (next_size < cmdline_bytes) {
			if (arg == index) {
				close(cmdline_fd);
				return OK;
			}
			/* Complete argument, skip it */
			__builtin_memmove(buffer, &buffer[next_size + 1], cmdline_bytes - next_size - 1);
			__builtin_memset(&buffer[cmdline_bytes - next_size - 1], 0, next_size + 1);
			cmdline_bytes -= next_size + 1;
			if (cmdline_bytes == 0) {
				/* Read more. */
				__builtin_memset(buffer, size, 0);
				cmdline_bytes = read(cmdline_fd, buffer, size - 1);
				if (cmdline_bytes < 0)
					die(cmdline_bytes, "Failed to read /proc/self/cmdline");
				if (cmdline_bytes == 0) {
					close(cmdline_fd);
					return EMPTY;
				}
			}
			continue;
		} else {
			/* Argument is potentially truncated, read additional bytes if the buffer supports it */
			if (arg == index) {
				/* Preserve existing data */
				if (next_size < size - 1) {
					long update = read(cmdline_fd, buffer + next_size, size - 1 - next_size /* Overwrite the dummy zero, but keep one at the end */);
					if (update < 0)
						die(update, "Failed to read /proc/self/cmdline");
					if (update == 0) {
						close(cmdline_fd);
						return (arg >= index) ? TRUNCATED : EMPTY;
					}
					cmdline_bytes += update;
					goto retry;
				} else {
					close(cmdline_fd);
					return (arg >= index) ? TRUNCATED : EMPTY;
				}
			} else {
				/* Discard the current truncated argument and retry */
				__builtin_memset(buffer, size, 0);
				cmdline_bytes = read(cmdline_fd, buffer, size - 1);
				if (cmdline_bytes < 0)
					die(cmdline_bytes, "Failed to read /proc/self/cmdline");
				if (cmdline_bytes == 0) {
					close(cmdline_fd);
					return EMPTY;
				}
				goto retry;
			}
		}
	}

	die(1, "Read past argv[index]");
}

#define PATH_MAX 4096
__attribute__((noreturn))
void _start(void)
{
	int error;

#if !defined(DISABLE_XZ)
	xz_crc32_init();
	xz_crc64_init();
#endif

	unsigned long init_offset, cleanup_offset;
	char vermagic[MODINFO_EXTRA_SPACE];
	__builtin_memset(vermagic, 0, sizeof(vermagic));
	char *reference = 0;

#if !defined(OVERRIDE_INIT_OFFSET) || !defined(OVERRIDE_CLEANUP_OFFSET) || !defined(OVERRIDE_VERMAGIC)
	char arg[PATH_MAX];
	switch (get_argv(arg, sizeof(arg), 2)) {
		case EMPTY: {
			unsigned long skip = __builtin_strlen("/lib/modules/");
			__builtin_memcpy(arg, "/lib/modules/", skip);
			put_zero_terminated_release(&arg[skip], sizeof(arg) - skip);

			print("Searching default path: ");
			print(arg);
			print("\n");
			break;
		}
		case TRUNCATED:
			die(0, "Search path is truncated!");
			break;
		case OK:
			break;
	}

	if (is_directory(arg)) {
		print("Finding reference module in "); print(arg); print("\n");
		reference = load_valid_module_from(AT_FDCWD, arg, load_module);
	} else {
		println("Loading reference module...");
		reference = load_module(AT_FDCWD, arg);
	}

	if (!reference)
		die(-ENOEXEC, "Failed to load reference module");

	println("Detecting settings...");
	if ((error = detect_settings(reference, &init_offset, &cleanup_offset, vermagic)) < 0)
		die(error, "Failed to detect settings");
#endif
#if defined(OVERRIDE_INIT_OFFSET)
	init_offset = OVERRIDE_INIT_OFFSET;
#endif
#if defined(OVERRIDE_CLEANUP_OFFSET)
	cleanup_offset = OVERRIDE_CLEANUP_OFFSET;
#endif
#if defined(OVERRIDE_VERMAGIC)
	__builtin_memset(vermagic, 0, sizeof(vermagic))
	__builtin_memcpy(vermagic, OVERRIDE_VERMAGIC, __builtin_strlen(OVERRIDE_VERMAGIC));
#endif

	char buffer[20];
	println("Found offsets:");
	print("    init_offset    "); print(int_to_string(init_offset, buffer, sizeof(buffer))); print("\n");
	print("    cleanup_offset "); print(int_to_string(cleanup_offset, buffer, sizeof(buffer))); print("\n");
	print("    vermagic       "); print(vermagic); print("\n");

#if defined(OVERRIDE_MODULE_ARGS)
	const char *module_arg = OVERRIDE_MODULE_ARGS;
	if (__builtin_strlen(module_arg) + 1 > MAX_ARG_LENGTH)
		die(-E2BIG, "Module argument string too long, try increasing MAX_ARG_LENGTH");
#else
	char module_arg[MAX_ARG_LENGTH];
	__builtin_memset(module_arg, 0, sizeof(module_arg));
	switch (get_argv(module_arg, sizeof(module_arg), 1)) {
		case EMPTY: module_arg[0] = 0; break;
		case TRUNCATED: die(-E2BIG, "Module argument string too long, try increasing MAX_ARG_LENGTH"); break;
		case OK: break;
	}
#endif

	println("Patching image...");
	if ((error = patch_image(init_offset, cleanup_offset, vermagic, module_arg)) < 0)
		die(error, "Failed to patch image");
#if defined(DUMP_PATCHED_IMAGE)
	println("Dumping image...");
	write(1, image, length);
#endif
#if !defined(DRY_RUN)
	println("Loading module...");
#if !defined(PASS_INIT_MODULE_ARGS)
	/* The different layouts of struct kernel_param mean that we cannot really
	 * pass normal arguments to a UKM loaded this way. Instead, we pass the
	 * arguments in a special section in the binary if it is present. This
	 * allows us to keep it easily accessible from the kernel without having
	 * to deal with mangling by any kind of processing. If you want to pass
	 * arguments to init_module directly anyways, use this flag, but things
	 * may break badly. You have been warned! Otherwise, the arguments will
	 * remain empty and only the patching method will be used.
	 */
	module_arg[0] = 0;
#else
	println("Passing arguments directly to init_module!");
#endif
	if ((error = init_module(image, (unsigned long) length, module_arg)) < 0)
		die(error, "Failed to load module");
	println("Done loading module...");
#if defined(UNLOAD_MODULE)
	println("Unloading module...");
	if ((error = delete_module(MODULE_NAME, 0)) < 0)
		die(error, "Failed to remove module");
	println("Done unloading module...");
#endif
#endif
	exit(0);
}
