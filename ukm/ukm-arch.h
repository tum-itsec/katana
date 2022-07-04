#ifndef __UKM_ARCH_H__
#define __UKM_ARCH_H__

/* Integer types */
#if defined(__x86_64__)
	#define uint8_t unsigned char
	#define uint16_t unsigned short
	#define uint32_t unsigned int
	#define uint64_t unsigned long
	#define int8_t signed char
	#define int16_t signed short
	#define int32_t signed int
	#define int64_t signed long
#elif defined(__i386__)
	#define uint8_t unsigned char
	#define uint16_t unsigned short
	#define uint32_t unsigned int
	#define uint64_t unsigned long long
	#define int8_t signed char
	#define int16_t signed short
	#define int32_t signed int
	#define int64_t signed long long
#elif defined(__aarch64__)
	#define uint8_t unsigned char
	#define uint16_t unsigned short
	#define uint32_t unsigned int
	#define uint64_t unsigned long
	#define int8_t signed char
	#define int16_t signed short
	#define int32_t signed int
	#define int64_t signed long
#elif defined(__mips__)
	#define uint8_t unsigned char
	#define uint16_t unsigned short
	#define uint32_t unsigned int
	#define uint64_t unsigned long long
	#define int8_t signed char
	#define int16_t signed short
	#define int32_t signed int
	#define int64_t signed long long
#else
	#error "Unsupported architecture - integer types not definedd!"
#endif

typedef char bool;
#define FALSE ((bool)0)
#define TRUE ((bool)1)
#define true TRUE
#define false FALSE


/* Syscall implementations */
#if defined(__x86_64__)
	#define _syscall_asm \
		"movq %[number], %%rax\n" \
		"movq %[a1], %%rdi\n" \
		"movq %[a2], %%rsi\n" \
		"movq %[a3], %%rdx\n" \
		"movq %[a4], %%r10\n" \
		"syscall\n" \
		"movq %%rax, %[result]\n"
	#define _syscall_clobber "rax", "rdi", "rsi", "rdx", "rcx", "r10", "r11", "cc", "memory"
	#define __NR_brk 12
	#define __NR_close 3
	#define __NR_exit 60
	#define __NR_delete_module 176
	#define __NR_getdents64 217
	#define __NR_init_module 175
	#define __NR_openat 257
	#define __NR_read 0
	#define __NR_uname 63
	#define __NR_write 1
#elif defined(__i386__)
	#define _syscall_asm
		"movl %[number], %%eax\n" \
		"movl %[a1], %%ebx\n" \
		"movl %[a2], %%ecx\n" \
		"movl %[a3], %%edx\n" \
		"movl %[a4], %%esi\n" \
		"int $0x80\n" \
		"movl %%eax, %[result];"
	#define _syscall_clobber "eax", "ebx", "ecx", "edx", "esi", "cc", "memory"
	#define __NR_brk 45
	#define __NR_close 6
	#define __NR_delete_module 129
	#define __NR_exit 1
	#define __NR_getdents64 220
	#define __NR_init_module 128
	#define __NR_openat 295
	#define __NR_read 3
	#define __NR_uname 122
	#define __NR_write 4
#elif defined(__mips__) /* for both __MIPSEB__ and __MIPSEL__, but not MIPS64. This is the o32 ABI. */
	/* Some demented person thought that it might be a good idea to return
	 * _positive_ values alongside the error flag so that all our normal
	 * checks don't work. We revert that.
	 * (Another one came up with the idea that GCC's inline assembler should
	 * pad all delay slots with NOPs, so that is why you won't find any below)
	 */
	#define _syscall_asm \
		"li $v0, %[number]\n" \
		"move $a0, %[a1]\n" \
		"move $a1, %[a2]\n" \
		"move $a2, %[a3]\n" \
		"move $a3, %[a4]\n" \
		"syscall\n" \
		"move %[result], $v0\n" \
		"beqz $a3, %=f\n" \
		"blez %[result], %=f\n" \
		"negu %[result]\n" \
		"%=:"
	#define _syscall_clobber \
		"v0", "v1", "a0", "a1", "a2", "a3", "at", "t0", "t1", "t2", \
		"t3", "t4", "t5", "t6", "t7", "t8", "t9", "hi", "lo", "memory"
	#define __NR_brk 4045
	#define __NR_close 4006
	#define __NR_delete_module 4129
	#define __NR_exit 4001
	#define __NR_getdents64 4219
	#define __NR_init_module 4128
	#define __NR_openat 4288
	#define __NR_read 4003
	#define __NR_uname 4122
	#define __NR_write 4004
#elif defined(__aarch64__)
	#define _syscall_asm \
		"mov w8, %[number]\n" \
		"mov x0, %[a1]\n" \
		"mov x1, %[a2]\n" \
		"mov x2, %[a3]\n" \
		"mov x3, %[a4]\n" \
		"svc #0\n" \
		"mov %[result], x0\n"
	#define _syscall_clobber \
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", \
		"r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", \
		"r29", "r30", "memory"
	#define __NR_brk 214
	#define __NR_close 57
	#define __NR_delete_module 106
	#define __NR_exit 93
	#define __NR_getdents64 61
	#define __NR_init_module 105
	#define __NR_openat 56
	#define __NR_read 63
	#define __NR_uname 160
	#define __NR_write 64
#else
	#error "Unsupported architecture - syscall not implemented!"
#endif

#define syscall(_number, _a1, _a2, _a3, _a4) ({ \
	long result; \
	long _la1 = (long) _a1; \
	long _la2 = (long) _a2; \
	long _la3 = (long) _a3; \
	long _la4 = (long) _a4; \
	asm volatile( \
		_syscall_asm \
		: [result]"=r"(result) \
		: [number]"i"(_number), [a1]"r"(_la1), [a2]"r"(_la2), [a3]"r"(_la3), [a4]"r"(_la4) \
		: _syscall_clobber \
	); \
	result; \
})

#define E2BIG 7
#define ENOEXEC 8
#define ENOMEM 12
#define ENOTDIR 20

static inline unsigned long brk(unsigned long addr)
{
	return (unsigned long) syscall(__NR_brk, addr, 0, 0, 0);
}

static inline int close(int fd)
{
	return (int) syscall(__NR_close, fd, 0, 0, 0);
}

static inline int delete_module(const char *name, int flags)
{
	return (int) syscall(__NR_delete_module, name, flags, 0, 0);
}

__attribute__((noreturn))
static inline void exit(int status)
{
	syscall(__NR_exit, status, 0, 0, 0);
	__builtin_unreachable();
}

#define DT_UNKNOWN 0
#define DT_DIR 4
#define DT_REG 8
struct linux_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static inline int getdents64(int fd, struct linux_dirent64 *dirp, unsigned count)
{
	return (int) syscall(__NR_getdents64, fd, dirp, count, 0);
}

static inline int init_module(void *image, unsigned long len, const char *module_args)
{
	return (int) syscall(__NR_init_module, image, len, module_args, 0);
}

#define AT_FDCWD -100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#if defined(__x86_64__) || defined(__i386__) || defined(__mips__)
	#define O_DIRECTORY 0x10000 /* Different on e.g. ARM */
#elif defined(__aarch64__)
	#define O_DIRECTORY 0x4000
#else
	#error "Unsupported architecture - O_DIRECTORY not defined!"
#endif

static inline int openat(int fd, const char *pathname, int flags, unsigned mode)
{
	return (int) syscall(__NR_openat, fd, pathname, flags, mode);
}

static inline long read(int fd, void *buffer, unsigned long size)
{
	return (long) syscall(__NR_read, fd, buffer, size, 0);
}

#define UTS_ENTRY_SIZE 65 /* Sufficient for all recent kernel versions (verified back to 2.6.11) */
struct utsname {
	char sysname[UTS_ENTRY_SIZE];
	char nodename[UTS_ENTRY_SIZE];
	char release[UTS_ENTRY_SIZE];
	char version[UTS_ENTRY_SIZE];
	char machine[UTS_ENTRY_SIZE];
	char domainname[UTS_ENTRY_SIZE];
};
static inline int uname(struct utsname *buffer)
{
	return (int) syscall(__NR_uname, buffer, 0, 0, 0);
}

static inline long write(int fd, const void *buf, unsigned long count)
{
	return (long) syscall(__NR_write, fd, buf, count, 0);
}

/* Utility functions */
__attribute__((noreturn))
static inline void die(int status, const char *message)
{
	write(2, message, __builtin_strlen(message));
	write(2, "\n", 1);
	exit(status);
}

#endif
