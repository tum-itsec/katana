#include <ukm-arch.h>

int strcmp(const char *s1, const char *s2)
{
	for (; *s1 != 0 && *s2 != 0 && *s1 == *s2; ++s1, ++s2);
	return *s1 - *s2;
}

int strncmp(const char *s1, const char *s2, unsigned long n)
{
	unsigned long counter = 0;
	for (; counter < n && *s1 != 0 && *s2 != 0 && *s1 == *s2; ++s1, ++s2, ++counter);
	return counter != n ? *s1 - *s2 : 0;
}

unsigned long strlen(const char *s)
{
	unsigned long length = 0;
	for (; *s != 0; ++s, ++length);
	return length;
}

#if defined(__x86_64__) || defined(__aarch64__)
int memcmp(const void *p1, const void *p2, unsigned long n)
#else
int memcmp(const void *p1, const void *p2, unsigned int n)
#endif
{
	unsigned int i = 0;
	const char *s1 = p1;
	const char *s2 = p2;
	for (; i < n && *s1 == *s2; ++s1, ++s2, ++i);
	return i < n ? *s1 - *s2 : 0;
}

void *memset(void *s, int c, unsigned long n)
{
	for (unsigned long i = 0; i < n; ++i)
		((char *) s)[i] = c;
	return s;
}

void *memcpy(void *dest, const void *src, unsigned long n)
{
	char *d = dest;
	const char *s = src;
	for (; n; --n) *d++ = *s++;
	return dest;
}

void *memmove(void *dest, const void *src, unsigned long n)
{
	char *d = dest;
	const char *s = src;
	if (s < d)
		for (s += n, d += n; n; --n)
			*--d = *--s;
	else
		for (; n; --n)
			*d++ = *s++;
	return dest;
}

/* This is completely absurd - it does _two_ syscalls per allocation! */
#define MALLOC_ALIGN_MASK 0x7 /* aligns to 0x8 */
void *malloc(unsigned long size)
{
	unsigned long start = brk(0);
	if (start > (unsigned long) -4096)
		return 0;
	unsigned long aligned = (start & MALLOC_ALIGN_MASK) ? (start | MALLOC_ALIGN_MASK) + 1 : start;
	unsigned long end = brk(aligned + size);
	if (end > (unsigned long) -4096)
		return 0;
	return (void *) start;
}
