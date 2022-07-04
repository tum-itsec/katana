#!/bin/sh
set -eux

# XZ Embedded (public domain, used in Linux to perform LZMA decompression)
if [ ! -e xz ]; then
	git clone https://git.tukaani.org/xz-embedded.git xz
fi
cp xz/linux/include/linux/xz.h xz/linux/lib/xz/{xz_crc32.c,xz_crc64.c,xz_dec_lzma2.c,xz_dec_stream.c,xz_dec_bcj.c,xz_lzma2.h,xz_private.h,xz_stream.h} xz/
cat > xz/xz_config.h <<-'EOF'
	#ifndef __XZ_CONFIG_H__
	#define __XZ_CONFIG_H__

	#include <ukm-arch.h>

	#define XZ_USE_CRC64
	#if defined(__x86_64__) || defined(__i386__)
		#define XZ_DEC_X86
	#endif

	#include "xz.h"

	/* We never free memory, but we can probably get away with it
	 * I don't want to implement a custom heap for this as well...
	 */
	void *malloc(unsigned long);
	#define kmalloc(size, flags) malloc(size)
	#define kfree(ptr) do {} while (0)
	#define vmalloc(size) malloc(size)
	#define vfree(ptr) do {} while (0)

	#define memeq(a, b, size) (__builtin_memcmp(a, b, size) == 0)
	#define memzero(buf, size) __builtin_memset(buf, 0, size)

	#ifndef min
	#	define min(x, y) ((x) < (y) ? (x) : (y))
	#endif
	#define min_t(type, x, y) min(x, y)

	#define __always_inline inline __attribute__((__always_inline__))

	#ifndef get_unaligned_le32
	static inline uint32_t get_unaligned_le32(const uint8_t *buf)
	{
		return (uint32_t)buf[0]
				| ((uint32_t)buf[1] << 8)
				| ((uint32_t)buf[2] << 16)
				| ((uint32_t)buf[3] << 24);
	}
	#endif

	#ifndef get_unaligned_be32
	static inline uint32_t get_unaligned_be32(const uint8_t *buf)
	{
		return (uint32_t)(buf[0] << 24)
				| ((uint32_t)buf[1] << 16)
				| ((uint32_t)buf[2] << 8)
				| (uint32_t)buf[3];
	}
	#endif

	#ifndef put_unaligned_le32
	static inline void put_unaligned_le32(uint32_t val, uint8_t *buf)
	{
		buf[0] = (uint8_t)val;
		buf[1] = (uint8_t)(val >> 8);
		buf[2] = (uint8_t)(val >> 16);
		buf[3] = (uint8_t)(val >> 24);
	}
	#endif

	#ifndef put_unaligned_be32
	static inline void put_unaligned_be32(uint32_t val, uint8_t *buf)
	{
		buf[0] = (uint8_t)(val >> 24);
		buf[1] = (uint8_t)(val >> 16);
		buf[2] = (uint8_t)(val >> 8);
		buf[3] = (uint8_t)val;
	}
	#endif

	#ifndef get_le32
	#	define get_le32 get_unaligned_le32
	#endif

	#endif
EOF

find xz -maxdepth 1 -type f \
	-a '(' -iname '*.c' -o -iname '*.h' ')' \
	-a '(' '!' -name 'xz_config.h' ')' \
	-exec sed -i \
		-e 's/memcmp/__builtin_memcmp/' \
		-e 's/memset/__builtin_memset/' \
		-e '/<stdint.h>/d' \
		{} ';'

find xz -maxdepth 1 -type f -iname '*.c' -exec cat {} '+' > xz/xz.c
