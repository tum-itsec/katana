#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

int64_t search_rel_pointer(const char* data, uint64_t len, uint64_t needle, int64_t offset) {
	// if the buffer len is not a multiple of 4, skip the last bytes of the buffer
	len = (len / 4) * 4;
	for(uint64_t i=0; i<len; i+= 4) {
		uint64_t cur_paddr = i + offset;
		uint32_t pot_entry = *(uint32_t *)(data+i);
		if(pot_entry + cur_paddr == needle) {
			return i;
		}
	}
	return -1;
}
