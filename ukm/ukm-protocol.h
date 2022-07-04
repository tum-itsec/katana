#ifndef __UKM_PROTOCOL_H__
#define  __UKM_PROTOCOL_H__

// Protocol description:
//    Magic number    "\xbaI" (2 bytes)
//    Packet type             (1 byte)
//    Architecture token      (1 byte)
//    Packet number           (4 bytes, network byte order)
//    Payload length          (2 bytes, network byte order)
//    Packet data             ...

#define PACKET_MAGIC "\xbaI"
#define PACKET_MAGIC_SIZE 2
#define PACKET_ARCH_OFFSET 3
#define PACKET_NUMBER_OFFSET 4
#define PACKET_LENGTH_OFFSET 8
#define PACKET_HEADER_SIZE 10
#define MAX_MTU 1492

// Packet types
enum ukm_packet_type {
	PACKET_TYPE_STATUS = 0,
	PACKET_TYPE_REGISTER_DATA = 1,
	PACKET_TYPE_MEMORY_DATA = 2,
	PACKET_TYPE_PAGING_DATA = 3,
	PACKET_TYPE_TEXT = 4,
	PACKET_TYPE_HEX = 5,
	__MAX_PACKET_TYPE
};

// Architectures
enum ukm_arch_type {
	ARCH_TYPE_X86_64   = 0,
	ARCH_TYPE_X86_32   = 1,
	ARCH_TYPE_MIPS32   = 2,
	ARCH_TYPE_ARM64    = 3,
	ARCH_TYPE_MIPS32EL = 4,
};
#if defined(__x86_64__)
#define UKM_PROTO_ARCHITECTURE ARCH_TYPE_X86_64
#elif defined(__i386__)
#define UKM_PROTO_ARCHITECTURE ARCH_TYPE_X86_32
#elif defined(__mips__)
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define UKM_PROTO_ARCHITECTRUE ARCH_TYPE_MIPS32EL
#else
#define UKM_PROTO_ARCHITECTURE ARCH_TYPE_MIPS32
#endif
#elif defined(__aarch64__)
#define UKM_PROTO_ARCHITECTURE ARCH_TYPE_ARM64
#else
#error "Remember to define UKM_PROTO_ARCHITECTURE for this architecture"
#endif

// Build a message
static inline void __do_send_packet(enum ukm_packet_type type, unsigned number, const char *data, int length, void (*send)(const char *data, int length)) {
	static char buffer[MAX_MTU];
	uint32_t n_number;
	uint16_t n_length;

	if (length > MAX_MTU - PACKET_HEADER_SIZE || length < 0)
		return;
	if (type >= __MAX_PACKET_TYPE)
		return;

	if (data)
		memcpy(&buffer[PACKET_HEADER_SIZE], data, length);
	else
		length = 0;

	n_number = htonl(number);
	n_length = htons(length);

	memcpy(buffer, PACKET_MAGIC, PACKET_MAGIC_SIZE);
	buffer[PACKET_MAGIC_SIZE] = (char) type;
	buffer[PACKET_ARCH_OFFSET] = (char) UKM_PROTO_ARCHITECTURE;
	memcpy(&buffer[PACKET_NUMBER_OFFSET], &n_number, 4);
	memcpy(&buffer[PACKET_LENGTH_OFFSET], &n_length, 2);
	return send(buffer, length + PACKET_HEADER_SIZE);
}

#define __send_packet_ready(counter, send) __do_send_packet(PACKET_TYPE_STATUS, (counter = 0), 0, 0, send)
#define __send_packet_error(error, counter, send) ({ unsigned char stored_error = error; __do_send_packet(PACKET_TYPE_STATUS, ++counter, (const char *) &stored_error, 1, send); })
#define __send_packet_done(counter, send) __do_send_packet(PACKET_TYPE_STATUS, ++counter, "\x00" /* "errno 0" */, 1, send)

#define __send_packet(type, counter, data, length, send) __do_send_packet(type, ++counter, data, length, send)

#endif
