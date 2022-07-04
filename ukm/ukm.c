#include <linux/cpumask.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/hugetlb.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/irqflags.h>
#include <linux/mmu_context.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/sched/mm.h>

#if defined(CONFIG_NETPOLL) && !defined(DISABLE_NETPOLL_SUPPORT)
#include <linux/netpoll.h>
#endif

#include <asm/checksum.h>
#include <net/ip6_checksum.h>
#include <net/arp.h>

#if defined(__mips__)
#include <asm/mipsregs.h>

#if defined(CONFIG_64BIT_PHYS_ADDR)
#error "36-bit+ physical address space on 32-bit MIPS is not supported (yet)"
#endif
#if !defined(CONFIG_PAGE_SIZE_4KB)
#error "Non-4KB default page size is not supported on MIPS (yet)"
#endif
#if defined(CONFIG_CPU_R3K_TLB)
#define UKM_MIPS_R3K
#endif

#if defined(UKM_MIPS_R3K)
#pragma message "Using MIPS R3K rules"
#endif
#endif

/* For building this module, make sure to disable CONFIG_TRIM_UNUSED_SYMBOLS,
 * or modpost will complain that the symbols are undefined!
 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tobias Holl <tobias.holl@tum.de>");
MODULE_DESCRIPTION("Universal kernel module");

#include <ukm-shared.h>
UKM_ARGS(config);
UKM_KERNEL_VERSION(version);

#include <ukm-protocol.h>
static unsigned packet_counter = 0;

#define print_once(...) ({ static bool printed = false; if (!printed) { printk(__VA_ARGS__); printed = true; } printed; })
#define goto_message(message, label) do { printk(KERN_ERR message "\n"); goto label; } while (0)

#if !defined(DEBUGGING_LEVEL)
#define DEBUGGING_LEVEL KERN_DEBUG
#endif
#if defined(ENABLE_DEBUGGING)
#define debug(...) printk(DEBUGGING_LEVEL __VA_ARGS__)
#endif
#if defined(VERBOSE_DEBUGGING)
#define verbose_debug(...) printk(DEBUGGING_LEVEL __VA_ARGS__)
#else
#define verbose_debug(...) do {} while (0)
#endif
#if !defined(UKM_TX_DEFAULT_DELAY_USECS)
#define UKM_TX_DEFAULT_DELAY_USECS 50
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htonll(v64) ((uint64_t) htonl(((uint64_t) (v64) >> 32) & 0xfffffffful) | ((uint64_t) htonl((uint64_t) (v64) & 0xfffffffful) << 32))
#else
#define htonll(v64) ((uint64_t) (v64))
#endif

static inline void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
	/* Inefficient, but OK here */
	const char *h;
	size_t pos;

	if (needlelen > haystacklen)
		return NULL;

	h = (const char *) haystack;
	for (pos = 0; pos + needlelen <= haystacklen; ++pos)
		if (memcmp(h + pos, needle, needlelen) == 0)
			return (void *) (h + pos);
	return NULL;
}

static inline int __strcmp(const char *s1, const char *s2)
{
	/* This is not exported on old kernels for whatever reason */
	for (; *s1 != 0 && *s2 != 0 && *s1 == *s2; ++s1, ++s2);
	return *s1 - *s2;
}

#if defined(UKM_MIPS_R3K)
__attribute__((__noinline__,optimize("O0"))) static unsigned long long __mul(unsigned long long a, unsigned int b)
{
	unsigned long long _res = 0;
#pragma GCC unroll 0
	while (b--)
		_res += a;
	return _res;
}
#endif

__attribute__((flatten)) static inline int __kstrtoul(const char *s, unsigned int base, unsigned long *res)
{
	/* Again, not exported on old kernels :/ */
	unsigned long long _res;
	unsigned int rv, c, lc, digit;

	if (s[0] == '+') ++s;

	if (base == 0) {
		if (s[0] == '0' && (s[1] | 0x20) == 'x' && isxdigit(s[2])) base = 16;
		else if (s[0] == '0') base = 8;
		else base = 10;
	}
	if (base == 16 && s[0] == '0' && (s[1] | 0x20) == 'x') s += 2;

	for (_res = 0, rv = 0;; ++rv, ++s) {
		c = *s;
		lc = c | 0x20;
		if ('0' <= c && c <= '9') digit = c - '0';
		else if ('a' <= lc && lc <= 'f') digit = lc - 'a' + 10;
		else break;
		if (digit >= base) break;
		if (unlikely(_res & (~0ull << 60)))
			if (_res > div_u64(ULLONG_MAX - digit, base))
				return -ERANGE;
#if defined(UKM_MIPS_R3K)
		/* Avoid generating MUL at all cost */
		_res = __mul(_res, base) + digit;
#else
		_res = _res * base + digit;
#endif
	}
	if (rv == 0) return -EINVAL;
	if (*s == '\n') ++s;
	if (*s) return -EINVAL;
	*res = _res;
	return 0;
}

#if defined(__mips__)
/* This is there just in case the kernel doesn't have it */
inline unsigned int __bswapsi2(unsigned int u)
{
	return (((u) & 0xff000000) >> 24) | (((u) & 0x00ff0000) >>  8) | (((u) & 0x0000ff00) <<  8) | (((u) & 0x000000ff) << 24);
}
#endif

/* This is the networking layer. If netpoll is present, we use that. However,
 * CONFIG_NETPOLL is disabled in the default config, so we need to emulate its
 * functionality with lower-level APIs for kernels without that option. We keep
 * netpoll around for stability (because it is a public API, I don't expect it
 * to change very much, as opposed to the internal APIs that our version uses).
 */

#if defined(CONFIG_NETPOLL) && !defined(DISABLE_NETPOLL_SUPPORT) /* NB: This is checked against the kernel against which the module is built, not the one on which it is loaded! */
	/* This aliases a struct netpoll, of which we do not know the size or layout,
	 * but 1024 bytes should be more than enough (on 4.9.210 the size is 84 bytes)
	 */
	static char __netpoll_buffer[1024];
	#define np ((struct netpoll *) __netpoll_buffer)

	extern int netpoll_parse_options(struct netpoll *, char *) __attribute__((weak));
	extern int netpoll_setup(struct netpoll *) __attribute__((weak));
	extern void netpoll_cleanup(struct netpoll *) __attribute__((weak));
	extern void netpoll_send_udp(struct netpoll *, const char *, int) __attribute__((weak));
	#define has_netpoll (&netpoll_parse_options && &netpoll_setup && &netpoll_cleanup && &netpoll_send_udp)
#else
	#pragma message "Disabling netpoll support"
	#define netpoll_parse_options(...) 0
	#define netpoll_setup(...) 0
	#define netpoll_cleanup(...) ((void) 0)
	#define netpoll_send_udp(...) ((void) 0)
	#define has_netpoll 0

	union inet_addr {
		__be32 ip;
		struct in6_addr in6;
	};
#endif

#if !defined(CONFIG_KALLSYMS)
	#error "Reference kernel must be built with CONFIG_KALLSYMS enabled."
#endif
extern unsigned long kallsyms_lookup_name(const char *name) __attribute__((weak)); /* Not exported on really old kernels - or really new kernels. */
extern int kallsyms_on_each_symbol(int (*fn)(void *, const char *, struct module *, unsigned long), void *data) __attribute__((weak));
static unsigned long (*__kallsyms_lookup_name)(const char *name) = NULL;
int __maybe_set_kallsyms_lookup_name(void * __attribute__((unused)) data, const char *name, struct module * __attribute__((unused)) mod, unsigned long address)
{
	if (__strcmp(name, "kallsyms_lookup_name") != 0)
		return 0;
	__kallsyms_lookup_name = (typeof(__kallsyms_lookup_name)) address;
	return 1; /* Stops the loop */
}

static struct {
	unsigned sport;
	union inet_addr sip;
	const char *sdev;
	unsigned dport;
	union inet_addr dip;
	unsigned char dmac[6];
	bool is_ipv6;
} parsed_config = {0};

extern struct net init_net __attribute__((weak));


/* Parse memory ranges from the config or from /proc/zoneinfo */
struct {
	unsigned long start_pfn;
	unsigned long end_pfn;
} memory_ranges[1024];
unsigned memory_range_count = 0;
unsigned long tx_delay = UKM_TX_DEFAULT_DELAY_USECS;

ssize_t ukm_kernel_read(struct file *fp, char *buffer, size_t count, loff_t offset)
{
	if (version_after(version, 4, 14, -1)) {
		return kernel_read(fp, buffer, count, &offset);
	} else {
		unsigned long address = (unsigned long) &kernel_read;
		return (size_t) (((int (*)(struct file *, loff_t, char *, unsigned long)) address)(fp, offset, buffer, (unsigned long) count));
	}
}

int parse_options(void)
{
	/* Find 'delay=' string in the config. */
	/* Find 'ranges=' string in the config. */
	char *match, *ini_match, *sep_match, *dash_match, *comma_match, *last_match, *key_match, buffer[512];
	int error = 0, bytes, fill = 0, offset = 0, length, has_span = 0, has_begin = 0;
	unsigned long begin = 0, end = 0, span = 0, space = sizeof(config);
	struct file *fp;

	ini_match = match = memmem(config, space, "ranges=", 7);
	if (!!match) {
		sep_match = memmem(match, space - (match - config), " ", 1);
		if (!sep_match) sep_match = config + space - 1;
		*match = 0;
		match += 6;
		/* begin1-end1,begin2-end2,... - The "end" PFNs are _inclusive_, as reported by /proc/iomem! */
		do {
			*match++ = 0;
			comma_match = memmem(match, sep_match - match, ",", 1);
			dash_match = memmem(match, comma_match - match, "-", 1);
			if (!dash_match) {
				printk(KERN_ERR "Invalid range: %s\n", match);
				return -EINVAL;
			}
			*dash_match = 0;
			if ((error = __kstrtoul(match, 0, &begin))) {
				printk(KERN_ERR "Invalid PFN: %s\n", match);
				return error;
			}
			if ((error = __kstrtoul(dash_match + 1, 0, &end))) {
				printk(KERN_ERR "Invalid PFN: %s\n", dash_match + 1);
				return error;
			}
			memory_ranges[memory_range_count].start_pfn = begin;
			memory_ranges[memory_range_count++].end_pfn = end;
			match = comma_match;
		} while (match);

		if (sep_match - config != space - 1)
			memmove(ini_match, sep_match + 1, space - (sep_match - config));
		space -= (sep_match + 1 - ini_match);
		config[space] = 0;
	} else {
		/* Try parsing /proc/zoneinfo */
		fp = filp_open("/proc/zoneinfo", O_RDONLY, 0);
		if (IS_ERR(fp) || !fp) {
			printk(KERN_ERR "Failed to open /proc/zoneinfo");
			return PTR_ERR(fp) && -EFAULT;
		}

read_block:
		if (fill >= sizeof(buffer)) {
			printk(KERN_ERR "Read buffer full, discarding partial line.\n");
			fill = 0;
		}

		bytes = ukm_kernel_read(fp, buffer + fill, sizeof(buffer) - 1 - fill /* -1 to ensure that buffer[fill] is valid */, offset);
		if (bytes < 0) {
			printk(KERN_ERR "Failed to read /proc/zoneinfo");
			error = bytes;
			goto done_reading;
		} else {
			fill += bytes;
			offset += bytes;
		}

		/* Discard irrelevant lines */
		for (last_match = buffer; last_match < buffer + fill; last_match = match + 1) {
			match = memmem(last_match, fill - (last_match - buffer), "\n", 1);
			if (!match && bytes) {
				/* Preserve potentially incomplete lines */
				if (last_match != buffer)
					memmove(buffer, last_match, (fill = fill - (last_match - buffer)));
				goto read_block;
			} else if (match) {
				*match = 0;
				length = match - last_match;
			} else {
				/* EOF anyways, process to the end */
				buffer[fill] = 0;
				length = fill - (last_match - buffer);
			}

			key_match = memmem(last_match, length, " spanned ", 9);
			if (key_match) {
				if (has_span && span != 0 /* Some non-mapped zones with span 0 but no start_pfn exist */)
					printk(KERN_WARNING "Duplicate 'spanned' entry in /proc/zoneinfo - overwriting old value\n");
				for (key_match += 9; *key_match == ' '; ++key_match);
				for (dash_match = key_match; '0' <= *dash_match && *dash_match <= '9'; ++dash_match);
				*dash_match = 0;
				if ((error = __kstrtoul(key_match, 10, &span))) {
					printk(KERN_ERR "Invalid number of spanned pages: %s\n", key_match);
					break;
				}
				has_span = 1;
			}

			key_match = memmem(last_match, length, " start_pfn: ", 12);
			if (key_match) {
				if (has_begin)
					printk(KERN_WARNING "Duplicate 'start_pfn' entry in /proc/zoneinfo - overwriting old value\n");
				for (key_match += 12; *key_match == ' '; ++key_match);
				for (dash_match = key_match; '0' <= *dash_match && *dash_match <= '9'; ++dash_match);
				*dash_match = 0;
				if ((error = __kstrtoul(key_match, 10, &begin))) {
					printk(KERN_ERR "Invalid start_pfn entry: %s\n", key_match);
					break;
				}
				has_begin = 1;
			}

			if (has_span && has_begin) {
				memory_ranges[memory_range_count].start_pfn = begin;
				memory_ranges[memory_range_count++].end_pfn = begin + span - 1;
				debug("Found PFN range %lx - %lx\n", begin, begin + span - 1);
				has_span = has_begin = 0;
			}
		}
done_reading:
		if (!error && (has_span || has_begin))
			printk(KERN_WARNING "Incomplete memory range from /proc/zoneinfo discarded!\n");
		filp_close(fp, 0);
	}

	ini_match = match = memmem(config, space, "delay=", 6);
	if (!!match) {
		sep_match = memmem(match, space - (match - config), " ", 1);
		if (!sep_match) sep_match = config + space - 1;
		*sep_match = 0;
		if ((error = __kstrtoul(match + 6, 0, &tx_delay))) {
			printk(KERN_ERR "Invalid delay: %s\n", match);
			return error;
		}

		if (sep_match - config != space - 1)
			memmove(ini_match, sep_match + 1, space - (sep_match - config));
		space -= (sep_match + 1 - ini_match);
		config[space] = 0;
	}

	/* Trim spaces at end */
	while (config[space - 1] == ' ')
		config[(space--) - 1] = 0;

	verbose_debug("Remaining configuration after parsing options: '%s'\n", config);

	return error;
}


/* Set up and clean up networking (netpoll if available, otherwise our ugly custom wrapper) */
int setup_network(void)
{
	int error;

	unsigned pos, index;
	bool is_ipv6;
	const char *end, *segment;

	if (has_netpoll) {
		/* Netpoll setup.
		 * We can leave .rx_hook empty (on old kernels that still have it) because
		 * we only want to transmit. Similarly, if we leave .drop empty, those
		 * kernels will simply free the skb in question.
		 * .name also only ever appears to be used for printing status messages
		 * via printk, so if we leave that empty it should just print (null) instead.
		 */
		error = netpoll_parse_options(np, config);
		if (error)
			goto_message("Netpoll rejected configuration", invalid_config);

		error = netpoll_setup(np);
		if (error) {
			printk(KERN_ERR "Failed to set up netpoll\n");
			return error;
		}
	} else {
		/* Parse the configuration manually and obtain the network device */
		if (version_before(version, 2, 6, 18)) {
			printk(KERN_ERR "Kernel version %d.%d.%d not supported\n", version.major, version.minor, version.patch);
			return -ENOSYS;
		}

		/* Source port */
		for (pos = 0; config[pos] >= '0' && config[pos] <= '9'; ++pos)
			parsed_config.sport = (10 * parsed_config.sport) + (config[pos] - '0');
		if (config[pos++] != '@')
			goto_message("Port number not followed by @", invalid_config);

		/* Source IP */
		segment = &config[pos];
		parsed_config.is_ipv6 = false;
		for (; config[pos] != '/'; ++pos) {
			if (!config[pos])
				goto_message("Truncated configuration", invalid_config);
			parsed_config.is_ipv6 |= (config[pos] == ':');
		}
		config[pos] = 0;
		if (parsed_config.is_ipv6 && !in6_pton(segment, -1, parsed_config.sip.in6.s6_addr, -1, &end))
			goto_message("Invalid source IPv6 address", invalid_config);
		else if (!parsed_config.is_ipv6 && !in4_pton(segment, -1, (__u8 *) &parsed_config.sip.ip, -1, &end))
			goto_message("Invalid source IPv4 address", invalid_config);

		/* Source device. Do not obtain a reference (yet). */
		segment = &config[++pos];
		for (; config[pos] != ','; ++pos)
			if (!config[pos])
				goto_message("Truncated configuration (source specification not followed by ,)", invalid_config);
		config[pos] = 0;
		parsed_config.sdev = segment;

		/* Destination port */
		for (++pos; config[pos] >= '0' && config[pos] <= '9'; ++pos)
			parsed_config.dport = (10 * parsed_config.dport) + (config[pos] - '0');
		if (config[pos++] != '@')
			goto_message("Port number not followed by @", invalid_config);

		/* Destination IP */
		segment = &config[pos];
		is_ipv6 = false;
		for (; config[pos] != '/'; ++pos) {
			if (!config[pos])
				goto_message("Truncated configuration", invalid_config);
			is_ipv6 |= (config[pos] == ':');
		}
		config[pos++] = 0;
		if (is_ipv6 != parsed_config.is_ipv6)
			goto_message("Mismatched IP versions", invalid_config);
		if (is_ipv6 && !in6_pton(segment, -1, parsed_config.dip.in6.s6_addr, -1, &end))
			goto_message("Invalid source IPv6 address", invalid_config);
		else if (!is_ipv6 && !in4_pton(segment, -1, (__u8 *) &parsed_config.dip.ip, -1, &end))
			goto_message("Invalid source IPv4 address", invalid_config);

		/* Destination MAC. Unfortunately, mac_pton doesn't exist before 3.0, so we have to do it manually */
		for (index = 0; index < 6; ++index) {
			parsed_config.dmac[index] = 0;
			if (config[pos] >= '0' && config[pos] <= '9')
				parsed_config.dmac[index] |= config[pos] - '0';
			else if (config[pos] >= 'a' && config[pos] <= 'f')
				parsed_config.dmac[index] |= config[pos] - 'a' + 0xa;
			else if (config[pos] >= 'A' && config[pos] <= 'F')
				parsed_config.dmac[index] |= config[pos] - 'A' + 0xa;
			else
				goto_message("Invalid target MAC address", invalid_config);

			parsed_config.dmac[index] <<= 4;
			++pos;

			if (config[pos] >= '0' && config[pos] <= '9')
				parsed_config.dmac[index] |= config[pos] - '0';
			else if (config[pos] >= 'a' && config[pos] <= 'f')
				parsed_config.dmac[index] |= config[pos] - 'a' + 0xa;
			else if (config[pos] >= 'A' && config[pos] <= 'F')
				parsed_config.dmac[index] |= config[pos] - 'A' + 0xa;
			else
				goto_message("Invalid target MAC address", invalid_config);

			++pos;
			if ((index == 5 && config[pos] != 0) || (index != 5 && config[pos] != ':'))
				goto_message("Invalid target MAC address", invalid_config);
			++pos;
		}
	}
	return 0;

invalid_config:
	printk(KERN_ERR "Invalid configuration: %s\n", config);
	return -EINVAL;
}

void cleanup_network(void)
{
	if (has_netpoll)
		netpoll_cleanup(np);
}


/* Obtain and return the network device when locking if netpoll is not available */
static struct net_device *__device = NULL;

static int __lock_init(void)
{
	if (!has_netpoll) {
		/* Get the target device without incrementing the reference count.
		 * Doing this every time is inefficient, so we only do it while
		 * entering and leaving locked state.
		 * __dev_get_by_name takes the network namespace since 2.6.24
		 */
		if (&init_net) {
			__device = __dev_get_by_name(&init_net, parsed_config.sdev);
		} else if (version_before(version, 2, 6, 24)) {
			struct net_device *(*__dev_get_by_name_without_namespace)(const char *) = (struct net_device *(*)(const char *))(&__dev_get_by_name);
			__device = __dev_get_by_name_without_namespace(parsed_config.sdev);
		} else {
			printk(KERN_ERR "__dev_get_by_name requires namespace, but init_net is not present\n");
			return -ENOSYS;
		}
		if (!__device) {
			printk(KERN_ERR "Unknown device: %s\n", parsed_config.sdev);
			return -ENODEV;
		}
	}
	return 0;
}

static void __lock_done(void)
{
	__device = NULL;
}


/* Network checksumming. Unfortunately, the functions that do this in the kernel
 * are sometimes inlined and sometimes symbols (depending on kernel version and
 * architecture), so we lift the generic checksum idea from asm-generic. They
 * should explicitly work for little and big-endian byte orders (c.f. RFC 1071).
 */
static __be16 csum_data(const unsigned char *data, unsigned long length, __wsum csum) {
	const __be16 *p = (const __be16 *) data, *end = (const __be16 *) &data[length & (~1ul)];
	if (length & 1ul) {
		/* Process last byte first, pad with zeroes */
		unsigned char new[2] = { data[length - 1], 0 };
		csum = csum_data(new, 2, csum);
	}
	for (; p < end; ++p) {
		csum += *p;
		while (csum > 0xFFFFul)
			csum = (csum & 0xFFFF) + (csum >> 16);
	}
	return (__sum16) csum;
}

static __be16 csum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, __u32 len, unsigned short proto, __wsum csum) {
	__be32 nlen = htonl(len);
	__u8 padded_proto[4] = {0, 0, 0, proto};
	/* Initial checksum over the words of the IP */
	csum = csum_data((const unsigned char *) &saddr->s6_addr, 16, csum);
	csum = csum_data((const unsigned char *) &daddr->s6_addr, 16, csum);
	/* Rest of the pseudoheader */
	csum = csum_data((const unsigned char *) &nlen, 4, csum);
	csum = csum_data(padded_proto, 4, csum);
	return csum;
}

static __be16 csum_tcpudp(__be32 saddr, __be32 daddr, unsigned short len, unsigned short proto, __wsum csum) {
	__u8 padded_proto[2] = {0, proto};
	__be16 nlen = htons(len);
	/* Initial checksum over the words of the IP (already in network byte order!) */
	csum = csum_data((const unsigned char *) &saddr, 4, csum);
	csum = csum_data((const unsigned char *) &daddr, 4, csum);
	/* Rest of the pseudoheader */
	csum = csum_data(padded_proto, 2, csum);
	csum = csum_data((const unsigned char *) &nlen, 2, csum);
	return csum;
}


/* Send packets */
extern struct netdev_queue *netdev_core_pick_tx(struct net_device *dev, struct sk_buff *skb, struct net_device *sb_dev) __attribute__((weak)); /* This replaces netdev_pick_tx in 5.2 */
static unsigned int ipv4_id;

static int __locked_dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	static unsigned long dev_hard_start_xmit = -1;
	static unsigned long dev_pick_tx_addr = -1;
	static unsigned long netdev_pick_tx_addr = -1;

	struct netdev_queue *txq = NULL;
	int rc = -1;

	if (version_after(version, 5, 8, -1))
		print_once(KERN_WARNING "New kernel version - verify that internal networking APIs remain consistent\n");

	/* dev_hard_start_xmit has a changing API (and isn't exported), so we
	 * need to trick a little...
	 * 2.6.18 - 2.6.26:
	 *   int dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev)
	 * 2.6.27 - 3.17:
	 *   int dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq)
	 * 3.18 - 5.7+:
	 *   struct sk_buff *dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq, int *rc)
	 */
	if (dev_hard_start_xmit == -1)
		dev_hard_start_xmit = __kallsyms_lookup_name("dev_hard_start_xmit");
	if (dev_hard_start_xmit == -1 || !dev_hard_start_xmit) {
		print_once(KERN_ERR "Failed to find dev_hard_start_xmit!\n");
		return -1;
	}
	#define dev_hard_start_xmit_2_6_18 ((int (*)(struct sk_buff *skb, struct net_device *dev))(dev_hard_start_xmit))
	#define dev_hard_start_xmit_2_6_27 ((int (*)(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq))(dev_hard_start_xmit))
	#define dev_hard_start_xmit_3_18_0 ((struct sk_buff *(*)(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq, int *rc))(dev_hard_start_xmit))

	if (dev_pick_tx_addr == -1)
		dev_pick_tx_addr = __kallsyms_lookup_name("dev_pick_tx"); /* This symbol is not exported, it exists when netdev_pick_tx or netdev_core_pick_tx do not exist */
	#define dev_pick_tx ((struct netdev_queue *(*)(struct net_device *dev, struct sk_buff *skb)) dev_pick_tx_addr)


	if (netdev_pick_tx_addr == -1)
		netdev_pick_tx_addr = __kallsyms_lookup_name("netdev_pick_tx"); /* This symbol is not exported, it exists when netdev_pick_tx or netdev_core_pick_tx do not exist */
	#define netdev_pick_tx_3_7_0 ((struct netdev_queue *(*)(struct net_device *dev, struct sk_buff *skb)) netdev_pick_tx_addr)
	#define netdev_pick_tx_3_13_0 ((struct netdev_queue *(*)(struct net_device *dev, struct sk_buff *skb, void *accel_priv)) netdev_pick_tx_addr)


	/* HARD_TX_LOCK calls into __netif_tx_lock since 2.6.24. Unfortunately all these
	 * lock calls are in static inline functions, so we can't use them because the
	 * inlined offsets might change. However, we are in stop_machine and so we can
	 * ignore the lock (because it is a spinlock).
	 */

	/* TODO: We still need to check whether the device is actually there and not frozen or
	 * otherwise stopped; right now we just ignore this condition:
	 *   netif_running(dev) && netif_device_present(dev) && !netif_xmit_frozen_or_stopped(txq)
	 */

	/* Get transmission queue if necessary */
	if (!version_before(version, 2, 6, 27)) {
		if (&netdev_core_pick_tx) {
			txq = netdev_core_pick_tx(dev, skb, NULL);
		} else if (netdev_pick_tx_addr) {
			if (version_before(version, 3, 13, 0))
				txq = netdev_pick_tx_3_7_0(dev, skb);
			else
				txq = netdev_pick_tx_3_13_0(dev, skb, NULL);
		} else if (dev_pick_tx) {
			txq = dev_pick_tx(dev, skb);
		} else {
			print_once(KERN_ERR "No device queue selection function found\n");
			return -1;
		}
	}

	/* SKB must already be linearized and checksummed at this point. */
	if (version_before(version, 2, 6, 27))
		rc = dev_hard_start_xmit_2_6_18(skb, dev);
	else if (version_before(version, 3, 18, 0))
		rc = dev_hard_start_xmit_2_6_27(skb, dev, txq);
	else
		skb = dev_hard_start_xmit_3_18_0(skb, dev, txq, &rc);

	return dev_xmit_complete(rc) ? 0 : -1; /* NB: dev_xmit_complete is static inline, but it compares to a constant that should not have changed recently */
}

void __send_message(const char *message, int length)
{
	struct sk_buff *skb;
	unsigned data_off, arp_len, udp_len, ip_len, ip_hdr_size;
	unsigned short protocol;
	unsigned short arp_proto;
	char *data, *tail, *arp_begin, *skb_proto;

	/* These should not change between kernel versions */
	struct arphdr arph = { .ar_hrd = 0, .ar_pro = htons(ETH_P_IP), .ar_hln = 6, .ar_pln = 4, .ar_op = htons(0xfeed) };
	struct udphdr udph;
	struct iphdr iph;
	struct ipv6hdr ip6h;
	__wsum csum;

	if (has_netpoll) {
		netpoll_send_udp(np, message, length);
	} else {
		if (!__device) {
			printk(KERN_ERR "Called __send_message before __lock_init or after __lock_done\n");
			return;
		}

		udp_len = length + sizeof(udph);
		ip_hdr_size = parsed_config.is_ipv6 ? sizeof(ip6h) : sizeof(iph);
		ip_len = udp_len + ip_hdr_size;
		protocol = parsed_config.is_ipv6 ? ETH_P_IPV6 : ETH_P_IP;

		/* Instead of allocating an SKB normally (via __alloc_skb), we
		 * use arp_create for the sole purpose of filling in the ->dev
		 * and ->protocol fields for us. This creates an ARP packet, so
		 * we must carefully destroy the rest of the packet to fill it
		 * with the correct IP and UDP headers.
		 */
		skb = arp_create(0xfeed, protocol, 0, __device, 0, parsed_config.dmac, NULL, NULL);
		if (!skb) {
			printk(KERN_ERR "Failed to create SKB\n");
			return;
		}
		/* Remove the ARP header from the packet data. ar_hrd may vary
		 * (it is set to dev->type), but the other fields should match
		 * on all devices with a MAC address, which we require anyways
		 * since it is part of the configuration format for netpoll.
		 */
		data = skb_push(skb, 0);
		tail = skb_put(skb, 0);
		arp_begin = memmem(data, tail - data, &arph.ar_pro, sizeof(arph) - sizeof(arph.ar_hrd)) - offsetof(struct arphdr, ar_pro);
		if (!arp_begin)
			goto_message("Failed to reclaim SKB space", cleanup_skb);
		arp_len = tail - arp_begin;
		data_off = arp_begin - data;

		/* Replace the protocol in the SKB immediately. Note that the
		 * sizeof(struct sk_buff) may be wrong, and so we just have to
		 * specify a large number and hope we don't crash the kernel.
		 * Also note that this is technically unsound if the 0x0806 ends
		 * up in a pointer somewhere (but this is fortunately very
		 * unlikely).
		 */
		arp_proto = htons(ETH_P_ARP);
		skb_proto = memmem((const void *) skb, 1024, &arp_proto, 2);
		if (!skb_proto)
			goto_message("Failed to set SKB protocol", cleanup_skb);
		put_unaligned(htons(protocol), (unsigned short *) skb_proto);

		/* Now that ->dev and ->protocol are set correctly, reallocate
		 * the SKB with enough space for our protocol. arp_create did
		 * set up an ethernet header for us, so the header space is
		 * correct. We need to add some tailroom (in theory, this should
		 * be __device->needed_tailroom, but we don't have access to
		 * this, so we use an approximation). We need ip_len - arp_len
		 * more space for data, plus additional tailroom.
		 */
		#define APPROX_TAILROOM 16
		if (pskb_expand_head(skb, 0, ip_len - arp_len + APPROX_TAILROOM, GFP_ATOMIC))
			goto_message("Failed to expand SKB", cleanup_skb);
		skb_put(skb, ip_len - arp_len);

		/* Copy data */
		if (skb_store_bits(skb, data_off + ip_hdr_size + sizeof(udph), message, length))
			goto_message("Failed to copy message to SKB\n", cleanup_skb);

		/* Create UDP header. */
		udph.source = htons(parsed_config.sport);
		udph.dest = htons(parsed_config.dport);
		udph.len = htons(udp_len);
		udph.check = 0;
		barrier();

		csum = csum_data(message, length, csum_data((const unsigned char *) &udph, sizeof(udph), 0));
		if (parsed_config.is_ipv6)
			udph.check = ~csum_ipv6(&parsed_config.sip.in6, &parsed_config.dip.in6, udp_len, IPPROTO_UDP, csum);
		else
			udph.check = ~csum_tcpudp(parsed_config.sip.ip, parsed_config.dip.ip, udp_len, IPPROTO_UDP, csum);
		if (udph.check == 0)
			udph.check = CSUM_MANGLED_0;
		if (skb_store_bits(skb, data_off + ip_hdr_size, (char *) &udph, sizeof(udph)))
			goto_message("Failed to copy UDP header to SKB", cleanup_skb);

		/* Create IP header */
		if (parsed_config.is_ipv6) {
			put_unaligned(0x60, (unsigned char *) &ip6h);
			ip6h.flow_lbl[0] = 0;
			ip6h.flow_lbl[1] = 0;
			ip6h.flow_lbl[2] = 0;
			ip6h.payload_len = htons(sizeof(struct udphdr) + length);
			ip6h.nexthdr = IPPROTO_UDP;
			ip6h.hop_limit = 32;
			ip6h.saddr = parsed_config.sip.in6;
			ip6h.daddr = parsed_config.dip.in6;
		} else {
			put_unaligned(0x45, (unsigned char *) &iph);
			iph.tos = 0;
			put_unaligned(htons(ip_len), &iph.tot_len);
			iph.id = htons(ipv4_id++);
			iph.frag_off = 0;
			iph.ttl = 64;
			iph.protocol = IPPROTO_UDP;
			put_unaligned(parsed_config.sip.ip, &iph.saddr);
			put_unaligned(parsed_config.dip.ip, &iph.daddr);
			iph.check = 0;
			barrier();
			iph.check = ~csum_data((unsigned char *) &iph, sizeof(iph), 0);
		}
		if (skb_store_bits(skb, data_off, parsed_config.is_ipv6 ? (char *) &ip6h : (char *) &iph, ip_hdr_size))
			goto_message("Failed to copy IP header to SKB", cleanup_skb);

		/* We theoretically need to set the header offsets in the SKB:
		 *    skb_set_transport_header(skb, ETH_HLEN + ip_hdr_size);
		 *    skb_set_network_header(skb, ETH_HLEN);
		 *    skb_reset_mac_header(skb);
		 * Unfortunately those functions are all static inline, and the
		 * fields only exist since 2.6.22 (before that, there is only
		 * mac_len, which is not really used). However, it seems that
		 * we can get away without setting the transport header if we
		 * abuse arp_create, so this appears to work for now. We
		 * sometimes cause kernel warnings because the users of the
		 * SKB are not properly set, but that should not matter.
		 *
		 * TODO: We need to check whether the NITs break when we force
		 * transmission like this, but from testing it seems to be fine.
		 *
		 * TODO: We should verify that kfree_skb is the right thing to
		 * do on error, and in which cases we still need to do so after
		 * __locked_dev_hard_start_xmit fails.
		 */

		if (__locked_dev_hard_start_xmit(skb, __device))
			printk(KERN_ERR "Failed sending packet\n");

		return;
cleanup_skb:
		kfree_skb(skb);
		return;
	}
}


/* stop_machine is exported starting with 2.6.27. Before that, we had
 * stop_machine_run (which takes a CPU number instead of the cpumask_t).
 * We wrap around that. Unfortunately, this means we cannot simply include
 * the relevant header, but need to reproduce the definition here.
 */
extern int stop_machine(int (*fn)(void *), void *data, const struct cpumask *cpus) __attribute__((weak));
extern int stop_machine_run(int (*fn)(void *), void *data, unsigned cpu_nr) __attribute__((weak));

static int lock_cpus(int (*fn)(void *), void *data)
{
	unsigned long flags;
	int result;
	if (&stop_machine) {
		return stop_machine(fn, data, NULL /* Any CPU */);
	} else if (&stop_machine_run) {
		return stop_machine_run(fn, data, 0 /* Always the first CPU (we don't know NR_CPUS, which would mean any CPU but is configurable) */);
	} else {
		/* Emulate stop_machine for non-SMP systems. If the system is actually multithreaded, we're screwed.
		 * Unfortunately, we can't rely on something like num_present_cpus() because the underlying symbols
		 * from SMP systems are not present on non-SMP systems.
		 */
		printk(KERN_WARNING "Emulating stop_machine for single-threaded system. If this system is multithreaded, this is a bug!\n");
		local_irq_save(flags);
		result = fn(data);
		local_irq_restore(flags);
		return result;
	}
}


/* Physical memory access (if not implemented directly in __arch_dump_pfn like for MIPS) */
#if defined(__x86_64__)
	#define __arch_default_prot() PAGE_KERNEL_NOCACHE
	static unsigned long __arch_get_addr_offset(void)
	{
		const uint8_t *insn_begin, *insn_current;
		unsigned long call_target = __kallsyms_lookup_name("remove_vm_area");
		unsigned target_register = 7, modrm_mod, modrm_reg, modrm_rm, rex_r, rex_b;
		int64_t displacement;

		if (!call_target) {
			__send_packet_error(EFAULT, packet_counter, __send_message);
			return (unsigned long) -1;
		}

		/* Find a call to remove_vm_area */
		for (insn_begin = (const uint8_t *) free_vm_area;; ++insn_begin) {
			if (*insn_begin == 0xe8) {
				displacement = * (const int32_t *) (insn_begin + 1);
				if ((unsigned long) insn_begin + 5 + displacement == call_target)
					goto found_call;
			} else if (*insn_begin == 0xc3) {
				__send_packet_error(EFAULT, packet_counter, __send_message);
				return (unsigned long) -1;
			}
		}

	found_call:
		/* Found the call to remove_vm_area. Go backwards until we find a mov rdi, reg - or a mov rdi, [reg + imm8] */
		for (insn_current = insn_begin - 3 /* 64-bit mov is at least 3 bytes */; insn_current >= (const uint8_t *) free_vm_area; --insn_current) {
			if ((insn_current[0] & 0xf8) != 0x48)
				continue; /* No REX.W prefix */
			if (insn_current[1] != 0x89 && insn_current[1] != 0x8b)
				continue; /* Not a move instruction, or in a format we don't care about */

			rex_r = (insn_current[0] >> 2) & 1;
			rex_b = insn_current[0] & 1;

			modrm_mod = (insn_current[2] >> 6) & 0x3;
			modrm_reg = (insn_current[2] >> 3) & 0x7;
			modrm_rm = insn_current[2] & 0x7;

			if (insn_current[1] == 0x89) {
				/* mov r/m64, r64 - never the target with offset, just see if we need to change the target_register */
				if (target_register == (modrm_rm | (rex_b << 3))) {
					if (modrm_mod == 3) {
						target_register = modrm_reg | (rex_r << 3);
					} else {
						__send_packet_error(EFAULT, packet_counter, __send_message);
						return (unsigned long) -1; /* Weird assignment to our target register that we did not expect... */
					}
				}
			} else if (insn_current[1] == 0x8b) {
				/* mov r64, r/m64 */
				/* TODO: We should check whether the SIB has a scale or an additional offset set and drop those */
				if (target_register == (modrm_reg | (rex_r << 3))) {
					if (modrm_mod == 3) { /* register */
						target_register = modrm_rm | (rex_b << 3);
					} else if (modrm_mod == 2) { /* disp32 */
						if ((modrm_rm == 4 && insn_current >= insn_begin - 7) || insn_current >= insn_begin - 6)
							continue; /* Not enough space */
						displacement = * (int32_t *) ((modrm_rm == 4) ? &insn_current[4] : &insn_current[3]);
					} else if (modrm_mod == 1) { /* disp8 */
						if ((modrm_rm == 4 && insn_current >= insn_begin - 4) || insn_current >= insn_begin - 3)
							continue; /* Not enough space */
						displacement = (modrm_rm == 4) ? insn_current[4] : insn_current[3];
					} else if (modrm_mod == 0) { /* dereference */
						displacement = 0;
					} else {
						BUG();
					}
					return displacement;
				}
			}
		}
		__send_packet_error(EFAULT, packet_counter, __send_message);
		return (unsigned long) -1;
	}
#elif defined(__aarch64__)
	#define __arch_default_prot() __pgprot(0x68000000000713) /* This is PROT_NORMAL, without the nG bit that requires a flag check against a non-existing symbol */
	static unsigned long __arch_get_addr_offset(void)
	{
		const uint32_t *insn;
		for (insn = (const uint32_t *) free_vm_area;; ++insn) {
			/* ldr xX, [xY + offset] (no increment) */
			if ((*insn & 0xffc00000u) == 0xf9400000)
				return ((*insn >> 10) & 0xfffu) << 3;
		}
	}
#else
	#define ARCH_NO_GENERIC_PHYS_ACCESS
#endif

#if !defined(ARCH_NO_GENERIC_PHYS_ACCESS)
	static void *map_phys(unsigned long paddr, unsigned long size)
	{
		static unsigned long get_vm_area_addr = -1;
		static unsigned long ioremap_page_range_addr = -1;
		static unsigned long addr_offset = -1;

		unsigned long offset = paddr & ~PAGE_MASK;
		unsigned long end, addr;
		struct vm_struct *area;

		if (get_vm_area_addr == -1)
			get_vm_area_addr = kallsyms_lookup_name("get_vm_area");
		BUG_ON(!get_vm_area_addr);
		#define get_vm_area ((struct vm_struct *(*)(unsigned long size, unsigned long flags)) get_vm_area_addr)

		if (ioremap_page_range_addr == -1)
			ioremap_page_range_addr = kallsyms_lookup_name("ioremap_page_range");
		BUG_ON(!ioremap_page_range_addr);
		#define ioremap_page_range ((int (*)(unsigned long addr, unsigned long end, phys_addr_t phys_addr, pgprot_t prot)) ioremap_page_range_addr)

		/* Find offset: struct vm_struct->addr is the first load offset in free_vm_area */
		if (addr_offset == -1) {
			addr_offset = __arch_get_addr_offset();
			BUG_ON(addr_offset == -1);
		}

		/* Page-align address and size */
		paddr &= PAGE_MASK;
		size = PAGE_ALIGN(size + offset);

		/* Check for wraparound */
		end = paddr + size - 1;
		BUG_ON(!size || end < paddr);
		#if defined(PHYS_MASK)
			BUG_ON(end & ~PHYS_MASK);
		#endif

		/* Get an area to map to */
		area = get_vm_area(size, VM_IOREMAP /* This is probably incorrect, but we don't really care */);
		BUG_ON(!area);

		/* Set up the mapping. ioremap sets ->phys_addr here too, but it does not appear to have any useful effect, and we don't actually know the offset for sure. */
		addr = *(unsigned long *) ((const char *) area + addr_offset);

		/* Add the mapping */
		BUG_ON(ioremap_page_range(addr, addr + size, paddr, __arch_default_prot()));

		return (void *)(addr + offset);
	}

	static void unmap_phys(const void *addr)
	{
		vunmap(addr);
	}
#endif


/* Generic page table walking code */
enum page_level {
	PAGE_LEVEL_PTE,
	PAGE_LEVEL_PMD,
	PAGE_LEVEL_PUD,
	PAGE_LEVEL_P4D,
	PAGE_LEVEL_PGD
};

#if defined(__x86_64__)
	/* The x64 page table uses PFNs, but the linear mappings via *_page_vaddr work. */
	#define pmd_page_vaddr_done(pte)
	#define pud_page_vaddr_done(pmd)
	#define p4d_page_vaddr_done(pud)
	#define pgd_page_vaddr_done(p4d)

	/* pmd_huge and pud_huge are functions here too. */
	__attribute__((weak)) int pmd_huge(pmd_t pmd)
	{
		return !pmd_none(pmd) && (pmd_val(pmd) & (_PAGE_PRESENT|_PAGE_PSE)) != _PAGE_PRESENT;
	}

	__attribute__((weak)) int pud_huge(pud_t pud)
	{
		return !!(pud_val(pud) & _PAGE_PSE);
	}

	/* Make sure to grab pgdir_shift and ptrs_per_p4d as weak symbols in case the target does
	 * not have them yet. See arch/x86/kernel/head64.c for their original definitions.
	 */
	__attribute__((weak)) unsigned int pgdir_shift = 39;
	__attribute__((weak)) unsigned int ptrs_per_p4d = 1;

	/* Set high bits (not part of the page table) */
	static unsigned long fixup_vaddr(unsigned long vaddr)
	{
		static unsigned long va_max_bit = -1, va_highbits = -1;
		if (va_max_bit == -1) {
			va_max_bit = (1ul << PGDIR_SHIFT) << (ilog2(PTRS_PER_PGD) - 1);
			va_highbits = ~((va_max_bit << 1) - 1);
		}
		if (vaddr & va_max_bit)
			vaddr |= va_highbits;
		return vaddr;
	}
#elif defined(__aarch64__)
	/* ARM64 does not have *_page_vaddr functions, because the page table only uses physical addresses */
	#define map_page_paddr(base, get_paddr, ptrs_per) map_phys(get_paddr(base), ptrs_per * sizeof(void *))

	#if !defined(pgd_page_vaddr)
		#define pgd_page_vaddr(pgd_e) map_page_paddr(pgd_e, pgd_page_paddr, PTRS_PER_PGD)
		#define pgd_page_vaddr_done(p4d) unmap_phys(p4d)
	#else
		#define pgd_page_vaddr_done(p4d)
	#endif
	#if !defined(p4d_page_vaddr)
		#define p4d_page_vaddr(p4d_e) map_page_paddr(p4d_e, p4d_page_paddr, PTRS_PER_P4D)
		#define p4d_page_vaddr_done(pud) unmap_phys(pud)
	#else
		#define p4d_page_vaddr_done(pud)
	#endif
	#if !defined(pud_page_vaddr)
		#define pud_page_vaddr(pud_e) map_page_paddr(pud_e, pud_page_paddr, PTRS_PER_PUD)
		#define pud_page_vaddr_done(pmd) unmap_phys(pmd)
	#else
		#define pud_page_vaddr_done(pmd)
	#endif
	#if !defined(pmd_page_vaddr)
		#define pmd_page_vaddr(pmd_e) map_page_paddr(pmd_e, pmd_page_paddr, PTRS_PER_PMD)
		#define pmd_page_vaddr_done(pte) unmap_phys(pte)
	#else
		#define pmd_page_vaddr_done(pte)
	#endif

	/* For some reason, pud_huge and pmd_huge are non-exported functions */
	#define pmd_huge(pmd) (pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT))
	#if !defined(__PAGETABLE_PMD_FOLDED)
		#define pud_huge(pud) (pud_val(pud) && !(pud_val(pud) & PUD_TABLE_BIT))
	#else
		#define pud_huge(pud) 0
	#endif

	#define fixup_vaddr(vaddr) (vaddr)
#else
	/* Paging works with virtual addresses already, or *_page_vaddr are defined properly, so no need to clean up */
	#define pmd_page_vaddr_done(pte)
	#define pud_page_vaddr_done(pmd)
	#define p4d_page_vaddr_done(pud)
	#define pgd_page_vaddr_done(p4d)

	#define fixup_vaddr(vaddr) (vaddr)
#endif


int __walk_page_table(pgd_t *pgd_base, int (*per_entry)(unsigned long address, pte_t *pte, enum page_level level), unsigned long base_address)
{
	int error = 0;
	bool p4d_folded_at_runtime = false;
	unsigned long pgd_index, p4d_index, pud_index, pmd_index, pte_index;
	unsigned long pgd_addr, p4d_addr, pud_addr, pmd_addr, pte_addr;
	pgd_t *pgd, pgd_e;
	p4d_t *p4d, p4d_e;
	pud_t *pud, pud_e;
	pmd_t *pmd, pmd_e;
	pte_t *pte, pte_e;

	/* The page table is an array of pgd_t (= unsigned long).
	 * Note that we do not use this to dump memory, as unmapped memory may still contain
	 * important data that we want to keep (not for initial analysis, but maybe later).
	 * Beware that your paging needs to be configured in the right way - otherwise, things
	 * break.
	 * TODO: Detect how many layers of paging there actually are on the target machine
	 * as opposed to relying on build-time defaults.
	 */

	pgd = pgd_base;

	#if defined(__x86_64__)
	/* NB: On x86-64 with 5-level paging support on systems with 4-level paging, pgd_present
	 * wíll always be true (even on an empty entry like this one), but it is actually the second
	 * level that is folded...
	 *
	 * TODO: Make sure that the x86-64 module runs on systems that aren't compiled with 5-level paging support!
	 */
	p4d_folded_at_runtime = !(__read_cr4() & X86_CR4_LA57); /* See arch/x86/boot/compressed/kaslr.c */
	#endif

	for (pgd_index = 0; pgd_index < PTRS_PER_PGD; ++pgd_index, ++pgd) {
		pgd_addr = base_address | (pgd_index << PGDIR_SHIFT);
		pgd_e = READ_ONCE(*pgd);
		if (!pgd_present(pgd_e) && !p4d_folded_at_runtime) /* If p4d_folded_at_runtime, pgd_present does not matter, and we need to check p4d_present later. This is counterintuitive! */
			continue;
		if (pgd_huge(pgd_e)) {
			if ((error = per_entry(fixup_vaddr(pgd_addr), (pte_t *) pgd, PAGE_LEVEL_PGD)))
				goto end;
			continue;
		}
		p4d = p4d_folded_at_runtime ? (p4d_t *) pgd : (p4d_t *) pgd_page_vaddr(pgd_e);
		if (!p4d)
			continue;

#if defined(__PAGETABLE_P4D_FOLDED)
		(void) p4d_index;
		p4d_addr = pgd_addr;
		p4d_e = READ_ONCE(*p4d);
		if (!p4d_present(p4d_e))
			continue;
		pud = (pud_t *) p4d;
		if (!pud)
			continue;
		{
#else
		for (p4d_index = 0; p4d_index < PTRS_PER_P4D; ++p4d_index, ++p4d) {
			p4d_addr = pgd_addr | (p4d_index << P4D_SHIFT);
			p4d_e = READ_ONCE(*p4d);
			if (!p4d_present(p4d_e))
				continue;
			if (p4d_huge(p4d_e)) {
				if ((error = per_entry(fixup_vaddr(p4d_addr), (pte_t *) p4d, PAGE_LEVEL_P4D)))
					goto end;
				continue;
			}
			pud = (pud_t *) p4d_page_vaddr(p4d_e);
			if (!pud)
				continue;
#endif

#if defined(__PAGETABLE_PUD_FOLDED)
			(void) pud_index;
			pud_addr = p4d_addr;
			pud_e = READ_ONCE(*pud);
			if (!pud_present(pud_e))
				continue;
			pmd = (pmd_t *) pud;
			if (!pmd)
				continue;
			{
#else
			for (pud_index = 0; pud_index < PTRS_PER_PUD; ++pud_index, ++pud) {
				pud_addr = p4d_addr | (pud_index << PUD_SHIFT);
				pud_e = READ_ONCE(*pud);
				if (!pud_present(pud_e))
					continue;
				if (pud_huge(pud_e)) {
					if ((error = per_entry(fixup_vaddr(pud_addr), (pte_t *) pud, PAGE_LEVEL_PUD)))
						goto end;
					continue;
				}
				pmd = (pmd_t *) pud_page_vaddr(pud_e);
				if (!pmd)
					continue;
#endif

#if defined(__PAGETABLE_PMD_FOLDED)
				(void) pmd_index;
				pmd_addr = pud_addr;
				pmd_e = READ_ONCE(*pmd);
				if (!pmd_present(pmd_e))
					continue;
				pte = (pte_t *) pmd;
				if (!pte)
					continue;
				{
#else
				for (pmd_index = 0; pmd_index < PTRS_PER_PMD; ++pmd_index, ++pmd) {
					pmd_addr = pud_addr | (pmd_index << PMD_SHIFT);
					pmd_e = READ_ONCE(*pmd);
					if (!pmd_present(pmd_e))
						continue;
					if (pmd_huge(pmd_e)) {
						if ((error = per_entry(fixup_vaddr(pmd_addr), (pte_t *) pmd, PAGE_LEVEL_PMD)))
							goto end;
						continue;
					}
					pte = (pte_t *) pmd_page_vaddr(pmd_e);
					if (!pte)
						continue;
#endif
					for (pte_index = 0; pte_index < PTRS_PER_PTE; ++pte_index, ++pte) {
						pte_addr = pmd_addr | (pte_index << PAGE_SHIFT);
						pte_e = READ_ONCE(*pte);
						if (!pte_present(pte_e))
							continue;
						if ((error = per_entry(fixup_vaddr(pte_addr), (pte_t *) pte, PAGE_LEVEL_PTE)))
							goto end;
					}

#if !defined(__PAGETABLE_PMD_FOLDED)
					pmd_page_vaddr_done(pte);
#endif
				}

#if !defined(__PAGETABLE_PUD_FOLDED)
				pud_page_vaddr_done(pmd);
#endif
			}

#if !defined(__PAGETABLE_P4D_FOLDED)
			p4d_page_vaddr_done(pud);
#endif
		}

		pgd_page_vaddr_done(p4d);
	}

end:
	return error;
}


#define PTE_DATA_TYPE typeof(pte_val(* (pte_t *) NULL))
#define PTE_SIZE_ULONGS ((sizeof(PTE_DATA_TYPE) + sizeof(unsigned long) - 1) / sizeof(unsigned long))
#if __SIZEOF_POINTER__ == 8
	int __dump_pte_64(unsigned long vaddr, pte_t *pte, enum page_level level)
	{
		unsigned long paddr = pte_pfn(*pte) << PAGE_SHIFT;
		unsigned long size =
			(level == PAGE_LEVEL_PTE) ? 1ul << PAGE_SHIFT :
			(level == PAGE_LEVEL_PMD) ? 1ul << PMD_SHIFT :
			(level == PAGE_LEVEL_PUD) ? 1ul << PUD_SHIFT :
			(level == PAGE_LEVEL_P4D) ? 1ul << P4D_SHIFT :
			(level == PAGE_LEVEL_PGD) ? 1ul << PGDIR_SHIFT : 0;

		PTE_DATA_TYPE value = pte_val(*pte);

		/* Protocol specifies [vaddr: 64 bit, paddr: 64 bit, size: 64 bit, pte entry: variable] in network byte order (the pte entry is copied bytewise) */
		unsigned long message[3 + PTE_SIZE_ULONGS] = { htonll(vaddr), htonll(paddr), htonll(size) };
		memcpy(&message[3], &value, sizeof(PTE_DATA_TYPE));

		__send_packet(PACKET_TYPE_PAGING_DATA, packet_counter, (const char *) message, sizeof(message), __send_message);
		udelay(tx_delay);
		return 0;
	}
#elif __SIZEOF_POINTER__ == 4
	int __dump_pte_32(unsigned long vaddr, pte_t *pte, enum page_level level)
	{
		unsigned long paddr = pte_pfn(*pte) << PAGE_SHIFT;
		unsigned long size =
			(level == PAGE_LEVEL_PTE) ? 1ul << PAGE_SHIFT :
			(level == PAGE_LEVEL_PMD) ? 1ul << PMD_SHIFT :
			(level == PAGE_LEVEL_PUD) ? 1ul << PUD_SHIFT :
			(level == PAGE_LEVEL_P4D) ? 1ul << P4D_SHIFT :
			(level == PAGE_LEVEL_PGD) ? 1ul << PGDIR_SHIFT : 0;

		PTE_DATA_TYPE value = pte_val(*pte);

		/* Protocol specifies [vaddr: 64 bit, paddr: 64 bit, size: 64 bit, pte entry: variable] in network byte order (the pte entry is copied bytewise) */
		unsigned long message[6 + PTE_SIZE_ULONGS] = { 0, htonl(vaddr), 0, htonl(paddr), 0, htonl(size) };
		memcpy(&message[6], &value, sizeof(PTE_DATA_TYPE));

		__send_packet(PACKET_TYPE_PAGING_DATA, packet_counter, (const char *) message, sizeof(message), __send_message);
		udelay(tx_delay);
		return 0;
	}
#endif


/* This is the memory dumping part. It manually walks the page tables to avoid
 * relying on (possibly IRQ-dependent and always changing) system APIs. To ensure
 * noone messes with our memory as much as possible, this should only be invoked
 * within stop_machine, i.e. with dump_memory.
 */

#if defined(__x86_64__)
	int __arch_dump_regs(void) { return 0; } /* We don't really care about any of the registers - CR3 is covered by __arch_dump_page_table */

	int __arch_dump_page_table(void)
	{
		unsigned long cr3 = 0;
		pgd_t *mapped_pgd_table;

		__asm__ volatile (
			"mov %%cr3, %[cr3]\n"
			: [cr3]"=r"(cr3)
		);

		mapped_pgd_table = (pgd_t *) map_phys(cr3 & ((unsigned long) PAGE_MASK), PTRS_PER_PGD * sizeof(void *));
		__walk_page_table(mapped_pgd_table, __dump_pte_64, 0);
		unmap_phys(mapped_pgd_table);

		return 0;
	}
#elif defined(__i386__)
#error "__arch_dump_* not implemented for i386"
#elif defined(__aarch64__)
	int __arch_dump_regs(void)
	{
		/* TODO: Find out if there are any interesting registers that we need */
		return 0;
	}

	int __arch_dump_page_table(void)
	{
		unsigned long ttbr0 = 0, ttbr1 = 0;
		pgd_t *mapped_pgd_table;

		__asm__ volatile (
			"mrs %[ttbr0], TTBR0_EL1\n"
			"mrs %[ttbr1], TTBR1_EL1\n"
			: [ttbr0]"=r"(ttbr0), [ttbr1]"=r"(ttbr1)
		);

		mapped_pgd_table = (pgd_t *) map_phys(ttbr0 & 0x0000fffffffffffful, PTRS_PER_PGD * sizeof(void *));
		__walk_page_table(mapped_pgd_table, __dump_pte_64, 0);
		unmap_phys(mapped_pgd_table);

		mapped_pgd_table = (pgd_t *) map_phys(ttbr1 & 0x0000fffffffffffful, PTRS_PER_PGD * sizeof(void *));
		__walk_page_table(mapped_pgd_table, __dump_pte_64, 0xffff000000000000ul);
		unmap_phys(mapped_pgd_table);

		return 0;
	}
#elif defined(__mips__)
	struct tlb_entry {
		unsigned entry_hi, entry_lo0, entry_lo1, page_mask;
	};

	extern long probe_kernel_read(void *dst, const void *src, size_t size) __attribute__((weak)); /* The kernel overlords decided to rename this in 5.8... */
	extern long copy_from_kernel_nofault(void *dst, const void *src, size_t size) __attribute__((weak)); /* ...to this */

	__attribute__((always_inline, flatten)) static inline void __read_tlb(struct tlb_entry *entry, unsigned index)
	{
#if defined(MIPS_TLB_IS_FOR_R3K)
		index <<= 8;
#endif
		write_c0_index(index);
		tlbw_use_hazard();
		tlb_read();
		tlbw_use_hazard();
		entry->page_mask = read_c0_pagemask();
		entry->entry_hi = read_c0_entryhi();
		entry->entry_lo0 = read_c0_entrylo0();
		entry->entry_lo1 = read_c0_entrylo1();
	}

	__attribute__((always_inline, flatten)) static inline void __write_tlb(struct tlb_entry *entry, unsigned index)
	{
#if defined(MIPS_TLB_IS_FOR_R3K)
		index <<= 8;
#endif
		write_c0_index(index);
		write_c0_pagemask(entry->page_mask);
		write_c0_entryhi(entry->entry_hi);
		write_c0_entrylo0(entry->entry_lo0);
		write_c0_entrylo1(entry->entry_lo1);
		mtc0_tlbw_hazard();
		tlb_write_indexed();
		tlbw_use_hazard();
	}

	#define CHUNK_SIZE 1024
#if !defined(MAPPING_ADDR)
	#define MAPPING_ADDR 0xf0f0f000
#endif
	#define TLB_COUNT 16
	static char _Alignas(PAGE_SIZE) dump_buffer[PAGE_SIZE];
	static uint32_t message_buffer[(CHUNK_SIZE + 3 + 8) / 4];
	typedef enum {
		SKIPPED_HERE = 0x1,
		SKIPPED_HERE_NEXT = 0x2,
		SKIPPED_STACK = 0x4,
		SKIPPED_STACK_NEXT = 0x8,
		SKIPPED_DUMP = 0x10,
		SKIPPED_DUMP_NEXT = 0x20,
	} skip_flags_t;
	int __arch_dump_pfn(unsigned long pfn)
	{
		struct tlb_entry backup, entry, register_values;
		skip_flags_t skip_flags = 0;
		unsigned index, offset, asid, here_key, stack_key, dump_key, backup_key, backup_index;
		typeof(probe_kernel_read) *read_nofault = probe_kernel_read ?: copy_from_kernel_nofault; /* TODO: probe_kernel_read only exists from 2.6.26 onwards */
#if !defined(UKM_MIPS_R3K)
		unsigned config1, config2, config3, grain;
		static int has_1kb_pages = -1;
#endif

		/* Save register values */
		backup_index = read_c0_index();
		register_values.page_mask = read_c0_pagemask();
		register_values.entry_hi = read_c0_entryhi();
		register_values.entry_lo0 = read_c0_entrylo0();
		register_values.entry_lo1 = read_c0_entrylo1();

		if (pfn > 0xffffff)
			return -E2BIG;

#if !defined(UKM_MIPS_R3K)
		if (has_1kb_pages == -1) {
			/* Initializing */
			has_1kb_pages = 0;
			config1 = read_c0_config1(); /* Does CP0 have Config2? */
			if (config1 & MIPS_CONF_M) {
				config2 = read_c0_config2(); /* Does CP0 have Config3? */
				if (config2 & MIPS_CONF_M) {
					config3 = read_c0_config3(); /* Does CP0 support 1KB pages in theory */
					if (config3 & MIPS_CONF3_SP) {
						grain = read_c0_pagegrain(); /* Are 1KB pages enabled */
						if (grain & PG_ESP) {
							debug("1KB pages are enabled\n");
							__send_packet(PACKET_TYPE_TEXT, packet_counter, "1KB pages are enabled\n", 22, __send_message);
							has_1kb_pages = 1;
						}
					}
				}
			}
		}
#endif

		__read_tlb(&backup, 0);

#if defined(UKM_MIPS_R3K)
		/* TODO: Find a way to distinguish R3K at runtime. */
		/* Ugh. */
		asid = backup.entry_hi & 0xfc0; /* No shift here. */
		entry.entry_hi = (MAPPING_ADDR & 0xfffff000) | asid;
		entry.entry_lo0 = (pfn << 12) | (0b1 << 11 /* Non-cacheable */) | (0b0 << 10 /* Read-only */) | (0b1 << 9 /* Valid */) | (0b1 << 8 /* Valid */);
		entry.entry_lo1 = 0; /* This will be ignored. */
		entry.page_mask = 0; /* This should now map 2 pages */
#else
		/* Register descriptions from MIPS Vol. III, ch. 8 - this is different from the TLB format! */
		/* Verified to match arch/mips/lib/dump_tlb.c (which is for R4K CPUs) */
		asid = backup.entry_hi & 0x3ff;
		entry.entry_hi = (MAPPING_ADDR & 0xffffe000) | (0b00 << 11 /* 1kB pages disabled */) | (0b0 << 10 /* Do not invalidate */) | (asid /* ASID (potentially extended) */);
		entry.entry_lo0 = (0b00 << 30 /* RI/XI, or ignored */) | (pfn << 6) | (0b010 << 3 /* Uncacheable */) | (0b0 << 2 /* Read-only */) | (0b1 << 1 /* Valid */) | (0b1 /* Global, ignore ASID */);
		entry.entry_lo1 = entry.entry_lo0;
		entry.page_mask = has_1kb_pages ? (0b11 << 11) : 0; /* 4kB pages */
#endif

		/* Ensure that this code and the stack remains mapped... otherwise we might run into trouble */
		here_key = ((unsigned long) &&probe_tlb) >> (PAGE_SHIFT + 1);
		stack_key = ((unsigned long) &backup) >> (PAGE_SHIFT + 1);
		dump_key = ((unsigned long) dump_buffer) >> (PAGE_SHIFT + 1);

probe_tlb:
		for (index = 0; index < TLB_COUNT; ++index) {
			__read_tlb(&backup, index);
			verbose_debug("pfn=%#lx: tlb#%d { hi=%#x, lo0=%#x, lo1=%#x, mask=%#x }\n", pfn, index, backup.entry_hi, backup.entry_lo0, backup.entry_lo1, backup.page_mask);
			backup_key = backup.entry_hi >> (PAGE_SHIFT + 1);
			if (backup_key == here_key && !(skip_flags & SKIPPED_HERE))
				skip_flags |= SKIPPED_HERE;
			else if (backup_key == here_key + 1 && !(skip_flags & SKIPPED_HERE_NEXT))
				skip_flags |= SKIPPED_HERE_NEXT;
			else if (backup_key == stack_key && !(skip_flags & SKIPPED_STACK))
				skip_flags |= SKIPPED_STACK;
			else if (backup_key == stack_key + 1 && !(skip_flags & SKIPPED_STACK_NEXT))
				skip_flags |= SKIPPED_STACK_NEXT;
			else if (backup_key == dump_key && !(skip_flags & SKIPPED_DUMP))
				skip_flags |= SKIPPED_DUMP;
			else if (backup_key == dump_key + 1 && !(skip_flags & SKIPPED_DUMP_NEXT))
				skip_flags |= SKIPPED_DUMP_NEXT;
			else
				goto found_tlb_entry;
		}
		__send_packet_error(ENOMEM, packet_counter, __send_message);
		return -ENOMEM;

found_tlb_entry:
		verbose_debug("pfn=%#lx: ENT#%d { hi=%#x, lo0=%#x, lo1=%#x, mask=%#x }\n", pfn, index, entry.entry_hi, entry.entry_lo0, entry.entry_lo1, entry.page_mask);
		__write_tlb(&entry, index);
		__read_tlb(&backup, index);
		verbose_debug("pfn=%#lx: VFY#%d { hi=%#x, lo0=%#x, lo1=%#x, mask=%#x }\n", pfn, index, backup.entry_hi, backup.entry_lo0, backup.entry_lo1, backup.page_mask);
		if (memcmp(&entry, &backup, sizeof(entry)) != 0) {
			debug("Failed to adjust TLB entry (no observable change)");
			goto probe_tlb;
		}
		if (read_nofault) {
			if (read_nofault(dump_buffer, (const char *) MAPPING_ADDR, PAGE_SIZE)) {
				debug("Failed to copy data");
				__read_tlb(&backup, index);
				verbose_debug("pfn=%#lx: RCK#%d { hi=%#x, lo0=%#x, lo1=%#x, mask=%#x }\n", pfn, index, backup.entry_hi, backup.entry_lo0, backup.entry_lo1, backup.page_mask);
				goto probe_tlb;
			}
		} else {
			for (offset = 0; offset < PAGE_SIZE; ++offset)
				dump_buffer[offset] = ((const char *) MAPPING_ADDR)[offset];
		}

		for (offset = 0; offset < PAGE_SIZE; offset += CHUNK_SIZE) {
			message_buffer[0] = htonl((sizeof(unsigned long) > 32) ? (pfn << PAGE_SHIFT) >> 32 : 0);
			message_buffer[1] = htonl(((pfn << PAGE_SHIFT) & 0xffffffffu) + offset);
			memcpy(&message_buffer[2], &dump_buffer[offset], offset + CHUNK_SIZE > PAGE_SIZE ? PAGE_SIZE - offset : CHUNK_SIZE);
			__send_packet(PACKET_TYPE_MEMORY_DATA, packet_counter, (const char *) message_buffer, sizeof(message_buffer), __send_message);
		}

		/* Restore register values */
		write_c0_pagemask(register_values.page_mask);
		write_c0_entryhi(register_values.entry_hi);
		write_c0_entrylo0(register_values.entry_lo0);
		write_c0_entrylo1(register_values.entry_lo1);
		write_c0_index(backup_index);

		udelay(tx_delay);
		return 0;
	}

	static uint32_t _Alignas(PAGE_SIZE) register_block[8 * 32];
	int __arch_dump_regs(void)
	{
		/* General-purpose registers are fairly useless here - we are
		 * using them all the time anyways. We could either dump the
		 * current userspace register values (we want to grab those
		 * later anyways) but since that would just duplicate the
		 * task_struct, we just limit ourselves to the C0 registers.
		 *
		 * TODO: Instead of hardcoding register checks, find out if
		 * there is a way to know whether a register exists in the
		 * first place
		 */
		#define __is_c0_banned(source, index) (/* Page walker registers */ (source == 5 && index >= 5) || (source == 6 && index == 6))
		#define __read_one_c0_register_indexed(source, into, index) into[index] = __is_c0_banned(source, index) ? 0xffffffffu : __read_32bit_c0_register(CONCATENATE($, source), index)
		#define __read_one_c0_register_full(source, into) do { \
			__read_one_c0_register_indexed(source, into, 0); \
			__read_one_c0_register_indexed(source, into, 1); \
			__read_one_c0_register_indexed(source, into, 2); \
			__read_one_c0_register_indexed(source, into, 3); \
			__read_one_c0_register_indexed(source, into, 4); \
			__read_one_c0_register_indexed(source, into, 5); \
			__read_one_c0_register_indexed(source, into, 6); \
			__read_one_c0_register_indexed(source, into, 7); \
		} while (0)
		#define __read_one_c0_register_into(source, into) __read_one_c0_register_full(source, ((uint32_t *) &into[source * 8]))
		#define __read_c0_registers(into) do { \
			__read_one_c0_register_into(0, into); \
			__read_one_c0_register_into(1, into); \
			__read_one_c0_register_into(2, into); \
			__read_one_c0_register_into(3, into); \
			__read_one_c0_register_into(4, into); \
			__read_one_c0_register_into(5, into); \
			__read_one_c0_register_into(6, into); \
			__read_one_c0_register_into(7, into); \
			__read_one_c0_register_into(8, into); \
			__read_one_c0_register_into(9, into); \
			__read_one_c0_register_into(10, into); \
			__read_one_c0_register_into(11, into); \
			__read_one_c0_register_into(12, into); \
			__read_one_c0_register_into(13, into); \
			__read_one_c0_register_into(14, into); \
			__read_one_c0_register_into(15, into); \
			__read_one_c0_register_into(16, into); \
			__read_one_c0_register_into(17, into); \
			__read_one_c0_register_into(18, into); \
			__read_one_c0_register_into(19, into); \
			__read_one_c0_register_into(21, into); \
			__read_one_c0_register_into(22, into); \
			__read_one_c0_register_into(23, into); \
			__read_one_c0_register_into(24, into); \
			__read_one_c0_register_into(25, into); \
			__read_one_c0_register_into(26, into); \
			__read_one_c0_register_into(27, into); \
			__read_one_c0_register_into(28, into); \
			__read_one_c0_register_into(29, into); \
			__read_one_c0_register_into(30, into); \
			__read_one_c0_register_into(31, into); \
		} while (0);

		__read_c0_registers(register_block);
		__send_packet(PACKET_TYPE_REGISTER_DATA, packet_counter, (const char *) register_block, sizeof(register_block), __send_message);
		return 0;
	}

	__asm__(
		".pushsection .rodata\n"
		".set push\n"
		".set noreorder\n"
		".local __mips_jr_ra\n"
		".type __mips_jr_ra, @object\n"
		"__mips_jr_ra:\n"
		"    jr $ra\n"
		"    nop\n"
		".local __mips_jr_ra_size\n"
		".type __mips_jr_ra_size, @object\n"
		"__mips_jr_ra_size:\n"
		"    .long (__mips_jr_ra_size - __mips_jr_ra) / 4\n"
		".set pop\n"
		".popsection\n"
	);
	extern unsigned long __mips_jr_ra_size;
	extern uint32_t __mips_jr_ra[];

	extern struct mm_struct init_mm __attribute__((weak));
	extern pte_t invalid_pte_table[PAGE_SIZE / sizeof(pte_t)];

	extern void use_mm(struct mm_struct *mm) __attribute__((weak)); /* Try to use this symbol if it exists */
	extern struct pid *find_vpid(int nr) __attribute__((weak)); /* ...otherwise use this one */

	typedef void *(*__vmalloc_t)(unsigned long, gfp_t, pgprot_t);
	typedef void *(*__vmalloc_node_range_t)(unsigned long size, unsigned long align, unsigned long start, unsigned long end, gfp_t gfp_mask, pgprot_t prot, unsigned long vm_flags, int node, const void *caller);

	unsigned long copied_page[PAGE_SIZE / sizeof(unsigned long)];

	int __arch_dump_page_table(void) /* It is sufficient for this function to dump all information necessary to locate the page table in the physical memory dump */
	{
		/* NB: This is not exported on all kernels, but it always exists. But on old kernels, this is __init - and therefore doesn't work.
		 * Beware that it may still be inlined (static!), but from testing it does not usually appear to be - even on the ancient low-end router kernels, it
		 * shows up in kallsyms despite being unloaded (i.e. the memory is now used for other purposes...)
		 * This function is
		 *     static void __init __attribute__((unused)) (- 2.6.21)
		 *     static void __init __maybe_unused (2.6.22 - 2.6.23)
		 *     static void __cpuinit __maybe_unused (2.6.24 - 3.10)
		 *     static void __maybe_unused (3.11 - 4.10)
		 *     void (4.11 -) (+ EXPORT_SYMBOL_GPL)
		 * This means that before 3.11, we cannot use it to find the location of pgd_current[THIS_CPU] (or any page table).
		 * Of course, if CONFIG_MIPS_PGD_C0_CONTEXT is defined (off by default essentially everywhere we are interested in right now), everything becomes easier.
		 * If there was an easy way to access swapper_pg_dir or init_mm (which contains .pgd = swapper_pg_dir), things would be much nicer, but those are very
		 * explicitly not exported (see e.g. comments on kvm_mips_suspend_mm). pgd_alloc is almost what we want, but only copies the userspace entries from init_mm.
		 * Since 5.2, there is also copy_init_mm, but obviously that is too new for us.
		 *
		 * We can use init_mm directly on kernels up to 2.6.30, but we have no such luck for 2.6.31 - 3.10. In theory, init_task.active_mm should point to init_mm,
		 * but this appears to only be the case while init_task is scheduled (i.e. not while our module is loading). Regardless, we should be able to use our own
		 * memory map. To find `current`, we partially disassemble `use_mm` (a fairly stable accessor function that also works well to get active_mm if needed).
		 */
		static unsigned long build_get_pgde32_addr = -1;
		static unsigned long __vmalloc_node_range_addr = -1;

		int i, ref_to_invalid_count, best_ref_to_invalid_count, error;
		unsigned target, current_offset, pgd_offset;
#if !defined(UKM_MIPS_R3K)
		unsigned config0;
#endif
		uint32_t *page, *orig_page;
		void *get_pgde32;
		unsigned long pt_vaddr, pgd_candidate;
		struct task_struct *current_ptr;
		struct mm_struct *mm_ptr = NULL;
		typeof(probe_kernel_read) *read_nofault = probe_kernel_read ?: copy_from_kernel_nofault; /* TODO: probe_kernel_read only exists from 2.6.26 onwards */

		if (build_get_pgde32_addr == -1)
			build_get_pgde32_addr = __kallsyms_lookup_name("build_get_pgde32");
		#define build_get_pgde32 ((void (*)(u32 **, unsigned int, unsigned int)) build_get_pgde32_addr)

		if (version_before(version, 3, 11, 0) || !build_get_pgde32) {
			/* Cannot use build_get_pgde32 - walk init_mm if possible. */
			if (&init_mm) {
				/* We have access to init_mm directly! This only happens in very old kernels (- 2.6.30) */
				mm_ptr = &init_mm;
			} else if ((mm_ptr = (struct mm_struct *) __kallsyms_lookup_name("init_mm"))) {
				/* We got lucky, CONFIG_KALLSYMS_ALL is enabled */
			} else {
				/* We can find init_mm via init_task.active_mm == &init_mm. To find the offset of active_mm, use the `use_mm` accessor function.
				 * TODO: Verify that this is sane if SMP is enabled and task_lock does something!
				 */
				page = (&use_mm ? (uint32_t *) &use_mm : &find_vpid ? (uint32_t *) &find_vpid : NULL);
				if (!page) {
					__send_packet(PACKET_TYPE_TEXT, packet_counter, "Neither use_mm nor find_vpid found\n", 35, __send_message);
					__send_packet_error(EFAULT, packet_counter, __send_message);
					return -EFAULT;
				}

				/* Find the load of `current` (lw relative to $gp) */
				while ((*page & 0xffe00000u) != 0x8f800000u)
					++page;

				/* Grab `current` */
				current_offset = (*page & 0xffff);
				if (current_offset > 0x200 || current_offset % 4 != 0) {
					__send_packet(PACKET_TYPE_TEXT, packet_counter, "Offset of 'current' exceeds 0x200 or is not aligned to 4 bytes\n", 58, __send_message);
					__send_packet_error(EFAULT, packet_counter, __send_message);
					return -EFAULT;
				}
				__asm__ volatile("move %[into], $gp\n" : [into]"=r"(target));
				current_ptr = *(struct task_struct **)(target + current_offset);

				mm_ptr = get_task_mm(current_ptr);
				mmput(mm_ptr);
			}
			/* Find .pgd member */
			best_ref_to_invalid_count = 0;
			pt_vaddr = 0;
			for (pgd_offset = 0; pgd_offset < 0x100; ++pgd_offset) {
				pgd_candidate = *((const unsigned long *) mm_ptr + pgd_offset);
				if (!pgd_candidate || pgd_candidate & 0xfff) /* Should technically also check that virt_addr_valid(pgd_candidate), but this sometimes requires __virt_addr_valid and sometimes not */
					continue;
				if (read_nofault(copied_page, (const void *) pgd_candidate, PAGE_SIZE)) /* Use probe_kernel_read to catch the fault if the page is not mapped (we should use _strict, but it doesn't always exist yet) */
					continue;
				/* Evaluate candidate - we expect quite a lot of pointers to invalid_pte_table... */
				ref_to_invalid_count = 0;
				for (i = 0; i < PAGE_SIZE / sizeof(unsigned long); ++i)
					if (copied_page[i] == (unsigned long) &invalid_pte_table[0])
						++ref_to_invalid_count;
				if (ref_to_invalid_count > best_ref_to_invalid_count) {
					best_ref_to_invalid_count = ref_to_invalid_count;
					pt_vaddr = pgd_candidate;
				}
			}
			if (!pt_vaddr) {
				__send_packet_error(ENOENT, packet_counter, __send_message);
				return -ENOENT;
			}
		} else {
			/* The prot argument to __vmalloc went away in 5.8 */
			if (version_before(version, 5, 8, 0)) {
				orig_page = page =  ((__vmalloc_t) &__vmalloc)(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_EXEC);
			} else {
				if (__vmalloc_node_range_addr == -1)
					__vmalloc_node_range_addr = __kallsyms_lookup_name("__vmalloc_node_range");
				if (__vmalloc_node_range_addr == -1 || !__vmalloc_node_range_addr) {
					print_once(KERN_ERR "Failed to find __vmalloc_node_range!\n");
					__send_packet_error(ENOSYS, packet_counter, __send_message);
					return -ENOSYS;
				}

				orig_page = page = ((__vmalloc_node_range_t) __vmalloc_node_range_addr)(PAGE_SIZE, 1, VMALLOC_START, VMALLOC_END, GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE, __builtin_return_address(0));
			}
			if (!page) {
				__send_packet_error(ENOMEM, packet_counter, __send_message);
				return -ENOMEM;
			}

			get_pgde32 = page;
			build_get_pgde32(&page, 8, 2); /* 2: $v0, 8: $t0 */

			/* Add return sequence: jr $ra; nop */
			for (i = 0; i < __mips_jr_ra_size; ++i)
				*page++ = __mips_jr_ra[i];

			/* Unfortunately, C0_BADVADDR is read-only per the spec (Vol. III, p. 177, ch. 9.24), so we need to compensate instead
			 * of setting this to zero. After get_pgde32, we always (for now!) have tmp = $t0 = (bad_vaddr >> PGDIR_SHIFT) << PGD_T_LOG2,
			 * which is exactly the offset added by get_pgde32. This should not change any time soon, but it might be worth verifying...
			 * TODO: Find something a little more stable.
			 */
			__asm__ volatile(
				"jalr %[get_pgde32]\n"
				"subu $v0, $v0, $t0\n"
				"move %[pt], $v0\n"
				: [pt]"=r"(pt_vaddr)
				: [get_pgde32]"r"(get_pgde32)
				: "$v0", "$t0"
			);
			vfree(orig_page);

			if (pt_vaddr & 0xfff) {
				/* The page table is page-aligned - this is a bug! */
				__send_packet(PACKET_TYPE_TEXT, packet_counter, "Page table is not page-aligned - verify assumptions\n", 52, __send_message);
				__send_packet_error(EFAULT, packet_counter, __send_message);
				return -EFAULT;
			}
		}

#if !defined(UKM_MIPS_R3K)
		/* Check we have a normal TLB-based MMU (otherwise, we can't walk it properly) */
		config0 = read_c0_config();
		if ((config0 & MIPS_CONF_MT) != MIPS_CONF_MT_TLB) {
			__send_packet(PACKET_TYPE_TEXT, packet_counter, "Not a standard TLB\n", 19, __send_message);
			__send_packet_error(EFAULT, packet_counter, __send_message);
			return -EFAULT;
		}

		/* TODO: Check we actually have 4KB pages as opposed to 1KB pages (CP0 Config3 SP) */
#endif

		/* Walk the page table */
		error = __walk_page_table((pgd_t *) pt_vaddr, __dump_pte_32, 0);
		if (error)
			__send_packet_error(-error, packet_counter, __send_message);

		/* Clean up */
		if (mm_ptr)
			mmput(mm_ptr);
		return error;
	}
#else
#error "__arch_dump_* not implemented on this architecture"
#endif

#if !defined(ARCH_NO_GENERIC_PHYS_ACCESS) && !defined(ARCH_OVERRIDE_GENERIC_DUMP_PFN)
/* If we have map_phys / unmap_phys implemented on this architecture and there is no override, use a generic version of __arch_dump_pfn */
#define CHUNK_SIZE 1024
static _Alignas(8) char message_buffer[8 + CHUNK_SIZE];
int __arch_dump_pfn(unsigned long pfn)
{
	unsigned long offset;
	const char *mapped_page = map_phys(pfn << PAGE_SHIFT, PAGE_SIZE);
	for (offset = 0; offset < PAGE_SIZE; offset += CHUNK_SIZE) {
		*((uint64_t *) &message_buffer[0]) = htonll((pfn << PAGE_SHIFT) + offset);
		memcpy(&message_buffer[8], &mapped_page[offset], offset + CHUNK_SIZE > PAGE_SIZE ? PAGE_SIZE - offset : CHUNK_SIZE);
		__send_packet(PACKET_TYPE_MEMORY_DATA, packet_counter, message_buffer, sizeof(message_buffer), __send_message);
	}
	unmap_phys(mapped_page);

	udelay(tx_delay);
	return 0;
}
#endif

#if !defined(ARCH_HAVE_DUMP_MEMORY)
/* By default, simply walk all the PFNs. Architectures can override this if necessary. */
int __arch_dump_memory(void)
{
	/* I would love to use min_low_pfn and max_pfn / highend_pfn here, but
	 * they are not exported and not consistent between versions and
	 * architectures. We can probably safely iterate pgdats and zones across
	 * versions, but the offsets of the zone_start_pfn and spanned_pages are
	 * unknown. /proc/zoneinfo has the necessary information, but it is a
	 * pain to read it from the kernel (although at least the format is
	 * somewhat stable). See parse_options to find the range parsing that we
	 * do.
	 */

	int error = 0;
	unsigned long pfn, it;
	for (it = 0; it < memory_range_count && !error; ++it)
		for (pfn = memory_ranges[it].start_pfn; pfn <= memory_ranges[it].end_pfn && !error; ++pfn)
			error = __arch_dump_pfn(pfn);
	return error;
}
#endif

int __locked_dump_memory(void * __attribute__((unused)) data)
{
	int error = 0;
	if ((error = __lock_init()))
		return error;

	__send_packet_ready(packet_counter, __send_message);
	if (!error) error = __arch_dump_regs();
	if (!error) error = __arch_dump_memory();
	if (!error) error = __arch_dump_page_table();
	__send_packet_done(packet_counter, __send_message);

	__lock_done();
	return error;
}

int dump_memory(void)
{
	int error;
	error = lock_cpus(__locked_dump_memory, NULL);
	if (error)
		printk(KERN_ERR "Memory dump failed\n");
	return error;
}


/* Initialization on load: Sets up networking and triggers the memory dump. */
int __init init(void)
{
	int error;
	printk(KERN_NOTICE "Loading configuration %s\n", config);

	if ((error = parse_options()))
		return error;

	/* We need kallsyms_lookup_name for this. Make sure it is available. */
	if (&kallsyms_lookup_name) {
		__kallsyms_lookup_name = &kallsyms_lookup_name;
	} else if (&kallsyms_on_each_symbol) {
		kallsyms_on_each_symbol(__maybe_set_kallsyms_lookup_name, NULL);
	} else {
		/* TODO: Implement some fallback with kprobes here */
		printk(KERN_ERR "Neither kallsyms_lookup_name nor kallsyms_on_each_symbol are available\n");
		return -EFAULT;
	}

	if (!__kallsyms_lookup_name) {
		printk(KERN_ERR "Kallsyms support is required but incomplete.\n");
		return -EFAULT;
	}

	/* Set up networking */
	if ((error = setup_network()))
		return error;

	printk(KERN_NOTICE "Module ready.\n");

	/* TODO: It would be nice to have a separate channel to trigger the memory dump */
	dump_memory();

	return 0;
}

/* Cleanup on unload: Gives back all the networking stuff. */
void __exit cleanup(void)
{
	cleanup_network();
	printk(KERN_NOTICE "Module unloaded.\n");
}

module_init(init)
module_exit(cleanup)
