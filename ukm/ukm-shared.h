#ifndef __UKM_MOD_H__
#define __UKM_MOD_H__

/* Shared utilities for both UKM kernel modules and the loader */

#define __STRINGIFY(s) #s
#define STRINGIFY(s) __STRINGIFY(s)

/* Using module parameters limits compatibility because the API keeps changing
 * (esp. with 2.6.36 by including the param_ops_* symbols, but also in other
 * versions by changing the layout of struct kernel_param). We therefore need
 * another way to communicate options to a UKM. In theory, we still have the
 * args member in struct module, but that is automatically parsed and triggers
 * a loading error on any unknown parameter. A more feasible idea is to
 * statically replace an argument string at load time. We use a custom section
 * to make finding this as easy as possible.
 */
#if !defined(MAX_ARG_LENGTH)
	#define MAX_ARG_LENGTH 256
#endif
#define UKM_ARG_SECTION "__ukm_args"
#define UKM_ARGS(name) \
	asm ( \
		".pushsection " UKM_ARG_SECTION ", \"wa\", @progbits\n" \
		".global " STRINGIFY(name) "\n" \
		".type " STRINGIFY(name) " STT_OBJECT\n" \
		".size " STRINGIFY(name) ", " STRINGIFY(MAX_ARG_LENGTH) "\n" \
		STRINGIFY(name) ":\n" \
		"        .skip " STRINGIFY(MAX_ARG_LENGTH) "\n" \
		".popsection\n" \
	); \
	extern char name[MAX_ARG_LENGTH] /* Can't use __attribute__((section(...))) because that would not set the section flags */


struct ukm_kernel_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patch;
} __attribute__((packed));

#define version_before(version, _major, _minor, _patch) ( \
	((version).major < (_major)) || \
	((version).major == (_major) && (version).minor < (_minor)) || \
	((version).major == (_major) && (version).minor == (_minor) && (version).patch < (_patch)) \
)
#define version_after(version, _major, _minor, _patch) ( \
	((version).major > (_major)) || \
	((version).major == (_major) && (version).minor > (_minor)) || \
	((version).major == (_major) && (version).minor == (_minor) && (version).patch > (_patch)) \
)

/* We also need to provide the module with the kernel version that it is running
 * on, because some functions change their API without changing their name
 * between versions. This is ultimately always a heuristic, but a pretty decent
 * one.
 */
#define UKM_KERNEL_VERSION_SECTION "__ukm_version"
#define UKM_KERNEL_VERSION_SPACE 16
#define UKM_KERNEL_VERSION(name) \
	asm ( \
		".pushsection " UKM_KERNEL_VERSION_SECTION ", \"a\", @progbits\n" \
		".global " STRINGIFY(name) "\n" \
		".type " STRINGIFY(name) " STT_OBJECT\n" \
		".size " STRINGIFY(name) ", " STRINGIFY(UKM_KERNEL_VERSION_SPACE) "\n" \
		STRINGIFY(name) ":\n" \
		"        .skip " STRINGIFY(UKM_KERNEL_VERSION_SPACE) "\n" \
		".popsection\n" \
	); \
	extern struct ukm_kernel_version name;

_Static_assert(sizeof(struct ukm_kernel_version) + _Alignof(struct ukm_kernel_version) <= UKM_KERNEL_VERSION_SPACE, "UKM_KERNEL_VERSION_SPACE is too small.");

#endif
