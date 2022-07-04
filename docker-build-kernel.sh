#!/bin/bash

set -eux

function die {
	echo "$@" >&2
	exit 1
}

# Check arguments
PROC="$0"
[ "$#" -ge 1 ] || die "Usage: $PROC [options] <tag or commit>"

# Set up output directory
OUTDIR="/output"
mkdir -p $OUTDIR

# Make a temporary directory for the GCC plugin
TMPDIR="/tmpdir"
mkdir -p $TMPDIR/flowana
mkdir -p $TMPDIR/const_structs

PLUGIN_ARG="-fplugin-arg-flowana-outdir=\"$TMPDIR/flowana\""
PLUGIN_ARG_STRUCT="-fplugin-arg-const_structs-outdir=\"$TMPDIR/const_structs\""
DISABLE_PLUGIN="n"
EXTRA_CFLAGS=""
DROP_INTO_BASH="n"
GCC_VERSION="5"
DEFCONFIG="n"
SUFFIX=""
RANDOMIZE="n"
RANDSTRUCT="n"
ENV_VARS=()
EXTRA_CONFIGS=()
while [ "$#" -ge 2 ]; do
	case "$1" in
		--debug)
			shift 1
			PLUGIN_ARG="-fplugin-arg-flowana-debug=true"
			;;
		--no-plugin)
			shift 1
			PLUGIN_ARG=""
			PLUGIN_ARG_STRUCT=""
			DISABLE_PLUGIN="y"
			;;
		--target)
			shift 1
			TARGET="$1"
			shift 1
			;;
		--dump-tree)
			shift 1
			EXTRA_CFLAGS="-fdump-tree-all"
			;;
		--def)
			shift 1
			DEFCONFIG="y"
			;;
		--randstruct)
			shift 1
			RANDSTRUCT="y"
			;;
		--suffix)
			shift 1
			SUFFIX="$1"
			shift 1
			;;
		--randomize)
			shift 1
			RANDOMIZE="y"
			;;
		--env)
			shift 1
			ENV_VARS+=("$1")
			shift 1
			;;
		--config)
			shift 1
			EXTRA_CONFIGS+=("$1")
			shift 1
			;;
		--gcc)
			shift 1
			GCC_VERSION="$1"
			shift 1
			;;
		--bash)
			shift 1
			DROP_INTO_BASH="y"
			;;
		*)
			die "Unknown option: $1"
			;;
	esac
done

# Setup gcc tooling
BINDIR="/newbin"
mkdir -p $BINDIR
ln -s "/usr/bin/gcc-$GCC_VERSION" /newbin/gcc
export PATH=/newbin:"$PATH"
export MAKEFLAGS="-j8"

[ "$#" -eq 1 ] || die "Usage: $PROC [options] <tag or commit>"
TAG="$1"

# Clean up
make mrproper
# Check out tag
git checkout --force "$TAG"
# Create config (x86_64, with debug info)
if [ $RANDOMIZE = "y" -a $DEFCONFIG = "y" ]; then
	die "Cannot use --def and --randomize together."
fi

# Force-enable certain options (debug info, 64-bit SMP kernel, printk & modules)
echo -e 'CONFIG_64BIT=y\nCONFIG_DEBUG_KERNEL=y\nCONFIG_DEBUG_INFO=y\nCONFIG_SMP=y\nCONFIG_PRINTK=y\nCONFIG_MODULES=y' > "$TMPDIR/allconfig"
echo -e 'CONFIG_DEBUG_INFO_REDUCED=n\nCONFIG_DEBUG_INFO_SPLIT=n\nCONFIG_COMPILE_TEST=n' >> "$TMPDIR/allconfig" # Make sure debug info is valid
if [ $RANDSTRUCT = "y" ]; then
	echo -e "CONFIG_GCC_PLUGIN_RANDSTRUCT=y" >> "$TMPDIR/allconfig"
else
	echo -e 'CONFIG_GCC_PLUGIN_RANDSTRUCT=n' >> "$TMPDIR/allconfig"
fi
echo -e 'CONFIG_DEBUG_INFO_BTF=n' >> "$TMPDIR/allconfig" # pahole on this system is too old :(
if [ ! -z "${EXTRA_CONFIGS+set}" ]; then
	for option in "${EXTRA_CONFIGS[@]}"; do
		echo "$option" >> "$TMPDIR/allconfig"
	done
fi

if [ $DISABLE_PLUGIN = "n" ]; then
	if [ $RANDSTRUCT = "y" ]; then
		PLUGIN_ARG_STRUCT="$PLUGIN_ARG_STRUCT -fplugin-arg-const_structs-noregister"
		PLUGIN_ARG="" # Disable flowana für --randstruct
	else
		PLUGIN_ARG_STRUCT="$PLUGIN_ARG_STRUCT -DRANDSTRUCT_PLUGIN"
	fi
fi

if [ $DEFCONFIG = "y" ]; then
	if [ ! -z "${ENV_VARS+set}" ]; then
		MAKEFLAGS="" make defconfig "${ENV_VARS[@]}"
	else
		MAKEFLAGS="" make defconfig
	fi
	# defconfig does not parse KCONFIG_ALLCONFIG :/
	while read option; do
		if [ -z "$option" ]; then
			continue
		fi
		VARNAME="${option%%=*}"
		VARVAL="${option#*=}"
		case "$VARVAL" in
			"y")
				scripts/config --enable "$VARNAME"
				;;
			"n")
				scripts/config --disable "$VARNAME"
				;;
			"m")
				scripts/config --module "$VARNAME"
				;;
			*)
				scripts/config --set-val "$VARNAME" "$VARVAL"
				;;
		esac
	done < "$TMPDIR/allconfig"
	CONFIG="olddefconfig"
	FALLBACK_CONFIG="oldconfig"
elif [ $RANDOMIZE = "y" ]; then
	CONFIG="randconfig"
else
	CONFIG="allnoconfig"
fi

if [ ! -z "${ENV_VARS+set}" ]; then
	env MAKEFLAGS="" KCONFIG_ALLCONFIG="$TMPDIR/allconfig" make "$CONFIG" "${ENV_VARS[@]}" || { \
		[ -n "${FALLBACK_CONFIG+set}" ] && env MAKEFLAGS="" KCONFIG_ALLCONFIG="$TMPDIR/allconfig" make "$FALLBACK_CONFIG" "${ENV_VARS[@]}"; \
	}
else
	env MAKEFLAGS="" KCONFIG_ALLCONFIG="$TMPDIR/allconfig" make "$CONFIG" || { \
		[ -n "${FALLBACK_CONFIG+set}" ] && env MAKEFLAGS="" KCONFIG_ALLCONFIG="$TMPDIR/allconfig" make "$FALLBACK_CONFIG"; \
	}
fi

# Disable compiler features that are not used by default on older kernels
if [ $DISABLE_PLUGIN = "y" ]; then
	PLUGIN=""
elif [ $RANDSTRUCT = "y" ]; then
	PLUGIN="-fplugin=/gcc-plugin-$GCC_VERSION/const_structs.so"
else
	PLUGIN="-fplugin=/gcc-plugin-$GCC_VERSION/flowana.so -fplugin=/gcc-plugin-$GCC_VERSION/const_structs.so"
fi
export KCFLAGS="$PLUGIN $PLUGIN_ARG $PLUGIN_ARG_STRUCT -fno-pie -fno-stack-protector $EXTRA_CFLAGS"
export KAFLAGS="-fno-pie -fno-stack-protector"
export KCPPFLAGS="-fno-pie -fno-stack-protector"
if [ -z "$SUFFIX" ]; then
	if [ $DEFCONFIG = "y" ]; then
		SUFFIX="-def"
	else
		SUFFIX=""
	fi
fi
# Keep the config
cp .config "$OUTDIR/config.${TAG}${SUFFIX}"

if [ $RANDSTRUCT = "n" ]; then
	# Create a stub randstruct include file. We need to compile with -DRANDSTRUCT_PLUGIN in order to get
	# the attribute information of gcc. However, this triggers inclusion of the hash of the seed into vermagic string.
	mkdir -p include/generated
	echo '#define RANDSTRUCT_HASHED_SEED "dummyseed"' > include/generated/randomize_layout_hash.h
fi

# Build
LOGFILE="build.log"
if [ -z "${TARGET+X}" ]; then
	make 2>&1 | tee "$LOGFILE"
else
	make $TARGET 2>&1 | tee "$LOGFILE" # Use MAKEFLAGS to configure this (e.g. MAKEFLAGS="-j8" ...)
fi
rm -f "$TMPDIR/allconfig"
# Join all the fields and delete the originals
FIELDS="$OUTDIR/fields.$TAG$SUFFIX.txt"
if [ $DISABLE_PLUGIN != "y" ]; then
	find "$TMPDIR/flowana/" -type f -exec cat {} \; > "$FIELDS"
	find "$TMPDIR/flowana/" -type f -delete
fi
# Join structinfo
python3 "/gcc-plugin-$GCC_VERSION/merge-const-structs.py" "$TMPDIR/const_structs/" "$OUTDIR/structinfo.$TAG$SUFFIX.json"
# Save the vmlinux
if [ -z "${TARGET+X}" -a -e vmlinux ]; then
	cp vmlinux "$OUTDIR/vmlinux.${TAG}${SUFFIX}"
fi
if [ "$DROP_INTO_BASH" = "y" ]; then
	exec /bin/bash
fi
