#!/usr/bin/env bash
# mayhem/build.sh — builds libglusterfs/libgfxdr/libgfrpc twice (sanitized+SanCov for the fuzzers,
# normal flags for the oracle probe), then the harnesses, their -standalone reproducers and the probe.
# Runs offline in /mayhem; every output lands in gitignored paths and is recreated from scratch.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

: "${SRC:=/mayhem}"
cd "$SRC"
OUT="$SRC/mayhem/build"
mkdir -p "$OUT"

# upstream's generated build system (configure, Makefile.in, config.h.in) is gitignored
[ -x "$SRC/configure" ] || ./autogen.sh >"$OUT/autogen.log" 2>&1 || { tail -30 "$OUT/autogen.log"; exit 1; }

CONFIGURE_OPTS=(--without-tcmalloc --disable-lto --disable-fuse-client --disable-georeplication
                --disable-events --disable-gnfs --disable-linux-io_uring --disable-firewalld)

# build_libs <dir> <static|shared> <cflags>: configure out of tree and build the three libraries
build_libs() {
    local dir="$1" mode="$2" cflags="$3"
    mkdir -p "$dir"
    if [ ! -f "$dir/config.status" ]; then
        local linkopts=()
        [ "$mode" = static ] && linkopts=(--disable-shared --enable-static)
        (cd "$dir" && env -u CFLAGS -u LDFLAGS "$SRC/configure" "${linkopts[@]}" "${CONFIGURE_OPTS[@]}" \
            CC="$CC" CFLAGS="$cflags" >"$dir/configure.log" 2>&1) || { tail -30 "$dir/configure.log"; exit 1; }
    fi
    make -C "$dir/libglusterfs/src" -j"$MAYHEM_JOBS" >"$dir/make.log" 2>&1 || { tail -30 "$dir/make.log"; exit 1; }
    make -C "$dir/rpc/xdr/src" -j"$MAYHEM_JOBS" >>"$dir/make.log" 2>&1 || { tail -30 "$dir/make.log"; exit 1; }
    make -C "$dir/rpc/rpc-lib/src" -j"$MAYHEM_JOBS" >>"$dir/make.log" 2>&1 || { tail -30 "$dir/make.log"; exit 1; }
}

# include/link flags for a harness built against the library build in <dir>
inc_flags() {
    local d="$1"
    echo "-DHAVE_CONFIG_H -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -DGF_LINUX_HOST_OS -include $d/config.h -include $d/site.h" \
         "-I$d -I$SRC/libglusterfs/src -I$d/libglusterfs/src -I$SRC/rpc/xdr/src -I$d/rpc/xdr/src" \
         "-I$SRC/rpc/rpc-lib/src -I/usr/include/uuid -I/usr/include/tirpc -I$SRC/mayhem -I$OUT"
}
lib_flags() {
    local d="$1"
    echo "$d/rpc/rpc-lib/src/.libs/libgfrpc.a $d/rpc/xdr/src/.libs/libgfxdr.a $d/libglusterfs/src/.libs/libglusterfs.a" \
         "-ltirpc -lz -lm -luuid -ldl -lurcu-bp -lurcu-common -lurcu-cds -lresolv -lrt -lpthread -lcrypto"
}

# 1) the fuzzed code: static libraries with the sanitizers, SanCov and DWARF<=3. GF_DISABLE_MEMPOOL
#    turns glusterfs' private pools into plain malloc so ASan sees every object.
SAN_DIR="$OUT/san"
build_libs "$SAN_DIR" static \
    "$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -DGF_DISABLE_MEMPOOL=1 -fsigned-char"

# 2) the XDR decoder table, from the generated rpcgen headers
bash "$SRC/mayhem/gen-xdr-table.sh" "$SAN_DIR/rpc/xdr/src" >"$OUT/xdr_table.inc"

# 3) harnesses: fuzzer binary + -standalone reproducer (+ lsan_off.o, SPEC §6.2 item 15)
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
INC="$(inc_flags "$SAN_DIR")"
LIBS="$(lib_flags "$SAN_DIR")"
for h in fuzz_dict_unserialize fuzz_xdr_decode fuzz_strparse; do
    # shellcheck disable=SC2086
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -DGF_DISABLE_MEMPOOL=1 -Wno-unused-result $INC \
        "$SRC/mayhem/$h.c" "$OUT/lsan_off.o" $LIB_FUZZING_ENGINE $LIBS -o "$SRC/$h"
    # shellcheck disable=SC2086
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -DGF_DISABLE_MEMPOOL=1 -Wno-unused-result $INC \
        "$SRC/mayhem/$h.c" "$OUT/lsan_off.o" "$OUT/standalone_main.o" $LIBS -o "$SRC/$h-standalone"
done

# 4) the oracle: the same libraries with upstream's normal flags and a dynamically linked KAT probe
NORM_DIR="$OUT/normal"
build_libs "$NORM_DIR" static "-g -O2 -fsigned-char $COVERAGE_FLAGS"
INC="$(inc_flags "$NORM_DIR")"
LIBS="$(lib_flags "$NORM_DIR")"
# shellcheck disable=SC2086
$CC -g -O2 $COVERAGE_FLAGS -Wno-unused-result $INC "$SRC/mayhem/kat_probe.c" $LIBS $COVERAGE_FLAGS \
    -o "$OUT/kat_probe"
