#!/usr/bin/env bash
# mayhem/build.sh — builds glusterfs' libraries twice (shared libgfapi stack, sanitized+SanCov, for the
# fuzzer; static libglusterfs/libgfxdr/libgfrpc with normal flags for the oracle probe), then the
# gfapi harness with its debug/fuzzfs backend xlator, its -standalone reproducer and the probe.
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

# build_libs <dir> <static|shared> <cflags>: configure out of tree and build the libraries
# (static: libglusterfs/libgfxdr/libgfrpc; shared: those plus libgfapi, its mount/api and meta xlators, installed
# under <dir>/inst because glusterfs dlopen()s its xlators from a compiled-in $(libdir)/glusterfs/<ver>/xlator)
build_libs() {
    local dir="$1" mode="$2" cflags="$3"
    mkdir -p "$dir"
    # libglusterfs compiles contrib/*.c into objects beside the sources, shared by every build tree
    find "$SRC/contrib" \( -name '*.o' -o -name '*.lo' \) -delete
    if [ ! -f "$dir/config.status" ]; then
        local linkopts=(--prefix="$dir/inst") ldflags=""
        if [ "$mode" = static ]; then linkopts+=(--disable-shared --enable-static); else ldflags="$cflags"; fi
        (cd "$dir" && env -u CFLAGS -u LDFLAGS "$SRC/configure" "${linkopts[@]}" "${CONFIGURE_OPTS[@]}" \
            CC="$CC" CFLAGS="$cflags" LDFLAGS="$ldflags" >"$dir/configure.log" 2>&1) || { tail -30 "$dir/configure.log"; exit 1; }
    fi
    local subdirs=(libglusterfs/src rpc/xdr/src rpc/rpc-lib/src) d
    [ "$mode" = shared ] && subdirs+=(api/src xlators/meta/src)
    : >"$dir/make.log"
    for d in "${subdirs[@]}"; do
        make -C "$dir/$d" -j"$MAYHEM_JOBS" GF_NO_UNDEFINED= >>"$dir/make.log" 2>&1 || { tail -30 "$dir/make.log"; exit 1; }
        [ "$mode" = shared ] && { make -C "$dir/$d" GF_NO_UNDEFINED= install >>"$dir/make.log" 2>&1 || { tail -30 "$dir/make.log"; exit 1; }; }
    done
    return 0
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

# 1) the fuzzed code: shared libraries (libgfapi loads its xlators with dlopen) with the sanitizers,
#    SanCov and DWARF<=3. GF_DISABLE_MEMPOOL turns glusterfs' private pools into plain malloc so ASan
#    sees every object. -fno-sanitize=null: glusterfs' list_entry()/container_of() take the member
#    offset through a null pointer (`&((type *)0)->member`), which UBSan's null check flags on every
#    list_for_each_entry(), already while the gfapi context is created; ASan still reports real null
#    dereferences, and the rest of UBSan stays on and halting. -fno-sanitize=function: the reference
#    counter calls its destructor (glfs_fd_destroy etc.) through a `void (*)(void *)` pointer on every
#    glfs_close(), a benign type mismatch the function check halts on. -fno-sanitize=shift-base: the
#    inode/dentry hash functions shift a signed int left (inode.c hash_dentry()), wrapping by design.
SAN_DIR="$OUT/san"
build_libs "$SAN_DIR" shared \
    "$SANITIZER_FLAGS -fno-sanitize=null,function,shift-base -fsanitize=fuzzer-no-link $DEBUG_FLAGS -DGF_DISABLE_MEMPOOL=1 -fsigned-char"
INST="$SAN_DIR/inst"

# 2) the backend xlator for the harness: a tiny in-memory tree, installed beside the real xlators
PKGVER="$(awk -F'"' '/define PACKAGE_VERSION/ {print $2}' "$SAN_DIR/config.h")"
XLDIR="$INST/lib/glusterfs/$PKGVER/xlator/debug"
mkdir -p "$XLDIR"
INC="$(inc_flags "$SAN_DIR")"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS -fno-sanitize=null,function,shift-base -fsanitize=fuzzer-no-link $DEBUG_FLAGS -DGF_DISABLE_MEMPOOL=1 -fPIC -shared $INC \
    "$SRC/mayhem/fuzzfs.c" -L"$INST/lib" -lglusterfs -o "$XLDIR/fuzzfs.so"

# 3) harness: fuzzer binary + -standalone reproducer (+ lsan_off.o, SPEC §6.2 item 15)
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
GFLIBS="-L$INST/lib -Wl,-rpath,$INST/lib -lgfapi -lglusterfs -lgfrpc -lgfxdr"
for h in fuzz_gfapi_at; do
    # shellcheck disable=SC2086
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -Wno-unused-result -I"$INST/include" -I"$INST/include/glusterfs" \
        -DFUZZFS_VOLFILE="\"$SRC/mayhem/fuzzfs.volfile\"" \
        "$SRC/mayhem/$h.c" "$OUT/lsan_off.o" $LIB_FUZZING_ENGINE $GFLIBS -o "$SRC/$h"
    # shellcheck disable=SC2086
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -Wno-unused-result -I"$INST/include" -I"$INST/include/glusterfs" \
        -DFUZZFS_VOLFILE="\"$SRC/mayhem/fuzzfs.volfile\"" \
        "$SRC/mayhem/$h.c" "$OUT/lsan_off.o" "$OUT/standalone_main.o" $GFLIBS -o "$SRC/$h-standalone"
done

# 4) the oracle: the same libraries with upstream's normal flags and a dynamically linked KAT probe
NORM_DIR="$OUT/normal"
build_libs "$NORM_DIR" static "-g -O2 -fsigned-char $COVERAGE_FLAGS"
INC="$(inc_flags "$NORM_DIR")"
LIBS="$(lib_flags "$NORM_DIR")"
# shellcheck disable=SC2086
$CC -g -O2 $COVERAGE_FLAGS -Wno-unused-result $INC "$SRC/mayhem/kat_probe.c" $LIBS $COVERAGE_FLAGS \
    -o "$OUT/kat_probe"
