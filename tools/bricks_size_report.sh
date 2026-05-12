#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BUILD_DIR=${1:-"$ROOT_DIR/build-bricks-size-report"}
CORE_LZ4=${VE_TLS_SIZE_CORE_ENABLE_LZ4:-ON}
CORE_ZLIB=${VE_TLS_SIZE_CORE_ENABLE_ZLIB:-OFF}
BRICKS_LZ4=${VE_TLS_SIZE_BRICKS_ENABLE_LZ4:-OFF}
BRICKS_ZLIB=${VE_TLS_SIZE_BRICKS_ENABLE_ZLIB:-OFF}

cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DVE_TLS_BUILD_BRICKS=ON \
    -DVE_TLS_ENABLE_CURL=OFF \
    -DVE_TLS_ENABLE_LZ4="$CORE_LZ4" \
    -DVE_TLS_ENABLE_ZLIB="$CORE_ZLIB" \
    -DVE_TLS_BRICKS_ENABLE_LZ4="$BRICKS_LZ4" \
    -DVE_TLS_BRICKS_ENABLE_ZLIB="$BRICKS_ZLIB" \
    -DVE_TLS_BUILD_TOOLS=OFF \
    -DVE_TLS_BUILD_TESTS=OFF

cmake --build "$BUILD_DIR" --target ve_tls_core
cmake --build "$BUILD_DIR" --target ve_tls_bricks_core

find_one() {
    find "$BUILD_DIR" -type f -name "$1" | sed -n '1p'
}

archive_bytes() {
    wc -c < "$1" | tr -d ' '
}

CORE_LIB=$(find_one "libve_tls_core.a")
BRICKS_LIB=$(find_one "libve_tls_bricks_core.a")

if [ -z "$CORE_LIB" ] || [ -z "$BRICKS_LIB" ]; then
    echo "failed to locate built static libraries under $BUILD_DIR" >&2
    exit 1
fi

echo "config,core_lz4=$CORE_LZ4,core_zlib=$CORE_ZLIB,bricks_lz4=$BRICKS_LZ4,bricks_zlib=$BRICKS_ZLIB"
echo "target,archive_bytes,path"
echo "ve_tls_core,$(archive_bytes "$CORE_LIB"),$CORE_LIB"
echo "ve_tls_bricks_core,$(archive_bytes "$BRICKS_LIB"),$BRICKS_LIB"

if command -v size >/dev/null 2>&1; then
    echo
    size "$CORE_LIB" "$BRICKS_LIB" || true
fi

if command -v nm >/dev/null 2>&1; then
    forbidden_re='pthread|curl|ve_tls_producer|ve_tls_env|ve_tls_http_curl|ve_tls_retry|metric|persistent|file_'
    forbidden=$(nm -g "$BRICKS_LIB" 2>/dev/null | grep -E "$forbidden_re" || true)
    echo
    if [ -n "$forbidden" ]; then
        echo "forbidden symbols found in ve_tls_bricks_core:" >&2
        echo "$forbidden" >&2
        exit 2
    fi
    echo "forbidden symbols: none"
fi
