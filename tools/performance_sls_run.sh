#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build_sls_perf}"

MODE="${MODE:-mock}"
CONFIG_PATH="${CONFIG_PATH:-}"

DURATION_S="${DURATION_S:-60}"
WRITERS="${WRITERS:-1}"
PROFILES="${PROFILES:-sls700 sls200}"
RATE_LIST="${RATE_LIST:-200000 100000 20000 10000 2000 1000 200 100}"
CLOSE_TIMEOUT_MS="${CLOSE_TIMEOUT_MS:-60000}"

VE_TLS_MAX_BUFFER_BYTES="${VE_TLS_MAX_BUFFER_BYTES:-67108864}"
VE_TLS_FLUSH_INTERVAL_MS="${VE_TLS_FLUSH_INTERVAL_MS:-3000}"
VE_TLS_LOG_BYTES_PER_PACKAGE="${VE_TLS_LOG_BYTES_PER_PACKAGE:-4194304}"
VE_TLS_LOG_COUNT_PER_PACKAGE="${VE_TLS_LOG_COUNT_PER_PACKAGE:-4096}"
VE_TLS_SEND_THREAD_COUNT="${VE_TLS_SEND_THREAD_COUNT:-16}"
VE_TLS_COMPRESS_TYPE="${VE_TLS_COMPRESS_TYPE:-lz4}"

mkdir -p "$BUILD_DIR"

if [[ "$MODE" == "curl" ]]; then
  cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DVE_TLS_BUILD_TESTS=OFF \
    -DVE_TLS_ENABLE_CURL=ON \
    -DVE_TLS_ENABLE_ZLIB=OFF \
    -DVE_TLS_ENABLE_LZ4=ON >/dev/null
else
  cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DVE_TLS_BUILD_TESTS=OFF \
    -DVE_TLS_ENABLE_CURL=OFF \
    -DVE_TLS_ENABLE_ZLIB=OFF \
    -DVE_TLS_ENABLE_LZ4=ON >/dev/null
fi

cmake --build "$BUILD_DIR" -j --target ve_tls_perf_sls >/dev/null

echo "| profile | target_lps | achieved_lps | us_per_log | raw_kb_s | cpu_pct_total | cpu_cores | rss_mb | close_rc | dropped | requests |"
echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"

for P in $PROFILES; do
  for RATE in $RATE_LIST; do
    export VE_TLS_MAX_BUFFER_BYTES
    export VE_TLS_FLUSH_INTERVAL_MS
    export VE_TLS_LOG_BYTES_PER_PACKAGE
    export VE_TLS_LOG_COUNT_PER_PACKAGE
    export VE_TLS_SEND_THREAD_COUNT
    export VE_TLS_COMPRESS_TYPE

    ARGS=(--mode "$MODE" --duration-s "$DURATION_S" --rate-lps "$RATE" --writers "$WRITERS" --profile "$P" --close-timeout-ms "$CLOSE_TIMEOUT_MS")
    if [[ "$MODE" == "curl" ]]; then
      ARGS+=(--config "$CONFIG_PATH")
    fi
    OUT="$("$BUILD_DIR/ve_tls_perf_sls" "${ARGS[@]}")"

    getv() { echo "$OUT" | tr ' ' '\n' | awk -F= -v k="$1" '$1==k{print $2; exit}'; }

    ACH="$(getv enq_lps)"
    US="$(getv us_per_log)"
    KB="$(getv raw_kb_s)"
    CPU_T="$(getv cpu_pct_total)"
    CPU_C="$(getv cpu_cores)"
    RSS="$(getv rss_mb)"
    CRC="$(getv close_rc)"
    DROP="$(getv logs_drop)"
    REQ="$(getv req)"

    printf "| %s | %s | %.2f | %.2f | %.2f | %.2f | %.2f | %.2f | %s | %s | %s |\n" \
      "$P" "$RATE" "${ACH:-0}" "${US:-0}" "${KB:-0}" "${CPU_T:-0}" "${CPU_C:-0}" "${RSS:-0}" "${CRC:-0}" "${DROP:-0}" "${REQ:-0}"
  done
done
