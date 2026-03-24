#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build_perf}"

for kv in "$@"; do
  if [[ "$kv" == *=* ]]; then
    export "$kv"
  fi
done

DURATION_S="${DURATION_S:-30}"
WRITER_THREADS="${WRITER_THREADS:-1}"
SEND_THREADS="${SEND_THREADS:-4}"
MESSAGE_BYTES_LIST="${MESSAGE_BYTES_LIST:-200 700}"
RATE_LIST="${RATE_LIST:-200000 100000 20000 10000 2000 1000 200 100}"
LOG_COUNT_PER_PACKAGE="${LOG_COUNT_PER_PACKAGE:-4096}"
FLUSH_INTERVAL_MS="${FLUSH_INTERVAL_MS:-3000}"
SEND_QUEUE_SIZE="${SEND_QUEUE_SIZE:-4096}"
MAX_BUFFER_BYTES="${MAX_BUFFER_BYTES:-67108864}"
COMPRESS_TYPE="${COMPRESS_TYPE:-lz4}"
CLOSE_TIMEOUT_MS="${CLOSE_TIMEOUT_MS:-60000}"

mkdir -p "$BUILD_DIR"

cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
  -DVE_TLS_BUILD_TESTS=OFF \
  -DVE_TLS_ENABLE_CURL=OFF \
  -DVE_TLS_ENABLE_ZLIB=OFF \
  -DVE_TLS_ENABLE_LZ4=ON >/dev/null

cmake --build "$BUILD_DIR" -j --target ve_tls_bench >/dev/null

echo "| message_bytes | rate_logs_s | writers | senders | avg_log_bytes | loops | dropped | duration_ms | us_per_log | requests | cpu_user_s | cpu_sys_s | max_rss_kb |"
echo "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"

for MSG in $MESSAGE_BYTES_LIST; do
  for RATE in $RATE_LIST; do
    OUT="$(
      /usr/bin/time -l "$BUILD_DIR/ve_tls_bench" \
        --duration-s "$DURATION_S" \
        --rate-lps "$RATE" \
        --message-bytes "$MSG" \
        --writer-threads "$WRITER_THREADS" \
        --send-thread-count "$SEND_THREADS" \
        --compress-type "$COMPRESS_TYPE" \
        --log-count-per-package "$LOG_COUNT_PER_PACKAGE" \
        --flush-interval-ms "$FLUSH_INTERVAL_MS" \
        --send-queue-size "$SEND_QUEUE_SIZE" \
        --max-buffer-bytes "$MAX_BUFFER_BYTES" \
        --close-timeout-ms "$CLOSE_TIMEOUT_MS" 2>&1
    )"

    DURATION_MS="$(echo "$OUT" | awk '/^bench close_rc=/{for(i=1;i<=NF;i++) if($i ~ /^duration_ms=/){split($i,a,"="); print a[2]}}')"
    LOOPS="$(echo "$OUT" | awk '/^bench loops=/{for(i=1;i<=NF;i++) if($i ~ /^loops=/){split($i,a,"="); print a[2]}}')"
    DROPPED="$(echo "$OUT" | awk '/^metrics logs_enqueued_total=/{for(i=1;i<=NF;i++) if($i ~ /^logs_dropped_total=/){split($i,a,"="); print a[2]}}')"
    BYTES_ENQ="$(echo "$OUT" | awk '/^metrics logs_enqueued_total=/{for(i=1;i<=NF;i++) if($i ~ /^bytes_enqueued_total=/){split($i,a,"="); print a[2]}}')"
    LOGS_ENQ="$(echo "$OUT" | awk '/^metrics logs_enqueued_total=/{for(i=1;i<=NF;i++) if($i ~ /^logs_enqueued_total=/){split($i,a,"="); print a[2]}}')"
    REQS="$(echo "$OUT" | awk '/^metrics requests_total=/{for(i=1;i<=NF;i++) if($i ~ /^requests_total=/){split($i,a,"="); print a[2]}}')"

    USER_S="$(echo "$OUT" | awk '/ real .* user .* sys/{for(i=1;i<=NF;i++){if($(i)=="user"){print $(i-1); exit}}}')"
    SYS_S="$(echo "$OUT" | awk '/ real .* user .* sys/{for(i=1;i<=NF;i++){if($(i)=="sys"){print $(i-1); exit}}}')"
    RSS_B="$(echo "$OUT" | awk '/maximum resident set size/{print $1; exit}')"
    RSS_KB="$(awk -v b="${RSS_B:-0}" 'BEGIN{printf "%.0f", b/1024.0}')"

    AVG_LOG_BYTES="$(awk -v b="${BYTES_ENQ:-0}" -v n="${LOGS_ENQ:-0}" 'BEGIN{if(n>0) printf "%.1f", b/n; else print "0"}')"
    US_PER_LOG="$(awk -v ms="${DURATION_MS:-0}" -v n="${LOOPS:-0}" 'BEGIN{if(n>0) printf "%.2f", (ms*1000.0)/n; else print "0"}')"

    echo "| $MSG | $RATE | $WRITER_THREADS | $SEND_THREADS | $AVG_LOG_BYTES | ${LOOPS:-0} | ${DROPPED:-0} | ${DURATION_MS:-0} | $US_PER_LOG | ${REQS:-0} | ${USER_S:-0} | ${SYS_S:-0} | $RSS_KB |"
  done
done
