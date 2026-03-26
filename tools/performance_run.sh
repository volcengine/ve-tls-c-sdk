#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build_perf}"

for kv in "$@"; do
  if [[ "$kv" == *=* ]]; then
    export "$kv"
  fi
done

DURATION_S="${DURATION_S:-5}"
RATE_LPS="${RATE_LPS:-20000}"
MESSAGE_BYTES="${MESSAGE_BYTES:-256}"
WRITE_MODE_LIST="${WRITE_MODE_LIST:-raw kv template}"
WRITER_THREADS_LIST="${WRITER_THREADS_LIST:-1 4 16}"
SEND_THREADS_LIST="${SEND_THREADS_LIST:-1 4 16}"
COMPRESS_TYPE_LIST="${COMPRESS_TYPE_LIST:-none lz4 zlib}"
QUEUE_FULL_POLICY_LIST="${QUEUE_FULL_POLICY_LIST:-block drop drop_sampled}"
PERF_WRITERS="${PERF_WRITERS:-4}"
PERF_SENDERS="${PERF_SENDERS:-4}"
LOG_COUNT_PER_PACKAGE="${LOG_COUNT_PER_PACKAGE:-4096}"
FLUSH_INTERVAL_MS="${FLUSH_INTERVAL_MS:-3000}"
FLUSH_EVERY_N="${FLUSH_EVERY_N:-1}"
SEND_QUEUE_SIZE="${SEND_QUEUE_SIZE:-4096}"
MAX_BUFFER_BYTES="${MAX_BUFFER_BYTES:-67108864}"
CLOSE_TIMEOUT_MS="${CLOSE_TIMEOUT_MS:-60000}"
BASELINE_THROUGHPUT_LPS="${BASELINE_THROUGHPUT_LPS:-}"
BASELINE_P99_MS="${BASELINE_P99_MS:-}"
AUTO_BASELINE_FROM_MATRIX="${AUTO_BASELINE_FROM_MATRIX:-1}"
STRICT_GATE="${STRICT_GATE:-0}"

mkdir -p "$BUILD_DIR"

ZLIB_ON=1
if ! cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
  -DVE_TLS_BUILD_TESTS=OFF \
  -DVE_TLS_ENABLE_CURL=OFF \
  -DVE_TLS_ENABLE_ZLIB=ON \
  -DVE_TLS_ENABLE_LZ4=ON >/dev/null 2>&1; then
  ZLIB_ON=0
  cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
    -DVE_TLS_BUILD_TESTS=OFF \
    -DVE_TLS_ENABLE_CURL=OFF \
    -DVE_TLS_ENABLE_ZLIB=OFF \
    -DVE_TLS_ENABLE_LZ4=ON >/dev/null
fi

cmake --build "$BUILD_DIR" -j --target ve_tls_bench >/dev/null

if [[ "$ZLIB_ON" -eq 0 ]]; then
  COMPRESS_TYPE_LIST="$(echo "$COMPRESS_TYPE_LIST" | sed 's/\bzlib\b//g' | xargs)"
fi

LAST_CLOSE_RC=0
LAST_LOOPS=0
LAST_DROPPED=0
LAST_DURATION_MS=0
LAST_THROUGHPUT=0
LAST_P99=0
LAST_REQUESTS=0
LAST_USER_S=0
LAST_SYS_S=0
LAST_RSS_KB=0

run_case() {
  local mode="$1"
  local compress="$2"
  local policy="$3"
  local writers="$4"
  local senders="$5"

  local out
  out="$(
    /usr/bin/time -l "$BUILD_DIR/ve_tls_bench" \
      --duration-s "$DURATION_S" \
      --rate-lps "$RATE_LPS" \
      --message-bytes "$MESSAGE_BYTES" \
      --writer-threads "$writers" \
      --send-thread-count "$senders" \
      --flush-every-n "$FLUSH_EVERY_N" \
      --write-mode "$mode" \
      --queue-full-policy "$policy" \
      --compress-type "$compress" \
      --log-count-per-package "$LOG_COUNT_PER_PACKAGE" \
      --flush-interval-ms "$FLUSH_INTERVAL_MS" \
      --send-queue-size "$SEND_QUEUE_SIZE" \
      --max-buffer-bytes "$MAX_BUFFER_BYTES" \
      --close-timeout-ms "$CLOSE_TIMEOUT_MS" 2>&1 || true
  )"

  LAST_CLOSE_RC="$(echo "$out" | awk '/^bench close_rc=/{for(i=1;i<=NF;i++) if($i ~ /^close_rc=/){split($i,a,"="); print a[2]}}')"
  LAST_DURATION_MS="$(echo "$out" | awk '/^bench close_rc=/{for(i=1;i<=NF;i++) if($i ~ /^duration_ms=/){split($i,a,"="); print a[2]}}')"
  LAST_LOOPS="$(echo "$out" | awk '/^bench loops=/{for(i=1;i<=NF;i++) if($i ~ /^loops=/){split($i,a,"="); print a[2]}}')"
  LAST_DROPPED="$(echo "$out" | awk '/^metrics logs_enqueued_total=/{for(i=1;i<=NF;i++) if($i ~ /^logs_dropped_total=/){split($i,a,"="); print a[2]}}')"
  LAST_REQUESTS="$(echo "$out" | awk '/^metrics requests_total=/{for(i=1;i<=NF;i++) if($i ~ /^requests_total=/){split($i,a,"="); print a[2]}}')"
  LAST_THROUGHPUT="$(echo "$out" | awk '/^throughput /{for(i=1;i<=NF;i++) if($i ~ /^logs_per_s=/){split($i,a,"="); print a[2]}}')"
  LAST_P99="$(echo "$out" | awk '/^metrics latency_buckets=/{for(i=1;i<=NF;i++) if($i ~ /^p99_ms_upper=/){split($i,a,"="); print a[2]}}')"

  LAST_USER_S="$(echo "$out" | awk '/ real .* user .* sys/{for(i=1;i<=NF;i++){if($(i)=="user"){print $(i-1); exit}}}')"
  LAST_SYS_S="$(echo "$out" | awk '/ real .* user .* sys/{for(i=1;i<=NF;i++){if($(i)=="sys"){print $(i-1); exit}}}')"
  local rss_b
  rss_b="$(echo "$out" | awk '/maximum resident set size/{print $1; exit}')"
  LAST_RSS_KB="$(awk -v b="${rss_b:-0}" 'BEGIN{printf "%.0f", b/1024.0}')"

  LAST_CLOSE_RC="${LAST_CLOSE_RC:-0}"
  LAST_DURATION_MS="${LAST_DURATION_MS:-0}"
  LAST_LOOPS="${LAST_LOOPS:-0}"
  LAST_DROPPED="${LAST_DROPPED:-0}"
  LAST_REQUESTS="${LAST_REQUESTS:-0}"
  LAST_THROUGHPUT="${LAST_THROUGHPUT:-0}"
  LAST_P99="${LAST_P99:-0}"
  LAST_USER_S="${LAST_USER_S:-0}"
  LAST_SYS_S="${LAST_SYS_S:-0}"
  LAST_RSS_KB="${LAST_RSS_KB:-0}"
}

echo "## Functional API Smoke (raw/kv/template + flush/close)"
echo
echo "| write_mode | compress | queue_policy | writers | senders | close_rc | loops | dropped | throughput_lps | p99_ms_upper | requests |"
echo "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"
for mode in $WRITE_MODE_LIST; do
  run_case "$mode" "none" "block" 1 1
  echo "| $mode | none | block | 1 | 1 | $LAST_CLOSE_RC | $LAST_LOOPS | $LAST_DROPPED | $LAST_THROUGHPUT | $LAST_P99 | $LAST_REQUESTS |"
done

echo
echo "## Concurrency Matrix (kv + none + block)"
echo
echo "| writers | senders | close_rc | loops | dropped | duration_ms | throughput_lps | p99_ms_upper | requests | cpu_user_s | cpu_sys_s | max_rss_kb |"
echo "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
for writers in $WRITER_THREADS_LIST; do
  for senders in $SEND_THREADS_LIST; do
    run_case "kv" "none" "block" "$writers" "$senders"
    echo "| $writers | $senders | $LAST_CLOSE_RC | $LAST_LOOPS | $LAST_DROPPED | $LAST_DURATION_MS | $LAST_THROUGHPUT | $LAST_P99 | $LAST_REQUESTS | $LAST_USER_S | $LAST_SYS_S | $LAST_RSS_KB |"
  done
done

echo
echo "## Perf Matrix (kv + fixed concurrency)"
echo
if [[ -n "$BASELINE_THROUGHPUT_LPS" && -n "$BASELINE_P99_MS" ]]; then
  echo "Baseline: throughput=${BASELINE_THROUGHPUT_LPS} logs/s, p99=${BASELINE_P99_MS} ms"
else
  if [[ "$AUTO_BASELINE_FROM_MATRIX" == "1" ]]; then
    echo "Baseline: auto (will use first perf case none+block)"
  else
    echo "Baseline: not provided (set BASELINE_THROUGHPUT_LPS and BASELINE_P99_MS to enable gate)"
  fi
fi
echo
echo "| compress | queue_policy | writers | senders | close_rc | loops | dropped | throughput_lps | p99_ms_upper | gate |"
echo "|---|---|---:|---:|---:|---:|---:|---:|---:|---|"
gate_total=0
gate_pass=0
gate_fail=0
baseline_is_auto=0
for compress in $COMPRESS_TYPE_LIST; do
  for policy in $QUEUE_FULL_POLICY_LIST; do
    run_case "kv" "$compress" "$policy" "$PERF_WRITERS" "$PERF_SENDERS"

    if [[ -z "$BASELINE_THROUGHPUT_LPS" && -z "$BASELINE_P99_MS" && "$AUTO_BASELINE_FROM_MATRIX" == "1" && "$compress" == "none" && "$policy" == "block" ]]; then
      BASELINE_THROUGHPUT_LPS="$LAST_THROUGHPUT"
      BASELINE_P99_MS="$LAST_P99"
      baseline_is_auto=1
    fi

    gate="N/A"
    if [[ -n "$BASELINE_THROUGHPUT_LPS" && -n "$BASELINE_P99_MS" ]]; then
      if [[ "$compress" == "none" && "$policy" == "block" ]]; then
        gate="BASELINE"
      else
        if [[ "$baseline_is_auto" -eq 1 ]]; then
          gate="AUTO"
        else
          throughput_target="$(awk -v b="$BASELINE_THROUGHPUT_LPS" 'BEGIN{printf "%.2f", b*1.2}')"
          p99_limit="$(awk -v b="$BASELINE_P99_MS" 'BEGIN{printf "%.2f", b*1.1}')"
          throughput_ok=0
          p99_ok=0
          awk -v x="$LAST_THROUGHPUT" -v y="$throughput_target" 'BEGIN{exit !(x>=y)}' && throughput_ok=1
          awk -v x="$LAST_P99" -v y="$p99_limit" 'BEGIN{exit !(x<=y)}' && p99_ok=1
          gate_total=$((gate_total + 1))
          if [[ "$throughput_ok" -eq 1 && "$p99_ok" -eq 1 ]]; then
            gate="PASS"
            gate_pass=$((gate_pass + 1))
          else
            gate="FAIL"
            gate_fail=$((gate_fail + 1))
          fi
        fi
      fi
    fi
    echo "| $compress | $policy | $PERF_WRITERS | $PERF_SENDERS | $LAST_CLOSE_RC | $LAST_LOOPS | $LAST_DROPPED | $LAST_THROUGHPUT | $LAST_P99 | $gate |"
  done
done

if [[ -n "$BASELINE_THROUGHPUT_LPS" && -n "$BASELINE_P99_MS" ]]; then
  echo
  if [[ "$baseline_is_auto" -eq 1 ]]; then
    echo "Gate summary: auto baseline in use (informational only), baseline_tps=${BASELINE_THROUGHPUT_LPS} baseline_p99=${BASELINE_P99_MS}"
  else
    echo "Gate summary: total=${gate_total} pass=${gate_pass} fail=${gate_fail} baseline_tps=${BASELINE_THROUGHPUT_LPS} baseline_p99=${BASELINE_P99_MS}"
  fi
  if [[ "$STRICT_GATE" == "1" && "$baseline_is_auto" -eq 0 && "$gate_fail" -gt 0 ]]; then
    exit 1
  fi
fi
