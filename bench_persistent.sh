#!/bin/bash
set -e

BENCH="${1:-./build-opt/ve_tls_bench}"
DIR="${2:-/tmp/ve-tls-bench}"
RUNS=5
DURATION_S=5
PROFILES="tls200 tls700 tls5120"

echo "========================================"
echo "  ve-tls-c-sdk Persistent Benchmark"
echo "========================================"
echo "Date:    $(date '+%Y-%m-%d %H:%M:%S')"
echo "Kernel:  $(uname -r)"
echo "CPU:     $(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 || echo 'N/A')"
echo "Cores:   $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo '?')"
echo "FS:      $(df -T "$DIR" 2>/dev/null | tail -1 || df "$DIR" 2>/dev/null | tail -1)"
echo "Bench:   $BENCH"
echo "Dir:     $DIR"
echo "Runs:    $RUNS per profile"
echo ""

if [ ! -x "$BENCH" ]; then
  echo "ERROR: bench binary not found: $BENCH"
  exit 1
fi

mkdir -p "$DIR"

median() {
  printf '%s\n' "$@" | sort -n | awk "{ a[NR]=\$1 } END { print a[int(NR/2)+1] }"
}

for profile in $PROFILES; do
  echo "========================================"
  echo "  Profile: $profile  (persistent kv, 4 writers, 1 sender, ${DURATION_S}s)"
  echo "========================================"

  produce_arr=()
  total_arr=()

  for i in $(seq 1 $RUNS); do
    rm -rf "${DIR:?}"/*

    output=$("$BENCH" \
      --use-persistent 1 \
      --profile "$profile" \
      --write-mode kv \
      --writer-threads 4 \
      --send-thread-count 1 \
      --duration-s "$DURATION_S" \
      --persistent-dir "$DIR" \
      2>&1) || true

    produce_lps=$(echo "$output" | grep -oP 'produce_lps=\K[0-9.]+' | head -1)
    total_lps=$(echo "$output" | grep -oP 'total_lps=\K[0-9.]+' | head -1)
    dropped=$(echo "$output" | grep -oP 'logs_dropped_total=\K[0-9]+' | head -1)

    produce_arr+=("${produce_lps:-0}")
    total_arr+=("${total_lps:-0}")

    echo "  Run $i: produce_lps=${produce_lps:-N/A}  total_lps=${total_lps:-N/A}  dropped=${dropped:-?}"
  done

  produce_med=$(median "${produce_arr[@]}")
  total_med=$(median "${total_arr[@]}")
  echo ""
  echo "  >>> Median: produce_lps=$produce_med  total_lps=$total_med"
  echo ""
done

echo "========================================"
echo "  Non-Persistent Baseline  (kv, 4 writers, 4 senders, 3s)"
echo "========================================"

produce_arr=()
total_arr=()

for i in $(seq 1 $RUNS); do
  output=$("$BENCH" \
    --use-persistent 0 \
    --profile tls700 \
    --write-mode kv \
    --writer-threads 4 \
    --send-thread-count 4 \
    --duration-s 3 \
    2>&1) || true

  produce_lps=$(echo "$output" | grep -oP 'produce_lps=\K[0-9.]+' | head -1)
  total_lps=$(echo "$output" | grep -oP 'total_lps=\K[0-9.]+' | head -1)

  produce_arr+=("${produce_lps:-0}")
  total_arr+=("${total_lps:-0}")

  echo "  Run $i: produce_lps=${produce_lps:-N/A}  total_lps=${total_lps:-N/A}"
done

produce_med=$(median "${produce_arr[@]}")
total_med=$(median "${total_arr[@]}")
echo ""
echo "  >>> Median: produce_lps=$produce_med  total_lps=$total_med"
echo ""

echo "========================================"
echo "  Done."
echo "========================================"
