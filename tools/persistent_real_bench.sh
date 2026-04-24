#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
SDK_ROOT="${SCRIPT_DIR:h}"
BUILD_DIR="${BUILD_DIR:-$SDK_ROOT/build-persistent-real}"
CONF_FILE="${CONF_FILE:-$SDK_ROOT/tools/real_demo.env}"
QUERY="$SDK_ROOT/tools/tls_search_logs.go"
QUERY_FORMAT="$SDK_ROOT/tools/tls_search_logs_format.go"
DEMO_RUNNER="$BUILD_DIR/ve_tls_demo_real"
BENCH_RUNNER="$BUILD_DIR/ve_tls_persistent_real_bench"
ARCHIVE_ROOT_DEFAULT="$BUILD_DIR/bench-results"

if [[ -z "${GO_SDK_ROOT:-}" && -d "/Users/bytedance/workspace/go/src/code.byted.org/volcengine/volc-sdk-golang" ]]; then
  GO_SDK_ROOT="/Users/bytedance/workspace/go/src/code.byted.org/volcengine/volc-sdk-golang"
fi
if [[ -z "${GO_BIN:-}" ]]; then
  if [[ -x "/Users/bytedance/workspace/go/go1.22.12/bin/go" ]]; then
    GO_BIN="/Users/bytedance/workspace/go/go1.22.12/bin/go"
  else
    GO_BIN="$(command -v go || true)"
  fi
fi
if [[ -z "${CMAKE_BIN:-}" ]]; then
  if command -v cmake >/dev/null 2>&1; then
    CMAKE_BIN="$(command -v cmake)"
  elif [[ -x "/opt/homebrew/bin/cmake" ]]; then
    CMAKE_BIN="/opt/homebrew/bin/cmake"
  else
    CMAKE_BIN=""
  fi
fi

usage() {
  cat <<'EOF'
usage: persistent_real_bench.sh [options]

options:
  --mode MODE               steady | recover | all (default: all)
  --rates CSV               steady mode rate sweep, default: 1000,2000,5000
  --duration-s N            steady mode duration seconds, default: 15
  --recover-records CSV     recover mode record sweep, default: 5000,20000
  --wait-ms N               runner wait time, default: 30000
  --query-timeout-ms N      service query timeout, default: 120000
  --flush-interval-ms N     benchmark flush interval, default: 1000
  --log-count-per-package N benchmark package count, default: 1024
  --send-thread-count N     benchmark sender count, default: 1
  --archive-dir PATH        archive directory, default: build-persistent-real/bench-results/<timestamp>
  --help                    show this help
EOF
}

if [[ ! -f "$CONF_FILE" ]]; then
  echo "missing config file: $CONF_FILE" >&2
  exit 2
fi
if [[ ! -f "$QUERY" ]]; then
  echo "missing query script: $QUERY" >&2
  exit 2
fi
if [[ -z "${GO_SDK_ROOT:-}" || ! -d "$GO_SDK_ROOT" ]]; then
  echo "missing GO_SDK_ROOT, please point it to volc-sdk-golang checkout" >&2
  exit 2
fi
if [[ -z "${GO_BIN:-}" || ! -x "$GO_BIN" ]]; then
  echo "missing GO_BIN: $GO_BIN" >&2
  exit 2
fi
if [[ ! -x "$DEMO_RUNNER" || ! -x "$BENCH_RUNNER" ]]; then
  if [[ -z "$CMAKE_BIN" || ! -x "$CMAKE_BIN" ]]; then
    echo "missing cmake to build benchmark/demo runners" >&2
    exit 2
  fi
  "$CMAKE_BIN" -S "$SDK_ROOT" -B "$BUILD_DIR" -DVE_TLS_ENABLE_CURL=ON
  "$CMAKE_BIN" --build "$BUILD_DIR" --target ve_tls_demo_real ve_tls_persistent_real_bench -j4
fi

MODE="all"
RATES_CSV="1000,2000,5000"
DURATION_S=15
RECOVER_RECORDS_CSV="5000,20000"
WAIT_MS=30000
QUERY_TIMEOUT_MS=120000
FLUSH_INTERVAL_MS=1000
LOG_COUNT_PER_PACKAGE=1024
SEND_THREAD_COUNT=1
ARCHIVE_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --rates) RATES_CSV="$2"; shift 2 ;;
    --duration-s) DURATION_S="$2"; shift 2 ;;
    --recover-records) RECOVER_RECORDS_CSV="$2"; shift 2 ;;
    --wait-ms) WAIT_MS="$2"; shift 2 ;;
    --query-timeout-ms) QUERY_TIMEOUT_MS="$2"; shift 2 ;;
    --flush-interval-ms) FLUSH_INTERVAL_MS="$2"; shift 2 ;;
    --log-count-per-package) LOG_COUNT_PER_PACKAGE="$2"; shift 2 ;;
    --send-thread-count) SEND_THREAD_COUNT="$2"; shift 2 ;;
    --archive-dir) ARCHIVE_DIR="$2"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

case "$MODE" in
  steady|recover|all) ;;
  *) echo "invalid mode: $MODE" >&2; exit 2 ;;
esac

set -a
source "$CONF_FILE"
set +a

export LOG_SERVICE_ENDPOINT="$VE_TLS_ENDPOINT"
export LOG_SERVICE_REGION="$VE_TLS_REGION"
export LOG_SERVICE_AK="$VE_TLS_ACCESS_KEY_ID"
export LOG_SERVICE_SK="$VE_TLS_ACCESS_KEY_SECRET"
export LOG_SERVICE_TOKEN="${VE_TLS_SECURITY_TOKEN:-}"
export LOG_SERVICE_TOPIC="$VE_TLS_TOPIC_ID"

if [[ -z "$ARCHIVE_DIR" ]]; then
  ARCHIVE_DIR="$ARCHIVE_ROOT_DEFAULT/$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$ARCHIVE_DIR"

query_exact() {
  local run_id="$1"
  local exact="$2"
  local start_ms="$3"
  local end_ms="$4"
  local timeout_ms="$5"
  local out_file="$6"
  (
    cd "$GO_SDK_ROOT"
    export GOCACHE=/tmp/go-build
    export PERSIST_QUERY_RUN_ID="$run_id"
    export PERSIST_QUERY_EXPECT_EXACT="$exact"
    export PERSIST_QUERY_START_MS="$start_ms"
    export PERSIST_QUERY_END_MS="$end_ms"
    export PERSIST_QUERY_TIMEOUT_MS="$timeout_ms"
    export PERSIST_QUERY_POLL_MS=1000
    export PERSIST_QUERY_LIMIT=1000
    export PERSIST_QUERY_INCLUDE_SEQS=0
    "$GO_BIN" run "$QUERY" "$QUERY_FORMAT"
  ) | tee "$out_file"
}

run_demo_capture() {
  local out_file="$1"
  local count="$2"
  local duration_s="$3"
  shift 3
  local start_ms=$(( $(date +%s) * 1000 ))
  set +e
  env "$@" "$DEMO_RUNNER" --config "$CONF_FILE" --count "$count" --duration-s "$duration_s" --wait-ms "$WAIT_MS" 2>&1 | tee "$out_file" >&2
  local rc=$?
  set -e
  local end_ms=$(( $(date +%s) * 1000 ))
  echo "$start_ms $end_ms $rc"
}

run_bench_capture() {
  local out_file="$1"
  shift
  local -a runner_args
  runner_args=()
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--" ]]; then
      shift
      break
    fi
    runner_args+=("$1")
    shift
  done
  local start_ms=$(( $(date +%s) * 1000 ))
  set +e
  env "$@" "$BENCH_RUNNER" --config "$CONF_FILE" "${runner_args[@]}" 2>&1 | tee "$out_file" >&2
  local rc=$?
  set -e
  local end_ms=$(( $(date +%s) * 1000 ))
  echo "$start_ms $end_ms $rc"
}

parse_run_result() {
  local file="$1"
  local field="$2"
  local line
  line="$(grep -E 'RUN_RESULT|PERSISTENT_REAL_BENCH' "$file" | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    echo ""
    return 0
  fi
  echo "$line" | sed -n "s/.*${field}=\\([^ ]*\\).*/\\1/p"
}

parse_last_search_field() {
  local file="$1"
  local field="$2"
  local line
  line="$(grep 'SEARCH_RESULT' "$file" | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    echo ""
    return 0
  fi
  echo "$line" | sed -n "s/.*${field}=\\([^ ]*\\).*/\\1/p"
}

calc_logs_per_s() {
  local count="$1"
  local elapsed_ms="$2"
  awk -v c="$count" -v ms="$elapsed_ms" 'BEGIN { if (ms <= 0) { print "0.00"; } else { printf "%.2f", c * 1000.0 / ms; } }'
}

bench_steady_once() {
  local rate="$1"
  local run_id="pbenchs${rate}_$(date +%s)"
  local dir="/tmp/ve-tls-persist-bench-$run_id"
  local log_file="$ARCHIVE_DIR/${run_id}.steady.log"
  local query_file="$ARCHIVE_DIR/${run_id}.steady.query.log"
  local timing
  local producer_start_ms
  local producer_end_ms
  local producer_rc
  local producer_elapsed_ms
  local add_ok
  local success
  local fail
  local close_rc
  local unique_seq
  local duplicates
  local query_end_ms
  local query_elapsed_ms
  local bench_pass=0

  echo "BENCH_START mode=steady rate=$rate run_id=$run_id archive=$log_file"
  timing="$(run_bench_capture "$log_file"     --mode steady     --duration-s "$DURATION_S"     --rate-lps "$rate"     --wait-ms "$WAIT_MS"     --run-id "$run_id"     --persistent-dir "$dir"     --send-thread-count "$SEND_THREAD_COUNT"     --     VE_TLS_ENDPOINT="$VE_TLS_ENDPOINT"     VE_TLS_REGION="$VE_TLS_REGION"     VE_TLS_TOPIC_ID="$VE_TLS_TOPIC_ID"     VE_TLS_ACCESS_KEY_ID="$VE_TLS_ACCESS_KEY_ID"     VE_TLS_ACCESS_KEY_SECRET="$VE_TLS_ACCESS_KEY_SECRET"     VE_TLS_SECURITY_TOKEN="${VE_TLS_SECURITY_TOKEN:-}"     VE_TLS_COMPRESS_TYPE="${VE_TLS_COMPRESS_TYPE:-lz4}"     VE_TLS_SEND_THREAD_COUNT="$SEND_THREAD_COUNT"     VE_TLS_REQUEST_TIMEOUT_MS=10000     VE_TLS_CONNECT_TIMEOUT_MS=10000     VE_TLS_SEND_QUEUE_SIZE=4096     VE_TLS_SEND_QUEUE_FULL_POLICY=block     VE_TLS_SEND_QUEUE_BLOCK_TIMEOUT_MS=100     VE_TLS_SEND_QUEUE_SAMPLE_EVERY_N=10     VE_TLS_HTTP_DEBUG=0     VE_TLS_USE_PERSISTENT=1     VE_TLS_PERSISTENT_FILE_PATH="$dir"     VE_TLS_MAX_PERSISTENT_LOG_COUNT=200000     VE_TLS_MAX_PERSISTENT_FILE_SIZE=8388608     VE_TLS_MAX_PERSISTENT_FILE_COUNT=32     VE_TLS_DEMO_RUN_ID="$run_id"     VE_TLS_FLUSH_INTERVAL_MS="$FLUSH_INTERVAL_MS"     VE_TLS_LOG_COUNT_PER_PACKAGE="$LOG_COUNT_PER_PACKAGE")"
  producer_start_ms="${timing%% *}"
  timing="${timing#* }"
  producer_end_ms="${timing%% *}"
  producer_rc="${timing##* }"
  producer_elapsed_ms=$(( producer_end_ms - producer_start_ms ))
  add_ok="$(parse_run_result "$log_file" add_ok)"
  success="$(parse_run_result "$log_file" success)"
  fail="$(parse_run_result "$log_file" fail)"
  close_rc="$(parse_run_result "$log_file" close_rc)"
  [[ -z "$add_ok" ]] && add_ok=0
  [[ -z "$success" ]] && success=0
  [[ -z "$fail" ]] && fail=0
  [[ -z "$close_rc" ]] && close_rc=-999

  query_exact "$run_id" "$add_ok" $(( producer_start_ms - 60000 )) $(( $(date +%s) * 1000 + 120000 )) "$QUERY_TIMEOUT_MS" "$query_file"
  query_end_ms=$(( $(date +%s) * 1000 ))
  query_elapsed_ms=$(( query_end_ms - producer_start_ms ))
  unique_seq="$(parse_last_search_field "$query_file" unique_seq)"
  duplicates="$(parse_last_search_field "$query_file" duplicates)"
  [[ -z "$unique_seq" ]] && unique_seq=0
  [[ -z "$duplicates" ]] && duplicates=0

  if [[ "$producer_rc" -eq 0 && "$close_rc" -eq 0 && "$fail" -eq 0 && "$unique_seq" -eq "$add_ok" ]]; then
    bench_pass=1
  fi

  echo "BENCH_RESULT mode=steady rate=$rate run_id=$run_id add_ok=$add_ok success=$success fail=$fail close_rc=$close_rc unique_seq=$unique_seq duplicates=$duplicates producer_ms=$producer_elapsed_ms query_ms=$query_elapsed_ms producer_lps=$(calc_logs_per_s "$add_ok" "$producer_elapsed_ms") end_to_end_lps=$(calc_logs_per_s "$unique_seq" "$query_elapsed_ms") pass=$bench_pass"
  return 0
}

bench_recover_once() {
  local records="$1"
  local run_id="pbenchr${records}_$(date +%s)"
  local dir="/tmp/ve-tls-persist-bench-$run_id"
  local seed_log="$ARCHIVE_DIR/${run_id}.recover.seed.log"
  local recover_log="$ARCHIVE_DIR/${run_id}.recover.log"
  local query_file="$ARCHIVE_DIR/${run_id}.recover.query.log"
  local timing
  local producer_start_ms
  local producer_end_ms
  local producer_rc
  local producer_elapsed_ms
  local add_ok
  local success
  local fail
  local close_rc
  local unique_seq
  local duplicates
  local query_end_ms
  local query_elapsed_ms
  local bench_pass=0

  echo "BENCH_START mode=recover records=$records run_id=$run_id archive=$recover_log"
  timing="$(run_demo_capture "$seed_log" "$records" 0 \
    VE_TLS_ENDPOINT="$VE_TLS_ENDPOINT" \
    VE_TLS_REGION="$VE_TLS_REGION" \
    VE_TLS_TOPIC_ID="$VE_TLS_TOPIC_ID" \
    VE_TLS_ACCESS_KEY_ID="$VE_TLS_ACCESS_KEY_ID" \
    VE_TLS_ACCESS_KEY_SECRET="$VE_TLS_ACCESS_KEY_SECRET" \
    VE_TLS_SECURITY_TOKEN="${VE_TLS_SECURITY_TOKEN:-}" \
    VE_TLS_COMPRESS_TYPE="${VE_TLS_COMPRESS_TYPE:-lz4}" \
    VE_TLS_SEND_THREAD_COUNT=1 \
    VE_TLS_REQUEST_TIMEOUT_MS=1000 \
    VE_TLS_CONNECT_TIMEOUT_MS=1000 \
    VE_TLS_HTTP_DEBUG=0 \
    VE_TLS_PROXY=http://127.0.0.1:9 \
    VE_TLS_USE_PERSISTENT=1 \
    VE_TLS_PERSISTENT_FILE_PATH="$dir" \
    VE_TLS_MAX_PERSISTENT_LOG_COUNT=500000 \
    VE_TLS_MAX_PERSISTENT_FILE_SIZE=8388608 \
    VE_TLS_MAX_PERSISTENT_FILE_COUNT=64 \
    VE_TLS_DEMO_RUN_ID="$run_id" \
    VE_TLS_DEMO_SCENARIO=recover_bench_seed \
    VE_TLS_DEMO_EXPECT_SUCCESS=0 \
    VE_TLS_DEMO_EXIT_AFTER_ENQUEUE=1 \
    VE_TLS_DEMO_PRINT_SUCCESS_CALLBACKS=0 \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=600000 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1000)"
  producer_rc="${timing##* }"
  if [[ "$producer_rc" -ne 90 ]]; then
    echo "BENCH_RESULT mode=recover records=$records run_id=$run_id seed_rc=$producer_rc pass=0"
    return 0
  fi
  sleep 5

  timing="$(run_bench_capture "$recover_log"     --mode recover     --wait-ms "$WAIT_MS"     --run-id "$run_id"     --persistent-dir "$dir"     --recover-expect "$records"     --send-thread-count "$SEND_THREAD_COUNT"     --     VE_TLS_ENDPOINT="$VE_TLS_ENDPOINT"     VE_TLS_REGION="$VE_TLS_REGION"     VE_TLS_TOPIC_ID="$VE_TLS_TOPIC_ID"     VE_TLS_ACCESS_KEY_ID="$VE_TLS_ACCESS_KEY_ID"     VE_TLS_ACCESS_KEY_SECRET="$VE_TLS_ACCESS_KEY_SECRET"     VE_TLS_SECURITY_TOKEN="${VE_TLS_SECURITY_TOKEN:-}"     VE_TLS_COMPRESS_TYPE="${VE_TLS_COMPRESS_TYPE:-lz4}"     VE_TLS_SEND_THREAD_COUNT="$SEND_THREAD_COUNT"     VE_TLS_REQUEST_TIMEOUT_MS=10000     VE_TLS_CONNECT_TIMEOUT_MS=10000     VE_TLS_SEND_QUEUE_SIZE=4096     VE_TLS_SEND_QUEUE_FULL_POLICY=block     VE_TLS_SEND_QUEUE_BLOCK_TIMEOUT_MS=100     VE_TLS_SEND_QUEUE_SAMPLE_EVERY_N=10     VE_TLS_HTTP_DEBUG=0     VE_TLS_USE_PERSISTENT=1     VE_TLS_PERSISTENT_FILE_PATH="$dir"     VE_TLS_MAX_PERSISTENT_LOG_COUNT=500000     VE_TLS_MAX_PERSISTENT_FILE_SIZE=8388608     VE_TLS_MAX_PERSISTENT_FILE_COUNT=64     VE_TLS_DEMO_RUN_ID="$run_id"     VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000     VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500     VE_TLS_FLUSH_INTERVAL_MS="$FLUSH_INTERVAL_MS"     VE_TLS_LOG_COUNT_PER_PACKAGE="$LOG_COUNT_PER_PACKAGE")"
  producer_start_ms="${timing%% *}"
  timing="${timing#* }"
  producer_end_ms="${timing%% *}"
  producer_rc="${timing##* }"
  producer_elapsed_ms=$(( producer_end_ms - producer_start_ms ))
  add_ok="$(parse_run_result "$recover_log" add_ok)"
  success="$(parse_run_result "$recover_log" success)"
  fail="$(parse_run_result "$recover_log" fail)"
  close_rc="$(parse_run_result "$recover_log" close_rc)"
  [[ -z "$add_ok" ]] && add_ok=0
  [[ -z "$success" ]] && success=0
  [[ -z "$fail" ]] && fail=0
  [[ -z "$close_rc" ]] && close_rc=-999

  query_exact "$run_id" "$records" $(( producer_start_ms - 60000 )) $(( $(date +%s) * 1000 + 120000 )) "$QUERY_TIMEOUT_MS" "$query_file"
  query_end_ms=$(( $(date +%s) * 1000 ))
  query_elapsed_ms=$(( query_end_ms - producer_start_ms ))
  unique_seq="$(parse_last_search_field "$query_file" unique_seq)"
  duplicates="$(parse_last_search_field "$query_file" duplicates)"
  [[ -z "$unique_seq" ]] && unique_seq=0
  [[ -z "$duplicates" ]] && duplicates=0

  if [[ "$producer_rc" -eq 0 && "$close_rc" -eq 0 && "$fail" -eq 0 && "$unique_seq" -eq "$records" ]]; then
    bench_pass=1
  fi

  echo "BENCH_RESULT mode=recover records=$records run_id=$run_id add_ok=$add_ok success=$success fail=$fail close_rc=$close_rc unique_seq=$unique_seq duplicates=$duplicates producer_ms=$producer_elapsed_ms query_ms=$query_elapsed_ms recover_lps=$(calc_logs_per_s "$records" "$producer_elapsed_ms") end_to_end_lps=$(calc_logs_per_s "$unique_seq" "$query_elapsed_ms") pass=$bench_pass"
  return 0
}

max_steady_rate=0
if [[ "$MODE" == "steady" || "$MODE" == "all" ]]; then
  for rate in ${(s:,:)RATES_CSV}; do
    result="$(bench_steady_once "$rate")"
    echo "$result"
    if echo "$result" | grep -q 'pass=1'; then
      max_steady_rate="$rate"
    else
      break
    fi
  done
  echo "BENCH_SUMMARY mode=steady max_pass_rate=$max_steady_rate archive_dir=$ARCHIVE_DIR"
fi

max_recover_records=0
if [[ "$MODE" == "recover" || "$MODE" == "all" ]]; then
  for records in ${(s:,:)RECOVER_RECORDS_CSV}; do
    result="$(bench_recover_once "$records")"
    echo "$result"
    if echo "$result" | grep -q 'pass=1'; then
      max_recover_records="$records"
    else
      break
    fi
  done
  echo "BENCH_SUMMARY mode=recover max_pass_records=$max_recover_records archive_dir=$ARCHIVE_DIR"
fi
