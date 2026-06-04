#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
SDK_ROOT="${SCRIPT_DIR:h}"
BUILD_DIR="${BUILD_DIR:-$SDK_ROOT/build-persistent-real}"
CONF_FILE="${CONF_FILE:-$SDK_ROOT/tools/real_demo.env}"
QUERY="$SDK_ROOT/tools/tls_search_logs.go"
QUERY_FORMAT="$SDK_ROOT/tools/tls_search_logs_format.go"
RUNNER="$BUILD_DIR/ve_tls_demo_real"

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
if [[ ! -x "$RUNNER" ]]; then
  if [[ -z "$CMAKE_BIN" || ! -x "$CMAKE_BIN" ]]; then
    echo "missing cmake to build ve_tls_demo_real" >&2
    exit 2
  fi
  "$CMAKE_BIN" -S "$SDK_ROOT" -B "$BUILD_DIR" -DVE_TLS_ENABLE_CURL=ON
  "$CMAKE_BIN" --build "$BUILD_DIR" --target ve_tls_demo_real -j4
fi

set -a
source "$CONF_FILE"
set +a

export LOG_SERVICE_ENDPOINT="$VE_TLS_ENDPOINT"
export LOG_SERVICE_REGION="$VE_TLS_REGION"
export LOG_SERVICE_AK="$VE_TLS_ACCESS_KEY_ID"
export LOG_SERVICE_SK="$VE_TLS_ACCESS_KEY_SECRET"
export LOG_SERVICE_TOKEN="${VE_TLS_SECURITY_TOKEN:-}"
export LOG_SERVICE_TOPIC="$VE_TLS_TOPIC_ID"

run_query_exact() {
  local run_id="$1"
  local exact="$2"
  local start_ms="$3"
  local end_ms="$4"
  local timeout_ms="${5:-60000}"
  local allow_duplicates="${6:-0}"
  (
    cd "$GO_SDK_ROOT"
    export GOCACHE=/tmp/go-build
    export PERSIST_QUERY_RUN_ID="$run_id"
    export PERSIST_QUERY_EXPECT_EXACT="$exact"
    export PERSIST_QUERY_START_MS="$start_ms"
    export PERSIST_QUERY_END_MS="$end_ms"
    export PERSIST_QUERY_TIMEOUT_MS="$timeout_ms"
    export PERSIST_QUERY_POLL_MS=1000
    export PERSIST_QUERY_LIMIT=500
    export PERSIST_QUERY_ALLOW_DUPLICATES="$allow_duplicates"
    "$GO_BIN" run "$QUERY" "$QUERY_FORMAT"
  )
}

run_demo() {
  local run_id="$1"
  local dir="$2"
  local count="$3"
  local wait_ms="$4"
  shift 4
  env \
    VE_TLS_ENDPOINT="$VE_TLS_ENDPOINT" \
    VE_TLS_REGION="$VE_TLS_REGION" \
    VE_TLS_TOPIC_ID="$VE_TLS_TOPIC_ID" \
    VE_TLS_ACCESS_KEY_ID="$VE_TLS_ACCESS_KEY_ID" \
    VE_TLS_ACCESS_KEY_SECRET="$VE_TLS_ACCESS_KEY_SECRET" \
    VE_TLS_SECURITY_TOKEN="${VE_TLS_SECURITY_TOKEN:-}" \
    VE_TLS_COMPRESS_TYPE="${VE_TLS_COMPRESS_TYPE:-lz4}" \
    VE_TLS_SEND_THREAD_COUNT=1 \
    VE_TLS_REQUEST_TIMEOUT_MS=50000 \
    VE_TLS_CONNECT_TIMEOUT_MS=10000 \
    VE_TLS_SEND_QUEUE_SIZE=1024 \
    VE_TLS_SEND_QUEUE_FULL_POLICY=block \
    VE_TLS_SEND_QUEUE_BLOCK_TIMEOUT_MS=100 \
    VE_TLS_SEND_QUEUE_SAMPLE_EVERY_N=10 \
    VE_TLS_HTTP_DEBUG=0 \
    VE_TLS_USE_PERSISTENT=1 \
    VE_TLS_PERSISTENT_FILE_PATH="$dir" \
    VE_TLS_MAX_PERSISTENT_LOG_COUNT=1000 \
    VE_TLS_MAX_PERSISTENT_FILE_SIZE=1048576 \
    VE_TLS_MAX_PERSISTENT_FILE_COUNT=8 \
    VE_TLS_DEMO_RUN_ID="$run_id" \
    "$@" \
    "$RUNNER" --config "$CONF_FILE" --count "$count" --wait-ms "$wait_ms"
}

run_expect_exit() {
  local expect_rc="$1"
  shift
  local rc=0
  set +e
  "$@"
  rc=$?
  set -e
  if [[ "$rc" -ne "$expect_rc" ]]; then
    echo "unexpected rc: got=$rc expect=$expect_rc" >&2
    exit 20
  fi
}

wait_expect_exit() {
  local pid="$1"
  local expect_rc="$2"
  local rc=0
  set +e
  wait "$pid"
  rc=$?
  set -e
  if [[ "$rc" -ne "$expect_rc" ]]; then
    echo "unexpected background rc: got=$rc expect=$expect_rc pid=$pid" >&2
    exit 21
  fi
}

corrupt_checkpoint_magic() {
  local dir="$1"
  local checkpoint="$dir/checkpoint"
  if [[ ! -f "$checkpoint" ]]; then
    echo "missing checkpoint file: $checkpoint" >&2
    exit 22
  fi
  printf '\x00' | dd of="$checkpoint" bs=1 seek=0 conv=notrunc >/dev/null 2>&1
}

scenario_baseline() {
  local run_id="pbase$(date +%s)"
  local dir="/tmp/ve-tls-persist-baseline-$run_id"
  local start_ms=$(( $(date +%s) * 1000 - 60000 ))
  echo "SCENARIO baseline run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 10 20000 \
    VE_TLS_DEMO_SCENARIO=baseline \
    VE_TLS_DEMO_EXPECT_SUCCESS=10 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  run_query_exact "$run_id" 10 "$start_ms" $(( $(date +%s) * 1000 + 60000 ))

  echo "SCENARIO baseline_recover run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 0 5000 \
    VE_TLS_DEMO_SCENARIO=baseline_recover \
    VE_TLS_DEMO_RECOVER=1 \
    VE_TLS_DEMO_EXPECT_SUCCESS=0 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  sleep 5
  run_query_exact "$run_id" 10 "$start_ms" $(( $(date +%s) * 1000 + 60000 ))
}

scenario_crash_before_send() {
  local run_id="pcrash$(date +%s)"
  local dir="/tmp/ve-tls-persist-crash-$run_id"
  local start_ms=$(( $(date +%s) * 1000 - 60000 ))
  echo "SCENARIO crash_before_send_enqueue run_id=$run_id dir=$dir"
  run_expect_exit 90 run_demo "$run_id" "$dir" 10 15000 \
    VE_TLS_DEMO_SCENARIO=crash_before_send \
    VE_TLS_DEMO_EXPECT_SUCCESS=10 \
    VE_TLS_DEMO_EXIT_AFTER_ENQUEUE=1 \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=600000 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1000
  sleep 12
  run_query_exact "$run_id" 0 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 5000

  echo "SCENARIO crash_before_send_recover run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 0 25000 \
    VE_TLS_DEMO_SCENARIO=crash_before_send_recover \
    VE_TLS_DEMO_RECOVER=1 \
    VE_TLS_DEMO_EXPECT_SUCCESS=10 \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  run_query_exact "$run_id" 10 "$start_ms" $(( $(date +%s) * 1000 + 60000 ))
}

scenario_partial_send_then_crash() {
  local run_id="ppart$(date +%s)"
  local dir="/tmp/ve-tls-persist-partial-$run_id"
  local start_ms=$(( $(date +%s) * 1000 - 60000 ))
  echo "SCENARIO partial_send_then_crash run_id=$run_id dir=$dir"
  run_expect_exit 91 run_demo "$run_id" "$dir" 30 30000 \
    VE_TLS_DEMO_SCENARIO=partial_send_then_crash \
    VE_TLS_DEMO_EXPECT_SUCCESS=30 \
    VE_TLS_DEMO_EXIT_AFTER_SUCCESS=10 \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  sleep 5
  echo "SCENARIO partial_send_recover run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 0 30000 \
    VE_TLS_DEMO_SCENARIO=partial_send_recover \
    VE_TLS_DEMO_RECOVER=1 \
    VE_TLS_DEMO_EXPECT_SUCCESS=20 \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  run_query_exact "$run_id" 30 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 60000 1
}

scenario_timeout_then_recover() {
  local run_id="ptimeout$(date +%s)"
  local dir="/tmp/ve-tls-persist-timeout-$run_id"
  local start_ms=$(( $(date +%s) * 1000 - 60000 ))
  echo "SCENARIO timeout_then_crash run_id=$run_id dir=$dir"
  run_expect_exit 90 run_demo "$run_id" "$dir" 10 5000 \
    VE_TLS_DEMO_SCENARIO=timeout_then_crash \
    VE_TLS_DEMO_EXPECT_SUCCESS=10 \
    VE_TLS_DEMO_EXIT_AFTER_ENQUEUE=1 \
    VE_TLS_DEMO_EXIT_DELAY_MS=2500 \
    VE_TLS_PROXY=http://127.0.0.1:9 \
    VE_TLS_REQUEST_TIMEOUT_MS=1000 \
    VE_TLS_CONNECT_TIMEOUT_MS=1000 \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  sleep 12
  run_query_exact "$run_id" 0 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 5000

  echo "SCENARIO timeout_recover run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 0 25000 \
    VE_TLS_DEMO_SCENARIO=timeout_recover \
    VE_TLS_DEMO_RECOVER=1 \
    VE_TLS_DEMO_EXPECT_SUCCESS=10 \
    VE_TLS_PROXY= \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  run_query_exact "$run_id" 10 "$start_ms" $(( $(date +%s) * 1000 + 60000 ))
}

scenario_terminal_auth_drop() {
  local run_id="pauthdrop$(date +%s)"
  local dir="/tmp/ve-tls-persist-authdrop-$run_id"
  local start_ms=$(( $(date +%s) * 1000 - 60000 ))
  echo "SCENARIO terminal_auth_drop run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 5 15000 \
    VE_TLS_DEMO_SCENARIO=terminal_auth_drop \
    VE_TLS_ACCESS_KEY_SECRET="${VE_TLS_ACCESS_KEY_SECRET}BAD" \
    VE_TLS_DEMO_EXPECT_SUCCESS=5 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  run_query_exact "$run_id" 0 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 5000

  echo "SCENARIO terminal_auth_drop_recover run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 0 5000 \
    VE_TLS_DEMO_SCENARIO=terminal_auth_drop_recover \
    VE_TLS_DEMO_RECOVER=1 \
    VE_TLS_DEMO_EXPECT_SUCCESS=0 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  run_query_exact "$run_id" 0 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 5000
}

scenario_quota_reject_new() {
  local run_id="pquota$(date +%s)"
  local dir="/tmp/ve-tls-persist-quota-$run_id"
  local start_ms=$(( $(date +%s) * 1000 - 60000 ))
  echo "SCENARIO quota_reject_new run_id=$run_id dir=$dir"
  run_expect_exit 90 run_demo "$run_id" "$dir" 20 5000 \
    VE_TLS_DEMO_SCENARIO=quota_reject_new \
    VE_TLS_DEMO_EXPECT_SUCCESS=0 \
    VE_TLS_DEMO_EXIT_AFTER_ENQUEUE=1 \
    VE_TLS_PROXY=http://127.0.0.1:9 \
    VE_TLS_REQUEST_TIMEOUT_MS=1000 \
    VE_TLS_CONNECT_TIMEOUT_MS=1000 \
    VE_TLS_PERSISTENT_MAX_RECORDS=5 \
    VE_TLS_PERSISTENT_OVERFLOW_POLICY=reject_new \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=600000 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1000
  sleep 12
  run_query_exact "$run_id" 0 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 5000

  echo "SCENARIO quota_reject_new_recover run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 0 25000 \
    VE_TLS_DEMO_SCENARIO=quota_reject_new_recover \
    VE_TLS_DEMO_RECOVER=1 \
    VE_TLS_DEMO_EXPECT_SUCCESS=5 \
    VE_TLS_PERSISTENT_MAX_RECORDS=5 \
    VE_TLS_PERSISTENT_OVERFLOW_POLICY=reject_new \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  run_query_exact "$run_id" 5 "$start_ms" $(( $(date +%s) * 1000 + 60000 ))
}

scenario_checkpoint_corruption() {
  local run_id="pckpt$(date +%s)"
  local dir="/tmp/ve-tls-persist-checkpoint-$run_id"
  local start_ms=$(( $(date +%s) * 1000 - 60000 ))
  echo "SCENARIO checkpoint_corruption_enqueue run_id=$run_id dir=$dir"
  run_expect_exit 90 run_demo "$run_id" "$dir" 10 5000 \
    VE_TLS_DEMO_SCENARIO=checkpoint_corruption \
    VE_TLS_DEMO_EXPECT_SUCCESS=0 \
    VE_TLS_DEMO_EXIT_AFTER_ENQUEUE=1 \
    VE_TLS_PROXY=http://127.0.0.1:9 \
    VE_TLS_REQUEST_TIMEOUT_MS=1000 \
    VE_TLS_CONNECT_TIMEOUT_MS=1000 \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=600000 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1000
  sleep 12
  run_query_exact "$run_id" 0 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 5000
  corrupt_checkpoint_magic "$dir"

  echo "SCENARIO checkpoint_corruption_recover run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 0 25000 \
    VE_TLS_DEMO_SCENARIO=checkpoint_corruption_recover \
    VE_TLS_DEMO_RECOVER=1 \
    VE_TLS_DEMO_EXPECT_SUCCESS=10 \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  run_query_exact "$run_id" 10 "$start_ms" $(( $(date +%s) * 1000 + 60000 ))
}

scenario_stale_takeover() {
  local run_id="ptake$(date +%s)"
  local dir="/tmp/ve-tls-persist-takeover-$run_id"
  local start_ms=$(( $(date +%s) * 1000 - 60000 ))
  local owner_pid=0
  echo "SCENARIO stale_takeover_writer run_id=$run_id dir=$dir"
  run_expect_exit 90 run_demo "$run_id" "$dir" 10 5000 \
    VE_TLS_DEMO_SCENARIO=stale_takeover_writer \
    VE_TLS_DEMO_EXPECT_SUCCESS=0 \
    VE_TLS_DEMO_EXIT_AFTER_ENQUEUE=1 \
    VE_TLS_PROXY=http://127.0.0.1:9 \
    VE_TLS_REQUEST_TIMEOUT_MS=1000 \
    VE_TLS_CONNECT_TIMEOUT_MS=1000 \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=600000 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1000
  sleep 12
  run_query_exact "$run_id" 0 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 5000

  echo "SCENARIO stale_takeover_owner run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 0 5000 \
    VE_TLS_DEMO_SCENARIO=stale_takeover_owner \
    VE_TLS_DEMO_EXPECT_SUCCESS=0 \
    VE_TLS_DEMO_EXIT_AFTER_ENQUEUE=1 \
    VE_TLS_DEMO_EXIT_DELAY_MS=5000 \
    VE_TLS_PERSISTENT_OPEN_MODE=takeover_if_stale \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=600000 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1000 \
    >/tmp/stale_takeover_owner_${run_id}.log 2>&1 &
  owner_pid=$!
  sleep 1

  echo "SCENARIO stale_takeover_blocked run_id=$run_id dir=$dir"
  run_expect_exit 1 run_demo "$run_id" "$dir" 0 1000 \
    VE_TLS_DEMO_SCENARIO=stale_takeover_blocked \
    VE_TLS_DEMO_RECOVER=1 \
    VE_TLS_DEMO_EXPECT_SUCCESS=0 \
    VE_TLS_PERSISTENT_OPEN_MODE=fail_if_owned

  wait_expect_exit "$owner_pid" 90
  sleep 4
  run_query_exact "$run_id" 0 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 5000

  echo "SCENARIO stale_takeover_recover run_id=$run_id dir=$dir"
  run_demo "$run_id" "$dir" 0 25000 \
    VE_TLS_DEMO_SCENARIO=stale_takeover_recover \
    VE_TLS_DEMO_RECOVER=1 \
    VE_TLS_DEMO_EXPECT_SUCCESS=10 \
    VE_TLS_PERSISTENT_OPEN_MODE=takeover_if_stale \
    VE_TLS_PERSISTENT_LEASE_TIMEOUT_MS=3000 \
    VE_TLS_PERSISTENT_HEARTBEAT_INTERVAL_MS=500 \
    VE_TLS_FLUSH_INTERVAL_MS=0 \
    VE_TLS_LOG_COUNT_PER_PACKAGE=1
  run_query_exact "$run_id" 10 "$start_ms" $(( $(date +%s) * 1000 + 60000 )) 60000 1
}

SCENARIOS=("$@")
if [[ "${#SCENARIOS[@]}" -eq 0 ]]; then
  SCENARIOS=(baseline crash_before_send partial_send_then_crash timeout_then_recover terminal_auth_drop quota_reject_new checkpoint_corruption stale_takeover)
fi

for scenario in "${SCENARIOS[@]}"; do
  case "$scenario" in
    baseline) scenario_baseline ;;
    crash_before_send) scenario_crash_before_send ;;
    partial_send_then_crash) scenario_partial_send_then_crash ;;
    timeout_then_recover) scenario_timeout_then_recover ;;
    terminal_auth_drop) scenario_terminal_auth_drop ;;
    quota_reject_new) scenario_quota_reject_new ;;
    checkpoint_corruption) scenario_checkpoint_corruption ;;
    stale_takeover) scenario_stale_takeover ;;
    *)
      echo "unknown scenario: $scenario" >&2
      exit 2
      ;;
  esac
done

echo "PERSISTENT_VALIDATION_OK"
