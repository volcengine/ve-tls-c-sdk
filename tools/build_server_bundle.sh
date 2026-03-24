#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build_server_release}"

cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DVE_TLS_BUILD_TESTS=OFF \
  -DVE_TLS_ENABLE_CURL=ON \
  -DVE_TLS_ENABLE_LZ4=ON \
  -DVE_TLS_ENABLE_ZLIB=OFF

cmake --build "$BUILD_DIR" -j --target ve_tls_demo_real

mkdir -p "$OUT_DIR"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
PKG_DIR="$OUT_DIR/ve_tls_demo_real-${OS}-${ARCH}"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"

cp "$BUILD_DIR/ve_tls_demo_real" "$PKG_DIR/"
cp "$ROOT_DIR/tools/real_demo_perf.env.template" "$PKG_DIR/real_demo.env"

cat > "$PKG_DIR/run.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

./ve_tls_demo_real --config "$DIR/real_demo.env" --count "${COUNT:-1000000}" --interval-ms "${INTERVAL_MS:-0}" --wait-ms "${WAIT_MS:-300000}"
EOF
chmod +x "$PKG_DIR/run.sh"

if command -v strip >/dev/null 2>&1; then
  strip "$PKG_DIR/ve_tls_demo_real" || true
fi

TAR="$OUT_DIR/ve_tls_demo_real-${OS}-${ARCH}.tar.gz"
tar -C "$OUT_DIR" -czf "$TAR" "ve_tls_demo_real-${OS}-${ARCH}"
echo "$TAR"
