# Platform Support

`live` keeps the producer feature set aligned with `main` and focuses on desktop/general C core build coverage. Android and iOS are intentionally out of this branch: mobile bridge SDK work belongs to the persistent/mobile SDK track.

## Support Matrix

| Platform | Status | Command | Tests | Notes |
| --- | --- | --- | --- | --- |
| macOS native | Verified | `cmake -S . -B build-live-final -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF && cmake --build build-live-final -j` | `ctest --test-dir build-live-final --output-on-failure` | Verified on the current macOS host. |
| macOS native + curl | Verified | `cmake -S . -B build-live-curl-real -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON && cmake --build build-live-curl-real -j` | `ctest --test-dir build-live-curl-real --output-on-failure` | Verified with Apple SDK libcurl `8.7.1` and real TLS send. |
| Windows 10 UCRT64 MinGW | Verified | `cmake -S . -B build-live-win-ucrt -G Ninja -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF && cmake --build build-live-win-ucrt -j` | `ctest --test-dir build-live-win-ucrt --output-on-failure` | Verified on Windows 10 10.0.19045 with MSYS2 UCRT64 gcc 16.1.0, CMake 4.3.2, Ninja 1.13.2. Produced `.exe` files have `MZ` PE magic. |
| Windows 10 UCRT64 MinGW + curl | Verified | `cmake -S . -B build-live-win-ucrt-curl -G Ninja -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON && cmake --build build-live-win-ucrt-curl -j` | `ctest --test-dir build-live-win-ucrt-curl --output-on-failure` | Verified with MSYS2 CURL `8.20.0`, real TLS send, and real multi-request benchmarks. |
| Windows 10 MSVC | Verified | `cmake -S . -B build-live-win-msvc -G Ninja -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF && cmake --build build-live-win-msvc -j` | `ctest --test-dir build-live-win-msvc --output-on-failure` | Verified with Visual Studio Build Tools 2022 under `C:\BuildTools`, MSVC `19.44.35226`. |
| Windows 10 MSVC + curl | Verified | `cmake -S . -B build-live-win-msvc-curl-vcpkg-msvc3 -G Ninja -DCMAKE_C_COMPILER=cl -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON -DCMAKE_TOOLCHAIN_FILE=C:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake && cmake --build build-live-win-msvc-curl-vcpkg-msvc3 -j 2` | `ctest --test-dir build-live-win-msvc-curl-vcpkg-msvc3 --output-on-failure` | Verified with vcpkg `curl:x64-windows` `8.20.0` and real TLS send. |
| Windows 10 clang-cl | Verified | `cmake -S . -B build-live-win-clangcl -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF && cmake --build build-live-win-clangcl -j` | `ctest --test-dir build-live-win-clangcl --output-on-failure` | Verified with Visual Studio LLVM clang-cl `19.1.5`. |
| Windows 10 clang-cl + curl | Verified | `cmake -S . -B build-live-win-clangcl-curl-vcpkg -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON -DCMAKE_TOOLCHAIN_FILE=C:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake && cmake --build build-live-win-clangcl-curl-vcpkg -j 2` | `ctest --test-dir build-live-win-clangcl-curl-vcpkg --output-on-failure` | Verified with vcpkg `curl:x64-windows` `8.20.0` and real TLS send. |
| Linux native | Expected | `cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF && cmake --build build-linux -j` | `ctest --test-dir build-linux --output-on-failure` | Not revalidated in this branch worktree yet. Existing POSIX pthread adapter remains the Linux path. |
| Android / iOS | Out of scope | N/A | N/A | Covered by the persistent/mobile bridge SDK track, not by `live`. |

## Windows Notes

Windows builds select:

- `adapters/src/ve_tls_adapter_win32.c`
- `adapters/src/ve_tls_platform_win32.c`

The no-curl build is verified with MSYS2 UCRT64 MinGW, MSVC, and clang-cl. The Windows curl build is verified with MSYS2 UCRT64 CURL `8.20.0` and with Visual Studio compatible vcpkg `curl:x64-windows` for MSVC and clang-cl. For VS toolchains, keep the vcpkg runtime DLL directory such as `C:\tools\vcpkg\installed\x64-windows\bin` on `PATH` when running curl-enabled executables.

## Windows Real TLS Send

Windows curl delivery was validated against a real TLS endpoint with credentials passed only through process environment variables.

Real demo coverage:

| Case | Command shape | Result |
| --- | --- | --- |
| lz4 demo | `ve_tls_demo_real.exe --count 10 --wait-ms 30000` with `VE_TLS_COMPRESS_TYPE=lz4` | `http=200`, `logs_enqueued=10`, `requests=1`, `failed=0`, `retries=0` |
| none demo | `ve_tls_demo_real.exe --count 10 --wait-ms 30000` with `VE_TLS_COMPRESS_TYPE=none` | `http=200`, `logs_enqueued=10`, `requests=1`, `failed=0`, `retries=0` |
| MSVC + vcpkg curl | `build-live-win-msvc-curl-vcpkg-msvc3\ve_tls_demo_real.exe --count 5 --wait-ms 30000` with `VE_TLS_COMPRESS_TYPE=lz4` | `http=200`, `logs_enqueued=5`, `requests=1`, `failed=0`, `retries=0` |
| clang-cl + vcpkg curl | `build-live-win-clangcl-curl-vcpkg\ve_tls_demo_real.exe --count 5 --wait-ms 30000` with `VE_TLS_COMPRESS_TYPE=lz4` | `http=200`, `logs_enqueued=5`, `requests=1`, `failed=0`, `retries=0` |

Real benchmark coverage:

| Profile | Target | Requests | Logs | Drops | Failed | Retries | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tls200` | `1000 logs/s` for `5s`, `log_count_per_package=100` | `50` | `5000` | `0` | `0` | `0` | `19.64MB` |
| `tls700` | `1000 logs/s` for `5s`, `log_count_per_package=100` | `50` | `5000` | `0` | `0` | `0` | `20.16MB` |
| `tls5120` | `200 logs/s` for `5s`, `log_count_per_package=50` | `20` | `1000` | `0` | `0` | `0` | `20.27MB` |

macOS curl delivery was also validated with Apple SDK libcurl `8.7.1`:

- `ve_tls_demo_real --count 5 --wait-ms 30000`: `http=200`, `logs_enqueued=5`, `requests=1`, `failed=0`, `retries=0`.
- `ve_tls_benchmark_tls 500 3 tls200` with `log_count_per_package=100`: `logs=1500`, `requests=15`, `failed=0`, `retries=0`, `rss=10.05MB`.

Do not commit real credentials. Pass endpoint, region, topic, and AK/SK through process environment variables only.

The benchmark tool uses platform-specific process accounting:

- POSIX: `getrusage`, `sysconf`, `usleep`.
- Windows: `GetProcessTimes`, `GetProcessMemoryInfo`, `Sleep`, linked with `psapi`.
