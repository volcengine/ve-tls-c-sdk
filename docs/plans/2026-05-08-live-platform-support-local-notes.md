# Live Platform Support Local Notes

## Baseline

- Worktree: `/private/tmp/ve-tls-c-sdk-live`
- Branch: `codex/live-platform-support`
- Baseline configure: `cmake -S . -B build-live-baseline -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF`
- Baseline build: `cmake --build build-live-baseline -j`
- Baseline tests: `ctest --test-dir build-live-baseline --output-on-failure`
- Result: native macOS Release no-curl build and `ve_tls_test_basic` pass.
- Warnings: no compiler warnings appeared in the baseline build output.

## Current POSIX Assumptions

- `CMakeLists.txt` selected `adapters/src/ve_tls_adapter_posix.c` and `adapters/src/ve_tls_platform_pthread.c` unconditionally before Task 2.
- `adapters/src/ve_tls_adapter_posix.c` depends on `unistd.h`, `open`, `close`, `read`, `write`, `lseek`, and `fsync`.
- `adapters/src/ve_tls_platform_pthread.c` depends on `pthread`, `clock_gettime`, `gettimeofday`, and `nanosleep`.
- `VE_TLS_ENABLE_PTHREAD=OFF` previously avoided linking `Threads::Threads` but did not remove the pthread platform source.

## Scope Correction

- `live` does not cover Android or iOS. Mobile bridge SDK work belongs to the persistent/mobile SDK track.
- The remaining `live` scope is desktop/general C core build support: macOS, Linux, and Windows.

## macOS Host Windows Toolchain Blocker

- `x86_64-w64-mingw32-gcc` is not installed on this host.
- `clang-cl` is not installed on this host.
- `cmake -S . -B build-live-win-mingw -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF -DCMAKE_SYSTEM_NAME=Windows` used `/usr/bin/cc` instead of a real Windows compiler.
- The produced `build-live-win-mingw/ve_tls_test_basic.exe` was `Mach-O 64-bit executable arm64`, not a Windows PE executable.
- Therefore this host cannot prove a real Windows build for Task 2. Current validation is limited to native macOS regression plus CMake source-selection checks.
- After Task 2 CMake changes, the Windows target selects `adapters/src/ve_tls_adapter_win32.c` and `adapters/src/ve_tls_platform_win32.c`.
- The post-change Windows build still fails on this host because `/usr/bin/cc` cannot find `windows.h`.
- Native POSIX `VE_TLS_ENABLE_PTHREAD=OFF` now fails at configure time instead of silently compiling the pthread platform source without linking `Threads::Threads`.

## Windows 10 UCRT64 Validation

- Host: `iv-74cva4gim516`, Windows 10 `10.0.19045.5011`.
- Toolchain installed through MSYS2 UCRT64 after `winget` source failures:
  - gcc `16.1.0`
  - cmake `4.3.2`
  - ninja `1.13.2`
  - git `2.54.0`
- Configure/build command:
  - `cmake -S . -B build-live-win-ucrt -G Ninja -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF`
  - `cmake --build build-live-win-ucrt -j`
- Test command:
  - `ctest --test-dir build-live-win-ucrt --output-on-failure`
- Result: Windows no-curl build passed and `ve_tls_test_basic` passed.
- Post MSVC test-race fix recheck: `cmake --build build-live-win-ucrt -j` and `ctest --test-dir build-live-win-ucrt --output-on-failure` passed.
- Output binaries include `ve_tls_demo.exe`, `ve_tls_demo_real.exe`, `ve_tls_bench.exe`, `ve_tls_benchmark_tls.exe`, `ve_tls_gen_raw_log.exe`, and `ve_tls_test_basic.exe`.
- PE evidence: `ve_tls_test_basic.exe` starts with `MZ`.
- Fixes needed by real Windows validation:
  - `core/src/ve_tls_sign.c`: wrap UTC time formatting so Windows uses `gmtime_s` instead of POSIX-only `gmtime_r`.
  - `tools/benchmark_tls.c`: replace POSIX-only timing/resource helpers with Windows `QueryPerformanceCounter`, `Sleep`, `GetProcessTimes`, and `GetProcessMemoryInfo`.
  - `CMakeLists.txt`: link `ve_tls_benchmark_tls` with `psapi` on Windows.

## Windows 10 UCRT64 CURL Validation

- Configure/build command:
  - `cmake -S . -B build-live-win-ucrt-curl -G Ninja -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON`
  - `cmake --build build-live-win-ucrt-curl -j`
- CMake found CURL through `C:/msys64/ucrt64/lib/cmake/CURL/CURLConfig.cmake`, version `8.20.0`.
- Test command:
  - `ctest --test-dir build-live-win-ucrt-curl --output-on-failure`
- Result: Windows curl build passed and `ve_tls_test_basic` passed.
- Post MSVC test-race fix recheck: `cmake --build build-live-win-ucrt-curl -j` and `ctest --test-dir build-live-win-ucrt-curl --output-on-failure` passed.
- PE evidence: `ve_tls_test_basic.exe` starts with `MZ`.
- Boundary: this validates compile/link/test with the curl adapter.

## Windows 10 Real TLS Send Validation

- Binary: `build-live-win-ucrt-curl/ve_tls_demo_real.exe`.
- Environment:
  - Real endpoint, region, topic, AK, and SK were passed through process environment variables only.
  - No real credentials were written to repo files.
- Demo results:
  - `VE_TLS_COMPRESS_TYPE=lz4 ve_tls_demo_real.exe --count 10 --wait-ms 30000`: send callback returned `http=200`; metrics `logs_enqueued=10`, `logs_dropped=0`, `batches=1`, `requests=1`, `failed=0`, `retries=0`, `bytes_sent=108`.
  - `VE_TLS_COMPRESS_TYPE=none ve_tls_demo_real.exe --count 10 --wait-ms 30000`: send callback returned `http=200`; metrics `logs_enqueued=10`, `logs_dropped=0`, `batches=1`, `requests=1`, `failed=0`, `retries=0`, `bytes_sent=503`.
- Single-batch benchmark smoke:
  - `tls200`, `500 logs/s`, `3s`: `logs=1500`, `requests=1`, `failed=0`, `retries=0`, `rss=13.82MB`.
  - `tls700`, `500 logs/s`, `3s`: `logs=1500`, `requests=1`, `failed=0`, `retries=0`, `rss=14.53MB`.
  - `tls5120`, `100 logs/s`, `3s`: `logs=300`, `requests=1`, `failed=0`, `retries=0`, `rss=15.03MB`.
- Multi-request benchmark:
  - `tls200`, `1000 logs/s`, `5s`, `TLS_PACKET_LOG_COUNT=100`: `logs=5000`, `batches=50`, `requests=50`, `failed=0`, `retries=0`, `rss=19.64MB`.
  - `tls700`, `1000 logs/s`, `5s`, `TLS_PACKET_LOG_COUNT=100`: `logs=5000`, `batches=50`, `requests=50`, `failed=0`, `retries=0`, `rss=20.16MB`.
  - `tls5120`, `200 logs/s`, `5s`, `TLS_PACKET_LOG_COUNT=50`: `logs=1000`, `batches=20`, `requests=20`, `failed=0`, `retries=0`, `rss=20.27MB`.

## macOS CURL Real TLS Validation

- Configure/build/test:
  - `cmake -S . -B build-live-curl-real -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON`
  - `cmake --build build-live-curl-real -j`
  - `ctest --test-dir build-live-curl-real --output-on-failure`
- CMake found Apple SDK libcurl `8.7.1`.
- Real endpoint results:
  - `ve_tls_demo_real --count 5 --wait-ms 30000`: send callback returned `http=200`; metrics `logs_enqueued=5`, `logs_dropped=0`, `batches=1`, `requests=1`, `failed=0`, `retries=0`, `bytes_sent=253`.
  - `ve_tls_benchmark_tls 500 3 tls200` with `TLS_PACKET_LOG_COUNT=100`: `logs=1500`, `batches=15`, `requests=15`, `failed=0`, `retries=0`, `rss=10.05MB`.

## Windows 10 MSVC / clang-cl Validation

- Visual Studio Build Tools 2022 was installed under `C:\BuildTools`.
- Toolchain versions:
  - MSVC `19.44.35226`
  - clang-cl `19.1.5`
- MSVC no-curl configure/build/test:
  - `cmake -S . -B build-live-win-msvc -G Ninja -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF`
  - `cmake --build build-live-win-msvc -j`
  - `ctest --test-dir build-live-win-msvc --output-on-failure`
- MSVC result: build passed and `ve_tls_test_basic` passed.
- clang-cl no-curl configure/build/test:
  - `cmake -S . -B build-live-win-clangcl -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=OFF`
  - `cmake --build build-live-win-clangcl -j`
  - `ctest --test-dir build-live-win-clangcl --output-on-failure`
- clang-cl result: build passed and `ve_tls_test_basic` passed.
- MSVC repeat check: `ctest --test-dir build-live-win-msvc --output-on-failure --repeat until-fail:10` passed 10/10 after fixing a test-only `export -> import -> export` race.
- clang-cl repeat check: `ctest --test-dir build-live-win-clangcl --output-on-failure --repeat until-fail:5` passed 5/5.
- Fixes needed by MSVC / clang-cl validation:
  - `compat/msvc/strings.h`: provide `strcasecmp` / `strncasecmp` aliases for Windows CRT.
  - `compat/msvc/unistd.h`: provide the small `usleep` surface used by tests/tools.
  - `core/include/ve_tls_msvc_compat.h`: force-include a narrow MSVC compatibility header; native MSVC uses `/experimental:c11atomics`, `_Thread_local`, `_strdup`, and small `__atomic_*` wrappers, while clang-cl only needs the `_strdup` mapping.
  - `tests/test_basic.c`: disable background worker threads inside `test_export_import_raw_buffer` so the test validates raw-buffer roundtrip deterministically instead of racing with import-triggered worker delivery.

## Windows 10 MSVC / clang-cl CURL Real TLS Validation

- VS-compatible libcurl dependency:
  - vcpkg installed under `C:\tools\vcpkg`, version `2026-04-08-e0612b42ce44e55a0e630f2ee9d3c533a63d8bc1`.
  - Installed package: `curl:x64-windows@8.20.0#1` with `zlib:x64-windows@1.3.2`.
  - `C:\tools\vcpkg\installed\x64-windows\share\curl\CURLConfig.cmake` exists.
  - `C:\tools\vcpkg\installed\x64-windows\bin\libcurl.dll` exists and must be on `PATH` for real demo execution.
- Installation notes:
  - vcpkg's direct downloads for CMake, 7zip, 7zr, PortableGit, and PowerShell Core were unreliable through the Win10 network path.
  - Successful path was to pre-seed the vcpkg download cache for CMake `4.3.2`, 7zip `26.01`, 7zr `26.01`, and PowerShell Core `7.6.1`, then put existing MSYS2 Git `2.54.0` on `PATH` for the install command.
- MSVC curl configure/build/test:
  - `cmake -S . -B build-live-win-msvc-curl-vcpkg-msvc3 -G Ninja -DCMAKE_MAKE_PROGRAM=C:\tools\vcpkg\downloads\tools\ninja-1.13.2-windows\ninja.exe -DCMAKE_C_COMPILER=cl -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON -DCMAKE_TOOLCHAIN_FILE=C:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake`
  - `cmake --build build-live-win-msvc-curl-vcpkg-msvc3 -j 2`
  - `ctest --test-dir build-live-win-msvc-curl-vcpkg-msvc3 --output-on-failure`
- MSVC result:
  - CMake compiler identification: `MSVC 19.44.35226.0`.
  - Build passed and `ve_tls_test_basic` passed.
  - Real endpoint send: `build-live-win-msvc-curl-vcpkg-msvc3\ve_tls_demo_real.exe --count 5 --wait-ms 30000` with `VE_TLS_COMPRESS_TYPE=lz4` returned `http=200`; metrics `logs_enqueued=5`, `logs_dropped=0`, `batches=1`, `requests=1`, `failed=0`, `retries=0`, `bytes_sent=253`.
- clang-cl curl configure/build/test:
  - `cmake -S . -B build-live-win-clangcl-curl-vcpkg -G Ninja -DCMAKE_MAKE_PROGRAM=C:\tools\vcpkg\downloads\tools\ninja-1.13.2-windows\ninja.exe -DCMAKE_C_COMPILER=clang-cl -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON -DCMAKE_TOOLCHAIN_FILE=C:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake`
  - `cmake --build build-live-win-clangcl-curl-vcpkg -j 2`
  - `ctest --test-dir build-live-win-clangcl-curl-vcpkg --output-on-failure`
- clang-cl result:
  - CMake compiler identification: `Clang 19.1.5 with MSVC-like command-line`.
  - Build passed and `ve_tls_test_basic` passed.
  - Real endpoint send: `build-live-win-clangcl-curl-vcpkg\ve_tls_demo_real.exe --count 5 --wait-ms 30000` with `VE_TLS_COMPRESS_TYPE=lz4` returned `http=200`; metrics `logs_enqueued=5`, `logs_dropped=0`, `batches=1`, `requests=1`, `failed=0`, `retries=0`, `bytes_sent=253`.
- Credential handling:
  - Real endpoint, region, topic, AK, and SK were passed through process environment variables only.
  - No real credentials were written to repo files.
