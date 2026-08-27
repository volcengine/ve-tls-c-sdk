cmake_minimum_required(VERSION 3.16)
project(ve_tls_c_sdk VERSION 0.3.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(VE_TLS_ENABLE_PTHREAD "Enable pthread-based runtime" ON)
option(VE_TLS_ENABLE_CURL "Enable libcurl http adapter" OFF)
option(VE_TLS_ENABLE_ZLIB "Enable zlib compression" ON)
option(VE_TLS_ENABLE_LZ4 "Enable lz4 compression" ON)
option(VE_TLS_BUILD_TESTS "Build unit tests" ON)
option(VE_TLS_BUILD_TOOLS "Build demo and benchmark tools" ON)
option(VE_TLS_ENABLE_COVERAGE "Enable llvm coverage instrumentation" OFF)
option(VE_TLS_ENABLE_ASAN "Enable address sanitizer" OFF)
option(VE_TLS_ENABLE_UBSAN "Enable undefined behavior sanitizer" OFF)

add_library(ve_tls_core)
set_target_properties(ve_tls_core PROPERTIES EXPORT_NAME core)

if(BUILD_SHARED_LIBS)
    # Public declarations opt back into default visibility through the API macro.
    set_target_properties(ve_tls_core PROPERTIES
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    target_compile_definitions(ve_tls_core
        PRIVATE VE_TLS_BUILDING_LIBRARY=1
        PUBLIC VE_TLS_SHARED=1
    )
endif()

target_sources(ve_tls_core PRIVATE
    core/src/ve_tls_producer.c
    core/src/producer/ve_tls_producer_queue.c
    core/src/producer/ve_tls_producer_builder.c
    core/src/producer/ve_tls_producer_common.c
    core/src/producer/ve_tls_producer_config.c
    core/src/producer/ve_tls_producer_manager.c
    core/src/producer/ve_tls_producer_sender.c
    core/src/producer/ve_tls_persistent_format.c
    core/src/producer/ve_tls_segment_store.c
    core/src/producer/ve_tls_checkpoint.c
    core/src/producer/ve_tls_lease.c
    core/src/producer/ve_tls_persistent.c
    core/src/producer/ve_tls_pool.c
    core/src/producer/ve_tls_snapshot.c
    core/src/producer/ve_tls_env.c
    core/src/ve_tls_alloc.c
    core/src/ve_tls_retry.c
    core/src/ve_tls_http_types.c
    core/src/ve_tls_proto.c
    core/src/ve_tls_compress.c
    core/src/ve_tls_error.c
    core/src/ve_tls_hash.c
    core/src/ve_tls_sign.c
    bindings/android/src/ve_tls_android_binding.c
    adapters/src/ve_tls_adapter_posix.c
    adapters/src/ve_tls_platform_pthread.c
)

if(VE_TLS_ENABLE_CURL)
    target_sources(ve_tls_core PRIVATE adapters/src/ve_tls_http_curl.c)
    find_package(CURL REQUIRED)
    target_link_libraries(ve_tls_core PRIVATE CURL::libcurl)
    target_compile_definitions(ve_tls_core PUBLIC VE_TLS_HAVE_CURL=1)
endif()

if(VE_TLS_ENABLE_ZLIB)
    find_package(ZLIB REQUIRED)
    target_link_libraries(ve_tls_core PUBLIC ZLIB::ZLIB)
    target_compile_definitions(ve_tls_core PUBLIC VE_TLS_HAVE_ZLIB=1)
endif()

if(VE_TLS_ENABLE_LZ4)
    target_sources(ve_tls_core PRIVATE third_party/lz4/lz4.c)
    target_include_directories(ve_tls_core PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4
    )
    target_compile_definitions(ve_tls_core PUBLIC VE_TLS_HAVE_LZ4=1)
    if(VE_TLS_ENABLE_UBSAN AND (CMAKE_C_COMPILER_ID MATCHES "Clang"))
        set_source_files_properties(third_party/lz4/lz4.c PROPERTIES COMPILE_OPTIONS "-fno-sanitize=undefined")
    endif()
endif()

target_include_directories(ve_tls_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/core/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/adapters/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/bindings/android/include>
    $<INSTALL_INTERFACE:include>
)

if(VE_TLS_ENABLE_PTHREAD)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(ve_tls_core PRIVATE Threads::Threads)
    target_compile_definitions(ve_tls_core PUBLIC VE_TLS_ENABLE_PTHREAD=1)
endif()

if(UNIX AND NOT APPLE)
    target_link_libraries(ve_tls_core PUBLIC m)
endif()

if(BUILD_SHARED_LIBS AND (APPLE OR UNIX))
    if(VE_TLS_ENABLE_CURL)
        set(VE_TLS_CURL_EXPORT "        ve_tls_http_client_init_curl;")
        set(VE_TLS_CURL_EXPORT_MACOS "_ve_tls_http_client_init_curl")
    else()
        set(VE_TLS_CURL_EXPORT "")
        set(VE_TLS_CURL_EXPORT_MACOS "")
    endif()
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ve_tls_exports.map
        ${CMAKE_CURRENT_BINARY_DIR}/ve_tls_exports.map
        @ONLY
    )
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ve_tls_exports.macos.txt
        ${CMAKE_CURRENT_BINARY_DIR}/ve_tls_exports.macos.txt
        @ONLY
    )
    if(APPLE)
        target_link_options(ve_tls_core PRIVATE
            "-Wl,-exported_symbols_list,${CMAKE_CURRENT_BINARY_DIR}/ve_tls_exports.macos.txt"
        )
    else()
        target_link_options(ve_tls_core PRIVATE
            "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/ve_tls_exports.map"
        )
    endif()
endif()

include(CMakePackageConfigHelpers)

if(VE_TLS_ENABLE_PTHREAD)
    set(VE_TLS_PACKAGE_NEEDS_THREADS ON)
else()
    set(VE_TLS_PACKAGE_NEEDS_THREADS OFF)
endif()
if(VE_TLS_ENABLE_ZLIB)
    set(VE_TLS_PACKAGE_NEEDS_ZLIB ON)
else()
    set(VE_TLS_PACKAGE_NEEDS_ZLIB OFF)
endif()
if(VE_TLS_ENABLE_CURL)
    set(VE_TLS_PACKAGE_NEEDS_CURL ON)
else()
    set(VE_TLS_PACKAGE_NEEDS_CURL OFF)
endif()

set(VE_TLS_PACKAGE_CONFIG_INSTALL_DIR "lib/cmake/ve_tls_core")
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ve_tls_coreConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/ve_tls_coreConfig.cmake
    INSTALL_DESTINATION ${VE_TLS_PACKAGE_CONFIG_INSTALL_DIR}
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/ve_tls_coreConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(TARGETS ve_tls_core
    EXPORT ve_tls_coreTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)
install(FILES
    core/include/ve_tls_alloc.h
    core/include/ve_tls_env.h
    core/include/ve_tls_error.h
    core/include/ve_tls_export.h
    core/include/ve_tls_http.h
    core/include/ve_tls_producer.h
    core/include/ve_tls_retry.h
    core/include/ve_tls_version.h
    adapters/include/ve_tls_http_curl.h
    adapters/include/ve_tls_platform.h
    bindings/android/include/ve_tls_android_binding.h
    DESTINATION include
)
install(EXPORT ve_tls_coreTargets
    FILE ve_tls_coreTargets.cmake
    NAMESPACE ve_tls::
    DESTINATION ${VE_TLS_PACKAGE_CONFIG_INSTALL_DIR}
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/ve_tls_coreConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/ve_tls_coreConfigVersion.cmake
    DESTINATION ${VE_TLS_PACKAGE_CONFIG_INSTALL_DIR}
)
install(FILES
    LICENSE
    THIRD_PARTY_NOTICES.md
    SBOM.spdx.json
    docs/abi.md
    docs/platform-contract.md
    docs/release-notes-0.3.0.md
    DESTINATION share/doc/ve_tls_core
)

if(BUILD_SHARED_LIBS AND (APPLE OR UNIX))
    add_custom_target(ve_tls_verify_exports
        COMMAND ${CMAKE_COMMAND}
            "-DVE_TLS_LIBRARY=$<TARGET_FILE:ve_tls_core>"
            "-DVE_TLS_APPROVED_FILE=${CMAKE_CURRENT_SOURCE_DIR}/abi/approved-symbols.txt"
            "-DVE_TLS_NM=${CMAKE_NM}"
            "-DVE_TLS_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
            "-DVE_TLS_EXPECT_CURL=${VE_TLS_ENABLE_CURL}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/verify_exports.cmake
        DEPENDS ve_tls_core
        VERBATIM
    )
endif()

if(VE_TLS_BUILD_TOOLS AND NOT ANDROID)
    add_executable(ve_tls_demo tools/demo.c)
    target_link_libraries(ve_tls_demo PRIVATE ve_tls_core)

    add_executable(ve_tls_demo_putlogs tools/putlogs_demo.c)
    target_link_libraries(ve_tls_demo_putlogs PRIVATE ve_tls_core)

    add_executable(ve_tls_demo_putlogsv2 tools/putlogsv2_demo.c)
    target_link_libraries(ve_tls_demo_putlogsv2 PRIVATE ve_tls_core)

    add_executable(ve_tls_demo_real tools/real_demo.c)
    target_link_libraries(ve_tls_demo_real PRIVATE ve_tls_core)

    add_executable(ve_tls_bench tools/bench.c)
    target_link_libraries(ve_tls_bench PRIVATE ve_tls_core)

    if(NOT BUILD_SHARED_LIBS)
        # These developer tools intentionally call internal helpers and are not
        # consumers of the approved shared-library ABI.
        add_executable(ve_tls_gen_raw_log tools/gen_raw_log.c)
        target_link_libraries(ve_tls_gen_raw_log PRIVATE ve_tls_core)
    endif()

    add_executable(ve_tls_perf_tls tools/perf_tls.c)
    target_link_libraries(ve_tls_perf_tls PRIVATE ve_tls_core)

    add_executable(ve_tls_benchmark_tls tools/benchmark_tls.c)
    target_link_libraries(ve_tls_benchmark_tls PRIVATE ve_tls_core)

    if(NOT BUILD_SHARED_LIBS)
        add_executable(ve_tls_persistent_bench tools/persistent_bench.c)
        target_link_libraries(ve_tls_persistent_bench PRIVATE ve_tls_core)
        target_include_directories(ve_tls_persistent_bench PRIVATE core/src)

        add_executable(ve_tls_persistent_real_bench tools/persistent_real_bench.c)
        target_link_libraries(ve_tls_persistent_real_bench PRIVATE ve_tls_core)
        target_include_directories(ve_tls_persistent_real_bench PRIVATE core/src)
    endif()
endif()

if(VE_TLS_BUILD_TESTS)
    enable_testing()
    enable_language(CXX)
    # test_basic intentionally reaches internal symbols and fault hooks. Keep it
    # on the static test build rather than weakening the shared-library ABI.
    if(NOT BUILD_SHARED_LIBS)
        target_compile_definitions(ve_tls_core PRIVATE VE_TLS_ENABLE_ALLOC_FAULT_INJECT=1)
        add_executable(ve_tls_test_basic tests/test_basic.c)
        target_link_libraries(ve_tls_test_basic PRIVATE ve_tls_core)
        target_include_directories(ve_tls_test_basic PRIVATE core/src)
        if(VE_TLS_ENABLE_LZ4)
            target_include_directories(ve_tls_test_basic PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4
            )
        endif()
        target_compile_definitions(ve_tls_test_basic PRIVATE VE_TLS_ENABLE_ALLOC_FAULT_INJECT=1)
        if(VE_TLS_ENABLE_CURL)
            target_compile_definitions(ve_tls_core PRIVATE VE_TLS_CURL_TEST_HOOKS=1)
            target_compile_definitions(ve_tls_test_basic PRIVATE VE_TLS_CURL_TEST_HOOKS=1)
        endif()
        add_test(NAME ve_tls_test_basic COMMAND ve_tls_test_basic)

        if(VE_TLS_ENABLE_LZ4)
            add_executable(ve_tls_test_lz4_host_consumer tests/test_lz4_host_consumer.c)
            target_link_libraries(ve_tls_test_lz4_host_consumer PRIVATE ve_tls_core)
            add_test(NAME ve_tls_lz4_host_consumer COMMAND ve_tls_test_lz4_host_consumer)
            add_test(NAME ve_tls_lz4_symbols
                COMMAND ${CMAKE_COMMAND}
                    "-DVE_TLS_LIBRARY=$<TARGET_FILE:ve_tls_core>"
                    "-DVE_TLS_NM=${CMAKE_NM}"
                    "-DVE_TLS_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_lz4_symbols.cmake
            )
        endif()
    endif()

    add_executable(ve_tls_test_android_binding tests/test_android_binding.c)
    target_link_libraries(ve_tls_test_android_binding PRIVATE ve_tls_core)
    add_test(NAME ve_tls_test_android_binding COMMAND ve_tls_test_android_binding)

    add_executable(ve_tls_test_cpp_headers tests/test_cpp_headers.cpp)
    target_link_libraries(ve_tls_test_cpp_headers PRIVATE ve_tls_core)
    target_compile_features(ve_tls_test_cpp_headers PRIVATE cxx_std_11)
    add_test(NAME ve_tls_test_cpp_headers COMMAND ve_tls_test_cpp_headers)

    if(BUILD_SHARED_LIBS AND (APPLE OR UNIX))
        add_test(NAME ve_tls_abi_exports
            COMMAND ${CMAKE_COMMAND}
                "-DVE_TLS_LIBRARY=$<TARGET_FILE:ve_tls_core>"
                "-DVE_TLS_APPROVED_FILE=${CMAKE_CURRENT_SOURCE_DIR}/abi/approved-symbols.txt"
                "-DVE_TLS_NM=${CMAKE_NM}"
                "-DVE_TLS_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
                "-DVE_TLS_EXPECT_CURL=${VE_TLS_ENABLE_CURL}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/verify_exports.cmake
        )
    endif()
    if(TARGET ve_tls_bench)
        add_test(NAME ve_tls_bench_help COMMAND ve_tls_bench --help)
        set_tests_properties(ve_tls_bench_help PROPERTIES
            PASS_REGULAR_EXPRESSION "--use-persistent 0\\|1.*--profile tls200\\|tls700\\|tls5120"
        )
        add_test(NAME ve_tls_bench_phase_metrics
            COMMAND ve_tls_bench
                --duration-s 1
                --rate-lps 1
                --message-bytes 200
                --writer-threads 1
                --write-mode kv
                --use-persistent 1
                --persistent-dir /tmp/ve_tls_bench_phase_metrics
                --compress-type none
                --close-timeout-ms 10000
        )
        set_tests_properties(ve_tls_bench_phase_metrics PROPERTIES
            PASS_REGULAR_EXPRESSION "bench phases .*produce_ms=.*close_ms=.*produce_lps=.*"
        )
        add_test(NAME ve_tls_bench_persistent_default_sender
            COMMAND ve_tls_bench
                --duration-s 1
                --rate-lps 1
                --message-bytes 200
                --writer-threads 1
                --write-mode kv
                --use-persistent 1
                --persistent-dir /tmp/ve_tls_bench_default_sender
                --compress-type none
                --close-timeout-ms 10000
        )
        set_tests_properties(ve_tls_bench_persistent_default_sender PROPERTIES
            PASS_REGULAR_EXPRESSION "bench config .*persistent=1.*senders=1"
        )
    endif()
    if(TARGET ve_tls_perf_tls)
        add_test(
            NAME ve_tls_perf_tls_output_fields
            COMMAND $<TARGET_FILE:ve_tls_perf_tls>
                --mode mock
                --duration-s 1
                --rate-lps 100
                --writers 1
                --profile tls200
                --close-timeout-ms 1000
        )
        set_tests_properties(ve_tls_perf_tls_output_fields PROPERTIES
            PASS_REGULAR_EXPRESSION "sdk_buffered_bytes_peak=[0-9][0-9]*.*sdk_buffered_bytes_final=[0-9][0-9]*"
        )
    endif()
    if(TARGET ve_tls_demo)
        add_test(NAME ve_tls_demo_help COMMAND ve_tls_demo --help)
        set_tests_properties(ve_tls_demo_help PROPERTIES
            PASS_REGULAR_EXPRESSION "VE_TLS_ENDPOINT.*VE_TLS_DEMO_MESSAGE"
        )
    endif()
    if(TARGET ve_tls_demo_putlogs)
        add_test(NAME ve_tls_demo_putlogs_help COMMAND ve_tls_demo_putlogs --help)
        set_tests_properties(ve_tls_demo_putlogs_help PROPERTIES
            PASS_REGULAR_EXPRESSION "VE_TLS_ENDPOINT.*VE_TLS_DEMO_MESSAGE"
        )
    endif()
    if(TARGET ve_tls_demo_putlogsv2)
        add_test(NAME ve_tls_demo_putlogsv2_help COMMAND ve_tls_demo_putlogsv2 --help)
        set_tests_properties(ve_tls_demo_putlogsv2_help PROPERTIES
            PASS_REGULAR_EXPRESSION "VE_TLS_CONTEXT_FLOW.*VE_TLS_API_VERSION"
        )
    endif()
    if(TARGET ve_tls_persistent_real_bench)
        add_test(NAME ve_tls_persistent_real_bench_help COMMAND ve_tls_persistent_real_bench --help)
        set_tests_properties(ve_tls_persistent_real_bench_help PROPERTIES
            PASS_REGULAR_EXPRESSION "--write-mode;--profile;--report-interval-s"
        )
    endif()
endif()

if(VE_TLS_ENABLE_ASAN OR VE_TLS_ENABLE_UBSAN)
    set(_sanitize_flags "")
    if(VE_TLS_ENABLE_ASAN)
        set(_sanitize_flags "${_sanitize_flags}address")
    endif()
    if(VE_TLS_ENABLE_UBSAN)
        if(_sanitize_flags STREQUAL "")
            set(_sanitize_flags "undefined")
        else()
            set(_sanitize_flags "${_sanitize_flags},undefined")
        endif()
    endif()
    foreach(tgt IN ITEMS
        ve_tls_core
        ve_tls_test_basic
        ve_tls_test_lz4_host_consumer
        ve_tls_test_android_binding
        ve_tls_test_cpp_headers
        ve_tls_demo
        ve_tls_demo_putlogs
        ve_tls_demo_putlogsv2
        ve_tls_demo_real
        ve_tls_bench
        ve_tls_gen_raw_log
        ve_tls_perf_tls
        ve_tls_benchmark_tls
        ve_tls_persistent_bench
        ve_tls_persistent_real_bench
    )
        if(TARGET ${tgt})
            target_compile_options(${tgt} PRIVATE -fsanitize=${_sanitize_flags} -fno-omit-frame-pointer)
            target_link_options(${tgt} PRIVATE -fsanitize=${_sanitize_flags})
        endif()
    endforeach()
    if(TARGET ve_tls_test_basic)
        set_tests_properties(ve_tls_test_basic PROPERTIES
            ENVIRONMENT "ASAN_OPTIONS=abort_on_error=1:detect_leaks=0;UBSAN_OPTIONS=halt_on_error=1"
        )
    endif()
endif()

if(VE_TLS_ENABLE_COVERAGE AND (CMAKE_C_COMPILER_ID MATCHES "Clang"))
    foreach(tgt IN ITEMS ve_tls_core ve_tls_test_basic)
        if(TARGET ${tgt})
            target_compile_options(${tgt} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
            target_link_options(${tgt} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
        endif()
    endforeach()
    if(TARGET ve_tls_test_basic)
        add_custom_target(ve_tls_coverage
            COMMAND ${CMAKE_COMMAND} -Dbin_dir=${CMAKE_BINARY_DIR} -Dtest_exe=$<TARGET_FILE:ve_tls_test_basic> -P ${CMAKE_SOURCE_DIR}/cmake/coverage.cmake
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
    endif()
endif()
