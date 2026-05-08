cmake_minimum_required(VERSION 3.16)
project(ve_tls_c_sdk C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(VE_TLS_ENABLE_PTHREAD "Enable pthread-based runtime" ON)
option(VE_TLS_ENABLE_CURL "Enable libcurl http adapter" OFF)
option(VE_TLS_ENABLE_ZLIB "Enable zlib compression" OFF)
option(VE_TLS_ENABLE_LZ4 "Enable lz4 compression" ON)
option(VE_TLS_BUILD_TESTS "Build unit tests" ON)
option(VE_TLS_BUILD_TOOLS "Build demo and benchmark tools" ON)
option(VE_TLS_ENABLE_COVERAGE "Enable llvm coverage instrumentation" OFF)
option(VE_TLS_ENABLE_ASAN "Enable address sanitizer" OFF)
option(VE_TLS_ENABLE_UBSAN "Enable undefined behavior sanitizer" OFF)

add_library(ve_tls_core)

target_sources(ve_tls_core PRIVATE
    core/src/ve_tls_producer.c
    core/src/producer/ve_tls_producer_queue.c
    core/src/producer/ve_tls_producer_builder.c
    core/src/producer/ve_tls_producer_common.c
    core/src/producer/ve_tls_producer_config.c
    core/src/producer/ve_tls_producer_manager.c
    core/src/producer/ve_tls_producer_sender.c
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
    target_include_directories(ve_tls_core PUBLIC third_party/lz4)
    target_compile_definitions(ve_tls_core PUBLIC VE_TLS_HAVE_LZ4=1)
    if(VE_TLS_ENABLE_UBSAN AND (CMAKE_C_COMPILER_ID MATCHES "Clang"))
        set_source_files_properties(third_party/lz4/lz4.c PROPERTIES COMPILE_OPTIONS "-fno-sanitize=undefined")
    endif()
endif()

target_include_directories(ve_tls_core PUBLIC
    core/include
    adapters/include
)

if(VE_TLS_ENABLE_PTHREAD)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(ve_tls_core PRIVATE Threads::Threads)
endif()

if(UNIX AND NOT APPLE)
    target_link_libraries(ve_tls_core PUBLIC m)
endif()

if(VE_TLS_BUILD_TOOLS AND NOT ANDROID)
    add_executable(ve_tls_demo tools/demo.c)
    target_link_libraries(ve_tls_demo PRIVATE ve_tls_core)

    add_executable(ve_tls_demo_real tools/real_demo.c)
    target_link_libraries(ve_tls_demo_real PRIVATE ve_tls_core)

    add_executable(ve_tls_bench tools/bench.c)
    target_link_libraries(ve_tls_bench PRIVATE ve_tls_core)

    add_executable(ve_tls_benchmark_tls tools/benchmark_tls.c)
    target_link_libraries(ve_tls_benchmark_tls PRIVATE ve_tls_core)

    add_executable(ve_tls_gen_raw_log tools/gen_raw_log.c)
    target_link_libraries(ve_tls_gen_raw_log PRIVATE ve_tls_core)

endif()

if(VE_TLS_BUILD_TESTS)
    enable_testing()
    add_executable(ve_tls_test_basic tests/test_basic.c)
    target_link_libraries(ve_tls_test_basic PRIVATE ve_tls_core)
    target_include_directories(ve_tls_test_basic PRIVATE core/src)
    add_test(NAME ve_tls_test_basic COMMAND ve_tls_test_basic)
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
    foreach(tgt IN ITEMS ve_tls_core ve_tls_test_basic ve_tls_demo ve_tls_demo_real ve_tls_bench ve_tls_benchmark_tls)
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
