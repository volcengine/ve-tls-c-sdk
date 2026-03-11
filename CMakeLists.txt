cmake_minimum_required(VERSION 3.16)
project(ve_tls_c_sdk C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(VE_TLS_ENABLE_PTHREAD "Enable pthread-based runtime" ON)
option(VE_TLS_ENABLE_CURL "Enable libcurl http adapter" OFF)
option(VE_TLS_ENABLE_ZLIB "Enable zlib compression" OFF)
option(VE_TLS_ENABLE_LZ4 "Enable lz4 compression" ON)
option(VE_TLS_BUILD_TESTS "Build unit tests" ON)

add_library(ve_tls_core)

target_sources(ve_tls_core PRIVATE
    core/src/ve_tls_producer.c
    core/src/producer/ve_tls_producer_queue.c
    core/src/producer/ve_tls_producer_common.c
    core/src/producer/ve_tls_producer_config.c
    core/src/producer/ve_tls_producer_manager.c
    core/src/producer/ve_tls_producer_sender.c
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

add_executable(ve_tls_demo tools/demo.c)
target_link_libraries(ve_tls_demo PRIVATE ve_tls_core)

add_executable(ve_tls_demo_real tools/real_demo.c)
target_link_libraries(ve_tls_demo_real PRIVATE ve_tls_core)

if(VE_TLS_BUILD_TESTS)
    enable_testing()
    add_executable(ve_tls_test_basic tests/test_basic.c)
    target_link_libraries(ve_tls_test_basic PRIVATE ve_tls_core)
    add_test(NAME ve_tls_test_basic COMMAND ve_tls_test_basic)
endif()
