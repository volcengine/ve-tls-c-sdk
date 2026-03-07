cmake_minimum_required(VERSION 3.16)
project(ve_tls_c_sdk C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(ve_tls_core
    core/src/ve_tls_producer.c
    adapters/src/ve_tls_adapter_posix.c
)

target_include_directories(ve_tls_core PUBLIC
    core/include
    adapters/include
)
