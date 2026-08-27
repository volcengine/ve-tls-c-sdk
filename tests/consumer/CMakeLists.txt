cmake_minimum_required(VERSION 3.16)
project(ve_tls_c_sdk_consumer C)

find_package(ve_tls_core CONFIG REQUIRED)

add_executable(ve_tls_consumer main.c)
target_link_libraries(ve_tls_consumer PRIVATE ve_tls::core)
