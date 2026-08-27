if(NOT DEFINED VE_TLS_LIBRARY OR NOT DEFINED VE_TLS_APPROVED_FILE)
    message(FATAL_ERROR "VE_TLS_LIBRARY and VE_TLS_APPROVED_FILE are required")
endif()
if(NOT EXISTS "${VE_TLS_LIBRARY}")
    message(FATAL_ERROR "shared library does not exist: ${VE_TLS_LIBRARY}")
endif()
if(NOT EXISTS "${VE_TLS_APPROVED_FILE}")
    message(FATAL_ERROR "approved symbol file does not exist: ${VE_TLS_APPROVED_FILE}")
endif()

if(NOT DEFINED VE_TLS_NM OR VE_TLS_NM STREQUAL "")
    find_program(VE_TLS_NM nm)
endif()
if(NOT VE_TLS_NM)
    message(FATAL_ERROR "nm was not found")
endif()

file(STRINGS "${VE_TLS_APPROVED_FILE}" approved_lines)
set(expected_symbols)
foreach(raw_line IN LISTS approved_lines)
    string(STRIP "${raw_line}" line)
    string(REGEX REPLACE "#.*$" "" line "${line}")
    string(STRIP "${line}" line)
    if(line STREQUAL "")
        continue()
    endif()
    if(NOT line MATCHES "^ve_tls_[A-Za-z0-9_]+$")
        message(FATAL_ERROR "invalid approved symbol entry: ${line}")
    endif()
    if(line STREQUAL "ve_tls_http_client_init_curl" AND NOT VE_TLS_EXPECT_CURL)
        continue()
    endif()
    list(APPEND expected_symbols "${line}")
endforeach()
list(REMOVE_DUPLICATES expected_symbols)

if(VE_TLS_SYSTEM_NAME STREQUAL "Darwin")
    execute_process(
        COMMAND "${VE_TLS_NM}" -gU "${VE_TLS_LIBRARY}"
        RESULT_VARIABLE nm_result
        OUTPUT_VARIABLE nm_output
        ERROR_VARIABLE nm_error
    )
    set(strip_macho_prefix TRUE)
else()
    execute_process(
        COMMAND "${VE_TLS_NM}" -D --defined-only --extern-only "${VE_TLS_LIBRARY}"
        RESULT_VARIABLE nm_result
        OUTPUT_VARIABLE nm_output
        ERROR_VARIABLE nm_error
    )
    set(strip_macho_prefix FALSE)
endif()
if(NOT nm_result EQUAL 0)
    message(FATAL_ERROR "nm failed (${nm_result}): ${nm_error}")
endif()

string(REPLACE "\r\n" "\n" nm_output "${nm_output}")
string(REPLACE "\r" "\n" nm_output "${nm_output}")
string(REPLACE "\n" ";" nm_lines "${nm_output}")
set(actual_symbols)
foreach(raw_line IN LISTS nm_lines)
    string(STRIP "${raw_line}" line)
    if(line STREQUAL "")
        continue()
    endif()
    # GNU nm appends @@VERSION to symbols selected by a version script.
    string(REGEX REPLACE "@@?.*$" "" line "${line}")
    string(REGEX MATCH "[_A-Za-z][_A-Za-z0-9]*$" symbol "${line}")
    if(symbol STREQUAL "")
        continue()
    endif()
    if(strip_macho_prefix)
        string(REGEX REPLACE "^_" "" symbol "${symbol}")
    endif()
    list(APPEND actual_symbols "${symbol}")
endforeach()
list(REMOVE_DUPLICATES actual_symbols)

set(missing_symbols)
foreach(symbol IN LISTS expected_symbols)
    list(FIND actual_symbols "${symbol}" symbol_index)
    if(symbol_index EQUAL -1)
        list(APPEND missing_symbols "${symbol}")
    endif()
endforeach()

set(unexpected_symbols)
foreach(symbol IN LISTS actual_symbols)
    list(FIND expected_symbols "${symbol}" symbol_index)
    if(symbol_index EQUAL -1)
        list(APPEND unexpected_symbols "${symbol}")
    endif()
endforeach()
list(SORT missing_symbols)
list(SORT unexpected_symbols)

if(missing_symbols OR unexpected_symbols)
    string(JOIN ", " missing_text ${missing_symbols})
    string(JOIN ", " unexpected_text ${unexpected_symbols})
    message(FATAL_ERROR
        "ABI export check failed. Missing: [${missing_text}] Unexpected: [${unexpected_text}]"
    )
endif()

list(SORT actual_symbols)
string(JOIN ", " actual_text ${actual_symbols})
message(STATUS "ABI export check passed: ${actual_text}")
