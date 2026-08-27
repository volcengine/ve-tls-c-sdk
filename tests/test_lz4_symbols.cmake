if(NOT DEFINED VE_TLS_LIBRARY)
    message(FATAL_ERROR "VE_TLS_LIBRARY is required")
endif()
if(NOT EXISTS "${VE_TLS_LIBRARY}")
    message(FATAL_ERROR "static library does not exist: ${VE_TLS_LIBRARY}")
endif()

if(NOT DEFINED VE_TLS_NM OR VE_TLS_NM STREQUAL "")
    find_program(VE_TLS_NM nm)
endif()
if(NOT VE_TLS_NM)
    message(FATAL_ERROR "nm was not found")
endif()

set(bundled_lz4_symbols
    LZ4_versionNumber
    LZ4_compressBound
    LZ4_sizeofState
    LZ4_compress_fast_extState
    LZ4_compress_fast
    LZ4_compress_default
    LZ4_compress_fast_force
    LZ4_compress_destSize
    LZ4_createStream
    LZ4_resetStream
    LZ4_freeStream
    LZ4_loadDict
    LZ4_compress_fast_continue
    LZ4_compress_forceExtDict
    LZ4_saveDict
    LZ4_decompress_safe
    LZ4_decompress_safe_partial
    LZ4_decompress_fast
    LZ4_createStreamDecode
    LZ4_freeStreamDecode
    LZ4_setStreamDecode
    LZ4_decompress_safe_continue
    LZ4_decompress_fast_continue
    LZ4_decompress_safe_usingDict
    LZ4_decompress_fast_usingDict
    LZ4_decompress_safe_forceExtDict
    LZ4_compress_limitedOutput
    LZ4_compress
    LZ4_compress_limitedOutput_withState
    LZ4_compress_withState
    LZ4_compress_limitedOutput_continue
    LZ4_compress_continue
    LZ4_uncompress
    LZ4_uncompress_unknownOutputSize
    LZ4_sizeofStreamState
    LZ4_resetStreamState
    LZ4_create
    LZ4_slideInputBuffer
    LZ4_decompress_safe_withPrefix64k
    LZ4_decompress_fast_withPrefix64k
)
list(LENGTH bundled_lz4_symbols bundled_lz4_symbol_count)
if(NOT bundled_lz4_symbol_count EQUAL 40)
    message(FATAL_ERROR "internal LZ4 symbol list must contain 40 entries")
endif()

set(expected_namespaced_symbols)
foreach(symbol IN LISTS bundled_lz4_symbols)
    list(APPEND expected_namespaced_symbols "VE_TLS_${symbol}")
endforeach()

execute_process(
    COMMAND "${VE_TLS_NM}" -g --defined-only "${VE_TLS_LIBRARY}"
    RESULT_VARIABLE nm_result
    OUTPUT_VARIABLE nm_output
    ERROR_VARIABLE nm_error
)
if(NOT nm_result EQUAL 0)
    message(FATAL_ERROR "nm failed (${nm_result}): ${nm_error}")
endif()

string(REPLACE "\r\n" "\n" nm_output "${nm_output}")
string(REPLACE "\r" "\n" nm_output "${nm_output}")
string(REPLACE "\n" ";" nm_lines "${nm_output}")
set(actual_namespaced_symbols)
set(bare_symbols)
foreach(raw_line IN LISTS nm_lines)
    string(STRIP "${raw_line}" line)
    if(line STREQUAL "")
        continue()
    endif()
    string(REGEX MATCH "[_A-Za-z][_A-Za-z0-9]*$" symbol "${line}")
    if(symbol STREQUAL "")
        continue()
    endif()
    if(symbol MATCHES "^_VE_TLS_LZ4_")
        string(SUBSTRING "${symbol}" 1 -1 symbol)
        list(APPEND actual_namespaced_symbols "${symbol}")
    elseif(symbol MATCHES "^VE_TLS_LZ4_")
        list(APPEND actual_namespaced_symbols "${symbol}")
    elseif(symbol MATCHES "^_LZ4_")
        string(SUBSTRING "${symbol}" 1 -1 symbol)
        list(APPEND bare_symbols "${symbol}")
    elseif(symbol MATCHES "^LZ4_")
        list(APPEND bare_symbols "${symbol}")
    endif()
endforeach()
list(REMOVE_DUPLICATES actual_namespaced_symbols)
list(REMOVE_DUPLICATES bare_symbols)
list(SORT actual_namespaced_symbols)
list(SORT expected_namespaced_symbols)
list(SORT bare_symbols)

if(bare_symbols)
    string(JOIN ", " bare_text ${bare_symbols})
    message(FATAL_ERROR "bundled static library defines bare LZ4 symbols: ${bare_text}")
endif()

if(NOT actual_namespaced_symbols STREQUAL expected_namespaced_symbols)
    string(JOIN ", " expected_text ${expected_namespaced_symbols})
    string(JOIN ", " actual_text ${actual_namespaced_symbols})
    message(FATAL_ERROR
        "bundled LZ4 symbol check failed. Expected: [${expected_text}] Actual: [${actual_text}]"
    )
endif()

message(STATUS "bundled LZ4 symbol check passed: ${actual_namespaced_symbols}")
