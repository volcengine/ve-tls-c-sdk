set(min_line_coverage 70)
if(DEFINED ENV{VE_TLS_COVERAGE_MIN_LINE})
  set(min_line_coverage $ENV{VE_TLS_COVERAGE_MIN_LINE})
endif()

if(NOT DEFINED bin_dir)
  message(FATAL_ERROR "bin_dir is required")
endif()
if(NOT DEFINED test_exe)
  message(FATAL_ERROR "test_exe is required")
endif()

set(profraw_glob "${bin_dir}/coverage-*.profraw")
file(GLOB existing_profraw "${profraw_glob}")
foreach(f IN LISTS existing_profraw)
  file(REMOVE "${f}")
endforeach()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=${bin_dir}/coverage-%p.profraw ctest -V
  WORKING_DIRECTORY ${bin_dir}
  RESULT_VARIABLE ctest_rc
)
if(NOT ctest_rc EQUAL 0)
  message(FATAL_ERROR "ctest failed: ${ctest_rc}")
endif()

find_program(profdata_tool NAMES llvm-profdata)
find_program(cov_tool NAMES llvm-cov)
if((NOT profdata_tool OR NOT cov_tool) AND APPLE)
  execute_process(COMMAND xcrun -f llvm-profdata OUTPUT_VARIABLE profdata_tool OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process(COMMAND xcrun -f llvm-cov OUTPUT_VARIABLE cov_tool OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()
if(NOT profdata_tool)
  message(FATAL_ERROR "llvm-profdata not found")
endif()
if(NOT cov_tool)
  message(FATAL_ERROR "llvm-cov not found")
endif()

file(GLOB profraws "${profraw_glob}")
list(LENGTH profraws profraw_count)
if(profraw_count EQUAL 0)
  message(FATAL_ERROR "no profraw files produced")
endif()

set(profdata "${bin_dir}/coverage.profdata")
execute_process(
  COMMAND ${profdata_tool} merge -sparse ${profraws} -o ${profdata}
  WORKING_DIRECTORY ${bin_dir}
  RESULT_VARIABLE merge_rc
)
if(NOT merge_rc EQUAL 0)
  message(FATAL_ERROR "llvm-profdata merge failed: ${merge_rc}")
endif()

execute_process(
  COMMAND ${cov_tool} report ${test_exe} -instr-profile=${profdata} -ignore-filename-regex=.*/third_party/.*|.*/adapters/.*|.*/tests/.*|.*/tools/.*
  WORKING_DIRECTORY ${bin_dir}
  OUTPUT_VARIABLE report_out
  RESULT_VARIABLE report_rc
)
if(NOT report_rc EQUAL 0)
  message(FATAL_ERROR "llvm-cov report failed: ${report_rc}")
endif()

string(REGEX MATCH "TOTAL[^\n]*" total_line "${report_out}")
if(NOT total_line)
  message(FATAL_ERROR "failed to find TOTAL line in llvm-cov report output:\n${report_out}")
endif()

string(REGEX MATCHALL "([0-9]+\\.[0-9]+)%" pct_list "${total_line}")
list(LENGTH pct_list pct_count)
if(pct_count LESS 1)
  message(FATAL_ERROR "failed to parse TOTAL percentages:\n${report_out}")
endif()

set(line_pct "0.00")
if(pct_count GREATER_EQUAL 3)
  list(GET pct_list 2 line_pct)
else()
  list(GET pct_list -1 line_pct)
endif()

string(REGEX MATCH "^([0-9]+)\\.([0-9]+)" _lm "${line_pct}")
if(NOT _lm)
  message(FATAL_ERROR "failed to parse line coverage value '${line_pct}'")
endif()
set(line_major "${CMAKE_MATCH_1}")
set(line_minor "${CMAKE_MATCH_2}")
string(LENGTH "${line_minor}" line_minor_len)
if(line_minor_len EQUAL 0)
  set(line_minor "00")
elseif(line_minor_len EQUAL 1)
  set(line_minor "${line_minor}0")
else()
  string(SUBSTRING "${line_minor}" 0 2 line_minor)
endif()

math(EXPR min_scaled "${min_line_coverage} * 100")
math(EXPR line_scaled "${line_major} * 100 + ${line_minor}")
message(STATUS "coverage line % = ${line_major}.${line_minor} (min ${min_line_coverage}.00)")

if(line_scaled LESS min_scaled)
  message(FATAL_ERROR "line coverage ${line_major}.${line_minor}% < ${min_line_coverage}.00%\n${report_out}")
endif()
