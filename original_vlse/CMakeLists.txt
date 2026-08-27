add_executable(original_vlse_demo demo.cpp)

target_include_directories(original_vlse_demo PRIVATE
    ${PROJECT_SOURCE_DIR}/original_vlse/include
    ${PROJECT_SOURCE_DIR}/Vacuum-Filter
)

add_test(NAME original_vlse_demo COMMAND original_vlse_demo)
