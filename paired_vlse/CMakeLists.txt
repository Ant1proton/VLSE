find_package(OpenSSL REQUIRED)

add_executable(paired_vlse_demo demo.cpp)

target_include_directories(paired_vlse_demo PRIVATE
    ${PROJECT_SOURCE_DIR}/paired_vlse/include
    ${PROJECT_SOURCE_DIR}/Vacuum-Filter
)

target_link_libraries(paired_vlse_demo PRIVATE OpenSSL::Crypto)

add_test(NAME paired_vlse_demo COMMAND paired_vlse_demo)
