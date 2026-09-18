add_executable(original_vlse_demo demo.cpp)

find_package(OpenSSL REQUIRED)

target_include_directories(original_vlse_demo PRIVATE
    ${PROJECT_SOURCE_DIR}/original_vlse/include
    ${PROJECT_SOURCE_DIR}/paired_vlse/include
    ${PROJECT_SOURCE_DIR}/common/include
    ${PROJECT_SOURCE_DIR}/Vacuum-Filter
)

target_link_libraries(original_vlse_demo PRIVATE
    vlse_ntl_oprf
    OpenSSL::Crypto)

add_test(NAME original_vlse_demo COMMAND original_vlse_demo)
