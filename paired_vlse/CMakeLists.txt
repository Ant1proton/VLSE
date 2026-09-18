find_package(OpenSSL REQUIRED)

add_executable(paired_vlse_demo demo.cpp)

target_include_directories(paired_vlse_demo PRIVATE
    ${PROJECT_SOURCE_DIR}/paired_vlse/include
    ${PROJECT_SOURCE_DIR}/common/include
    ${PROJECT_SOURCE_DIR}/Vacuum-Filter
)

target_link_libraries(paired_vlse_demo PRIVATE
    vlse_ntl_oprf
    OpenSSL::Crypto)

add_test(NAME paired_vlse_demo COMMAND paired_vlse_demo)

add_executable(paired_collision_test collision_test.cpp)
target_include_directories(paired_collision_test PRIVATE
    ${PROJECT_SOURCE_DIR}/paired_vlse/include
    ${PROJECT_SOURCE_DIR}/Vacuum-Filter)
target_link_libraries(paired_collision_test PRIVATE OpenSSL::Crypto)
add_test(NAME paired_collision_test COMMAND paired_collision_test)
