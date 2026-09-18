find_package(OpenSSL REQUIRED)

add_executable(vlse_protocol_benchmark vlse_protocol_benchmark.cpp)
target_include_directories(vlse_protocol_benchmark PRIVATE
    ${PROJECT_SOURCE_DIR}/common/include
    ${PROJECT_SOURCE_DIR}/original_vlse/include
    ${PROJECT_SOURCE_DIR}/paired_vlse/include
    ${PROJECT_SOURCE_DIR}/Vacuum-Filter)
target_link_libraries(vlse_protocol_benchmark PRIVATE
    vlse_ntl_oprf
    OpenSSL::Crypto)

add_executable(lse_protocol_benchmark lse_author_flow_benchmark.cpp)
target_include_directories(lse_protocol_benchmark PRIVATE
    ${PROJECT_SOURCE_DIR}/common/include)
target_link_libraries(lse_protocol_benchmark PRIVATE vlse_ntl_oprf)

add_test(
    NAME vlse_paired_protocol_smoke
    COMMAND vlse_protocol_benchmark --layout paired --keywords 256 --queries 8 --dmax 1 --seed 7)
add_test(
    NAME vlse_original_protocol_smoke
    COMMAND vlse_protocol_benchmark --layout original --keywords 256 --queries 8 --dmax 1 --seed 7)
add_test(
    NAME lse_protocol_smoke
    COMMAND lse_protocol_benchmark --keywords 256 --queries 8 --dmax 1 --seed 7)
