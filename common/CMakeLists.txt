find_path(NTL_INCLUDE_DIR NTL/ZZ.h
    HINTS /opt/homebrew/include /usr/local/include /usr/include)
find_library(NTL_LIBRARY NAMES ntl
    HINTS /opt/homebrew/lib /opt/homebrew/opt/ntl/lib /usr/local/lib /usr/lib)
find_library(GMP_LIBRARY NAMES gmp
    HINTS /opt/homebrew/lib /opt/homebrew/opt/gmp/lib /usr/local/lib /usr/lib)
find_path(CRYPTOPP_INCLUDE_DIR cryptopp/sha.h
    HINTS /opt/homebrew/include /usr/local/include /usr/include)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp crypto++
    HINTS /opt/homebrew/lib /opt/homebrew/opt/cryptopp/lib /usr/local/lib /usr/lib)

if(NOT NTL_INCLUDE_DIR OR NOT NTL_LIBRARY OR NOT GMP_LIBRARY OR
   NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR
        "NTL, GMP, and Crypto++ are required for the shared OPRF backend")
endif()

add_library(vlse_ntl_oprf src/ntl_oprf.cpp)
target_include_directories(vlse_ntl_oprf PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${NTL_INCLUDE_DIR}
    ${CRYPTOPP_INCLUDE_DIR})
target_link_libraries(vlse_ntl_oprf PUBLIC
    ${NTL_LIBRARY}
    ${GMP_LIBRARY}
    ${CRYPTOPP_LIBRARY})

add_executable(oprf_consistency_test tests/oprf_consistency_test.cpp)
target_link_libraries(oprf_consistency_test PRIVATE vlse_ntl_oprf)
add_test(NAME oprf_consistency_test COMMAND oprf_consistency_test)
