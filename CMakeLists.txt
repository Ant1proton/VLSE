cmake_minimum_required(VERSION 3.10)
project(VLSE)

set(CMAKE_CXX_STANDARD 14)

# 根据架构设置编译选项
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mpopcnt -march=native")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv8-a")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
endif()

# 找到OpenSSL库
find_package(OpenSSL REQUIRED)

# 找到或设置 Crypto++ 路径
find_path(CRYPTOPP_INCLUDE_DIR cryptlib.h
    HINTS /opt/homebrew/include/cryptopp /usr/local/include/cryptopp /usr/include/cryptopp
)

find_library(CRYPTOPP_LIBRARY
    NAMES cryptopp crypto++
    HINTS /opt/homebrew/lib /usr/local/lib /usr/lib
)

# 找到或设置 NTL 路径
find_path(NTL_INCLUDE_DIR NTL/ZZ.h
    HINTS /opt/homebrew/include /usr/local/include /usr/include
)

find_library(NTL_LIBRARY
    NAMES ntl
    HINTS /opt/homebrew/lib /usr/local/lib /usr/lib
)

# 添加vacuum filter源文件
add_executable(main 
    Vacuum-Filter/test.cpp
)

# 添加三重VF测试程序
add_executable(test_triple_vf 
    test_triple_vf.cpp
)

# 添加主程序（使用TripleVacuumFilter）
add_executable(main_triple 
    main.cpp
    src/database.cpp
    src/Pub_para.cpp
    src/util.cpp
)

# 包含头文件目录
target_include_directories(main PRIVATE
    ${CMAKE_SOURCE_DIR}/Vacuum-Filter
    ${CMAKE_SOURCE_DIR}/Vacuum-Filter/ModifiedCuckooFilter/src
)

target_include_directories(test_triple_vf PRIVATE
    ${CMAKE_SOURCE_DIR}/Vacuum-Filter
    ${CMAKE_SOURCE_DIR}/Vacuum-Filter/ModifiedCuckooFilter/src
)

target_include_directories(main_triple PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/Vacuum-Filter
    ${CMAKE_SOURCE_DIR}/Vacuum-Filter/ModifiedCuckooFilter/src
    ${CRYPTOPP_INCLUDE_DIR}
    ${NTL_INCLUDE_DIR}
)

# 链接OpenSSL库
target_link_libraries(main OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(test_triple_vf OpenSSL::SSL OpenSSL::Crypto)

# 链接所有需要的库到main_triple
target_link_libraries(main_triple 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ${CRYPTOPP_LIBRARY}
    ${NTL_LIBRARY}
)
