cmake_minimum_required(VERSION 3.22)

# 项目名称
project(SELPSI)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -Wall")

# 包含头文件路径
include_directories(
    "../include"
    "../../include"
    "/opt/homebrew/include/cryptopp"  # 修改为正确的 cryptopp 路径
    "/opt/homebrew/Cellar/gmp/6.2.1_1/include"
    "/opt/homebrew/Cellar/ntl/11.5.1/include/"
)

# 链接库文件路径
link_directories(
    "../src"
    "../../util"
    "/opt/homebrew/lib"  # 修改为正确的 cryptopp 库路径
    "/opt/homebrew/Cellar/gmp/6.2.1_1/lib"
    "/opt/homebrew/Cellar/ntl/11.5.1/lib/"
)

# 添加可执行文件
add_executable(main "../main.cpp" "../../util/database.cpp" "../src/Pub_para.cpp" "../src/util.cpp")

# 链接库文件
target_link_libraries(main "gmp" "ntl" "cryptopp")
