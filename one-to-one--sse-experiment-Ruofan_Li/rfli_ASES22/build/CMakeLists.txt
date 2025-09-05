cmake_minimum_required (VERSION 3.22)
# 这里写项目名字
project (ASES22)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -Wall")
# 库文件路径
include_directories("/opt/homebrew/Cellar/gmp/6.2.1_1/include" "/opt/homebrew/Cellar/ntl/11.5.1/include/" "../include" "../../include")
# 源代码的路径
link_directories("/opt/homebrew/Cellar/gmp/6.2.1_1/lib" "/opt/homebrew/Cellar/ntl/11.5.1/lib/" "../src" "../../util")
# 将源代码添加到此项目的可执行文件，第一个参数为可执行文件的名字
add_executable (main "../main.cpp" "../src/BCP.cpp" "../src/ASES22.cpp" "../../util/database.cpp")
# 需要引入的库文件，第一个参数需要与上行保持一致
target_link_libraries(main "gmp" "ntl")


