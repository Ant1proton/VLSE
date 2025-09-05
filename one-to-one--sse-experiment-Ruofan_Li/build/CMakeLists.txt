cmake_minimum_required (VERSION 3.22)
# 这里写项目名字
project (SSE)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
# 源代码的路径
link_directories("/usr/local/lib" "../src")
# 将源代码添加到此项目的可执行文件，第一个参数为可执行文件的名字
add_executable (SSE ../main.cpp ../crypto/convert.cpp ../crypto/eccbaseop.cpp
../crypto/prf.cpp ../crypto/random.cpp ../crypto/sm2.cpp ../crypto/sm3.cpp ../crypto/sm4.cpp
../util/util.cpp ../util/store_file.cpp ../util/database.cpp ../edb/edb.cpp ../edb/tool.cpp
../edb/system.cpp ../psi/psi.cpp)
# 需要引入的库文件，第一个参数需要与上行保持一致
target_link_libraries(SSE gmp gmpxx ssl crypto)
# 库文件路径
include_directories("/usr/local/include" "../include")

