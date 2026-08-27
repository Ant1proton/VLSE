cmake_minimum_required(VERSION 3.16)
project(VLSEExamples LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

enable_testing()

add_subdirectory(original_vlse)
add_subdirectory(paired_vlse)
