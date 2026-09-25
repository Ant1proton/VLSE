cmake_minimum_required(VERSION 3.16)
project(VLSEExamples LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

enable_testing()

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Vacuum-Filter/hashutil.h")
    message(FATAL_ERROR
        "Missing Vacuum-Filter dependency. Run git submodule update --init --recursive; "
        "for a source archive, extract wuwuz/Vacuum-Filter commit "
        "ec234bfc189af9e6180688495535c623ad352190 into Vacuum-Filter/.")
endif()

add_subdirectory(common)
add_subdirectory(paired_vlse)
add_subdirectory(benchmarks)
