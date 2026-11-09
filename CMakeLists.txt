cmake_minimum_required(VERSION 3.16)
project(PyCppCrypt VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(pycppcrypt SHARED
    cpp/crypt.cpp
    cpp/bridge.cpp
)
target_include_directories(pycppcrypt PRIVATE cpp)
target_link_libraries(pycppcrypt PRIVATE OpenSSL::Crypto)
target_compile_features(pycppcrypt PRIVATE cxx_std_17)
set_target_properties(pycppcrypt PROPERTIES
    OUTPUT_NAME pycppcrypt
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

add_executable(pycppcrypt_benchmark
    cpp/benchmark.cpp
    cpp/crypt.cpp
)
target_include_directories(pycppcrypt_benchmark PRIVATE cpp)
target_link_libraries(pycppcrypt_benchmark PRIVATE OpenSSL::Crypto)
target_compile_features(pycppcrypt_benchmark PRIVATE cxx_std_17)

if(MSVC)
    target_compile_options(pycppcrypt PRIVATE /W4 /permissive-)
    target_compile_options(pycppcrypt_benchmark PRIVATE /W4 /permissive-)
else()
    target_compile_options(pycppcrypt PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(pycppcrypt_benchmark PRIVATE -Wall -Wextra -Wpedantic)
endif()
