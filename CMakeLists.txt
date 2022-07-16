cmake_minimum_required(VERSION 3.10)

project(SPIRIT)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

enable_testing()

#find_package(OpenSSL REQUIRED)
#include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(src)
add_subdirectory(src/scalableFuzzy)
add_subdirectory(src/pqFMD)