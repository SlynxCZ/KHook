cmake_minimum_required(VERSION 3.25)

project(khook LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(src)
set(SAFETYHOOK_FETCH_ZYDIS ON BOOL "Force enable Zydis fetch...")
add_subdirectory(third_party/safetyhook)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(safetyhook PRIVATE "-fPIC")
    target_compile_options(Zydis PRIVATE "-fPIC")
endif()