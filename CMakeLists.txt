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

#set_target_properties(safetyhook PROPERTIES COMPILE_OPTIONS "-m32" LINK_FLAGS "-m32")
#set_target_properties(Zydis PROPERTIES COMPILE_OPTIONS "-m32" LINK_FLAGS "-m32")
#set_target_properties(khook_lib PROPERTIES COMPILE_OPTIONS "-m32" LINK_FLAGS "-m32")
#set_target_properties(khook PROPERTIES COMPILE_OPTIONS "-m32" LINK_FLAGS "-m32")

target_compile_options(khook PRIVATE -msse)
target_compile_options(khook_lib PRIVATE -msse)
target_compile_options(khook PRIVATE -g)
target_compile_options(khook_lib PRIVATE -g)