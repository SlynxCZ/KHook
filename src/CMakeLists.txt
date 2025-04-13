add_library(khook_lib SHARED
    "detour.cpp"
)

target_include_directories(khook_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(khook_lib PUBLIC safetyhook)

add_executable(khook
    "main.cpp"
)

target_link_libraries(khook PRIVATE khook_lib)