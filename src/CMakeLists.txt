add_executable(khook
    "detour.cpp"
    "main.cpp"
)

target_include_directories(khook PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(khook PUBLIC safetyhook)