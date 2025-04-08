add_library(khook SHARED
    "detour.cpp"
)

target_include_directories(khook PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)