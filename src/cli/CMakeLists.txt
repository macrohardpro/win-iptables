# src/cli/CMakeLists.txt — winiptables CLI 可执行文件

add_executable(winiptables
    main.cpp
    parser.cpp
    ipc_client.cpp
)

target_include_directories(winiptables PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${CMAKE_SOURCE_DIR}/third_party/json/single_include"
)

target_link_libraries(winiptables
    PRIVATE
        winiptables-core
)

# MSVC 编译选项
target_compile_options(winiptables PRIVATE
    /W4
    /WX
    /utf-8
)

target_compile_definitions(winiptables PRIVATE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
