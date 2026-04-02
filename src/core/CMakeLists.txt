# src/core/CMakeLists.txt — winiptables-core 静态库

add_library(winiptables-core STATIC
    model.cpp
    rule_store.cpp
    rule_engine.cpp
    rule_builder.cpp
    table_pipeline.cpp
    packet.cpp
    capture.cpp
    stateful.cpp
    nat_table.cpp
    persist.cpp
    log.cpp
    matches/basic.cpp
    matches/tcp.cpp
    matches/multiport.cpp
    matches/state.cpp
)

target_include_directories(winiptables-core
    PUBLIC
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/third_party/spdlog/include"
)

target_link_libraries(winiptables-core
    PUBLIC
        WinDivert::WinDivert
        ws2_32
        iphlpapi
)

# MSVC 编译选项
target_compile_options(winiptables-core PRIVATE
    /W4
    /WX
    /utf-8
)

# Windows 目标版本（Windows 10）
target_compile_definitions(winiptables-core PUBLIC
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
