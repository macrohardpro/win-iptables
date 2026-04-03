# src/service/CMakeLists.txt — winiptables-svc 服务可执行文件

add_executable(winiptables-svc
    main.cpp
    service.cpp
    ipc_server.cpp
    command_dispatcher.cpp
)

target_include_directories(winiptables-svc
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_SOURCE_DIR}/third_party/json/single_include"
)

target_link_libraries(winiptables-svc
    PRIVATE
        winiptables-core
        advapi32   # RegisterServiceCtrlHandlerEx, SetServiceStatus, SCM API
)

# MSVC 编译选项
target_compile_options(winiptables-svc PRIVATE
    /W4
    /WX
    /utf-8
)

target_compile_definitions(winiptables-svc PRIVATE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
