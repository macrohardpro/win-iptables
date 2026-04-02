cmake_minimum_required(VERSION 3.20)
project(winiptables VERSION 0.1.0 LANGUAGES CXX)

# 仅支持 Windows 平台
if(NOT WIN32)
    message(FATAL_ERROR "winiptables only supports Windows.")
endif()

# C++17 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 将 cmake/ 目录加入模块搜索路径
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# 所有产物统一输出到 build/bin/<config>/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# 查找 WinDivert
find_package(WinDivert REQUIRED)

# 全局包含目录
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")

# 子目录
add_subdirectory(src/core)
add_subdirectory(src/cli)
add_subdirectory(src/service)

# 测试（默认关闭，需要时用 -DBUILD_TESTS=ON 开启）
option(BUILD_TESTS "Build unit tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
