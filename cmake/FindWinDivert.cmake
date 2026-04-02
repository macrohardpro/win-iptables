# FindWinDivert.cmake
# 查找 WinDivert 头文件和库文件
#
# 搜索路径优先级：
#   1. 用户通过 -DWINDIVERT_ROOT=<path> 指定的路径
#   2. 项目内置的 third_party/windivert/ 目录
#
# 导出目标：
#   WinDivert::WinDivert  — 包含头文件路径和链接库的 IMPORTED 目标
#
# 输出变量（兼容旧式用法）：
#   WINDIVERT_FOUND
#   WINDIVERT_INCLUDE_DIR
#   WINDIVERT_LIBRARY

set(_WINDIVERT_SEARCH_PATHS
    "${WINDIVERT_ROOT}"
    "${CMAKE_CURRENT_LIST_DIR}/../third_party/windivert"
)

find_path(WINDIVERT_INCLUDE_DIR
    NAMES windivert.h
    PATHS ${_WINDIVERT_SEARCH_PATHS}
    PATH_SUFFIXES include
    NO_DEFAULT_PATH
)

# 根据目标架构选择正确的库目录
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_WINDIVERT_ARCH_SUFFIX "x64")
else()
    set(_WINDIVERT_ARCH_SUFFIX "x86")
endif()

find_library(WINDIVERT_LIBRARY
    NAMES WinDivert
    PATHS ${_WINDIVERT_SEARCH_PATHS}
    PATH_SUFFIXES
        "lib/${_WINDIVERT_ARCH_SUFFIX}"
        "lib"
        "${_WINDIVERT_ARCH_SUFFIX}"
    NO_DEFAULT_PATH
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WinDivert
    REQUIRED_VARS WINDIVERT_INCLUDE_DIR WINDIVERT_LIBRARY
)

if(WINDIVERT_FOUND AND NOT TARGET WinDivert::WinDivert)
    add_library(WinDivert::WinDivert UNKNOWN IMPORTED)
    set_target_properties(WinDivert::WinDivert PROPERTIES
        IMPORTED_LOCATION             "${WINDIVERT_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${WINDIVERT_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(WINDIVERT_INCLUDE_DIR WINDIVERT_LIBRARY)
