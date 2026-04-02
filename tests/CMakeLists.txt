# tests/CMakeLists.txt — 测试套件（Google Test）

# 默认使用 third_party/googletest（离线，无需网络）
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/googletest"
    "${CMAKE_CURRENT_BINARY_DIR}/googletest"
    EXCLUDE_FROM_ALL
)

# 辅助函数：快速添加测试可执行文件
function(add_winiptables_test target_name source_file)
    add_executable(${target_name} ${source_file})
    target_link_libraries(${target_name}
        PRIVATE
            winiptables-core
            GTest::gtest_main
    )
    target_compile_options(${target_name} PRIVATE
        /W4
        /utf-8
    )
    target_compile_definitions(${target_name} PRIVATE
        _WIN32_WINNT=0x0A00
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    include(GoogleTest)
    gtest_discover_tests(${target_name})
endfunction()

# 各测试目标
add_winiptables_test(test_model         test_model.cpp)
add_winiptables_test(test_rule_store    test_rule_store.cpp)
add_winiptables_test(test_rule_engine   test_rule_engine.cpp)
add_winiptables_test(test_packet_parse  test_packet_parse.cpp)
add_winiptables_test(test_persist       test_persist.cpp)
add_winiptables_test(test_matches         test_matches.cpp)
add_winiptables_test(test_table_pipeline test_table_pipeline.cpp)

# CLI 解析器测试（任务 12.6）
add_executable(test_parser test_parser.cpp ../src/cli/parser.cpp)
target_include_directories(test_parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/cli
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)
target_link_libraries(test_parser
    PRIVATE
        GTest::gtest_main
)
target_compile_options(test_parser PRIVATE
    /W4
    /WX
    /utf-8
)
target_compile_definitions(test_parser PRIVATE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
include(GoogleTest)
gtest_discover_tests(test_parser)

# 日志测试程序
add_executable(test_log test_log.cpp)
target_include_directories(test_log PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/spdlog/include
)
target_link_libraries(test_log PRIVATE
    winiptables-core
)
target_compile_options(test_log PRIVATE
    /W4
    /WX
    /utf-8
)
target_compile_definitions(test_log PRIVATE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
