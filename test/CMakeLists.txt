set(TEST_BINARY_NAME "${PROJECT_NAME}-test")

add_executable(${TEST_BINARY_NAME} "catch_amalgamated.cpp" "tests.cpp")
target_compile_features(${TEST_BINARY_NAME} PUBLIC cxx_std_14)
target_include_directories(${TEST_BINARY_NAME} PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(${TEST_BINARY_NAME} PRIVATE ${PROJECT_NAME})

add_custom_target(test ${TEST_BINARY_NAME})
