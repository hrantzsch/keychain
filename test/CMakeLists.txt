set(TEST_BINARY_NAME "${PROJECT_NAME}-test")

# see comment in test-main.cpp
add_library("catchmain" OBJECT "main.cpp")
target_compile_features(catchmain PUBLIC cxx_std_11)

add_executable(${TEST_BINARY_NAME} $<TARGET_OBJECTS:catchmain> "tests.cpp")
target_include_directories(${TEST_BINARY_NAME} PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(${TEST_BINARY_NAME} PRIVATE ${PROJECT_NAME})

add_custom_target(test ${TEST_BINARY_NAME})
