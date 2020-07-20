set(FUZZING_BINARY_NAME "${PROJECT_NAME}-fuzz")

add_executable(${FUZZING_BINARY_NAME} "main.cpp")
target_include_directories(${FUZZING_BINARY_NAME} PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(${FUZZING_BINARY_NAME} PRIVATE ${PROJECT_NAME})

add_custom_target(fuzz-target ${FUZZING_BINARY_NAME})
