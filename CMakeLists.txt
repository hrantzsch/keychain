cmake_minimum_required(VERSION 3.12.4)

set(PROJECT_NAME "keychain")
project(${PROJECT_NAME})

option(BUILD_TESTS "Build tests for ${PROJECT_NAME}" OFF)

if (MSVC)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++11")
else (MSVC)
    set (CMAKE_CXX_STANDARD 11)
endif (MSVC)

# enable compiler warnings
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wall -Wextra -pedantic")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W2 /WX")
endif ()

if (WIN32)
    add_definitions(-DKEYCHAIN_WINDOWS=1)

    list(APPEND SOURCES "keychain_win.cpp")

    list(APPEND KEYCHAIN_LIBRARIES crypt32)

elseif (APPLE)
    add_definitions(-DKEYCHAIN_MACOS=1)

    list(APPEND SOURCES "keychain_mac.cpp")

    find_library(COREFOUNDATION_LIBRARY CoreFoundation REQUIRED)
    list(APPEND KEYCHAIN_LIBRARIES ${COREFOUNDATION_LIBRARY})

    find_library(SECURITY_LIBRARY Security REQUIRED)
    list(APPEND KEYCHAIN_LIBRARIES ${SECURITY_LIBRARY})

else (WIN32)  # assuming Linux
    add_definitions(-DKEYCHAIN_LINUX=1)

    list(APPEND SOURCES "keychain_linux.cpp")

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(KEYCHAIN REQUIRED glib-2.0 libsecret-1)

endif (WIN32)

add_library(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${KEYCHAIN_INCLUDE_DIRS})
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "keychain.h")
target_link_libraries(${PROJECT_NAME} PUBLIC ${KEYCHAIN_LIBRARIES})

# Code Coverage Configuration
option(CODE_COVERAGE "Enable coverage reporting" OFF)
if(CODE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(COVERAGE_COMPILE_FLAGS "--coverage -g -O0")
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${COVERAGE_COMPILE_FLAGS}")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} \"--coverage\"")
    endif()
endif()

option(FUZZING "Enable fuzzing" OFF)
if(FUZZING)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "fuzzing requires clang")
    endif()
    set(FUZZING_COMPILE_FLAGS "-g -fsanitize=fuzzer")
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${FUZZING_COMPILE_FLAGS}")
endif()


install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION       lib
        ARCHIVE DESTINATION       lib
        PUBLIC_HEADER DESTINATION include/keychain)

if (BUILD_TESTS)
    add_subdirectory("test")
endif (BUILD_TESTS)

if (FUZZING)
    add_subdirectory("fuzzing")
endif(FUZZING)
