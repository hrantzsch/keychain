cmake_minimum_required(VERSION 3.12.4)

set(PROJECT_NAME "keychain")
project(${PROJECT_NAME})

option(BUILD_TESTS "Build tests for ${PROJECT_NAME}" OFF)

if (MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++17")
else (MSVC)
  set (CMAKE_CXX_STANDARD 17)
endif (MSVC)

if (WIN32)
    list(APPEND SOURCES "keytar_win.cc")

    list(APPEND KEYCHAIN_LIBRARIES crypt32)

elseif (APPLE)
    list(APPEND SOURCES "keychain_mac.cpp")

    find_library(COREFOUNDATION_LIBRARY CoreFoundation REQUIRED)
    list(APPEND KEYCHAIN_LIBRARIES ${COREFOUNDATION_LIBRARY})

    find_library(SECURITY_LIBRARY Security REQUIRED)
    list(APPEND KEYCHAIN_LIBRARIES ${SECURITY_LIBRARY})

else (WIN32)  # assuming Linux
    list(APPEND SOURCES "keychain_posix.cpp")

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(KEYCHAIN REQUIRED glib-2.0 libsecret-1)

endif (WIN32)

add_library (${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${KEYCHAIN_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} ${KEYCHAIN_LIBRARIES})

if (BUILD_TESTS)
    add_subdirectory("test")
endif (BUILD_TESTS)
