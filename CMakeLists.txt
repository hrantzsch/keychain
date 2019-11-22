cmake_minimum_required(VERSION 3.12.4)

project("keychain")
set(BINARY_NAME "test-keychain")

if (MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++17")
else (MSVC)
  set (CMAKE_CXX_STANDARD 17)
endif (MSVC)

# see comment in test-main.cpp
add_library("catchmain" OBJECT "test-main.cpp")

set(SOURCES "tests.cpp")

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

add_executable(${BINARY_NAME} $<TARGET_OBJECTS:catchmain> ${SOURCES})

target_include_directories(${BINARY_NAME} PRIVATE ${KEYCHAIN_INCLUDE_DIRS})
target_link_libraries(${BINARY_NAME} ${KEYCHAIN_LIBRARIES})

add_custom_target(test ${BINARY_NAME})
