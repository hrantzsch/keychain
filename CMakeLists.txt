cmake_minimum_required(VERSION 3.15.0)

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
    list(APPEND SOURCES "keytar_mac.cc")

    find_library(COREFOUNDATION_LIBRARY CoreFoundation REQUIRED)
    list(APPEND KEYCHAIN_LIBRARIES ${COREFOUNDATION_LIBRARY})

    find_library(SECURITY_LIBRARY Security REQUIRED)
    list(APPEND KEYCHAIN_LIBRARIES ${SECURITY_LIBRARY})

else (WIN32)  # assuming Linux
    list(APPEND SOURCES "keytar_posix.cc")

    set(GLIB_INCLUDE_DIRS "/usr/include/glib-2.0" "/usr/lib/glib-2.0/include")
    set(SECRET_INCLUDE_DIR "/usr/include/libsecret-1")
    include_directories(${SECRET_INCLUDE_DIR} ${GLIB_INCLUDE_DIRS})

    list(APPEND KEYCHAIN_LIBRARIES "/usr/lib/libsecret-1.so")
    list(APPEND KEYCHAIN_LIBRARIES "/usr/lib/libglib-2.0.so")
endif (WIN32)

add_executable(${BINARY_NAME} $<TARGET_OBJECTS:catchmain> ${SOURCES})
target_link_libraries(${BINARY_NAME} ${KEYCHAIN_LIBRARIES})

add_custom_target(test ${BINARY_NAME})
