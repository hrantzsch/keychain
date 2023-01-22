cmake_minimum_required(VERSION 3.12.4)

project(keychain)

option(BUILD_TESTS "Build tests for ${PROJECT_NAME}" OFF)

add_library(${PROJECT_NAME})
target_include_directories(${PROJECT_NAME}
    PUBLIC
        "include"
    PRIVATE
        "src"
        "include/keychain")

set_target_properties(${PROJECT_NAME}
    PROPERTIES PUBLIC_HEADER "include/keychain/keychain.h")

target_compile_features(${PROJECT_NAME}
    PUBLIC
        cxx_std_11)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W2 /WX>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -pedantic -Werror>)

if (WIN32)
    target_compile_definitions(${PROJECT_NAME}
        PUBLIC
            -DKEYCHAIN_WINDOWS=1)

    target_sources(${PROJECT_NAME}
        PRIVATE
            "src/keychain_win.cpp")

    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            crypt32)
elseif (APPLE)
    target_compile_definitions(${PROJECT_NAME}
        PUBLIC
            -DKEYCHAIN_MACOS=1)

    target_sources(${PROJECT_NAME}
        PRIVATE
            "src/keychain_mac.cpp")

    # We're using the deprecated "Legacy Password Storage" API
    # (SecKeychainFindGenericPassword and friends)
    target_compile_options(${PROJECT_NAME}
        PRIVATE
            "-Wno-error=deprecated-declarations")

    find_library(COREFOUNDATION_LIBRARY CoreFoundation REQUIRED)
    find_library(SECURITY_LIBRARY Security REQUIRED)

    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            ${COREFOUNDATION_LIBRARY}
            ${SECURITY_LIBRARY})
else () # assuming Linux
    target_compile_definitions(${PROJECT_NAME}
        PUBLIC
            -DKEYCHAIN_LINUX=1)

    target_sources(${PROJECT_NAME}
        PRIVATE
            "src/keychain_linux.cpp")

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLIB2 IMPORTED_TARGET glib-2.0)
    pkg_check_modules(LIBSECRET IMPORTED_TARGET libsecret-1)

    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            PkgConfig::GLIB2
            PkgConfig::LIBSECRET)
endif ()

# Code Coverage Configuration
option(CODE_COVERAGE "Enable coverage reporting" OFF)
if (CODE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(COVERAGE_COMPILE_FLAGS "--coverage -g -O0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COVERAGE_COMPILE_FLAGS}")
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    endif ()
endif ()

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/keychain)

if (BUILD_TESTS)
    add_subdirectory("test")
endif ()
