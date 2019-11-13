/**
 * This file exists to reduce compile time with catch. It should be compiled to
 * an object file ONCE, so it only needs to be linked when compiling test cases.
 * see also https://github.com/catchorg/Catch2/blob/master/docs/slow-compiles.md
 */
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
