#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.10)
project(xue)

option(BUILD_DOCS "Build documentation")
option(BUILD_TESTS "Build static analysis and unit tests")

set(XUE_INCLUDE ${PROJECT_SOURCE_DIR}/include)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_CLANG_TIDY clang-tidy -header-filter=${XUE_INCLUDE}
    -checks=-*,bugprone-*,cert-*-c,misc-*,perf*)

add_library(xue INTERFACE)
target_include_directories(xue INTERFACE ${XUE_INCLUDE})
install(DIRECTORY ${XUE_INCLUDE}/ DESTINATION include)

find_program(FORMAT NAMES clang-format REQUIRED)
add_custom_target(format COMMAND
    ${PROJECT_SOURCE_DIR}/scripts/format.sh
    ${PROJECT_SOURCE_DIR}
    ${FORMAT})

if(BUILD_TESTS)
    enable_testing()
    find_package(Catch2 REQUIRED)

    add_library(catch test/catch.cpp)
    target_compile_features(catch PUBLIC cxx_std_17)

    add_executable(test_xue test/test_xue.cpp)
    target_link_libraries(test_xue PRIVATE catch)
    target_link_options(test_xue PRIVATE
        -fuse-ld=gold -fsanitize=address -fsanitize=leak
        -fsanitize=undefined)
    target_compile_options(test_xue PRIVATE
        -O1 -fno-omit-frame-pointer -fuse-ld=gold
        -fsanitize=address -fsanitize=leak -fsanitize=undefined)
    target_compile_definitions(test_xue PRIVATE XUE_TEST)
    target_include_directories(test_xue PRIVATE ${XUE_INCLUDE})

    add_test(NAME test_xue COMMAND test_xue)
endif()

if(BUILD_DOCS)
    find_program(DOXYGEN NAMES doxygen REQUIRED)
    add_custom_target(docs COMMAND
        ${CMAKE_COMMAND} -E chdir ${PROJECT_SOURCE_DIR} ${DOXYGEN} .doxygen.txt)
endif()
