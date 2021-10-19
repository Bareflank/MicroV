#
# Copyright (C) 2020 Assured Information Security, Inc.
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

set(GIT_TAG         d2030b602dfb82286da056cfee867abc6ac001eb)

FetchContent_Declare(
    hypervisor
    GIT_REPOSITORY  https://github.com/bareflank/hypervisor.git
    GIT_TAG         ${GIT_TAG}
)

FetchContent_GetProperties(hypervisor)
if(NOT hypervisor_POPULATED)
    set(HYPERVISOR_BUILD_EXAMPLES_OVERRIDE ON)
    set(HYPERVISOR_BUILD_TESTS_OVERRIDE ON)
    set(HYPERVISOR_INCLUDE_INFO_OVERRIDE ON)
    set(HYPERVISOR_EXTENSIONS "microv")
    set(HYPERVISOR_EXTENSIONS_DIR ${CMAKE_SOURCE_DIR}/vmm)
    FetchContent_Populate(hypervisor)
    add_subdirectory(${hypervisor_SOURCE_DIR} ${hypervisor_BINARY_DIR})
endif()

include(${bsl_SOURCE_DIR}/cmake/function/bf_check_dependency.cmake)
bf_check_dependency(hypervisor ${GIT_TAG})
