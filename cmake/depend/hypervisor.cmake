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

FetchContent_Declare(
    hypervisor
    GIT_REPOSITORY  https://github.com/bareflank/hypervisor.git
    GIT_TAG         4e42d5e26b9651bda98c8ba0a066e834a69e7be5
)

FetchContent_GetProperties(hypervisor)
if(NOT hypervisor_POPULATED)
    set(HYPERVISOR_BUILD_EXAMPLES_OVERRIDE ON)
    set(HYPERVISOR_BUILD_TESTS_OVERRIDE ON)
    set(HYPERVISOR_INCLUDE_INFO_OVERRIDE ON)
    set(HYPERVISOR_EXTENSIONS "vmm")
    set(HYPERVISOR_EXTENSIONS_DIR ${CMAKE_SOURCE_DIR}/vmm)
    FetchContent_Populate(hypervisor)
    add_subdirectory(${hypervisor_SOURCE_DIR} ${hypervisor_BINARY_DIR})
endif()
