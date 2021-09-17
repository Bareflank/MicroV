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

include(ExternalProject)
set (MICROV_ADD_VM_CROSS_COMPILE_DIR ${CMAKE_CURRENT_LIST_DIR})


# Add Extension Cross Compile Directory
#
# Uses ExternalProject_Add to add a subdirectory, but cross compiles instead
# instead of adding a subdirectory to the main project like add_subdirectory.
# This is needed to ensure the cross compiled code can have it's own toolchain.
#
# SOURCE_DIR: The location of the CMakeLists.txt that describes how to compile
#   the cross compiled components
#
function(microv_add_vm_cross_compile SOURCE_DIR)
    if(CMAKE_BUILD_TYPE STREQUAL ASAN OR
       CMAKE_BUILD_TYPE STREQUAL UBSAN)
        set(CMAKE_BUILD_TYPE DEBUG)
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        set(CMAKE_TOOLCHAIN_FILE ${MICROV_ADD_VM_CROSS_COMPILE_DIR}/../toolchain/x64/vm.cmake)
    elseif(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        set(CMAKE_TOOLCHAIN_FILE ${MICROV_ADD_VM_CROSS_COMPILE_DIR}/../toolchain/x64/vm.cmake)
    elseif(HYPERVISOR_TARGET_ARCH STREQUAL "aarch64")
        set(CMAKE_TOOLCHAIN_FILE ${MICROV_ADD_VM_CROSS_COMPILE_DIR}/../toolchain/aarch64/vm.cmake)
    else()
        message(FATAL_ERROR "Unsupported HYPERVISOR_TARGET_ARCH: ${HYPERVISOR_TARGET_ARCH}")
    endif()

    hypervisor_add_cmake_args()

    list(APPEND CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/vm_cross_compile
    )

    ExternalProject_Add(
        vm_cross_compile
        PREFIX          ${CMAKE_BINARY_DIR}/vm_cross_compile
        STAMP_DIR       ${CMAKE_BINARY_DIR}/vm_cross_compile/stamp
        TMP_DIR         ${CMAKE_BINARY_DIR}/vm_cross_compile/tmp
        BINARY_DIR      ${CMAKE_BINARY_DIR}/vm_cross_compile/build
        LOG_DIR         ${CMAKE_BINARY_DIR}/vm_cross_compile/logs
        SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/${SOURCE_DIR}
        CMAKE_ARGS      ${CMAKE_ARGS}
        UPDATE_COMMAND  ${CMAKE_COMMAND} -E echo -- Skip
    )

    ExternalProject_Add_Step(
        vm_cross_compile
        vm_cross_compile_cleanup
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/vm_cross_compile/src
        DEPENDEES configure
    )
endfunction(microv_add_vm_cross_compile)
