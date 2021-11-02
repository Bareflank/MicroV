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

cmake_minimum_required(VERSION 3.13)
project(hypervisor_extensions ASM C CXX)

if(NOT UNIX)
    return()
endif()

macro(add_vmlinux NAME)
    add_custom_target(vmlinuz-${NAME}
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/config_${NAME} ${linux_BINARY_DIR}/.config
        COMMAND ${CMAKE_COMMAND} -E chdir ${linux_BINARY_DIR} make oldconfig
        COMMAND ${CMAKE_COMMAND} -E chdir ${linux_BINARY_DIR} make -j
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/vm_cross_compile/bin/
        COMMAND ${CMAKE_COMMAND} -E copy ${linux_BINARY_DIR}/arch/x86/boot/bzImage ${CMAKE_BINARY_DIR}/vm_cross_compile/bin/bzImage-${NAME}
        COMMAND sync
        VERBATIM
    )
endmacro(add_vmlinux)

macro(add_userspace NAME)
    add_executable(${NAME} ${ARGN})
    target_link_options(init PRIVATE -static)
endmacro(add_userspace)

add_vmlinux(release)
add_vmlinux(debug)

add_userspace(init init.cpp)

add_custom_target(initrd
    DEPENDS init
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_BINARY_DIR}/initrd
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/initrd/
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/initrd/dev
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/initrd/etc
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/initrd/proc
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/initrd/sbin
    COMMAND ${CMAKE_COMMAND} -E copy /etc/localtime ${CMAKE_CURRENT_BINARY_DIR}/initrd/etc/localtime
    COMMAND ${CMAKE_COMMAND} -E copy init ${CMAKE_CURRENT_BINARY_DIR}/initrd/sbin/
    COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/initrd/ ${CMAKE_SOURCE_DIR}/utils/linux/build_initrd.sh
    COMMAND ${CMAKE_COMMAND} -E copy initrd.cpio.gz ${CMAKE_BINARY_DIR}/vm_cross_compile/bin/
    VERBATIM
)