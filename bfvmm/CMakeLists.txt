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

cmake_minimum_required(VERSION 3.13)
project(microv_bfvmm LANGUAGES C CXX VERSION 1.1.0)

init_project(microv_bfvmm INTERFACE)

string(TIMESTAMP MICROV_COMPILE_DATE "%b %d, %Y")
string(TIMESTAMP MICROV_COMPILE_TIME "%H:%M")

set(MICROV_COMPILE_BY $ENV{USER})
set(MICROV_COMPILE_DOMAIN "domain")
set(MICROV_COMPILE_HOST "host")
set(MICROV_COMPILER "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
set(MICROV_VERSION ${PROJECT_VERSION_MAJOR})
set(MICROV_SUBVERSION ${PROJECT_VERSION_MINOR})
set(MICROV_EXTRAVERSION "0")
set(MICROV_CHANGESET "changeset")

configure_file(
    ${PROJECT_SOURCE_DIR}/include/compiler.h.in
    ${CMAKE_BINARY_DIR}/include/compiler.h
    @ONLY
)

# -----------------------------------------------------------------------------
# Generator expressions
# -----------------------------------------------------------------------------

set(XEN $<BOOL:${BUILD_XEN}>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>>)
set(BUILD_INCLUDE $<AND:$<COMPILE_LANGUAGE:CXX>,${BUILD}>)

# -----------------------------------------------------------------------------
# VMM
# -----------------------------------------------------------------------------

target_compile_definitions(microv_bfvmm INTERFACE $<${XEN}:__XEN__>)
target_compile_definitions(microv_bfvmm INTERFACE $<${X64}:__x86_64__>)

add_subdirectory(src/domain)
add_subdirectory(src/hve)

if(BUILD_XEN)
    add_subdirectory(src/xen)
endif()

add_executable(microv_vmm)
target_sources(microv_vmm PRIVATE $<${X64}:src/main/arch/intel_x64/vcpu_factory.cpp>)
target_sources(microv_vmm PRIVATE $<${X64}:src/main/arch/intel_x64/domain_factory.cpp>)

target_link_libraries(microv_bfvmm INTERFACE microv_domain microv_hve microv_xen)
target_link_libraries(microv_vmm PRIVATE microv_bfvmm)

# -----------------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------------

install(DIRECTORY include/ DESTINATION include/microv)
install(TARGETS microv_vmm DESTINATION bin EXPORT microv-vmm-targets)

fini_project()
