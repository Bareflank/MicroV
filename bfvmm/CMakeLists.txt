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
project(boxy_bfvmm C CXX)

init_project(boxy_bfvmm INTERFACE)

# -----------------------------------------------------------------------------
# Generator expressions
# -----------------------------------------------------------------------------

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>>)
set(BUILD_INCLUDE $<AND:$<COMPILE_LANGUAGE:CXX>,${BUILD}>)

# -----------------------------------------------------------------------------
# VMM
# -----------------------------------------------------------------------------

add_subdirectory(src/domain)
add_subdirectory(src/hve)

add_executable(boxy_vmm)
target_sources(boxy_vmm PRIVATE $<${X64}:src/main/arch/intel_x64/vcpu_factory.cpp>)
target_sources(boxy_vmm PRIVATE $<${X64}:src/main/arch/intel_x64/domain_factory.cpp>)

target_link_libraries(boxy_bfvmm INTERFACE boxy_domain boxy_hve)
target_link_libraries(boxy_vmm PRIVATE boxy_bfvmm)

# -----------------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------------

install(DIRECTORY include/ DESTINATION include/boxy)
install(TARGETS boxy_vmm DESTINATION bin EXPORT boxy-vmm-targets)

fini_project()
