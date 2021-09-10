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

add_library(uvvmm_xen)

target_link_libraries(uvvmm_xen PUBLIC uvvmm_hve uvvmm_domain)
target_include_directories(uvvmm_xen PUBLIC
    $<${BUILD_INCLUDE}:${PROJECT_SOURCE_DIR}/include>
    $<${BUILD_INCLUDE}:${PROJECT_SOURCE_DIR}/../include>
    $<${BUILD_INCLUDE}:${PROJECT_SOURCE_DIR}/../deps/xen/xen/include>
    $<${BUILD_INCLUDE}:${CMAKE_BINARY_DIR}/include>
)
target_sources(uvvmm_xen PRIVATE
    $<${X64}:cpuid.cpp>
    $<${X64}:cpupool.cpp>
    $<${X64}:domain.cpp>
    $<${X64}:evtchn.cpp>
    $<${X64}:flask.cpp>
    $<${X64}:gnttab.cpp>
    $<${X64}:hvm.cpp>
    $<${X64}:physdev.cpp>
    $<${X64}:platform_pci.cpp>
    $<${X64}:util.cpp>
    $<${X64}:memory.cpp>
    $<${X64}:version.cpp>
    $<${X64}:vcpu.cpp>
)
target_compile_definitions(uvvmm_xen PRIVATE $<$<BOOL:${XEN_READCONSOLE_ROOTVM}>:XEN_READCONSOLE_ROOTVM>)

install(TARGETS uvvmm_xen DESTINATION lib EXPORT uvvmm-vmm-targets)
