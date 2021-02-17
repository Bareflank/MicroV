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

add_library(uvvmm_hve)

target_link_libraries(uvvmm_hve PUBLIC vmm::bfvmm uvvmm_domain)
target_include_directories(uvvmm_hve PUBLIC
    $<${BUILD_INCLUDE}:${XUE_DIR}/include>
    $<${BUILD_INCLUDE}:${PROJECT_SOURCE_DIR}/include>
    $<${BUILD_INCLUDE}:${PROJECT_SOURCE_DIR}/../include>
    $<${XEN}:${PROJECT_SOURCE_DIR}/../deps/xen/xen/include>
)
target_sources(uvvmm_hve PRIVATE
    $<${X64}:arch/intel_x64/apic/lapic.cpp>
    $<${X64}:arch/intel_x64/apic/x2apic.cpp>
    $<${X64}:arch/intel_x64/vmexit/cpuid.cpp>
    $<${X64}:arch/intel_x64/vmexit/external_interrupt.cpp>
    $<${X64}:arch/intel_x64/vmexit/io_instruction.cpp>
    $<${X64}:arch/intel_x64/vmexit/msr.cpp>
    $<${X64}:arch/intel_x64/vmexit/mtrr.cpp>
    $<${X64}:arch/intel_x64/vmexit/pci_cfg.cpp>
    $<${X64}:arch/intel_x64/vmexit/vmcall.cpp>
    $<${X64}:arch/intel_x64/vmexit/yield.cpp>
    $<${X64}:arch/intel_x64/vmcall/domain_op.cpp>
    $<${X64}:arch/intel_x64/vmcall/event_op.cpp>
    $<${X64}:arch/intel_x64/vmcall/run_op.cpp>
    $<${X64}:arch/intel_x64/vmcall/vcpu_op.cpp>
    $<${X64}:arch/intel_x64/disassembler.cpp>
    $<${X64}:arch/intel_x64/domain.cpp>
    $<${X64}:arch/intel_x64/uart.cpp>
    $<${X64}:arch/intel_x64/xsave.asm>
    $<${X64}:arch/intel_x64/xstate.cpp>
    $<${X64}:arch/intel_x64/vcpu.cpp>
)

install(TARGETS uvvmm_hve DESTINATION lib EXPORT uvvmm-vmm-targets)
