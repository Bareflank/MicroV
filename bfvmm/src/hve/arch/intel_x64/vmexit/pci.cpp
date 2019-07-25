//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vmexit/pci.h>

#define HDL_IO(p, i, o) m_vcpu->add_io_instruction_handler(p, {i}, {o})
#define EMU_IO(p, i, o) m_vcpu->emulate_io_instruction(p, {i}, {o});

using base_vcpu = microv::intel_x64::pci_handler::base_vcpu;
using info = microv::intel_x64::pci_handler::info;

static bool emu_guest_in(base_vcpu *vcpu, info &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFF;
    return true;
}

static bool ignore(base_vcpu *vcpu, info &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

namespace microv::intel_x64 {

pci_handler::pci_handler(vcpu *vcpu) : m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpuid::is_host_vm_vcpu(vcpu->id())) {
        return;
    }

    EMU_IO(0xCF8, emu_guest_in, ignore);
    EMU_IO(0xCFA, emu_guest_in, ignore);
    EMU_IO(0xCFB, emu_guest_in, ignore);
    EMU_IO(0xCFC, emu_guest_in, ignore);
    EMU_IO(0xCFD, emu_guest_in, ignore);
    EMU_IO(0xCFE, emu_guest_in, ignore);
    EMU_IO(0xCFF, emu_guest_in, ignore);
}

void pci_handler::enable_host_defaults()
{
    expects(vcpuid::is_host_vm_vcpu(m_vcpu->id()));

    HDL_IO(0xCF8, ignore, ignore);
    HDL_IO(0xCFC, ignore, ignore);
    HDL_IO(0xCFD, ignore, ignore);
    HDL_IO(0xCFE, ignore, ignore);
    HDL_IO(0xCFF, ignore, ignore);
}

}
