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
#include <hve/arch/intel_x64/pci/pci_configuration_space.h>

#define make_io_instruction_delegate(a)                                         \
    bfvmm::intel_x64::io_instruction_handler::handler_delegate_t::create<pci_configuration_space_handler, &pci_configuration_space_handler::a>(this)

#define EMULATE_IO_INSTRUCTION(a,b,c)                                           \
    m_vcpu->emulate_io_instruction(                                             \
        a, make_io_instruction_delegate(b), make_io_instruction_delegate(c)     \
    );                                                                          \

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

pci_configuration_space_handler::pci_configuration_space_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpuid::is_host_vm_vcpu(vcpu->id())) {
        return;
    }

    EMULATE_IO_INSTRUCTION(0x0CF8, handle_in_0x0CF8, handle_out_0x0CF8);
    EMULATE_IO_INSTRUCTION(0x0CFA, handle_in_0x0CFA, handle_out_0x0CFA);
    EMULATE_IO_INSTRUCTION(0x0CFB, handle_in_0x0CFB, handle_out_0x0CFB);
    EMULATE_IO_INSTRUCTION(0x0CFC, handle_in_0x0CFC, handle_out_0x0CFC);
    EMULATE_IO_INSTRUCTION(0x0CFD, handle_in_0x0CFD, handle_out_0x0CFD);
    EMULATE_IO_INSTRUCTION(0x0CFE, handle_in_0x0CFE, handle_out_0x0CFE);
    EMULATE_IO_INSTRUCTION(0x0CFF, handle_in_0x0CFF, handle_out_0x0CFF);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
pci_configuration_space_handler::handle_in_0x0CF8(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFF;
    return true;
}

bool
pci_configuration_space_handler::handle_out_0x0CF8(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
pci_configuration_space_handler::handle_in_0x0CFA(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFF;
    return true;
}

bool
pci_configuration_space_handler::handle_out_0x0CFA(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}
bool
pci_configuration_space_handler::handle_in_0x0CFB(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFF;
    return true;
}

bool
pci_configuration_space_handler::handle_out_0x0CFB(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
pci_configuration_space_handler::handle_in_0x0CFC(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFF;
    return true;
}

bool
pci_configuration_space_handler::handle_out_0x0CFC(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
pci_configuration_space_handler::handle_in_0x0CFD(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFF;
    return true;
}

bool
pci_configuration_space_handler::handle_out_0x0CFD(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
pci_configuration_space_handler::handle_in_0x0CFE(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFF;
    return true;
}

bool
pci_configuration_space_handler::handle_out_0x0CFE(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
pci_configuration_space_handler::handle_in_0x0CFF(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFF;
    return true;
}

bool
pci_configuration_space_handler::handle_out_0x0CFF(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

}
