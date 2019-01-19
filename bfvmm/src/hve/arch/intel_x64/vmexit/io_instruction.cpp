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
#include <hve/arch/intel_x64/vmexit/io_instruction.h>

#define make_io_instruction_delegate(a)                                         \
    bfvmm::intel_x64::io_instruction_handler::handler_delegate_t::create<io_instruction_handler, &io_instruction_handler::a>(this)

#define EMULATE_IO_INSTRUCTION(a,b,c)                                           \
    m_vcpu->emulate_io_instruction(                                             \
        a, make_io_instruction_delegate(b), make_io_instruction_delegate(c)     \
    );                                                                          \

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

io_instruction_handler::io_instruction_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpu->is_dom0()) {
        return;
    }

    vcpu->trap_on_all_io_instruction_accesses();

    EMULATE_IO_INSTRUCTION(0x0070, handle_in_0x0070, handle_out_0x0070);
    EMULATE_IO_INSTRUCTION(0x0071, handle_in_0x0071, handle_out_0x0071);
    EMULATE_IO_INSTRUCTION(0x04D0, handle_in_0x04D0, handle_out_0x04D0);
    EMULATE_IO_INSTRUCTION(0x04D1, handle_in_0x04D1, handle_out_0x04D1);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
io_instruction_handler::handle_in_0x0070(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("reading from port 0x70 not supported");
    return true;
}

bool
io_instruction_handler::handle_out_0x0070(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    // TODO:
    //
    // When a write to this port occurs, the guest is attempting to either enable
    // or disable NMIs. We need to modify the base hypervisor so that we can swallow
    // an NMI if it occurs and NMIs are disabled.
    //

    return true;
}

bool
io_instruction_handler::handle_in_0x0071(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
io_instruction_handler::handle_out_0x0071(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
io_instruction_handler::handle_in_0x04D0(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
io_instruction_handler::handle_out_0x04D0(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
io_instruction_handler::handle_in_0x04D1(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
io_instruction_handler::handle_out_0x04D1(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

}
