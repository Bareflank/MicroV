//
// Copyright (C) 2018 Assured Information Security, Inc.
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
#include <hve/arch/intel_x64/vmexit/cpuid.h>

#define make_delegate(a)                                                        \
    eapis::intel_x64::cpuid_handler::handler_delegate_t::create<cpuid_handler, &cpuid_handler::a>(this)

#define EMULATE_CPUID(a,b)                                                      \
    m_vcpu->add_cpuid_handler(                                                  \
        a, make_delegate(b)                                                     \
    );

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

cpuid_handler::cpuid_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpuid::is_host_vm_vcpu(vcpu->id())) {
        return;
    }

    // Note:
    //
    // Every leaf that is supported is handled here. All reserved bits must
    // be set to 0. Otherwise a new feature could be enabled that we are not
    // aware of in the future.
    //

    EMULATE_CPUID(0x00000000, handle_0x00000000);
    EMULATE_CPUID(0x00000001, handle_0x00000001);
    EMULATE_CPUID(0x00000006, handle_0x00000006);
    EMULATE_CPUID(0x00000007, handle_0x00000007);
    EMULATE_CPUID(0x0000000D, handle_0x0000000D);
    EMULATE_CPUID(0x0000000F, handle_0x0000000F);
    EMULATE_CPUID(0x00000010, handle_0x00000010);
    EMULATE_CPUID(0x00000015, handle_0x00000015);
    EMULATE_CPUID(0x00000016, handle_0x00000016);
    EMULATE_CPUID(0x80000000, handle_0x80000000);
    EMULATE_CPUID(0x80000001, handle_0x80000001);
    EMULATE_CPUID(0x80000007, handle_0x80000007);
    EMULATE_CPUID(0x80000008, handle_0x80000008);

    EMULATE_CPUID(0x40000000, handle_0x40000000);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid_handler::handle_0x00000000(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
cpuid_handler::handle_0x00000001(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rcx &= 0x21FC3203;
    info.rdx &= 0x1FCBEBFB;

    // Note:
    //
    // The following tells Linux that it is in a VM.
    //

    info.rcx |= 0x80000000;

    return true;
}

bool
cpuid_handler::handle_0x00000006(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0;
    info.rbx = 0;
    info.rcx = 0;
    info.rdx = 0;

    return true;
}

bool
cpuid_handler::handle_0x00000007(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    if (info.rcx != 0) {
        info.rax = 0;
        info.rbx = 0;
        info.rcx = 0;
        info.rdx = 0;
    }

    info.rax = 0;
    info.rbx &= 0x19C23D9;
    info.rcx = 0;
    info.rdx = 0;

    return true;
}

bool
cpuid_handler::handle_0x0000000D(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0;
    info.rbx = 0;
    info.rcx = 0;
    info.rdx = 0;

    return true;
}

bool
cpuid_handler::handle_0x0000000F(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0;
    info.rbx = 0;
    info.rcx = 0;
    info.rdx = 0;

    return true;
}

bool
cpuid_handler::handle_0x00000010(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0;
    info.rbx = 0;
    info.rcx = 0;
    info.rdx = 0;

    return true;
}

bool
cpuid_handler::handle_0x00000015(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rdx = 0;
    return true;
}

bool
cpuid_handler::handle_0x00000016(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax &= 0xFFFF;
    info.rbx &= 0xFFFF;
    info.rcx &= 0xFFFF;
    info.rdx = 0;

    return true;
}

bool
cpuid_handler::handle_0x80000000(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rbx = 0;
    info.rcx = 0;
    info.rdx = 0;

    return true;
}

bool
cpuid_handler::handle_0x80000001(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rbx = 0;
    info.rcx &= 0x121;
    info.rdx &= 0x2C100800;

    return true;
}

bool
cpuid_handler::handle_0x80000007(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    if ((info.rdx & 0x100) == 0) {
        bfalert_info(0, "Non-Invariant TSC not supported!!!");
    }

    info.rax = 0;
    info.rbx = 0;
    info.rcx = 0;
    info.rdx &= 0x100;

    return true;
}

bool
cpuid_handler::handle_0x80000008(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax &= 0xFFFF;
    info.rbx = 0;
    info.rcx = 0;
    info.rdx = 0;

    return true;
}

bool
cpuid_handler::handle_0x40000000(
    gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax &= 0xBFBFBFBF;
    info.rbx = 0;
    info.rcx = 0;
    info.rdx = 0;

    return true;
}

}
