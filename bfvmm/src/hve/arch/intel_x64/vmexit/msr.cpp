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
#include <hve/arch/intel_x64/vmexit/msr.h>

#define make_rdmsr_delegate(a)                                                  \
    eapis::intel_x64::rdmsr_handler::handler_delegate_t::create<msr_handler, &msr_handler::a>(this)

#define make_wrmsr_delegate(a)                                                  \
    eapis::intel_x64::wrmsr_handler::handler_delegate_t::create<msr_handler, &msr_handler::a>(this)

#define EMULATE_MSR(a,b,c)                                                      \
    m_vcpu->emulate_rdmsr(                                                      \
        a, make_rdmsr_delegate(b)                                               \
    );                                                                          \
    m_vcpu->emulate_wrmsr(                                                      \
        a, make_wrmsr_delegate(c)                                               \
    );

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

msr_handler::msr_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpuid::is_host_vm_vcpu(vcpu->id())) {
        return;
    }

    EMULATE_MSR(0x000001A0, handle_rdmsr_0x000001A0, handle_wrmsr_0x000001A0);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
msr_handler::handle_rdmsr_zero(
    gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
msr_handler::handle_wrmsr_ignore(
    gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
msr_handler::handle_rdmsr_0x000001A0(
    gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val =
        emulate_rdmsr(
            gsl::narrow_cast<::x64::msrs::field_type>(vcpu->rcx())
        );

    // Enable the following:
    // - Fast Strings

    info.val &= 0x1801;
    return true;
}

bool
msr_handler::handle_wrmsr_0x000001A0(
    gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0x1A0 is not supported");
    return false;
}

}
