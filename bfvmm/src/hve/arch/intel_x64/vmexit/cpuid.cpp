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

#define PASS_THROUGH_CPUID(a)                                                   \
    vcpu->add_cpuid_handler(                                                    \
        a, eapis::intel_x64::cpuid_handler::handler_delegate_t::create<cpuid_handler, &cpuid_handler::handle_pass_through>(this) \
    );

#define EMULATE_CPUID(a, b)                                                     \
    vcpu->emulate_cpuid(                                                        \
        a, eapis::intel_x64::cpuid_handler::handler_delegate_t::create<cpuid_handler, &cpuid_handler::b>(this) \
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

    PASS_THROUGH_CPUID(0x00000000);

    EMULATE_CPUID(0x80000000, handle_0x80000000);
    EMULATE_CPUID(0x80000001, handle_0x80000001);
    EMULATE_CPUID(0x400000BF, handle_0x400000BF);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid_handler::handle_pass_through(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
cpuid_handler::handle_0x80000000(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    auto [rax, rbx, rcx, rdx] =
        ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rax()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rbx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rcx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rdx())
        );

    bfignored(rbx);
    bfignored(rcx);
    bfignored(rdx);

    info.rax = rax;
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

    auto [rax, rbx, rcx, rdx] =
        ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rax()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rbx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rcx()),
            gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rdx())
        );

    info.rax = rax;
    info.rbx = 0x0;
    info.rcx = rcx & 0x121U;
    info.rdx = rdx & 0x2C100800U;

    return true;
}

bool
cpuid_handler::handle_0x400000BF(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfdebug_ndec(0, "debug", vcpu->rcx());

    info.ignore_write = true;
    return true;
}

}
