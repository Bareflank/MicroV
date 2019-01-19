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
#include <hve/arch/intel_x64/vmexit/msr.h>

#define make_rdmsr_delegate(a)                                                  \
    bfvmm::intel_x64::rdmsr_handler::handler_delegate_t::create<x2apic_handler, &x2apic_handler::a>(this)

#define make_wrmsr_delegate(a)                                                  \
    bfvmm::intel_x64::wrmsr_handler::handler_delegate_t::create<x2apic_handler, &x2apic_handler::a>(this)

#define EMULATE_MSR(a,b,c)                                                      \
    m_vcpu->emulate_rdmsr(                                                      \
        a, make_rdmsr_delegate(b)                                               \
    );                                                                          \
    m_vcpu->emulate_wrmsr(                                                      \
        a, make_wrmsr_delegate(c)                                               \
    );





#include <iostream>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

x2apic_handler::x2apic_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpuid::is_host_vm_vcpu(vcpu->id())) {
        return;
    }

    EMULATE_MSR(0x0000001B, handle_rdmsr_0x0000001B, handle_wrmsr_0x0000001B);

    EMULATE_MSR(0x00000802, handle_rdmsr_0x00000802, handle_wrmsr_0x00000802);
    EMULATE_MSR(0x00000803, handle_rdmsr_0x00000803, handle_wrmsr_0x00000803);
    EMULATE_MSR(0x00000808, handle_rdmsr_0x00000808, handle_wrmsr_0x00000808);
    EMULATE_MSR(0x0000080B, handle_rdmsr_0x0000080B, handle_wrmsr_0x0000080B);
    EMULATE_MSR(0x0000080D, handle_rdmsr_0x0000080D, handle_wrmsr_0x0000080D);
    EMULATE_MSR(0x0000080F, handle_rdmsr_0x0000080F, handle_wrmsr_0x0000080F);
    EMULATE_MSR(0x00000828, handle_rdmsr_0x00000828, handle_wrmsr_0x00000828);

    EMULATE_MSR(0x00000810, handle_rdmsr_0x00000810, handle_wrmsr_0x00000810);
    EMULATE_MSR(0x00000811, handle_rdmsr_0x00000811, handle_wrmsr_0x00000811);
    EMULATE_MSR(0x00000812, handle_rdmsr_0x00000812, handle_wrmsr_0x00000812);
    EMULATE_MSR(0x00000813, handle_rdmsr_0x00000813, handle_wrmsr_0x00000813);
    EMULATE_MSR(0x00000814, handle_rdmsr_0x00000814, handle_wrmsr_0x00000814);
    EMULATE_MSR(0x00000815, handle_rdmsr_0x00000815, handle_wrmsr_0x00000815);
    EMULATE_MSR(0x00000816, handle_rdmsr_0x00000816, handle_wrmsr_0x00000816);
    EMULATE_MSR(0x00000817, handle_rdmsr_0x00000817, handle_wrmsr_0x00000817);

    EMULATE_MSR(0x00000820, handle_rdmsr_0x00000820, handle_wrmsr_0x00000820);
    EMULATE_MSR(0x00000821, handle_rdmsr_0x00000821, handle_wrmsr_0x00000821);
    EMULATE_MSR(0x00000822, handle_rdmsr_0x00000822, handle_wrmsr_0x00000822);
    EMULATE_MSR(0x00000823, handle_rdmsr_0x00000823, handle_wrmsr_0x00000823);
    EMULATE_MSR(0x00000824, handle_rdmsr_0x00000824, handle_wrmsr_0x00000824);
    EMULATE_MSR(0x00000825, handle_rdmsr_0x00000825, handle_wrmsr_0x00000825);
    EMULATE_MSR(0x00000826, handle_rdmsr_0x00000826, handle_wrmsr_0x00000826);
    EMULATE_MSR(0x00000827, handle_rdmsr_0x00000827, handle_wrmsr_0x00000827);

    EMULATE_MSR(0x00000832, handle_rdmsr_0x00000832, handle_wrmsr_0x00000832);
    EMULATE_MSR(0x00000835, handle_rdmsr_0x00000835, handle_wrmsr_0x00000835);
    EMULATE_MSR(0x00000836, handle_rdmsr_0x00000836, handle_wrmsr_0x00000836);
    EMULATE_MSR(0x00000837, handle_rdmsr_0x00000837, handle_wrmsr_0x00000837);
    EMULATE_MSR(0x00000838, handle_rdmsr_0x00000838, handle_wrmsr_0x00000838);
}

uint8_t
x2apic_handler::timer_vector() const noexcept
{
    using namespace ::intel_x64::msrs::ia32_x2apic_lvt_timer;

    if (timer_mode::get(m_0x00000832) != timer_mode::tsc_deadline) {
        m_vcpu->halt("non-TSC deadline timer unsupported");
    }

    return gsl::narrow_cast<uint8_t>(vector::get(m_0x00000832));
}

// -----------------------------------------------------------------------------
// General MSRs
// -----------------------------------------------------------------------------

bool
x2apic_handler::handle_rdmsr_0x0000001B(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x0000001B & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x0000001B(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    if ((info.val & 0xFFF) != 0xD00) {
        vcpu->halt("Disabling x2APIC is not supported");
    }

    m_0x0000001B = info.val & 0xFFFFFFFF;
    return true;
}

// -----------------------------------------------------------------------------
// General Purpose Registers
// -----------------------------------------------------------------------------

bool
x2apic_handler::handle_rdmsr_0x00000802(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000802(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to APIC ID not supported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000803(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x00040010U;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000803(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to APIC VERSION not supported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000808(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000808(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    if (info.val != 0) {
        vcpu->halt("non-zero TPR not supported");
    }

    return true;
}

bool
x2apic_handler::handle_rdmsr_0x0000080B(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("reading the APIC EOI is not supported");
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x0000080B(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
x2apic_handler::handle_rdmsr_0x0000080D(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    bfalert_info(0, "unimplemented read from LDR");

    info.val = 0;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x0000080D(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to APIC LDR not supported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x0000080F(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x0000080F & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x0000080F(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_0x0000080F = info.val & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000828(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000828 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000828(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_0x00000828 = info.val & 0xFFFFFFFF;
    return true;
}

// -----------------------------------------------------------------------------
// ISR
// -----------------------------------------------------------------------------

bool
x2apic_handler::handle_rdmsr_0x00000810(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000810 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000810(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000811(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000811 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000811(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000812(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000812 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000812(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000813(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000813 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000813(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000814(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000814 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000814(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000815(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000815 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000815(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000816(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000816 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000816(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000817(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000817 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000817(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

// -----------------------------------------------------------------------------
// IRR
// -----------------------------------------------------------------------------

bool
x2apic_handler::handle_rdmsr_0x00000820(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000820 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000820(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000821(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000821 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000821(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000822(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000822 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000822(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000823(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000823 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000823(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000824(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000824 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000824(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000825(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000825 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000825(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000826(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000826 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000826(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000827(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000827 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000827(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("writing to an IRR is unsupported");
    return true;
}

// -----------------------------------------------------------------------------
// LVT
// -----------------------------------------------------------------------------

bool
x2apic_handler::handle_rdmsr_0x00000832(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000832 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000832(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_0x00000832 = info.val & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000835(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000835 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000835(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    bfalert_nhex(0, "unimplemented write to LINT0", info.val);

    m_0x00000835 = info.val & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000836(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000836 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000836(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    bfalert_nhex(0, "unimplemented write to LINT1", info.val);

    m_0x00000836 = info.val & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000837(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0x00000837 & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000837(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_0x00000837 = info.val & 0xFFFFFFFF;
    return true;
}

bool
x2apic_handler::handle_rdmsr_0x00000838(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
x2apic_handler::handle_wrmsr_0x00000838(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    if (info.val != 0) {
        vcpu->halt("non-zero LVT initial count not supported");
    }

    return true;
}

}
