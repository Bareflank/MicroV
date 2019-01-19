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
#include <hve/arch/intel_x64/vmexit/yield.h>

#define make_rdmsr_delegate(a)                                                  \
    bfvmm::intel_x64::rdmsr_handler::handler_delegate_t::create<yield_handler, &yield_handler::a>(this)

#define make_wrmsr_delegate(a)                                                  \
    bfvmm::intel_x64::wrmsr_handler::handler_delegate_t::create<yield_handler, &yield_handler::a>(this)

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

yield_handler::yield_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    // Notes:
    //
    // We we the TSC ratio to kHz because the manual states that you take the
    // value of the ratio and multiply it by 133.33MHz. The issue is that we
    // don't want to use floating point numbers here, so we have to convert
    // to kHz to be able to convert this to an integer value.
    //

    using namespace vmcs_n;
    using namespace ::intel_x64::msrs;

    if (vcpu->is_dom0()) {
        return;
    }

    m_tsc_freq = ia32_platform_info::max_nonturbo_ratio::get() * 133330;
    m_pet_shift = ia32_vmx_misc::preemption_timer_decrement::get();

    if (m_tsc_freq == 0) {
        vcpu->halt("No TSC frequency info available. System unsupported");
    }

    vcpu->add_handler(
        exit_reason::basic_exit_reason::hlt,
        ::handler_delegate_t::create<yield_handler, &yield_handler::handle_hlt>(this)
    );

    vcpu->add_handler(
        exit_reason::basic_exit_reason::preemption_timer_expired,
        ::handler_delegate_t::create<yield_handler, &yield_handler::handle_preemption>(this)
    );

    EMULATE_MSR(0x000006E0, handle_rdmsr_0x000006E0, handle_wrmsr_0x000006E0);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
yield_handler::handle_hlt(gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);

    // Notes:
    //
    // - We disable blocking_by_sti because the guest executes an STI right
    //   before executing a hlt (to ensure that interrupts are enabled) which
    //   triggers this flag. Since we have a VM exit, the flag is meaningless
    //   but it will trigger a VM entry failure when we attempt to inject.
    // - The TSC ratio is in kHz. The TSC Deadline is in ticks, and we need
    //   to convert to microseconds, which is what bfexec accepts. To do this,
    //   we use the following formula (remember that Hz == ticks per second)
    //
    //   ticks = TSC Deadline - current TSC;
    //   tsc_freq_hz = tsc_freq * 1000;
    //   seconds = ticks / tsc_freq_hz;
    //
    //   Therefore:
    //
    //   microseconds = seconds * 1000000
    //   microseconds = (ticks / tsc_freq_hz) * 1000000
    //   microseconds = (ticks / (tsc_freq * 1000)) * 1000000
    //   microseconds = (ticks / tsc_freq) * 1000
    //
    //   We take one more final step which is to move the multiple in front to
    //   ensure we remove the highest possible amount of loss due to rounding.
    //
    //   microseconds = (ticks * 1000) / tsc_freq
    //
    // - Also note that in this function we get the
    //   TSC Deadline - current TSC (i.e. ticks) value from the PET. When the
    //   deadline is written to we set the PET with that value which
    //   emulates the APIC Timer. If the guest continues to execute, eventually
    //   the PET will fire, and we inject an interrupt and wait for the next
    //   deadline write. If the guest writes the deadline and then hlts, it is
    //   because the guest is telling us that it has nothing to do. In this
    //   case we take the reminaing PET ticks and convert them to microseconds
    //   using the above formula.
    //
    // - Also, in this function we inject, while in the others we queue.
    //   We should always queue because it is safer as it handles when the
    //   guest cannot be interrupted. In the hlt handler however we cannot
    //   queue because there isn't an instruction to retire, and we also know
    //   that we are always in an interruptable state so an injection is
    //   the better approach.
    //

    vmcs_n::guest_interruptibility_state::blocking_by_sti::disable();

    m_vcpu->inject_external_interrupt(
        m_vcpu->apic_timer_vector()
    );

    m_vcpu->disable_preemption_timer();
    m_vcpu->advance();

    if (auto pet = m_vcpu->get_preemption_timer(); pet > 0) {
        auto yield = ((pet << m_pet_shift) * 1000) / m_tsc_freq;

        m_vcpu->parent_vcpu()->load();
        m_vcpu->parent_vcpu()->return_yield(yield);
    }

    return true;
}

bool
yield_handler::handle_preemption(gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);

    m_vcpu->queue_external_interrupt(
        m_vcpu->apic_timer_vector()
    );

    m_vcpu->disable_preemption_timer();
    return true;
}

bool
yield_handler::handle_rdmsr_0x000006E0(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("reading from the TSC Deadline is not supported");
    return true;
}

bool
yield_handler::handle_wrmsr_0x000006E0(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    if (auto tsc = ::x64::read_tsc::get(); info.val > tsc) {
        if (auto pet = (info.val - tsc) >> m_pet_shift; pet > 0) {
            m_vcpu->set_preemption_timer(pet);
            return true;
        }

        m_vcpu->set_preemption_timer(1);
        return true;
    }

    m_vcpu->queue_external_interrupt(
        m_vcpu->apic_timer_vector()
    );

    return true;
}

}
