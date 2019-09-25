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

#define EMULATE_MSR(a,r,w)                                                      \
    m_vcpu->emulate_rdmsr(a, {&yield_handler::r, this});                        \
    m_vcpu->emulate_wrmsr(a, {&yield_handler::w, this});

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace microv::intel_x64
{

//
// The following formula for the TSC frequency (in MHz) is derived from the
// description of the Max Non-Turbo Ratio field of the MSR_PLATFORM_INFO msr:
//
//      tsc_freq_MHz = bus_freq_MHz * MSR_PLATFORM_INFO[15:8]
//      tsc_freq_MHz = bus_freq_MHz * platform_info::max_nonturbo_ratio::get()
//
// Note that, most, if not all, systems that (1) aren't Nehalem
// and (2) support invariant TSC (i.e. cpuid.80000007:EDX[8] == 1)
// have a bus_freq_MHz == 100 MHz.
//
// There is an alternative method for deriving TSC frequency based strictly
// on cpuid. If invariant TSC is supported and cpuid.15H:EBX[31:0] != 0, then
// the following equation holds (note the Hz rather than MHz):
//
//      tsc_freq_Hz = (ART frequency) * (TSC / ART ratio)
//      tsc_freq_Hz = (cpuid.15H:ECX) * (cpuid.15H:EBX / cpuid.15H:EAX)
//
// where the ART a.k.a "Always Running Timer" runs at the core crystal clock
// frequency. But ECX may (and in practice does) return 0, in which case the
// formula is nonsense. Clearly we have to get the ART frequency somewhere
// else, but I haven't been able to find it. Section 18.7.3 presents the
// same formula above and mentions using cpuid.15H with the max turbo ratio,
// but that doesn't make sense either.
//
// For now we just use the MSR_PLATFORM_INFO formula
//

static uint64_t bus_freq_khz()
{
    namespace version = ::intel_x64::cpuid::feature_information::eax;

    uint32_t display_family = 0;
    uint32_t display_model = 0;

    const auto eax = version::get();
    const auto fam_id = version::family_id::get(eax);

    /* Set display_family */
    if (fam_id != 0xF) {
        display_family = fam_id;
    } else {
        display_family = version::extended_family_id::get(eax) + fam_id;
    }

    /* Set display_model */
    if (fam_id == 0x6 || fam_id == 0xF) {
        const auto model = version::model::get(eax);
        const auto ext_model = version::extended_model_id::get(eax);
        display_model = (ext_model << 4) | model;
    } else {
        display_model = version::model::get(eax);
    }

    if (display_family != 0x06) {
        bfalert_info(0, "bus_freq_MHz: unsupported display_family");
        return 0;
    }

    switch (display_model) {
        case 0x4E: // section 2.16
        case 0x55:
        case 0x5E:
        case 0x66:
        case 0x8E:
        case 0x9E:
        case 0x5C: // table 2-12
        case 0x7A:
        case 0x2A: // table 2-19
        case 0x2D:
        case 0x3A: // table 2-24
        case 0x3E: // table 2-25
        case 0x3C: // table 2-28
        case 0x3F:
        case 0x45:
        case 0x46:
        case 0x3D: // section 2.14
        case 0x47:
        case 0x4F: // table 2-35
        case 0x56:
        case 0x57: // table 2-43
        case 0x85:
            return 100000;

        case 0x1A: // table 2-14
        case 0x1E:
        case 0x1F:
        case 0x2E:
            return 133330;

        default:
            bfalert_nhex(0, "Unknown cpuid display_model", display_model);
            return 0;
    }
}

static inline uint64_t tsc_freq_khz(uint64_t bus_freq_khz)
{
    using namespace ::intel_x64::msrs;

    const auto platform_info = 0xCE;
    const auto ratio = (get(platform_info) & 0xFF00) >> 8;

    return bus_freq_khz * ratio;
}

//
// According to section 25.5.1, the VMX preemption timer (pet)
// ticks every time bit X of the TSC changes, where X is the
// value of IA32_VMX_MISC[4:0]. So
//
// pet_freq = tsc_freq >> IA32_VMX_MISC[4:0]
//
static inline uint64_t pet_freq_khz(uint64_t tsc_freq_khz)
{
    using namespace ::intel_x64::msrs;

    const auto div = ia32_vmx_misc::preemption_timer_decrement::get();
    return tsc_freq_khz >> div;
}

static inline bool tsc_supported()
{ return ::intel_x64::cpuid::feature_information::edx::tsc::is_enabled(); }

static inline bool invariant_tsc_supported()
{ return ::intel_x64::cpuid::invariant_tsc::edx::available::is_enabled(); }

yield_handler::yield_handler(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;
    using namespace ::intel_x64::msrs;

    if (vcpu->is_dom0()) {
        return;
    }

    expects(tsc_supported());
    expects(invariant_tsc_supported());

    m_tsc_freq = tsc_freq_khz(bus_freq_khz());
    m_pet_shift = ia32_vmx_misc::preemption_timer_decrement::get();

    if (m_tsc_freq == 0) {
        vcpu->halt("No TSC frequency info available. System unsupported");
    }

    vcpu->add_hlt_handler(
        {&yield_handler::handle_hlt, this}
    );

    vcpu->add_preemption_timer_handler(
        {&yield_handler::handle_preemption, this}
    );

    EMULATE_MSR(0x000006E0, handle_rdmsr_0x000006E0, handle_wrmsr_0x000006E0);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
yield_handler::handle_hlt(
    vcpu_t *vcpu,
    bfvmm::intel_x64::hlt_handler::info_t &info)
{
    bfignored(vcpu);

    if (vmcs_n::guest_rflags::interrupt_enable_flag::is_disabled()) {
        return false;
    }

    // Notes:
    //
    // - We disable blocking_by_sti because the guest executes an STI right
    //   before executing a hlt (to ensure that interrupts are enabled) which
    //   triggers this flag. Since we have a VM exit, the flag is meaningless
    //   but it will trigger a VM entry failure when we attempt to inject.
    // - The TSC ratio is in kHz. The TSC Deadline is in ticks, and we need
    //   to convert to microseconds, which is what uvctl accepts. To do this,
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

        m_vcpu->save_xstate();
        m_vcpu->root_vcpu()->load();
        m_vcpu->root_vcpu()->return_yield(yield);
    }

    return true;
}

bool
yield_handler::handle_preemption(vcpu_t *vcpu)
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
    vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("reading from the TSC Deadline is not supported");
    return true;
}

bool
yield_handler::handle_wrmsr_0x000006E0(
    vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
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
