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

#define EMULATE_MSR(a, r, w)                                                   \
    m_vcpu->emulate_rdmsr(a, {&yield_handler::r, this});                       \
    m_vcpu->emulate_wrmsr(a, {&yield_handler::w, this});

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace microv::intel_x64 {

static inline void display_family_model(uint32_t &family, uint32_t &model)
{
    namespace version = ::intel_x64::cpuid::feature_information::eax;

    uint32_t display_family{};
    uint32_t display_model{};

    const auto eax = version::get();
    const auto fam_id = version::family_id::get(eax);

    /// NOTES:
    ///
    /// The algorithm showing how to retrieve the DisplayFamily and DisplayModel
    /// is described in Vol.2A below "Figure 3-6. Version Information Returned
    /// by CPUID in EAX"

    // Set display_family
    if (fam_id != 0xF) {
        display_family = fam_id;
    } else {
        display_family = version::extended_family_id::get(eax) + fam_id;
    }

    // Set display_model
    if (fam_id == 0x6 || fam_id == 0xF) {
        const auto model = version::model::get(eax);
        const auto ext_model = version::extended_model_id::get(eax);
        display_model = (ext_model << 4) | model;
    } else {
        display_model = version::model::get(eax);
    }

    family = display_family;
    model = display_model;
}

static inline uint64_t bus_freq_khz()
{
    uint32_t display_family{};
    uint32_t display_model{};

    display_family_model(display_family, display_model);

    if (display_family != 0x06) {
        bfalert_info(0, "bus_freq_MHz: unsupported display_family");
        return 0;
    }

    switch (display_model) {
    case 0x4E:    // section 2.16
    case 0x55:
    case 0x5E:
    case 0x66:
    case 0x8E:
    case 0x9E:
    case 0x5C:    // table 2-12
    case 0x7A:
    case 0x2A:    // table 2-19
    case 0x2D:
    case 0x3A:    // table 2-24
    case 0x3E:    // table 2-25
    case 0x3C:    // table 2-28
    case 0x3F:
    case 0x45:
    case 0x46:
    case 0x3D:    // section 2.14
    case 0x47:
    case 0x4F:    // table 2-35
    case 0x56:
    case 0x57:    // table 2-43
    case 0x85:
        return 100000;

    case 0x1A:    // table 2-14
    case 0x1E:
    case 0x1F:
    case 0x2E:
        return 133330;

    default:
        bfalert_nhex(
            0, "bus_freq_khz: Unknown cpuid display_model", display_model);
        return 0;
    }
}

static inline uint32_t crystal_clock_khz()
{
    uint32_t display_model;
    uint32_t ignored;

    display_family_model(ignored, display_model);

    switch (display_model) {
    case 0x4E:
    case 0x5E:
    case 0x8E:
    case 0x9E:
        return 24000;

    case 0x5F:
        return 25000;

    case 0x5C:
        return 19200;

    default:
        bfalert_nhex(
            0, "crystal_clock_khz: Unknown cpuid display_model", display_model);
        return 0;
    };
}

/// NOTES:
///
/// As per "Vol3. 18.18.3 Determining the Processor Base Frequency",
/// for Intel processors in which the nominal core crystal clock frequency is
/// enumerated in CPUID.15H.ECX and the core crystal clock ratio is encoded in
/// CPUID.15H (see Table 3-8 "Information Returned by CPUID Instruction"), the
/// nominal TSC frequency can be determined by using the following formula:
///
///     TSC_freq_Hz = ( CPUID.15H.ECX * CPUID.15H.EBX ) ÷ CPUID.15H.EAX
///     TSC_freq_Hz = ( crystal_Hz * tsc_crystal_ratio_numerator ) ÷ tsc_crystal_ratio_denominator
///
/// For Intel processors in which CPUID.15H.EBX ÷ CPUID.0x15.EAX is enumerated
/// but CPUID.15H.ECX is not enumerated, Table 18-68 can be used to look up the
/// nominal core crystal clock frequency.
///
/// If the crystal clock frequency is not enumerated in CPUID.15H.ECX, we can
/// closely aproximate its value by using the processor base frequency (Mhz)
/// in CPUID.16H.EAX and the following formula:
///
///     Crystal_freq_Khz = (CPUID.16H.EAX * 1000) * CPUID.15H.EAX ÷ CPUID.15H.EBX
///     Crystal_freq_Khz = (proc_Khz) * tsc_crystal_ratio_denominator ÷ tsc_crystal_ratio_numerator
///
/// If we are unable to use the CPUID.15H method to calculate the TSC frequency,
/// i.e. (1) if CPUID.15H.EBX or CPUID.15H.EAX is not enumerated, or (2) if
/// CPUID.15H.ECX is not enumerated and we don't have a known value for the
/// crystal clock frequency or (3) CPUID.15H.ECX is not enumerated and CPUID.16H
/// is not available to aproximate the crystal frequency, we have to revert back
/// to using the MSR_PLATFORM_INFO formula which is less accurate on some
/// platforms.
///
/// The following equation for the TSC frequency (in MHz) is derived from the
/// description of the Max Non-Turbo Ratio field of the MSR_PLATFORM_INFO msr:
///
///     TSC_freq_MHz = bus_freq_MHz * MSR_PLATFORM_INFO[15:8]
///     TSC_freq_MHz = bus_freq_MHz * platform_info::max_nonturbo_ratio::get()
///
/// Note that, most, if not all, systems that (1) aren't Nehalem
/// and (2) support invariant TSC (i.e. cpuid.80000007:EDX[8] == 1)
/// have a bus_freq_MHz == 100 MHz.
///
static uint64_t tsc_freq_khz()
{
    using namespace ::intel_x64;

    const auto regs{::x64::cpuid::get(0, 0, 0, 0)};
    const auto max_cpuid{regs.rax};

    if (max_cpuid < 0x15) {
        bferror_info(
            0, "tsc_freq_khz: Time Stamp Count CPUID leaf is not supported");
        return 0;
    }

    // eax = tsc/crystal ratio denominator
    // ebx = tsc/crystal ratio numerator
    // ecx = crystal in Hz
    const auto [eax, ebx, ecx, edx] =
        ::x64::cpuid::get(cpuid::time_stamp_count::addr, 0, 0, 0);
    uint32_t crystal_khz = 0;

    if (ecx != 0 && eax != 0 && ebx != 0) {
        crystal_khz = ecx / 1000;
    } else if (ecx == 0 && eax != 0 && ebx != 0) {
        // The nominal frequency of the core crystal clock is not enumerated, so
        // use kown values
        crystal_khz = crystal_clock_khz();

        if (crystal_khz == 0 && max_cpuid >= cpuid::processor_freq::addr) {
            // Last resort to get the crystal clock frequency
            const auto proc_mhz = cpuid::processor_freq::eax::get();
            crystal_khz = proc_mhz * 1000 * eax / ebx;
        }
    }

    if (eax == 0 || ebx == 0 || crystal_khz == 0) {
        // revert back to using the MSR_PLATFORM_INFO method to calibrate TSC

        const uint64_t bus_freq = bus_freq_khz();
        const auto nonturbo_ratio =
            msrs::ia32_platform_info::max_nonturbo_ratio::get();

        return bus_freq * nonturbo_ratio;
    }

    return crystal_khz * ebx / eax;
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
{
    return ::intel_x64::cpuid::feature_information::edx::tsc::is_enabled();
}

static inline bool invariant_tsc_supported()
{
    return ::intel_x64::cpuid::invariant_tsc::edx::available::is_enabled();
}

yield_handler::yield_handler(gsl::not_null<vcpu *> vcpu) : m_vcpu{vcpu}
{
    using namespace vmcs_n;
    using namespace ::intel_x64::msrs;

    expects(tsc_supported());
    expects(invariant_tsc_supported());

    m_tsc_freq = tsc_freq_khz();
    m_pet_shift = ia32_vmx_misc::preemption_timer_decrement::get();

    if (vcpu->is_dom0()) {
        return;
    }

    if (m_tsc_freq == 0) {
        vcpu->halt("No TSC frequency info available. System unsupported");
    }

    vcpu->add_hlt_handler({&yield_handler::handle_hlt, this});

    vcpu->add_preemption_timer_handler(
        {&yield_handler::handle_preemption, this});

    EMULATE_MSR(0x000006E0, handle_rdmsr_0x000006E0, handle_wrmsr_0x000006E0);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool yield_handler::handle_hlt(vcpu_t *vcpu,
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

    m_vcpu->inject_external_interrupt(m_vcpu->apic_timer_vector());

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

bool yield_handler::handle_preemption(vcpu_t *vcpu)
{
    bfignored(vcpu);

    m_vcpu->queue_external_interrupt(m_vcpu->apic_timer_vector());

    m_vcpu->disable_preemption_timer();
    return true;
}

bool yield_handler::handle_rdmsr_0x000006E0(
    vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("reading from the TSC Deadline is not supported");
    return true;
}

bool yield_handler::handle_wrmsr_0x000006E0(
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

    m_vcpu->queue_external_interrupt(m_vcpu->apic_timer_vector());

    return true;
}

}
