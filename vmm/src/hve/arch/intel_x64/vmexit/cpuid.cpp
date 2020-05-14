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
#include <hve/arch/intel_x64/vmexit/cpuid.h>

#define EMULATE_CPUID(a,b)                                                     \
    m_vcpu->add_cpuid_emulator(a, {&cpuid_handler::b, this});

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace microv::intel_x64
{

// Passthrough should only be used for cpuid leaves that 1) we dont mind the
// guest seeing and 2) have no reserved bits.
//
// Reserved bits represent future CPU features, so we have to make certain
// they are explicitly set to 0, otherwise fancy new feature XYZ will be leaked
// to the guest when its bits are "unreserved", which may or may not be what
// we want.
//
static inline bool cpuid_passthrough(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();
    return vcpu->advance();
}

cpuid_handler::cpuid_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpu->is_dom0()) {
        return;
    }

    vcpu->enable_cpuid_whitelisting();

    // Note:
    //
    // Every leaf that is supported is handled here. Every other leaf
    // is emulated by ::cpuid_zeros_emulator in intel_x64/vcpu.cpp. That
    // emulator returns zeros in rax-rdx without executing cpuid at all.
    //

    EMULATE_CPUID(0x00000000, handle_0x00000000);
    EMULATE_CPUID(0x00000001, handle_0x00000001);
    EMULATE_CPUID(0x00000002, handle_0x00000002);
    EMULATE_CPUID(0x00000004, handle_0x00000004);
    EMULATE_CPUID(0x00000007, handle_0x00000007);
    EMULATE_CPUID(0x0000000A, handle_0x0000000A);
    EMULATE_CPUID(0x0000000D, handle_0x0000000D);
    EMULATE_CPUID(0x00000015, handle_0x00000015);
    EMULATE_CPUID(0x00000016, handle_0x00000016);
    EMULATE_CPUID(0x80000000, handle_0x80000000);
    EMULATE_CPUID(0x80000001, handle_0x80000001);
    EMULATE_CPUID(0x80000002, handle_0x80000002);
    EMULATE_CPUID(0x80000003, handle_0x80000003);
    EMULATE_CPUID(0x80000004, handle_0x80000004);
    EMULATE_CPUID(0x80000006, handle_0x80000006);
    EMULATE_CPUID(0x80000007, handle_0x80000007);
    EMULATE_CPUID(0x80000008, handle_0x80000008);

    EMULATE_CPUID(0x40000000, handle_0x40000000);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid_handler::handle_0x00000000(vcpu_t *vcpu)
{
    return cpuid_passthrough(vcpu);
}

static inline void handle_0x00000001_rcx(vcpu_t *vcpu)
{
    using namespace ::intel_x64::cpuid::feature_information;

    uint64_t rcx{0};

    rcx |= ecx::sse3::mask;
    rcx |= ecx::pclmulqdq::mask;
//  rcx |= ecx::dtes64::mask;
//  rcx |= ecx::monitor::mask;

//  rcx |= ecx::ds_cpl::mask;
//  rcx |= ecx::vmx::mask;
//  rcx |= ecx::smx::mask;
//  rcx |= ecx::eist::mask;

//  rcx |= ecx::tm2::mask;
    rcx |= ecx::ssse3::mask;
//  rcx |= ecx::cnxt_id::mask;
//  rcx |= ecx::sdbg::mask;

    rcx |= ecx::fma::mask;
    rcx |= ecx::cmpxchg16b::mask;
//  rcx |= ecx::xtpr_update_control::mask;
//  rcx |= ecx::pdcm::mask;

//  bit 16 reserved
//  rcx |= ecx::pcid::mask; // TODO: work on enabling this
//  rcx |= ecx::dca::mask;
    rcx |= ecx::sse41::mask;

    rcx |= ecx::sse42::mask;
    rcx |= ecx::x2apic::mask;
    rcx |= ecx::movbe::mask;
    rcx |= ecx::popcnt::mask;

    rcx |= ecx::tsc_deadline::mask;
    rcx |= ecx::aesni::mask;
    rcx |= ecx::xsave::mask;
//  rcx |= ecx::osxsave::mask; // handled below

    rcx |= ecx::avx::mask;
    rcx |= ecx::f16c::mask;
    rcx |= ecx::rdrand::mask;
    rcx |= 0x80000000U; // set bit 31 to tell Linux it is in a VM

    // Set osxsave based on current cr4 value
    if (::intel_x64::cr4::osxsave::is_enabled(vcpu->cr4())) {
        rcx |= ecx::osxsave::mask;
    }

    vcpu->set_rcx(vcpu->rcx() & rcx);
}

static inline void handle_0x00000001_rdx(vcpu_t *vcpu)
{
    using namespace ::intel_x64::cpuid::feature_information;

    uint64_t rdx{0};

    rdx |= edx::fpu::mask;
    rdx |= edx::vme::mask;
//  rdx |= edx::de::mask;
    rdx |= edx::pse::mask;

    rdx |= edx::tsc::mask;
    rdx |= edx::msr::mask;
    rdx |= edx::pae::mask;
    rdx |= edx::mce::mask; // FIXME: think about machine-check handling (and NMIs) from guest

    rdx |= edx::cx8::mask;
    rdx |= edx::apic::mask;
//  bit 10 reserved
//  rdx |= edx::sep::mask;

    rdx |= edx::mtrr::mask;
    rdx |= edx::pge::mask;
    rdx |= edx::mca::mask; // FIXME: related to bit mce above
    rdx |= edx::cmov::mask;

    rdx |= edx::pat::mask;
    rdx |= edx::pse_36::mask;
//  rdx |= edx::psn::mask;
    rdx |= edx::clfsh::mask;

//  bit 20 reserved
//  rdx |= edx::ds::mask;
//  rdx |= edx::acpi::mask;
    rdx |= edx::mmx::mask;

    rdx |= edx::fxsr::mask;
    rdx |= edx::sse::mask;
    rdx |= edx::sse2::mask;
    rdx |= edx::ss::mask;

//  rdx |= edx::htt::mask;
//  rdx |= edx::tm::mask;
//  bit 30 reserved
//  rdx |= edx::pbe::mask;

    vcpu->set_rdx(vcpu->rdx() & rdx);
}

bool
cpuid_handler::handle_0x00000001(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    // Mask off APIC IDs, set initial APIC ID to 0
    vcpu->set_rbx(vcpu->rbx() & 0x0000FFFF);

    handle_0x00000001_rcx(vcpu);
    handle_0x00000001_rdx(vcpu);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000002(vcpu_t *vcpu)
{
    return cpuid_passthrough(vcpu);
}

bool
cpuid_handler::handle_0x00000004(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    // Bits 31-26 and 25-14 advertise the number of addressable IDs that use
    // this cache, so set those fields to zero (callers must add 1 to the field
    // value according to the SDM).
    vcpu->set_rax(vcpu->rax() & 0x000003FF);

    // ebx and ecx are passed-through. edx[2:0] exposes wbinvd/invd and
    // other cache attributes. All other bits are reserved.
    vcpu->set_rdx(vcpu->rdx() & 0x00000007);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000007(vcpu_t *vcpu)
{
    if (vcpu->rcx() > 0) {
        vcpu->set_rax(0);
        vcpu->set_rbx(0);
        vcpu->set_rcx(0);
        vcpu->set_rdx(0);

        return vcpu->advance();
    }

    vcpu->execute_cpuid();

    vcpu->set_rax(0);

    // TODO: look into passing through bit 10 (INVPCID)
    vcpu->set_rbx(vcpu->rbx() & 0x219C23F9);

    // TODO: look into passing through bit 2 (UMIP)
    // TODO: look into passing through bit 25 (CLDEMOTE)
    // TODO: look into passing through bit 27-28 (MOVDIRI*)
    vcpu->set_rcx(vcpu->rcx() & 0x00400000);

    // TODO: look into passing through bit 4 (fast short rep mov)
    // TODO: look into passing through bit 26-31 (speculative shit)
    vcpu->set_rdx(0);

    return vcpu->advance();
}

// TODO: look into leaf 9 (direct cache access) for NDVM

bool
cpuid_handler::handle_0x0000000A(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(0);

    /* Disable perf events 0-6 by setting them to 1 */
    vcpu->set_rbx(vcpu->rbx() | 0x0000007F);

    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x0000000D(vcpu_t *vcpu)
{
    const auto subleaf = vcpu->rcx();
    vcpu->execute_cpuid();

    /*
     * Remove any contribution that IA32_XSS bits make to the XSAVES size area.
     * This has no effect when Linux is the root domain, because Linux doesn't
     * use supervisor states. Windows does however, and if we dont remove the
     * size contribution, it will trip a warning in do_extra_xstate_size_checks
     * in Linux's fpu initializaiton.
     */
    if (subleaf == 1) {
        /* Save the original values other than EBX */
        const auto rax = vcpu->rax();
        const auto rcx = vcpu->rcx();
        const auto rdx = vcpu->rdx();

        /* Read the size required for current XCR0 bits */
        vcpu->set_rax(0xD);
        vcpu->set_rcx(0x0);
        vcpu->execute_cpuid();
        auto rbx = vcpu->rbx();

        vcpu->set_rax(rax);
        vcpu->set_rbx(rbx);
        vcpu->set_rcx(rcx);
        vcpu->set_rdx(rdx);
    }

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000015(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rdx(0);
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000016(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(vcpu->rax() & 0x0000FFFF);
    vcpu->set_rbx(vcpu->rbx() & 0x0000FFFF);
    vcpu->set_rcx(vcpu->rcx() & 0x0000FFFF);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000000(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000001(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rbx(0);
    vcpu->set_rcx(vcpu->rcx() & 0x00000121);
    vcpu->set_rdx(vcpu->rdx() & 0x2C100800);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000002(vcpu_t *vcpu)
{
    return cpuid_passthrough(vcpu);
}

bool
cpuid_handler::handle_0x80000003(vcpu_t *vcpu)
{
    return cpuid_passthrough(vcpu);
}

bool
cpuid_handler::handle_0x80000004(vcpu_t *vcpu)
{
    return cpuid_passthrough(vcpu);
}

bool
cpuid_handler::handle_0x80000006(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(vcpu->rcx() & 0xFFFFF0FF);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000007(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    if ((vcpu->rdx() & 0x100) == 0) {
        bfalert_info(0, "Non-Invariant TSC. System not supported!!!");
    }

    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(vcpu->rdx() & 0x00000100);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000008(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(vcpu->rax() & 0x0000FFFF);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x40000000(vcpu_t *vcpu)
{
    vcpu->set_rax(0xBFBFBFBF);
    return vcpu->advance();
}

}
