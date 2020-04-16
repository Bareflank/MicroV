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
    // Every leaf that is supported is handled here. All reserved bits must
    // be set to 0. Otherwise a new feature could be enabled that we are not
    // aware of in the future.
    //

    EMULATE_CPUID(0x00000000, handle_0x00000000);
    EMULATE_CPUID(0x00000001, handle_0x00000001);
    EMULATE_CPUID(0x00000002, handle_0x00000002);
    EMULATE_CPUID(0x00000004, handle_0x00000004);
    EMULATE_CPUID(0x00000006, handle_0x00000006);
    EMULATE_CPUID(0x00000007, handle_0x00000007);
    EMULATE_CPUID(0x0000000A, handle_0x0000000A);
    EMULATE_CPUID(0x0000000B, handle_0x0000000B);
    EMULATE_CPUID(0x0000000D, handle_0x0000000D);
    EMULATE_CPUID(0x0000000F, handle_0x0000000F);
    EMULATE_CPUID(0x00000010, handle_0x00000010);
    EMULATE_CPUID(0x00000015, handle_0x00000015);
    EMULATE_CPUID(0x00000016, handle_0x00000016);
    EMULATE_CPUID(0x80000000, handle_0x80000000);
    EMULATE_CPUID(0x80000001, handle_0x80000001);
    EMULATE_CPUID(0x80000002, handle_0x80000002);
    EMULATE_CPUID(0x80000003, handle_0x80000003);
    EMULATE_CPUID(0x80000004, handle_0x80000004);
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
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000001(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rcx(vcpu->rcx() & 0x61FC3203);
    vcpu->set_rdx(vcpu->rdx() & 0x1FCBFBFB);

    // Note:
    //
    // The following tells Linux that it is in a VM.
    //

    vcpu->set_rcx(vcpu->rcx() | 0x80000000);

    // Enable xsave and avx
    vcpu->set_rcx(vcpu->rcx() | (1UL << 26));
    vcpu->set_rcx(vcpu->rcx() | (1UL << 28));

    // Set osxsave based on current cr4 value
    auto osxsave = vcpu->cr4() & (1UL << 18);
    if (osxsave) {
        vcpu->set_rcx(vcpu->rcx() | (1UL << 27));
    } else {
        vcpu->set_rcx(vcpu->rcx() & ~(1UL << 27));
    }

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000002(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000004(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(vcpu->rax() & 0x000003FF);
    vcpu->set_rax(vcpu->rax() | 0x04004000);
    vcpu->set_rdx(vcpu->rdx() & 0x00000007);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000006(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000007(vcpu_t *vcpu)
{
    if (vcpu->gr2() != 0) {
        return vcpu->advance();
    }

    vcpu->execute_cpuid();

    vcpu->set_rax(0);
    vcpu->set_rbx(vcpu->rbx() & 0x019D23F9);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x0000000A(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    vcpu->set_rax(0);
    vcpu->set_rbx(vcpu->rbx() & 0x0000007F);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x0000000B(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
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
cpuid_handler::handle_0x0000000F(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

bool
cpuid_handler::handle_0x00000010(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

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
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000003(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000004(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();
    return vcpu->advance();
}

bool
cpuid_handler::handle_0x80000007(vcpu_t *vcpu)
{
    vcpu->execute_cpuid();

    if ((vcpu->rdx() & 0x100) == 0) {
        bfalert_info(0, "Non-Invariant TSC not supported!!!");
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
