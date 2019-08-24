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

#include <bfgsl.h>
#include <bfdebug.h>
#include <arch/intel_x64/crs.h>
#include <arch/intel_x64/cpuid.h>
#include <hve/arch/intel_x64/xstate.h>
#include <hve/arch/intel_x64/vcpu.h>

extern "C" void xstate_save(uint64_t xcr0, uint64_t rfbm, void *area);
extern "C" void xstate_load(uint64_t xcr0, uint64_t rfbm, void *area);

namespace microv::intel_x64 {

/*
 * Each xsave/xrstor calculates the "RFBM", which represents the set of state
 * components that the user wants to save. In general, each state component
 * maps to a subset of bits in the RFBM, e.g., SSE state is RFBM[1] and MPX
 * state is RFBM[4:3].
 *
 * Note that RFBM == (EDX:EAX & (XCR0 | IA32_XSS_MSR)). XCR0 is the bitmask
 * that specifies *user* state components and IA32_XSS_MSR is the bitmask that
 * specifies *supervisor* state components.
 *
 * Currently, the VMM saves and restores the SSE state component (XMM
 * registers) manually on each vmexit/vmentry. This is why m_rfbm is the value
 * of XCR0 with bit 1 clear. Note if the host and guest vcpu both try to use
 * any supervisor state, then we would need to include IA32_XSS_MSR into the
 * m_rfbm calculation. Right now the guest vcpus will not write that MSR
 * because it is blacklisted, so we don't have to worry about saving supervisor
 * states here.
 */

#pragma pack(push, 1)

struct x87_state {
    uint16_t fcw;
    uint16_t fsw;
    uint8_t ftw;
    uint8_t rsvd;
    uint16_t fop;
    uint64_t fip; /* assumes REX.W = 1 */
    uint64_t fdp; /* assumes REX.W = 1 */
};

struct xsave_header {
    uint64_t xstate_bv;
    uint64_t xcomp_bv;
    uint64_t rsvd[6];
};

#pragma pack(pop)

static constexpr uint64_t x87_mask = (1 << 0);
static constexpr uint64_t sse_mask = (1 << 1);
static constexpr uint64_t cpuid_leaf = 0xD;
static constexpr uint64_t legacy_size = 512;
static constexpr uint64_t header_size = sizeof(xsave_header);
static constexpr uint64_t min_area_size = legacy_size + header_size;
static constexpr uintptr_t area_align = 0x40;

static_assert(header_size == 64);

xstate::xstate(class vcpu *vcpu) : m_vcpu{vcpu}
{
    if (vcpu->is_host_vcpu()) {
        expects(::intel_x64::vmcs::guest_cr4::osxsave::is_enabled());
        m_xcr0 = ::intel_x64::xcr0::get();
        m_rfbm = m_xcr0 & ~sse_mask;
        m_size = ::x64::cpuid::ebx::get(cpuid_leaf);
        m_area = std::make_unique<char[]>(m_size);
        memset(m_area.get(), 0, m_size);
    } else {
        /* Bit 0 of xcr0 must always be 1 */
        m_xcr0 = x87_mask;
        m_rfbm = m_xcr0;
        m_size = ::x64::cpuid::ecx::get(cpuid_leaf);
        m_area = std::make_unique<char[]>(m_size);
        memset(m_area.get(), 0, m_size);

        /* Initialize x87 state. See vol. 1, section 13.6 */
        auto x87 = reinterpret_cast<struct x87_state *>(m_area.get());
        x87->fcw = 0x37;
        x87->ftw = 0xFF;
    }

    ensures((reinterpret_cast<uintptr_t>(m_area.get()) & (area_align - 1)) == 0);
    vcpu->add_xsetbv_handler({&xstate::handle_xsetbv, this});
}

void xstate::save()
{
    xstate_save(m_xcr0, m_rfbm, m_area.get());
}

void xstate::load()
{
    xstate_load(m_xcr0, m_rfbm, m_area.get());
}

bool xstate::handle_xsetbv(base_vcpu *vcpu, xsetbv_info &info)
{
    if (vcpu->is_host_vcpu()) {
        expects(::intel_x64::xcr0::get() == m_xcr0);
        bfalert_info(0, "xsetbv attempt");
        bfalert_subnhex(0, "old", m_xcr0);
        bfalert_subnhex(0, "new", info.val);
    } else {
        m_xcr0 = info.val;
        m_rfbm = info.val & ~sse_mask;
    }

    return true;
}

}
