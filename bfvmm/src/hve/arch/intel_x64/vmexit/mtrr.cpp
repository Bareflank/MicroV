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
#include <hve/arch/intel_x64/vmexit/mtrr.h>

#define EMULATE_MSR(a,r,w)                                                      \
    m_vcpu->emulate_rdmsr(a, {&mtrr_handler::r, this});                         \
    m_vcpu->emulate_wrmsr(a, {&mtrr_handler::w, this});

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

mtrr_handler::mtrr_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpu->is_dom0()) {
        return;
    }

    EMULATE_MSR(0x000000FE, handle_rdmsr_0x000000FE, handle_wrmsr_0x000000FE);
    EMULATE_MSR(0x00000200, handle_rdmsr_0x00000200, handle_wrmsr_0x00000200);
    EMULATE_MSR(0x00000201, handle_rdmsr_0x00000201, handle_wrmsr_0x00000201);
    EMULATE_MSR(0x000002FF, handle_rdmsr_0x000002FF, handle_wrmsr_0x000002FF);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

// Note:
//
// For now this MTRR handler creates a single variable range that tells the
// guest that all of memory is cacheable. Once we add support for VT-d, we
// will need to make this more granular to ensure that we mimic the same
// cache type that the actual hardware states for any pass-through devices.
//

bool
mtrr_handler::handle_rdmsr_0x000000FE(
    vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 1;
    return true;
}

bool
mtrr_handler::handle_wrmsr_0x000000FE(
    vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0xFE is not supported");
    return false;
}

bool
mtrr_handler::handle_rdmsr_0x00000200(
    vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x6;
    return true;
}

bool
mtrr_handler::handle_wrmsr_0x00000200(
    vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0x200 is not supported");
    return false;
}

bool
mtrr_handler::handle_rdmsr_0x00000201(
    vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x0;
    return true;
}

bool
mtrr_handler::handle_wrmsr_0x00000201(
    vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0x201 is not supported");
    return false;
}

bool
mtrr_handler::handle_rdmsr_0x000002FF(
    vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_mtrr_def_type;
    return true;
}

bool
mtrr_handler::handle_wrmsr_0x000002FF(
    vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_mtrr_def_type = info.val;
    return true;
}

}
