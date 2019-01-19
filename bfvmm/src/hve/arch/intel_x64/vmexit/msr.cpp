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
    bfvmm::intel_x64::rdmsr_handler::handler_delegate_t::create<msr_handler, &msr_handler::a>(this)

#define make_wrmsr_delegate(a)                                                  \
    bfvmm::intel_x64::wrmsr_handler::handler_delegate_t::create<msr_handler, &msr_handler::a>(this)

#define ADD_WRMSR_HANDLER(a,b)                                                  \
    m_vcpu->add_wrmsr_handler(                                                  \
        a, make_wrmsr_delegate(b)                                               \
    );

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

    vcpu->add_run_delegate(
        bfvmm::vcpu::run_delegate_t::create<msr_handler, &msr_handler::isolate_msr__on_run>(this)
    );

    vcpu->add_exit_handler(
        handler_delegate_t::create<msr_handler, &msr_handler::isolate_msr__on_exit>(this)
    );

    if (vcpu->is_domU()) {
        vcpu->trap_on_all_rdmsr_accesses();
        vcpu->trap_on_all_wrmsr_accesses();
    }

    this->isolate_msr(::x64::msrs::ia32_star::addr);
    this->isolate_msr(::x64::msrs::ia32_lstar::addr);
    this->isolate_msr(::x64::msrs::ia32_cstar::addr);
    this->isolate_msr(::x64::msrs::ia32_fmask::addr);
    this->isolate_msr(::x64::msrs::ia32_kernel_gs_base::addr);

    if (vcpu->is_dom0()) {
        return;
    }

    vcpu->pass_through_msr_access(::x64::msrs::ia32_pat::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_efer::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_fs_base::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_gs_base::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_sysenter_cs::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_sysenter_eip::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_sysenter_esp::addr);

    EMULATE_MSR(0x00000034, handle_rdmsr_0x00000034, handle_wrmsr_0x00000034);
    EMULATE_MSR(0x000000CE, handle_rdmsr_0x000000CE, handle_wrmsr_0x000000CE);
    EMULATE_MSR(0x00000140, handle_rdmsr_0x00000140, handle_wrmsr_0x00000140);
    EMULATE_MSR(0x000001A0, handle_rdmsr_0x000001A0, handle_wrmsr_0x000001A0);
    EMULATE_MSR(0x00000606, handle_rdmsr_0x00000606, handle_wrmsr_0x00000606);
    EMULATE_MSR(0x0000064E, handle_rdmsr_0x0000064E, handle_wrmsr_0x0000064E);
    EMULATE_MSR(0xC0000103, handle_rdmsr_0xC0000103, handle_wrmsr_0xC0000103);
}

// -----------------------------------------------------------------------------
// Isolate MSR Functions
// -----------------------------------------------------------------------------

void
msr_handler::isolate_msr(uint32_t msr)
{
    m_vcpu->pass_through_rdmsr_access(msr);
    ADD_WRMSR_HANDLER(msr, isolate_msr__on_write);

    if (m_vcpu->is_dom0()) {
        m_msrs[msr] = ::x64::msrs::get(msr);
    }
}

void
msr_handler::isolate_msr__on_run(bfobject *obj)
{
    // Note:
    //
    // Note that this function is executed on every entry, so we want to
    // limit what we are doing here. This is an expensive function to
    // execute.

    // Note:
    //
    // We don't use the MSR load/store pages as Intel actually states not to
    // use them so that you can use lazy load/store. To make this work we have
    // 4 different types of MSRs that we have to deal with:
    //
    // - Type 1 (Pass-Through):
    //
    //   This type of MSR is being saved and restored my the VMCS for us.
    //   As a result, these are MSRs that the VMM can actually use if it wants,
    //   and these MSRs are the reason why we have to emulate read/write access
    //   to the MSRs as we need to ensure that all pass-through MSRs are saved
    //   and restored to the VMCS and not the actual hardware.
    //
    // - Type 2 (Isolated):
    //
    //   These are MSRs that are just like Pass-Through, but we do not have
    //   a VMCS field to load/store them (thank you Intel). For these MSRs,
    //   we have to mimic the VMCS functionality. Intel provides a load/store
    //   bitmap to handle this, but we use the lazy load algorithm that is
    //   stated in the SDM to improve performance. What this means is that we
    //   only load/store these MSRs on world switches. These MSRs have to be
    //   saved/loaded for both dom0 and all domUs to work (just like what
    //   the VMCS is doing for us)
    //
    // - Type 3 (Emulated):
    //
    //   Emulated MSRs are MSRs that don't actually exist. That is, a domU can
    //   read/write to them, but the value is never written back to actual
    //   hardware, but instead is read/written to a fake value that is stored
    //   in memory in this class by the hypervisor. These types of MSRs are
    //   usually init/reporting MSRs
    //
    // - Type 4 (Costly):
    //
    //   There is only one of these MSRs and that is the kernel_gs_base. There
    //   is no way to watch a store to this MSR as swapgs does not trap
    //   (thanks again Intel), and as a result, we treat this MSR just like an
    //   isolated MSR, but we have to take an added step and save its value on
    //   every single VM exit.
    //

    if (obj != nullptr) {
        for (const auto &msr : m_msrs) {
            ::x64::msrs::set(msr.first, msr.second);
        }
    }
}

bool
msr_handler::isolate_msr__on_exit(
    gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);

    // Note:
    //
    // Note that this function is executed on every exit, so we want to
    // limit what we are doing here. This is an expensive function to
    // execute.
    //

    using namespace ::x64::msrs;
    using namespace ::intel_x64::vmcs;

    m_msrs[ia32_kernel_gs_base::addr] = ia32_kernel_gs_base::get();

    return false;
}

bool
msr_handler::isolate_msr__on_write(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_msrs[info.msr] = info.val;
    return true;
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
msr_handler::handle_rdmsr_0x00000034(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
msr_handler::handle_wrmsr_0x00000034(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0x34 is not supported");
    return true;
}
bool
msr_handler::handle_rdmsr_0x000000CE(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val =
        emulate_rdmsr(
            gsl::narrow_cast<::x64::msrs::field_type>(vcpu->rcx())
        );

    info.val &= 0xFF00;
    return true;
}

bool
msr_handler::handle_wrmsr_0x000000CE(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0xCE is not supported");
    return false;
}

bool
msr_handler::handle_rdmsr_0x00000140(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_vcpu->inject_exception(13, 0);
    info.ignore_write = true;
    info.ignore_advance = true;

    return true;
}

bool
msr_handler::handle_wrmsr_0x00000140(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0x140 is not supported");
    return true;
}

bool
msr_handler::handle_rdmsr_0x000001A0(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val =
        emulate_rdmsr(
            gsl::narrow_cast<::x64::msrs::field_type>(vcpu->rcx())
        );

    info.val &= 0x1801;
    return true;
}

bool
msr_handler::handle_wrmsr_0x000001A0(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0x1A0 is not supported");
    return false;
}

bool
msr_handler::handle_rdmsr_0x00000606(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_vcpu->inject_exception(13, 0);
    info.ignore_write = true;
    info.ignore_advance = true;

    return true;
}

bool
msr_handler::handle_wrmsr_0x00000606(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0x606 is not supported");
    return true;
}

bool
msr_handler::handle_rdmsr_0x0000064E(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
msr_handler::handle_wrmsr_0x0000064E(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(info);

    vcpu->halt("wrmsr to 0x64E is not supported");
    return true;
}

bool
msr_handler::handle_rdmsr_0xC0000103(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_0xC0000103 & 0xFFFFFFFF;
    return true;
}

bool
msr_handler::handle_wrmsr_0xC0000103(
    gsl::not_null<vcpu_t *> vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_0xC0000103 = info.val & 0xFFFFFFFF;
    return true;
}

}
