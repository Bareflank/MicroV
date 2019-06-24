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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <bfgsl.h>
#include <bfarch.h>
#include <bfvcpuid.h>
#include <bfobject.h>
#include <bfexports.h>
#include <bfsupport.h>
#include <bfcallonce.h>
#include <bfexception.h>

#include <vcpu/vcpu_manager.h>
#include <debug/debug_ring/debug_ring.h>
#include <memory_manager/memory_manager.h>
#include <memory_manager/arch/x64/cr3/mmap.h>

#include <cstring>
#include <memory>
#include <xue.h>

static bfn::once_flag g_init_flag;

void
WEAK_SYM global_init()
{ }

#ifdef BF_INTEL_X64
#include <hve/arch/intel_x64/vcpu.h>

void
WEAK_SYM vcpu_init_nonroot(vcpu_t *vcpu)
{ bfignored(vcpu); }

void
WEAK_SYM vcpu_fini_nonroot(vcpu_t *vcpu)
{ bfignored(vcpu); }

#endif

struct xue g_xue{};
struct xue_ops g_xue_ops{};

extern "C" int64_t
private_init_xue(struct xue *xue) noexcept
{
    using attr_t = bfvmm::x64::cr3::mmap::attr_type;
    using mem_t = bfvmm::x64::cr3::mmap::memory_type;

    /*
     * Copy the kernel's xue instance by value. This invalidates
     * every pointer field, so we have to remap them into our
     * address space below.
     */
    memcpy(&g_xue, xue, sizeof(*xue));
    xue_init_ops(&g_xue, &g_xue_ops);

    auto mmio_hva = g_mm->alloc_map(xue->xhc_mmio_size);
    for (auto i = 0; i < xue->xhc_mmio_size; i += XUE_PAGE_SIZE) {
        g_cr3->map_4k(reinterpret_cast<uint64_t>(mmio_hva) + i,
                      xue->xhc_mmio_phys + i,
                      attr_t::read_write,
                      mem_t::uncacheable);
    }

    g_xue.xhc_mmio = reinterpret_cast<uint8_t *>(mmio_hva);

    const struct xue_dbc_reg *kreg = xue->dbc_reg;
    const struct xue_dbc_ctx *kctx = xue->dbc_ctx;

    uint64_t ctx_hpa = kreg->cp;
    uint64_t erst_hpa = kreg->erstba;
    uint64_t etrb_hpa = kreg->erdp;
    uint64_t otrb_hpa = ((uint64_t)kctx->ep_out[3] << 32) | kctx->ep_out[2];
    uint64_t itrb_hpa = ((uint64_t)kctx->ep_in[3] << 32) | kctx->ep_in[2];

    etrb_hpa &= ~0xFFFULL;
    otrb_hpa &= ~0xFFFULL;
    itrb_hpa &= ~0xFFFULL;

    static_assert(XUE_PAGE_SIZE == BAREFLANK_PAGE_SIZE);

    auto ctx = g_mm->alloc_map(XUE_PAGE_SIZE);
    auto erst = g_mm->alloc_map(XUE_PAGE_SIZE);
    auto etrb = g_mm->alloc_map(XUE_TRB_RING_CAP * sizeof(struct xue_trb));
    auto otrb = g_mm->alloc_map(XUE_TRB_RING_CAP * sizeof(struct xue_trb));
    auto itrb = g_mm->alloc_map(XUE_TRB_RING_CAP * sizeof(struct xue_trb));

    g_cr3->map_4k(ctx, ctx_hpa);
    g_cr3->map_4k(erst, erst_hpa);

    for (auto i = 0; i < XUE_TRB_RING_CAP * sizeof(struct xue_trb); i += 4096) {
        g_cr3->map_4k((uint64_t)etrb + i, etrb_hpa + i);
        g_cr3->map_4k((uint64_t)otrb + i, otrb_hpa + i);
        g_cr3->map_4k((uint64_t)itrb + i, itrb_hpa + i);
    }

    g_xue.dbc_ctx = (struct xue_dbc_ctx *)ctx;
    g_xue.dbc_erst = (struct xue_erst_segment *)erst;
    g_xue.dbc_ering.trb = (struct xue_trb *)etrb;
    g_xue.dbc_oring.trb = (struct xue_trb *)otrb;
    g_xue.dbc_iring.trb = (struct xue_trb *)itrb;

    auto out_work = g_mm->alloc_map(XUE_WORK_RING_CAP);
    for (auto i = 0; i < XUE_WORK_RING_CAP; i += XUE_PAGE_SIZE) {
        g_cr3->map_4k((uint64_t)out_work + i, g_xue.dbc_owork.phys + i);
    }

    g_xue.dbc_owork.buf = (uint8_t *)out_work;
    g_xue.dbc_reg = (struct xue_dbc_reg *)((uint64_t)mmio_hva +
                                           xue->xhc_dbc_offset);
    return ENTRY_SUCCESS;
}

extern "C" int64_t
private_add_md(struct memory_descriptor *md) noexcept
{
    return guard_exceptions(MEMORY_MANAGER_FAILURE, [&] {

        auto virt = static_cast<bfvmm::memory_manager::integer_pointer>(md->virt);
        auto phys = static_cast<bfvmm::memory_manager::integer_pointer>(md->phys);
        auto type = static_cast<bfvmm::memory_manager::attr_type>(md->type);

        g_mm->add_md(virt, phys, type);
    });
}

extern "C" int64_t
private_set_rsdp(uintptr_t rsdp) noexcept
{
    g_rsdp = rsdp;
    return ENTRY_SUCCESS;
}

extern "C" int64_t
private_uefi_boot(bool uefi_boot) noexcept
{
    g_uefi_boot = uefi_boot;
    return ENTRY_SUCCESS;
}

extern "C" int64_t
private_init_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_START_FAILED, [&]() {

        bfn::call_once(g_init_flag, global_init);

        g_vcm->create(arg, nullptr);

        auto vcpu = g_vcm->get<vcpu_t *>(arg);
        vcpu->load();

        vcpu_init_nonroot(vcpu);
        vcpu->run();

        ::x64::cpuid::get(0x4BF00010, 0, 0, 0);
        ::x64::cpuid::get(0x4BF00011, 0, 0, 0);

        return ENTRY_SUCCESS;
    });
}

extern "C" int64_t
private_fini_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_STOP_FAILED, [&]() {

        ::x64::cpuid::get(0x4BF00020, 0, 0, 0);
        ::x64::cpuid::get(0x4BF00021, 0, 0, 0);

        auto vcpu = g_vcm->get<vcpu_t *>(arg);
        vcpu->load();

        vcpu->hlt();
        vcpu_fini_nonroot(vcpu);

        g_vcm->destroy(arg, nullptr);

        return ENTRY_SUCCESS;
    });
}

extern "C" int64_t
bfmain(uintptr_t request, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    bfignored(arg2);
    bfignored(arg3);

    switch (request) {
        case BF_REQUEST_INIT:
            return ENTRY_SUCCESS;

        case BF_REQUEST_FINI:
            return ENTRY_SUCCESS;

        case BF_REQUEST_ADD_MDL:
            return private_add_md(reinterpret_cast<memory_descriptor *>(arg1));

        case BF_REQUEST_SET_RSDP:
            return private_set_rsdp(arg1);

        case BF_REQUEST_GET_DRR:
            return get_drr(arg1, reinterpret_cast<debug_ring_resources_t **>(arg2));

        case BF_REQUEST_VMM_INIT:
            return private_init_vmm(arg1);

        case BF_REQUEST_VMM_FINI:
            return private_fini_vmm(arg1);

        case BF_REQUEST_INIT_XUE:
            return private_init_xue((struct xue *)arg1);

        case BF_REQUEST_UEFI_BOOT:
            return private_uefi_boot((bool)arg1);

        default:
            break;
    }

    return ENTRY_ERROR_UNKNOWN;
}
