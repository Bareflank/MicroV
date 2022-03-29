/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <debug.h>
#include <detect_hypervisor.h>
#include <g_mut_hndl.h>
#include <kvm_dtable.h>
#include <kvm_segment.h>
#include <kvm_sregs.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <mv_types.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vcpu_t.h>

/** @brief stores the structure of the RDL we will send to MicroV */
static struct mv_rdl_t const g_reg_rdl = {
    .reg0 = ((uint64_t)0),
    .reg1 = ((uint64_t)0),
    .reg2 = ((uint64_t)0),
    .reg3 = ((uint64_t)0),
    .reg4 = ((uint64_t)0),
    .reg5 = ((uint64_t)0),
    .reg6 = ((uint64_t)0),
    .reg7 = ((uint64_t)0),
    .reserved1 = ((uint64_t)0),
    .reserved2 = ((uint64_t)0),
    .reserved3 = ((uint64_t)0),
    .num_entries = ((uint64_t)0),

    {
        /** es segment registers (selector and GDT fields) */
        {(uint64_t)mv_reg_t_es_selector, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_es_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_es_limit, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_es_attrib, ((uint64_t)0)},

        /** es segment registers (selector and GDT fields) */
        {(uint64_t)mv_reg_t_cs_selector, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_cs_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_cs_limit, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_cs_attrib, ((uint64_t)0)},

        /** es segment registers (selector and GDT fields) */
        {(uint64_t)mv_reg_t_ss_selector, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_ss_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_ss_limit, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_ss_attrib, ((uint64_t)0)},

        /** es segment registers (selector and GDT fields) */
        {(uint64_t)mv_reg_t_ds_selector, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_ds_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_ds_limit, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_ds_attrib, ((uint64_t)0)},

        /** es segment registers (selector and GDT fields) */
        {(uint64_t)mv_reg_t_fs_selector, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_fs_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_fs_limit, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_fs_attrib, ((uint64_t)0)},

        /** es segment registers (selector and GDT fields) */
        {(uint64_t)mv_reg_t_gs_selector, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_gs_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_gs_limit, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_gs_attrib, ((uint64_t)0)},

        /** es segment registers (selector and GDT fields) */
        {(uint64_t)mv_reg_t_ldtr_selector, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_ldtr_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_ldtr_limit, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_ldtr_attrib, ((uint64_t)0)},

        /** es segment registers (selector and GDT fields) */
        {(uint64_t)mv_reg_t_tr_selector, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_tr_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_tr_limit, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_tr_attrib, ((uint64_t)0)},

        /** GDT register fields */
        {(uint64_t)mv_reg_t_gdtr_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_gdtr_limit, ((uint64_t)0)},

        /** IDT register fields */
        {(uint64_t)mv_reg_t_idtr_base, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_idtr_limit, ((uint64_t)0)},

        /** control registers */
        {(uint64_t)mv_reg_t_cr0, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_cr2, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_cr3, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_cr4, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_cr8, ((uint64_t)0)},
    }};

/** @brief stores the structure of the RDL we will send to MicroV */
static struct mv_rdl_t const g_msr_rdl = {
    .reg0 = ((uint64_t)0),
    .reg1 = ((uint64_t)0),
    .reg2 = ((uint64_t)0),
    .reg3 = ((uint64_t)0),
    .reg4 = ((uint64_t)0),
    .reg5 = ((uint64_t)0),
    .reg6 = ((uint64_t)0),
    .reg7 = ((uint64_t)0),
    .reserved1 = ((uint64_t)0),
    .reserved2 = ((uint64_t)0),
    .reserved3 = ((uint64_t)0),
    .num_entries = ((uint64_t)0),

    {
        {EFER_REG, ((uint64_t)0)},
        {APIC_BASE_REG, ((uint64_t)0)},
    }};

/**
 * <!-- description -->
 *   @brief Sets a KVM segment struct's attribute fields
 *
 * <!-- inputs/outputs -->
 *   @param attrib the attributes to use
 *   @param pmut_seg the kvm_segment to set the attribute fields for
 */
static void
set_kvm_segment_attrib(uint64_t const attrib, struct kvm_segment *const pmut_seg) NOEXCEPT
{
    pmut_seg->type = (uint8_t)((attrib >> ATTRIB_TYPE_SHIFT) & ATTRIB_TYPE_MASK);
    pmut_seg->present = (uint8_t)((attrib >> ATTRIB_PRESENT_SHIFT) & ATTRIB_PRESENT_MASK);
    pmut_seg->dpl = (uint8_t)((attrib >> ATTRIB_DPL_SHIFT) & ATTRIB_DPL_MASK);
    pmut_seg->db = (uint8_t)((attrib >> ATTRIB_DB_SHIFT) & ATTRIB_DB_MASK);
    pmut_seg->l = (uint8_t)((attrib >> ATTRIB_L_SHIFT) & ATTRIB_L_MASK);
    pmut_seg->g = (uint8_t)((attrib >> ATTRIB_G_SHIFT) & ATTRIB_G_MASK);
    pmut_seg->avl = (uint8_t)((attrib >> ATTRIB_AVL_SHIFT) & ATTRIB_AVL_MASK);
    pmut_seg->s = (uint8_t)((attrib >> ATTRIB_S_SHIFT) & ATTRIB_S_MASK);
}

/**
 * <!-- description -->
 *   @brief Handles the register list portion of the kvm_get_sregs IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD static int64_t
handle_reg_list(struct shim_vcpu_t const *const vcpu, struct kvm_sregs *const pmut_args) NOEXCEPT
{
    int64_t mut_ret = SHIM_FAILURE;
    uint64_t mut_i;
    struct mv_rdl_entry_t const *mut_src_entry;
    struct mv_rdl_entry_t *pmut_mut_dst_entry;

    struct mv_rdl_t *const pmut_rdl = (struct mv_rdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_rdl);

    pmut_rdl->num_entries = ((uint64_t)0);
    while (1) {
        platform_expects(pmut_rdl->num_entries < MV_RDL_MAX_ENTRIES);

        mut_src_entry = &g_reg_rdl.entries[pmut_rdl->num_entries];
        pmut_mut_dst_entry = &pmut_rdl->entries[pmut_rdl->num_entries];

        if (((uint64_t)0) == mut_src_entry->reg) {
            break;
        }

        pmut_mut_dst_entry->reg = mut_src_entry->reg;
        ++pmut_rdl->num_entries;
    }

    shared_page_for_curent_pp__before_mv_op(pmut_rdl);
    if (mv_vs_op_reg_get_list(g_mut_hndl, vcpu->vsid)) {
        bferror("mv_vs_op_reg_get_list failed");
        shared_page_for_curent_pp__after_mv_op(pmut_rdl);
        goto release_shared_page;
    }
    shared_page_for_curent_pp__after_mv_op(pmut_rdl);

    if (pmut_rdl->num_entries >= MV_RDL_MAX_ENTRIES) {
        bferror("the RDL's num_entries is no longer valid");
        goto release_shared_page;
    }

    for (mut_i = ((uint64_t)0); mut_i < pmut_rdl->num_entries; ++mut_i) {
        mut_src_entry = &pmut_rdl->entries[mut_i];

        switch ((int32_t)mut_src_entry->reg) {
            case mv_reg_t_es_selector: {
                pmut_args->es.selector = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_es_base: {
                pmut_args->es.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_es_limit: {
                pmut_args->es.limit = (uint32_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_es_attrib: {
                set_kvm_segment_attrib(mut_src_entry->val, &pmut_args->es);
                continue;
            }

            case mv_reg_t_cs_selector: {
                pmut_args->cs.selector = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_cs_base: {
                pmut_args->cs.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_cs_limit: {
                pmut_args->cs.limit = (uint32_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_cs_attrib: {
                set_kvm_segment_attrib(mut_src_entry->val, &pmut_args->cs);
                continue;
            }

            case mv_reg_t_ss_selector: {
                pmut_args->ss.selector = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_ss_base: {
                pmut_args->ss.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_ss_limit: {
                pmut_args->ss.limit = (uint32_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_ss_attrib: {
                set_kvm_segment_attrib(mut_src_entry->val, &pmut_args->ss);
                continue;
            }

            case mv_reg_t_ds_selector: {
                pmut_args->ds.selector = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_ds_base: {
                pmut_args->ds.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_ds_limit: {
                pmut_args->ds.limit = (uint32_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_ds_attrib: {
                set_kvm_segment_attrib(mut_src_entry->val, &pmut_args->ds);
                continue;
            }

            case mv_reg_t_gs_selector: {
                pmut_args->gs.selector = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_gs_base: {
                pmut_args->gs.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_gs_limit: {
                pmut_args->gs.limit = (uint32_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_gs_attrib: {
                set_kvm_segment_attrib(mut_src_entry->val, &pmut_args->gs);
                continue;
            }

            case mv_reg_t_fs_selector: {
                pmut_args->fs.selector = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_fs_base: {
                pmut_args->fs.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_fs_limit: {
                pmut_args->fs.limit = (uint32_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_fs_attrib: {
                set_kvm_segment_attrib(mut_src_entry->val, &pmut_args->fs);
                continue;
            }

            case mv_reg_t_ldtr_selector: {
                pmut_args->ldt.selector = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_ldtr_base: {
                pmut_args->ldt.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_ldtr_limit: {
                pmut_args->ldt.limit = (uint32_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_ldtr_attrib: {
                set_kvm_segment_attrib(mut_src_entry->val, &pmut_args->ldt);
                continue;
            }

            case mv_reg_t_tr_selector: {
                pmut_args->tr.selector = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_tr_base: {
                pmut_args->tr.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_tr_limit: {
                pmut_args->tr.limit = (uint32_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_tr_attrib: {
                set_kvm_segment_attrib(mut_src_entry->val, &pmut_args->tr);
                continue;
            }

            case mv_reg_t_gdtr_base: {
                pmut_args->gdt.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_gdtr_limit: {
                pmut_args->gdt.limit = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_idtr_base: {
                pmut_args->idt.base = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_idtr_limit: {
                pmut_args->idt.limit = (uint16_t)mut_src_entry->val;
                continue;
            }

            case mv_reg_t_cr0: {
                pmut_args->cr0 = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_cr2: {
                pmut_args->cr2 = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_cr3: {
                pmut_args->cr3 = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_cr4: {
                pmut_args->cr4 = mut_src_entry->val;
                continue;
            }

            case mv_reg_t_cr8: {
                pmut_args->cr8 = mut_src_entry->val;
                continue;
            }

            default: {
                break;
            }
        }

        if (((uint64_t)0) != mut_src_entry->reg) {
            bferror("unknown mv_reg_t returned by MicroV");
            goto release_shared_page;
        }

        bferror("MicroV returned a num_entries that does not match the shim's");
        goto release_shared_page;
    }

    mut_ret = SHIM_SUCCESS;

release_shared_page:
    release_shared_page_for_current_pp(pmut_rdl);

    return mut_ret;
}

/**
 * <!-- description -->
 *   @brief Handles the MSR list portion of the kvm_get_sregs IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD static int64_t
handle_msr_list(struct shim_vcpu_t const *const vcpu, struct kvm_sregs *const pmut_args) NOEXCEPT
{
    int64_t mut_ret = SHIM_FAILURE;
    uint64_t mut_i;
    struct mv_rdl_entry_t const *mut_src_entry;
    struct mv_rdl_entry_t *pmut_mut_dst_entry;

    struct mv_rdl_t *const pmut_rdl = (struct mv_rdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_rdl);

    pmut_rdl->num_entries = ((uint64_t)0);
    while (1) {
        platform_expects(pmut_rdl->num_entries < MV_RDL_MAX_ENTRIES);

        mut_src_entry = &g_msr_rdl.entries[pmut_rdl->num_entries];
        pmut_mut_dst_entry = &pmut_rdl->entries[pmut_rdl->num_entries];

        if (((uint64_t)0) == mut_src_entry->reg) {
            break;
        }

        pmut_mut_dst_entry->reg = mut_src_entry->reg;
        ++pmut_rdl->num_entries;
    }

    shared_page_for_curent_pp__before_mv_op(pmut_rdl);
    if (mv_vs_op_msr_get_list(g_mut_hndl, vcpu->vsid)) {
        bferror("mv_vs_op_msr_get_list failed");
        shared_page_for_curent_pp__after_mv_op(pmut_rdl);
        goto release_shared_page;
    }
    shared_page_for_curent_pp__after_mv_op(pmut_rdl);

    if (pmut_rdl->num_entries >= MV_RDL_MAX_ENTRIES) {
        bferror("the RDL's num_entries is no longer valid");
        goto release_shared_page;
    }

    for (mut_i = ((uint64_t)0); mut_i < pmut_rdl->num_entries; ++mut_i) {
        mut_src_entry = &pmut_rdl->entries[mut_i];

        switch (mut_src_entry->reg) {
            case EFER_REG: {
                pmut_args->efer = mut_src_entry->val;
                continue;
            }

            case APIC_BASE_REG: {
                pmut_args->apic_base = mut_src_entry->val;
                continue;
            }

            default: {
                break;
            }
        }

        if (((uint64_t)0) != mut_src_entry->reg) {
            bferror("unknown MSR returned by MicroV");
            goto release_shared_page;
        }

        bferror("MicroV returned a num_entries that does not match the shim's");
        goto release_shared_page;
    }

    mut_ret = SHIM_SUCCESS;

release_shared_page:
    release_shared_page_for_current_pp(pmut_rdl);

    return mut_ret;
}

#if 0

/**
 * <!-- description -->
 *   @brief Handles the interrupt bitmap list portion of the kvm_get_sregs
 *     IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD static int64_t
handle_interrupt_bitmap(
    struct shim_vcpu_t const *const vcpu, struct kvm_sregs *const pmut_args) NOEXCEPT
{
    (void)vcpu;
    (void)pmut_args;

    /** TODO
     * - We need to implement this. To support this, we will likely need
     *   to add a hypercall to MicroV to get this data, so the spec will
     *   have to be modified.
     */

    return SHIM_SUCCESS;
}

#endif

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_get_sregs.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_get_sregs(
    struct shim_vcpu_t const *const vcpu, struct kvm_sregs *const pmut_args) NOEXCEPT
{
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != vcpu);
    platform_expects(NULL != pmut_args);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }

    if (handle_reg_list(vcpu, pmut_args)) {
        bferror("handle_reg_list failed");
        return SHIM_FAILURE;
    }

    if (handle_msr_list(vcpu, pmut_args)) {
        bferror("handle_msr_list failed");
        return SHIM_FAILURE;
    }

    // if (handle_interrupt_bitmap(vcpu, pmut_args)) {
    //     bferror("handle_interrupt_bitmap failed");
    //     return SHIM_FAILURE;
    // }

    return SHIM_SUCCESS;
}
