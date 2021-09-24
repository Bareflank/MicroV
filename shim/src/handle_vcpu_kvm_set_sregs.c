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
 *   @param seg the kvm_segment to get the attribute fields from
 *   @param pmut_attrib the attributes to set
 */
static void
set_kvm_segment_attrib(struct kvm_segment const *const seg, uint64_t *const pmut_attrib) NOEXCEPT
{
    *pmut_attrib = ((uint64_t)0);
    *pmut_attrib |= (((uint64_t)seg->type & ATTRIB_TYPE_MASK) << ATTRIB_TYPE_SHIFT);
    *pmut_attrib |= (((uint64_t)seg->present & ATTRIB_PRESENT_MASK) << ATTRIB_PRESENT_SHIFT);
    *pmut_attrib |= (((uint64_t)seg->dpl & ATTRIB_DPL_MASK) << ATTRIB_DPL_SHIFT);
    *pmut_attrib |= (((uint64_t)seg->db & ATTRIB_DB_MASK) << ATTRIB_DB_SHIFT);
    *pmut_attrib |= (((uint64_t)seg->l & ATTRIB_L_MASK) << ATTRIB_L_SHIFT);
    *pmut_attrib |= (((uint64_t)seg->g & ATTRIB_G_MASK) << ATTRIB_G_SHIFT);
    *pmut_attrib |= (((uint64_t)seg->avl & ATTRIB_AVL_MASK) << ATTRIB_AVL_SHIFT);
    *pmut_attrib |= (((uint64_t)seg->s & ATTRIB_S_MASK) << ATTRIB_S_SHIFT);
}

/**
 * <!-- description -->
 *   @brief Handles the register list portion of the kvm_set_sregs IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD static int64_t
handle_reg_list(struct shim_vcpu_t const *const vcpu, struct kvm_sregs const *const args) NOEXCEPT
{
    struct mv_rdl_entry_t const *mut_src_entry;
    struct mv_rdl_entry_t *pmut_mut_dst_entry;

    struct mv_rdl_t *const pmut_rdl = (struct mv_rdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_rdl);

    pmut_rdl->num_entries = ((uint64_t)0);
    while (1) {
        platform_expects(pmut_rdl->num_entries < MV_RDL_MAX_ENTRIES);

        mut_src_entry = &g_reg_rdl.entries[pmut_rdl->num_entries];
        pmut_mut_dst_entry = &pmut_rdl->entries[pmut_rdl->num_entries];

        pmut_mut_dst_entry->reg = mut_src_entry->reg;
        switch ((int32_t)pmut_mut_dst_entry->reg) {
            case mv_reg_t_es_selector: {
                pmut_mut_dst_entry->val = (uint64_t)args->es.selector;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_es_base: {
                pmut_mut_dst_entry->val = args->es.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_es_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->es.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_es_attrib: {
                set_kvm_segment_attrib(&args->es, &pmut_mut_dst_entry->val);
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_cs_selector: {
                pmut_mut_dst_entry->val = (uint64_t)args->cs.selector;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_cs_base: {
                pmut_mut_dst_entry->val = args->cs.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_cs_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->cs.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_cs_attrib: {
                set_kvm_segment_attrib(&args->cs, &pmut_mut_dst_entry->val);
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ss_selector: {
                pmut_mut_dst_entry->val = (uint64_t)args->ss.selector;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ss_base: {
                pmut_mut_dst_entry->val = args->ss.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ss_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->ss.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ss_attrib: {
                set_kvm_segment_attrib(&args->ss, &pmut_mut_dst_entry->val);
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ds_selector: {
                pmut_mut_dst_entry->val = (uint64_t)args->ds.selector;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ds_base: {
                pmut_mut_dst_entry->val = args->ds.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ds_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->ds.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ds_attrib: {
                set_kvm_segment_attrib(&args->ds, &pmut_mut_dst_entry->val);
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_gs_selector: {
                pmut_mut_dst_entry->val = (uint64_t)args->gs.selector;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_gs_base: {
                pmut_mut_dst_entry->val = args->gs.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_gs_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->gs.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_gs_attrib: {
                set_kvm_segment_attrib(&args->gs, &pmut_mut_dst_entry->val);
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_fs_selector: {
                pmut_mut_dst_entry->val = (uint64_t)args->fs.selector;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_fs_base: {
                pmut_mut_dst_entry->val = args->fs.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_fs_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->fs.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_fs_attrib: {
                set_kvm_segment_attrib(&args->fs, &pmut_mut_dst_entry->val);
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ldtr_selector: {
                pmut_mut_dst_entry->val = (uint64_t)args->ldt.selector;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ldtr_base: {
                pmut_mut_dst_entry->val = args->ldt.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ldtr_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->ldt.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_ldtr_attrib: {
                set_kvm_segment_attrib(&args->ldt, &pmut_mut_dst_entry->val);
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_tr_selector: {
                pmut_mut_dst_entry->val = (uint64_t)args->tr.selector;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_tr_base: {
                pmut_mut_dst_entry->val = args->tr.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_tr_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->tr.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_tr_attrib: {
                set_kvm_segment_attrib(&args->tr, &pmut_mut_dst_entry->val);
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_gdtr_base: {
                pmut_mut_dst_entry->val = args->gdt.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_gdtr_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->gdt.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_idtr_base: {
                pmut_mut_dst_entry->val = args->idt.base;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_idtr_limit: {
                pmut_mut_dst_entry->val = (uint64_t)args->idt.limit;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_cr0: {
                pmut_mut_dst_entry->val = args->cr0;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_cr2: {
                pmut_mut_dst_entry->val = args->cr2;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_cr3: {
                pmut_mut_dst_entry->val = args->cr3;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_cr4: {
                pmut_mut_dst_entry->val = args->cr4;
                ++pmut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_cr8: {
                pmut_mut_dst_entry->val = args->cr8;
                ++pmut_rdl->num_entries;
                continue;
            }

            default: {
                break;
            }
        }

        break;
    }

    if (mv_vs_op_reg_set_list(g_mut_hndl, vcpu->vsid)) {
        bferror("mv_vs_op_reg_set_list failed");
        return SHIM_FAILURE;
    }

    return SHIM_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Handles the MSR list portion of the kvm_set_sregs IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD static int64_t
handle_msr_list(struct shim_vcpu_t const *const vcpu, struct kvm_sregs const *const args) NOEXCEPT
{
    struct mv_rdl_entry_t const *mut_src_entry;
    struct mv_rdl_entry_t *pmut_mut_dst_entry;

    struct mv_rdl_t *const pmut_rdl = (struct mv_rdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_rdl);

    pmut_rdl->num_entries = ((uint64_t)0);
    while (1) {
        platform_expects(pmut_rdl->num_entries < MV_RDL_MAX_ENTRIES);

        mut_src_entry = &g_msr_rdl.entries[pmut_rdl->num_entries];
        pmut_mut_dst_entry = &pmut_rdl->entries[pmut_rdl->num_entries];

        pmut_mut_dst_entry->reg = mut_src_entry->reg;
        switch (pmut_mut_dst_entry->reg) {
            case EFER_REG: {
                pmut_mut_dst_entry->val = (uint64_t)args->efer;
                ++pmut_rdl->num_entries;
                continue;
            }

            case APIC_BASE_REG: {
                pmut_mut_dst_entry->val = (uint64_t)args->apic_base;
                ++pmut_rdl->num_entries;
                continue;
            }

            default: {
                break;
            }
        }

        break;
    }

    if (mv_vs_op_msr_set_list(g_mut_hndl, vcpu->vsid)) {
        bferror("mv_vs_op_msr_set_list failed");
        return SHIM_FAILURE;
    }

    return SHIM_SUCCESS;
}

#if 0

/**
 * <!-- description -->
 *   @brief Handles the interrupt bitmap list portion of the kvm_set_sregs
 *     IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD static int64_t
handle_interrupt_bitmap(
    struct shim_vcpu_t const *const vcpu, struct kvm_sregs const *const args) NOEXCEPT
{
    (void)vcpu;
    (void)args;

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
 *   @brief Handles the execution of kvm_set_sregs.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_set_sregs(
    struct shim_vcpu_t const *const vcpu, struct kvm_sregs const *const args) NOEXCEPT
{
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != vcpu);
    platform_expects(NULL != args);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }

    if (handle_reg_list(vcpu, args)) {
        bferror("handle_reg_list failed");
        return SHIM_FAILURE;
    }

    if (handle_msr_list(vcpu, args)) {
        bferror("handle_msr_list failed");
        return SHIM_FAILURE;
    }

    // if (handle_interrupt_bitmap(vcpu, args)) {
    //     bferror("handle_interrupt_bitmap failed");
    //     return SHIM_FAILURE;
    // }

    return SHIM_SUCCESS;
}
