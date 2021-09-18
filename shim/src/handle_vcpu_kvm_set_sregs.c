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
#include <g_mut_hndl.h>
#include <kvm_dtable.h>
#include <kvm_segment.h>
#include <kvm_sregs.h>
#include <kvm_sregs_idxs.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vcpu_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_set_sregs.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu pass the vsid to hypercall
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_set_sregs(
    struct shim_vcpu_t *const pmut_vcpu, struct kvm_sregs *const pmut_args) NOEXCEPT
{
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);

    struct mv_rdl_t *const pmut_reg_rdl = (struct mv_rdl_t *const)shared_page_for_current_pp();
    platform_expects(NULL != pmut_reg_rdl);

    struct mv_rdl_t *const pmut_msr_rdl = (struct mv_rdl_t *const)shared_page_for_current_pp();
    platform_expects(NULL != pmut_msr_rdl);

    pmut_reg_rdl->entries[ES_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_es_selector;
    pmut_reg_rdl->entries[ES_LIMIT_IDX].reg = (uint64_t)mv_reg_t_es_limit;
    pmut_reg_rdl->entries[ES_BASE_IDX].reg = (uint64_t)mv_reg_t_es_base;
    pmut_reg_rdl->entries[ES_ATTRIB_IDX].reg = (uint64_t)mv_reg_t_es_attrib;
    pmut_reg_rdl->entries[CS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_cs_selector;
    pmut_reg_rdl->entries[CS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_cs_limit;
    pmut_reg_rdl->entries[CS_BASE_IDX].reg = (uint64_t)mv_reg_t_cs_base;
    pmut_reg_rdl->entries[CS_ATTRIB_IDX].reg = (uint64_t)mv_reg_t_cs_attrib;
    pmut_reg_rdl->entries[DS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_ds_selector;
    pmut_reg_rdl->entries[DS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_ds_limit;
    pmut_reg_rdl->entries[DS_BASE_IDX].reg = (uint64_t)mv_reg_t_ds_base;
    pmut_reg_rdl->entries[DS_ATTRIB_IDX].reg = (uint64_t)mv_reg_t_ds_attrib;
    pmut_reg_rdl->entries[FS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_fs_selector;
    pmut_reg_rdl->entries[FS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_fs_limit;
    pmut_reg_rdl->entries[FS_BASE_IDX].reg = (uint64_t)mv_reg_t_fs_base;
    pmut_reg_rdl->entries[FS_ATTRIB_IDX].reg = (uint64_t)mv_reg_t_fs_attrib;
    pmut_reg_rdl->entries[GS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_gs_selector;
    pmut_reg_rdl->entries[GS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_gs_limit;
    pmut_reg_rdl->entries[GS_BASE_IDX].reg = (uint64_t)mv_reg_t_gs_base;
    pmut_reg_rdl->entries[GS_ATTRIB_IDX].reg = (uint64_t)mv_reg_t_gs_attrib;
    pmut_reg_rdl->entries[SS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_ss_selector;
    pmut_reg_rdl->entries[SS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_ss_limit;
    pmut_reg_rdl->entries[SS_BASE_IDX].reg = (uint64_t)mv_reg_t_ss_base;
    pmut_reg_rdl->entries[SS_ATTRIB_IDX].reg = (uint64_t)mv_reg_t_ss_attrib;
    pmut_reg_rdl->entries[LDT_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_ldtr_selector;
    pmut_reg_rdl->entries[LDT_LIMIT_IDX].reg = (uint64_t)mv_reg_t_ldtr_limit;
    pmut_reg_rdl->entries[LDT_BASE_IDX].reg = (uint64_t)mv_reg_t_ldtr_base;
    pmut_reg_rdl->entries[LDT_ATTRIB_IDX].reg = (uint64_t)mv_reg_t_ldtr_attrib;
    pmut_reg_rdl->entries[TR_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_tr_selector;
    pmut_reg_rdl->entries[TR_LIMIT_IDX].reg = (uint64_t)mv_reg_t_tr_limit;
    pmut_reg_rdl->entries[TR_BASE_IDX].reg = (uint64_t)mv_reg_t_tr_base;
    pmut_reg_rdl->entries[TR_ATTRIB_IDX].reg = (uint64_t)mv_reg_t_tr_attrib;
    pmut_reg_rdl->entries[GDT_LIMIT_IDX].reg = (uint64_t)mv_reg_t_gdtr_limit;
    pmut_reg_rdl->entries[GDT_BASE_IDX].reg = (uint64_t)mv_reg_t_gdtr_base;
    pmut_reg_rdl->entries[IDT_LIMIT_IDX].reg = (uint64_t)mv_reg_t_idtr_limit;
    pmut_reg_rdl->entries[IDT_BASE_IDX].reg = (uint64_t)mv_reg_t_idtr_base;
    pmut_reg_rdl->entries[CR0_IDX].reg = (uint64_t)mv_reg_t_cr0;
    pmut_reg_rdl->entries[CR2_IDX].reg = (uint64_t)mv_reg_t_cr2;
    pmut_reg_rdl->entries[CR3_IDX].reg = (uint64_t)mv_reg_t_cr3;
    pmut_reg_rdl->entries[CR4_IDX].reg = (uint64_t)mv_reg_t_cr4;
    pmut_reg_rdl->entries[CR8_IDX].reg = (uint64_t)mv_reg_t_cr8;

    pmut_reg_rdl->entries[ES_SELECTOR_IDX].val = (uint64_t)pmut_args->es.selector;
    pmut_reg_rdl->entries[ES_LIMIT_IDX].val = (uint64_t)pmut_args->es.limit;
    pmut_reg_rdl->entries[ES_BASE_IDX].val = (uint64_t)pmut_args->es.base;

    pmut_reg_rdl->entries[ES_ATTRIB_IDX].val = (uint64_t)(
        ((uint64_t)((pmut_args->es.type) << ATTRIB_TYPE_SHIFT)) |
        ((uint64_t)((pmut_args->es.s) << ATTRIB_S_SHIFT)) |
        ((uint64_t)((pmut_args->es.dpl) << ATTRIB_DPL_SHIFT)) |
        ((uint64_t)((pmut_args->es.present) << ATTRIB_PRESENT_SHIFT)) |
        ((uint64_t)((pmut_args->es.avl) << ATTRIB_AVL_SHIFT)) |
        ((uint64_t)((pmut_args->es.l) << ATTRIB_L_SHIFT)) |
        ((uint64_t)((pmut_args->es.g) << ATTRIB_G_SHIFT)) |
        ((uint64_t)((pmut_args->es.db) << ATTRIB_DB_SHIFT)));

    pmut_reg_rdl->entries[CS_SELECTOR_IDX].val = (uint64_t)mv_reg_t_cs_selector;
    pmut_reg_rdl->entries[CS_LIMIT_IDX].val = (uint64_t)mv_reg_t_cs_limit;
    pmut_reg_rdl->entries[CS_BASE_IDX].val = (uint64_t)mv_reg_t_cs_base;
    pmut_reg_rdl->entries[CS_ATTRIB_IDX].val = (uint64_t)(
        (((uint64_t)pmut_args->cs.type) << ATTRIB_TYPE_SHIFT) |
        (((uint64_t)pmut_args->cs.s) << ATTRIB_S_SHIFT) |
        (((uint64_t)pmut_args->cs.dpl) << ATTRIB_DPL_SHIFT) |
        (((uint64_t)pmut_args->cs.present) << ATTRIB_PRESENT_SHIFT) |
        (((uint64_t)pmut_args->cs.avl) << ATTRIB_AVL_SHIFT) |
        (((uint64_t)pmut_args->cs.l) << ATTRIB_L_SHIFT) |
        (((uint64_t)pmut_args->cs.g) << ATTRIB_G_SHIFT) |
        (((uint64_t)pmut_args->cs.db) << ATTRIB_DB_SHIFT));

    /*    pmut_reg_rdl->entries[DS_SELECTOR_IDX].val = (uint64_t)mv_reg_t_ds_selector;
    pmut_reg_rdl->entries[DS_LIMIT_IDX].val = (uint64_t)mv_reg_t_ds_limit;
    pmut_reg_rdl->entries[DS_BASE_IDX].val = (uint64_t)mv_reg_t_ds_base;
    pmut_reg_rdl->entries[DS_ATTRIB_IDX].val = (uint64_t)(
        (pmut_args->ds.type << ATTRIB_TYPE_SHIFT) | (pmut_args->ds.s << ATTRIB_S_SHIFT) |
        (pmut_args->ds.dpl << ATTRIB_DPL_SHIFT) | (pmut_args->ds.present << ATTRIB_PRESENT_SHIFT) |
        (pmut_args->ds.avl << ATTRIB_AVL_SHIFT) | (pmut_args->ds.l << ATTRIB_L_SHIFT) |
        (pmut_args->ds.g << ATTRIB_G_SHIFT) | (pmut_args->ds.db << ATTRIB_DB_SHIFT));

    pmut_reg_rdl->entries[FS_SELECTOR_IDX].val = (uint64_t)mv_reg_t_fs_selector;
    pmut_reg_rdl->entries[FS_LIMIT_IDX].val = (uint64_t)mv_reg_t_fs_limit;
    pmut_reg_rdl->entries[FS_BASE_IDX].val = (uint64_t)mv_reg_t_fs_base;
    pmut_reg_rdl->entries[FS_ATTRIB_IDX].val = (uint64_t)(
        (pmut_args->fs.type << ATTRIB_TYPE_SHIFT) | (pmut_args->fs.s << ATTRIB_S_SHIFT) |
        (pmut_args->fs.dpl << ATTRIB_DPL_SHIFT) | (pmut_args->fs.present << ATTRIB_PRESENT_SHIFT) |
        (pmut_args->fs.avl << ATTRIB_AVL_SHIFT) | (pmut_args->fs.l << ATTRIB_L_SHIFT) |
        (pmut_args->fs.g << ATTRIB_G_SHIFT) | (pmut_args->fs.db << ATTRIB_DB_SHIFT));

    pmut_reg_rdl->entries[GS_SELECTOR_IDX].val = (uint64_t)mv_reg_t_gs_selector;
    pmut_reg_rdl->entries[GS_LIMIT_IDX].val = (uint64_t)mv_reg_t_gs_limit;
    pmut_reg_rdl->entries[GS_BASE_IDX].val = (uint64_t)mv_reg_t_gs_base;
    pmut_reg_rdl->entries[GS_ATTRIB_IDX].val = (uint64_t)(
        (pmut_args->gs.type << ATTRIB_TYPE_SHIFT) | (pmut_args->gs.s << ATTRIB_S_SHIFT) |
        (pmut_args->gs.dpl << ATTRIB_DPL_SHIFT) | (pmut_args->gs.present << ATTRIB_PRESENT_SHIFT) |
        (pmut_args->gs.avl << ATTRIB_AVL_SHIFT) | (pmut_args->gs.l << ATTRIB_L_SHIFT) |
        (pmut_args->gs.g << ATTRIB_G_SHIFT) | (pmut_args->gs.db << ATTRIB_DB_SHIFT));

    pmut_reg_rdl->entries[SS_SELECTOR_IDX].val = (uint64_t)mv_reg_t_ss_selector;
    pmut_reg_rdl->entries[SS_LIMIT_IDX].val = (uint64_t)mv_reg_t_ss_limit;
    pmut_reg_rdl->entries[SS_BASE_IDX].val = (uint64_t)mv_reg_t_ss_base;
    pmut_reg_rdl->entries[SS_ATTRIB_IDX].val = (uint64_t)(
        (pmut_args->ss.type << ATTRIB_TYPE_SHIFT) | (pmut_args->ss.s << ATTRIB_S_SHIFT) |
        (pmut_args->ss.dpl << ATTRIB_DPL_SHIFT) | (pmut_args->ss.present << ATTRIB_PRESENT_SHIFT) |
        (pmut_args->ss.avl << ATTRIB_AVL_SHIFT) | (pmut_args->ss.l << ATTRIB_L_SHIFT) |
        (pmut_args->ss.g << ATTRIB_G_SHIFT) | (pmut_args->ss.db << ATTRIB_DB_SHIFT));

    pmut_reg_rdl->entries[LDT_SELECTOR_IDX].val = (uint64_t)mv_reg_t_ldtr_selector;
    pmut_reg_rdl->entries[LDT_LIMIT_IDX].val = (uint64_t)mv_reg_t_ldtr_limit;
    pmut_reg_rdl->entries[LDT_BASE_IDX].val = (uint64_t)mv_reg_t_ldtr_base;
    pmut_reg_rdl->entries[LDT_ATTRIB_IDX].val = (uint64_t)(
        (pmut_args->ldt.type << ATTRIB_TYPE_SHIFT) | (pmut_args->ldt.s << ATTRIB_S_SHIFT) |
        (pmut_args->ldt.dpl << ATTRIB_DPL_SHIFT) |
        (pmut_args->ldt.present << ATTRIB_PRESENT_SHIFT) |
        (pmut_args->ldt.avl << ATTRIB_AVL_SHIFT) | (pmut_args->ldt.l << ATTRIB_L_SHIFT) |
        (pmut_args->ldt.g << ATTRIB_G_SHIFT) | (pmut_args->ldt.db << ATTRIB_DB_SHIFT));
*/
    pmut_reg_rdl->entries[TR_SELECTOR_IDX].val = (uint64_t)mv_reg_t_tr_selector;
    pmut_reg_rdl->entries[TR_LIMIT_IDX].val = (uint64_t)mv_reg_t_tr_limit;
    pmut_reg_rdl->entries[TR_BASE_IDX].val = (uint64_t)mv_reg_t_tr_base;

    pmut_reg_rdl->entries[TR_ATTRIB_IDX].val = (uint64_t)(
        (pmut_args->tr.type << ATTRIB_TYPE_SHIFT) | (pmut_args->tr.s << ATTRIB_S_SHIFT) |
        (pmut_args->tr.dpl << ATTRIB_DPL_SHIFT) | (pmut_args->tr.present << ATTRIB_PRESENT_SHIFT) |
        (pmut_args->tr.avl << ATTRIB_AVL_SHIFT) | (pmut_args->tr.l << ATTRIB_L_SHIFT) |
        (pmut_args->tr.g << ATTRIB_G_SHIFT) | (pmut_args->tr.db << ATTRIB_DB_SHIFT));

    pmut_reg_rdl->entries[GDT_LIMIT_IDX].val = (uint64_t)mv_reg_t_gdtr_limit;
    pmut_reg_rdl->entries[GDT_BASE_IDX].val = (uint64_t)mv_reg_t_gdtr_base;
    pmut_reg_rdl->entries[IDT_LIMIT_IDX].val = (uint64_t)mv_reg_t_idtr_limit;
    pmut_reg_rdl->entries[IDT_BASE_IDX].val = (uint64_t)mv_reg_t_idtr_base;
    pmut_reg_rdl->entries[CR0_IDX].val = (uint64_t)mv_reg_t_cr0;
    pmut_reg_rdl->entries[CR2_IDX].val = (uint64_t)mv_reg_t_cr2;
    pmut_reg_rdl->entries[CR3_IDX].val = (uint64_t)mv_reg_t_cr3;
    pmut_reg_rdl->entries[CR4_IDX].val = (uint64_t)mv_reg_t_cr4;
    pmut_reg_rdl->entries[CR8_IDX].val = (uint64_t)mv_reg_t_cr8;

    pmut_reg_rdl->num_entries = TOTAL_SREGS_SET_NUM_REG_ENTRIES;

    if (mv_vs_op_reg_set_list(g_mut_hndl, pmut_vcpu->vsid)) {
        bferror("ms_vs_op_reg_set_list failed");
        return SHIM_FAILURE;
    }

    pmut_msr_rdl->entries[MSR_EFER_IDX].reg = (uint64_t)mv_msr_t_efer;
    pmut_msr_rdl->entries[MSR_APIC_BASE_IDX].reg = (uint64_t)mv_msr_t_apic_base;

    pmut_msr_rdl->entries[MSR_EFER_IDX].val = (uint64_t)mv_msr_t_efer;
    pmut_msr_rdl->entries[MSR_APIC_BASE_IDX].val = (uint64_t)mv_msr_t_apic_base;

    pmut_msr_rdl->num_entries = TOTAL_SREGS_SET_NUM_MSR_ENTRIES;

    if (mv_vs_op_msr_set_list(g_mut_hndl, pmut_vcpu->vsid)) {
        bferror("ms_vs_op_msr_set_list failed");
        return SHIM_FAILURE;
    }

    return SHIM_SUCCESS;
}
