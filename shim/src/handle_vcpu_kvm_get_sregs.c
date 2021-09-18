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
 *   @brief Handles the execution of set_sreg_segment.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_seg setting the attrib index value of the segment
 *   @param mut_attrib_index contains the attrib index of the segment
 *   @param pmut_reg_rdl contains the values of the segment
 */
static void
set_sreg_segment(
    struct kvm_segment *const pmut_seg,
    uint8_t mut_attrib_index,
    struct mv_rdl_t *const pmut_reg_rdl)
{

    pmut_seg->type = (uint8_t)(
        (pmut_reg_rdl->entries[mut_attrib_index].val & ATTRIB_TYPE_MASK) >> ATTRIB_TYPE_SHIFT);
    pmut_seg->present = (uint8_t)(
        (pmut_reg_rdl->entries[mut_attrib_index].val & ATTRIB_PRESENT_MASK) >>
        ATTRIB_PRESENT_SHIFT);
    pmut_seg->dpl = (uint8_t)(
        (pmut_reg_rdl->entries[mut_attrib_index].val & ATTRIB_DPL_MASK) >> ATTRIB_DPL_SHIFT);
    pmut_seg->db = (uint8_t)(
        (pmut_reg_rdl->entries[mut_attrib_index].val & ATTRIB_DB_MASK) >> ATTRIB_DB_SHIFT);
    pmut_seg->l =
        (uint8_t)((pmut_reg_rdl->entries[mut_attrib_index].val & ATTRIB_L_MASK) >> ATTRIB_L_SHIFT);
    pmut_seg->g =
        (uint8_t)((pmut_reg_rdl->entries[mut_attrib_index].val & ATTRIB_G_MASK) >> ATTRIB_G_SHIFT);
    pmut_seg->avl = (uint8_t)(
        (pmut_reg_rdl->entries[mut_attrib_index].val & ATTRIB_AVL_MASK) >> ATTRIB_AVL_SHIFT);
    pmut_seg->s =
        (uint8_t)((pmut_reg_rdl->entries[mut_attrib_index].val & ATTRIB_S_MASK) >> ATTRIB_S_SHIFT);
}
/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_get_sregs.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu arguments received from private data
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_get_sregs(
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

    pmut_reg_rdl->num_entries = TOTAL_SREGS_NUM_REG_ENTRIES;

    if (mv_vs_op_reg_get_list(g_mut_hndl, pmut_vcpu->vsid)) {
        bferror("ms_vs_op_reg_get_list failed");
        return SHIM_FAILURE;
    }

    pmut_args->es.selector = (uint16_t)pmut_reg_rdl->entries[ES_SELECTOR_IDX].val;
    pmut_args->es.limit = (uint32_t)pmut_reg_rdl->entries[ES_LIMIT_IDX].val;
    pmut_args->es.base = pmut_reg_rdl->entries[ES_BASE_IDX].val;
    set_sreg_segment(&pmut_args->es, ES_ATTRIB_IDX, pmut_reg_rdl);

    pmut_args->cs.selector = (uint16_t)pmut_reg_rdl->entries[CS_SELECTOR_IDX].val;
    pmut_args->cs.limit = (uint32_t)pmut_reg_rdl->entries[CS_LIMIT_IDX].val;
    pmut_args->cs.base = pmut_reg_rdl->entries[CS_BASE_IDX].val;
    set_sreg_segment(&pmut_args->cs, CS_ATTRIB_IDX, pmut_reg_rdl);

    pmut_args->ds.selector = (uint16_t)pmut_reg_rdl->entries[DS_SELECTOR_IDX].val;
    pmut_args->ds.limit = (uint32_t)pmut_reg_rdl->entries[DS_LIMIT_IDX].val;
    pmut_args->ds.base = pmut_reg_rdl->entries[DS_BASE_IDX].val;
    set_sreg_segment(&pmut_args->ds, DS_ATTRIB_IDX, pmut_reg_rdl);

    pmut_args->fs.selector = (uint16_t)pmut_reg_rdl->entries[FS_SELECTOR_IDX].val;
    pmut_args->fs.limit = (uint32_t)pmut_reg_rdl->entries[FS_LIMIT_IDX].val;
    pmut_args->fs.base = pmut_reg_rdl->entries[FS_BASE_IDX].val;
    set_sreg_segment(&pmut_args->fs, FS_ATTRIB_IDX, pmut_reg_rdl);

    pmut_args->gs.selector = (uint16_t)pmut_reg_rdl->entries[GS_SELECTOR_IDX].val;
    pmut_args->gs.limit = (uint32_t)pmut_reg_rdl->entries[GS_LIMIT_IDX].val;
    pmut_args->gs.base = pmut_reg_rdl->entries[GS_BASE_IDX].val;
    set_sreg_segment(&pmut_args->gs, GS_ATTRIB_IDX, pmut_reg_rdl);

    pmut_args->ss.selector = (uint16_t)pmut_reg_rdl->entries[SS_SELECTOR_IDX].val;
    pmut_args->ss.limit = (uint32_t)pmut_reg_rdl->entries[SS_LIMIT_IDX].val;
    pmut_args->ss.base = pmut_reg_rdl->entries[SS_BASE_IDX].val;
    set_sreg_segment(&pmut_args->ss, SS_ATTRIB_IDX, pmut_reg_rdl);

    pmut_args->tr.selector = (uint16_t)pmut_reg_rdl->entries[TR_SELECTOR_IDX].val;
    pmut_args->tr.limit = (uint32_t)pmut_reg_rdl->entries[TR_LIMIT_IDX].val;
    pmut_args->tr.base = pmut_reg_rdl->entries[TR_BASE_IDX].val;
    set_sreg_segment(&pmut_args->tr, TR_ATTRIB_IDX, pmut_reg_rdl);

    pmut_args->ldt.selector = (uint16_t)pmut_reg_rdl->entries[LDT_SELECTOR_IDX].val;
    pmut_args->ldt.limit = (uint32_t)pmut_reg_rdl->entries[LDT_LIMIT_IDX].val;
    pmut_args->ldt.base = pmut_reg_rdl->entries[LDT_BASE_IDX].val;
    set_sreg_segment(&pmut_args->ldt, LDT_ATTRIB_IDX, pmut_reg_rdl);

    pmut_args->gdt.limit = (uint16_t)pmut_reg_rdl->entries[GDT_LIMIT_IDX].val;
    pmut_args->gdt.base = pmut_reg_rdl->entries[GDT_BASE_IDX].val;

    pmut_args->idt.limit = (uint16_t)pmut_reg_rdl->entries[IDT_LIMIT_IDX].val;
    pmut_args->idt.base = pmut_reg_rdl->entries[IDT_BASE_IDX].val;

    pmut_args->cr0 = pmut_reg_rdl->entries[CR0_IDX].val;
    pmut_args->cr2 = pmut_reg_rdl->entries[CR2_IDX].val;
    pmut_args->cr3 = pmut_reg_rdl->entries[CR3_IDX].val;
    pmut_args->cr4 = pmut_reg_rdl->entries[CR4_IDX].val;
    pmut_args->cr8 = pmut_reg_rdl->entries[CR8_IDX].val;

    pmut_msr_rdl->entries[MSR_EFER_IDX].reg = (uint64_t)mv_msr_t_efer;
    pmut_msr_rdl->entries[MSR_APIC_BASE_IDX].reg = (uint64_t)mv_msr_t_apic_base;
    pmut_msr_rdl->num_entries = TOTAL_SREGS_NUM_MSR_ENTRIES;

    if (mv_vs_op_msr_get_list(g_mut_hndl, pmut_vcpu->vsid)) {
        bferror("ms_vs_op_msr_get_list failed");
        return SHIM_FAILURE;
    }

    pmut_args->efer = pmut_msr_rdl->entries[MSR_EFER_IDX].val;
    pmut_args->apic_base = pmut_msr_rdl->entries[MSR_APIC_BASE_IDX].val;

    return SHIM_SUCCESS;
}
