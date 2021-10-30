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
#include <kvm_regs.h>
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
        {(uint64_t)mv_reg_t_rax, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_rbx, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_rcx, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_rdx, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_rsi, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_rdi, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_rsp, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_rbp, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_r8, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_r9, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_r10, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_r11, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_r12, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_r13, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_r14, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_r15, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_rip, ((uint64_t)0)},
        {(uint64_t)mv_reg_t_rflags, ((uint64_t)0)},
    }};

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_set_regs.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_set_regs(
    struct shim_vcpu_t const *const vcpu, struct kvm_regs const *const args) NOEXCEPT
{
    int64_t mut_ret = SHIM_FAILURE;
    struct mv_rdl_t *pmut_mut_rdl;
    struct mv_rdl_entry_t const *mut_src_entry;
    struct mv_rdl_entry_t *pmut_mut_dst_entry;

    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != vcpu);
    platform_expects(NULL != args);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        goto ret;
    }

    pmut_mut_rdl = (struct mv_rdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_mut_rdl);

    pmut_mut_rdl->num_entries = ((uint64_t)0);
    while (1) {
        platform_expects(pmut_mut_rdl->num_entries < MV_RDL_MAX_ENTRIES);

        mut_src_entry = &g_reg_rdl.entries[pmut_mut_rdl->num_entries];
        pmut_mut_dst_entry = &pmut_mut_rdl->entries[pmut_mut_rdl->num_entries];

        pmut_mut_dst_entry->reg = mut_src_entry->reg;
        switch ((int32_t)pmut_mut_dst_entry->reg) {
            case mv_reg_t_rax: {
                pmut_mut_dst_entry->val = args->rax;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_rbx: {
                pmut_mut_dst_entry->val = args->rbx;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_rcx: {
                pmut_mut_dst_entry->val = args->rcx;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_rdx: {
                pmut_mut_dst_entry->val = args->rdx;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_rsi: {
                pmut_mut_dst_entry->val = args->rsi;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_rdi: {
                pmut_mut_dst_entry->val = args->rdi;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_rsp: {
                pmut_mut_dst_entry->val = args->rsp;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_rbp: {
                pmut_mut_dst_entry->val = args->rbp;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_r8: {
                pmut_mut_dst_entry->val = args->r8;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_r9: {
                pmut_mut_dst_entry->val = args->r9;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_r10: {
                pmut_mut_dst_entry->val = args->r10;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_r11: {
                pmut_mut_dst_entry->val = args->r11;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_r12: {
                pmut_mut_dst_entry->val = args->r12;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_r13: {
                pmut_mut_dst_entry->val = args->r13;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_r14: {
                pmut_mut_dst_entry->val = args->r14;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_r15: {
                pmut_mut_dst_entry->val = args->r15;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_rip: {
                pmut_mut_dst_entry->val = args->rip;
                ++pmut_mut_rdl->num_entries;
                continue;
            }

            case mv_reg_t_rflags: {
                pmut_mut_dst_entry->val = args->rflags;
                ++pmut_mut_rdl->num_entries;
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
        goto release_shared_page;
    }

    mut_ret = SHIM_SUCCESS;

release_shared_page:
    release_shared_page_for_current_pp();

ret:
    return mut_ret;
}
