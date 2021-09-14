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
#include <kvm_regs.h>
#include <kvm_regs_idxs.h>
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
 *   @brief Handles the execution of kvm_get_regs.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu arguments received from private data	
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_get_regs(
    struct shim_vcpu_t *const pmut_vcpu, struct kvm_regs *const pmut_args) NOEXCEPT

{

    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);

    struct mv_rdl_t *const pmut_rdl = (struct mv_rdl_t *const)shared_page_for_current_pp();
    platform_expects(NULL != pmut_rdl);

    pmut_rdl->entries[RAX_IDX].reg = (uint64_t)mv_reg_t_rax;
    pmut_rdl->entries[RBX_IDX].reg = (uint64_t)mv_reg_t_rbx;
    pmut_rdl->entries[RCX_IDX].reg = (uint64_t)mv_reg_t_rcx;
    pmut_rdl->entries[RDX_IDX].reg = (uint64_t)mv_reg_t_rdx;
    pmut_rdl->entries[RSI_IDX].reg = (uint64_t)mv_reg_t_rsi;
    pmut_rdl->entries[RDI_IDX].reg = (uint64_t)mv_reg_t_rdi;
    pmut_rdl->entries[RBP_IDX].reg = (uint64_t)mv_reg_t_rbp;
    pmut_rdl->entries[R8_IDX].reg = (uint64_t)mv_reg_t_r8;
    pmut_rdl->entries[R9_IDX].reg = (uint64_t)mv_reg_t_r9;
    pmut_rdl->entries[R10_IDX].reg = (uint64_t)mv_reg_t_r10;
    pmut_rdl->entries[R11_IDX].reg = (uint64_t)mv_reg_t_r11;
    pmut_rdl->entries[R12_IDX].reg = (uint64_t)mv_reg_t_r12;
    pmut_rdl->entries[R13_IDX].reg = (uint64_t)mv_reg_t_r13;
    pmut_rdl->entries[R14_IDX].reg = (uint64_t)mv_reg_t_r14;
    pmut_rdl->entries[R15_IDX].reg = (uint64_t)mv_reg_t_r15;
    pmut_rdl->entries[RSP_IDX].reg = (uint64_t)mv_reg_t_rsp;
    pmut_rdl->entries[RIP_IDX].reg = (uint64_t)mv_reg_t_rip;
    pmut_rdl->entries[RFLAGS_IDX].reg = (uint64_t)mv_reg_t_rflags;
    pmut_rdl->num_entries = TOTAL_NUM_ENTRIES;

    if (mv_vs_op_reg_get_list(g_mut_hndl, pmut_vcpu->vsid)) {
        bferror("ms_vs_op_reg_get_list failed");
        return SHIM_FAILURE;
    }

    pmut_args->rax = pmut_rdl->entries[RAX_IDX].val;
    pmut_args->rbx = pmut_rdl->entries[RBX_IDX].val;
    pmut_args->rcx = pmut_rdl->entries[RCX_IDX].val;
    pmut_args->rdx = pmut_rdl->entries[RDX_IDX].val;
    pmut_args->rsi = pmut_rdl->entries[RSI_IDX].val;
    pmut_args->rdi = pmut_rdl->entries[RDI_IDX].val;
    pmut_args->rbp = pmut_rdl->entries[RBP_IDX].val;
    pmut_args->r8 = pmut_rdl->entries[R8_IDX].val;
    pmut_args->r9 = pmut_rdl->entries[R9_IDX].val;
    pmut_args->r10 = pmut_rdl->entries[R10_IDX].val;
    pmut_args->r11 = pmut_rdl->entries[R11_IDX].val;
    pmut_args->r12 = pmut_rdl->entries[R12_IDX].val;
    pmut_args->r13 = pmut_rdl->entries[R13_IDX].val;
    pmut_args->r14 = pmut_rdl->entries[R14_IDX].val;
    pmut_args->r15 = pmut_rdl->entries[R15_IDX].val;
    pmut_args->rsp = pmut_rdl->entries[RSP_IDX].val;
    pmut_args->rip = pmut_rdl->entries[RIP_IDX].val;
    pmut_args->rflags = pmut_rdl->entries[RFLAGS_IDX].val;

    return SHIM_SUCCESS;
}
