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
#include <kvm_regs.h>
#include <mv_rdl_entry_t.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <platform.h>
#include <shim_vcpu_t.h>
#include <types.h>

/* Remove me */
#define HYPERVISOR_PAGE_SIZE 13
#define HYPERVISOR_MAX_PPS 10

/* Remove me */
/**
 * @struct page_t
 *
 * <!-- description -->
 *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
 *   @var page_t::data
 *   Member reg holds data 
*/

struct page_t
{
    uint8_t data[HYPERVISOR_PAGE_SIZE];
};

/* Remove me */
struct page_t g_shared_pages[HYPERVISOR_MAX_PPS] = {0};

/* Remove me */
uint32_t
platform_current_cpu(void)
{
    return 10;
}

/* Remove me */
void *
shared_page_for_this_pp(void)
{
    uint32_t ppid = platform_current_cpu();
    platform_expects(ppid < HYPERVISOR_MAX_PPS);

    return &g_shared_pages[ppid];
}

/* Remove me */
uint16_t
ms_vs_op_reg_get_list(uint64_t const vsid)
{
    return 1;
}

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_get_regs.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu paramter to extract the vsid
 *   @param regs the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
int64_t
handle_vcpu_kvm_get_regs(struct shim_vcpu_t const *const vcpu, struct kvm_regs *const regs)
{
    const int RAX_IDX = 0;
    const int RBX_IDX = 1;
    const int RCX_IDX = 2;
    const int RDX_IDX = 3;
    const int RSI_IDX = 4;
    const int RDI_IDX = 5;
    const int RBP_IDX = 6;
    const int R8_IDX = 7;
    const int R9_IDX = 8;
    const int R10_IDX = 9;
    const int R11_IDX = 10;
    const int R12_IDX = 11;
    const int R13_IDX = 12;
    const int R14_IDX = 13;
    const int R15_IDX = 14;
    const int RSP_IDX = 15;
    const int RIP_IDX = 16;
    const int RFLAGS_IDX = 17;

    struct mv_rdl_t *const rdl = (struct mv_rdl_t *const)shared_page_for_this_pp();

    rdl->entries[RAX_IDX].reg = mv_reg_t_rax;
    rdl->entries[RBX_IDX].reg = mv_reg_t_rbx;
    rdl->entries[RCX_IDX].reg = mv_reg_t_rcx;
    rdl->entries[RDX_IDX].reg = mv_reg_t_rdx;
    rdl->entries[RSI_IDX].reg = mv_reg_t_rsi;
    rdl->entries[RDI_IDX].reg = mv_reg_t_rdi;
    rdl->entries[RBP_IDX].reg = mv_reg_t_rbp;
    rdl->entries[R8_IDX].reg = mv_reg_t_r8;
    rdl->entries[R9_IDX].reg = mv_reg_t_r9;
    rdl->entries[R10_IDX].reg = mv_reg_t_r10;
    rdl->entries[R11_IDX].reg = mv_reg_t_r11;
    rdl->entries[R12_IDX].reg = mv_reg_t_r12;
    rdl->entries[R13_IDX].reg = mv_reg_t_r13;
    rdl->entries[R14_IDX].reg = mv_reg_t_r14;
    rdl->entries[R15_IDX].reg = mv_reg_t_r15;
    rdl->entries[RSP_IDX].reg = mv_reg_t_rsp;
    rdl->entries[RIP_IDX].reg = mv_reg_t_rip;
    rdl->entries[RFLAGS_IDX].reg = mv_reg_t_rflags;

    if (ms_vs_op_reg_get_list(vcpu->vsid)) {
        bferror("ms_vs_op_reg_get_list failed");
        return SHIM_FAILURE;
    }

    regs->rax = rdl->entries[RAX_IDX].val;
    regs->rbx = rdl->entries[RBX_IDX].val;
    regs->rcx = rdl->entries[RCX_IDX].val;
    regs->rdx = rdl->entries[RDX_IDX].val;
    regs->rsi = rdl->entries[RSI_IDX].val;
    regs->rdi = rdl->entries[RDI_IDX].val;
    regs->rbp = rdl->entries[RBP_IDX].val;
    regs->r8 = rdl->entries[R8_IDX].val;
    regs->r9 = rdl->entries[R9_IDX].val;
    regs->r10 = rdl->entries[R10_IDX].val;
    regs->r11 = rdl->entries[R11_IDX].val;
    regs->r12 = rdl->entries[R12_IDX].val;
    regs->r13 = rdl->entries[R13_IDX].val;
    regs->r14 = rdl->entries[R14_IDX].val;
    regs->r15 = rdl->entries[R15_IDX].val;
    regs->rsp = rdl->entries[RSP_IDX].val;
    regs->rip = rdl->entries[RIP_IDX].val;
    regs->rflags = rdl->entries[RFLAGS_IDX].val;

    return SHIM_SUCCESS;
}
