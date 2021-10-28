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
#include <kvm_cpuid2.h>
#include <mv_cdl_t.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_types.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vcpu_t.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_set_cpuid2.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_ioctl_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_set_cpuid2(struct shim_vcpu_t const *const vcpu, struct kvm_cpuid2 *const pmut_ioctl_args) NOEXCEPT
{
    uint64_t mut_i;
    uint64_t mut_num_entries = ((uint64_t)0);

    struct mv_cdl_t *const pmut_cdl = (struct mv_cdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_cdl);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }

    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);

    for (mut_i = ((uint64_t)0); mut_i < pmut_ioctl_args->nent; ++mut_i) {
        /* Do not allow QEMU to set hypervisor cpuid leaves. */
        if (0x40000000 == (pmut_ioctl_args->entries[mut_i].function & 0xFFFFFF00)) {
            continue;
        }

        pmut_cdl->entries[mut_num_entries].fun = pmut_ioctl_args->entries[mut_i].function;
        pmut_cdl->entries[mut_num_entries].idx = pmut_ioctl_args->entries[mut_i].index;
        pmut_cdl->entries[mut_num_entries].eax = pmut_ioctl_args->entries[mut_i].eax;
        pmut_cdl->entries[mut_num_entries].ebx = pmut_ioctl_args->entries[mut_i].ebx;
        pmut_cdl->entries[mut_num_entries].ecx = pmut_ioctl_args->entries[mut_i].ecx;
        pmut_cdl->entries[mut_num_entries].edx = pmut_ioctl_args->entries[mut_i].edx;

        ++mut_num_entries;
    }

    pmut_cdl->num_entries = mut_num_entries;

    if (mv_vs_op_cpuid_set_list(g_mut_hndl, vcpu->vsid)) {
        bferror("mv_vs_op_cpuid_set_list failed");
        return SHIM_FAILURE;
    }

    return SHIM_SUCCESS;
}
