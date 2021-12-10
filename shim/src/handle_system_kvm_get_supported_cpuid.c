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
#include <kvm_cpuid_entry2.h>
#include <mv_cdl_t.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_types.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_check_extension.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_ioctl_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure, and SHIM_2BIG when
 *      the number of CPUID entries is greater than what was set in nent. When SHIM_2BIG is
 *      returned, the correct number of CPUID entries is set in the nent field.
 */
NODISCARD int64_t
handle_system_kvm_get_supported_cpuid(struct kvm_cpuid2 *const pmut_ioctl_args) NOEXCEPT
{
    int64_t mut_ret = SHIM_FAILURE;
    uint32_t const init_fun = ((uint32_t)0x00000000);
    uint32_t const init_xfun = ((uint32_t)0x80000000);
    uint32_t mut_fun = init_fun;
    uint32_t mut_xfun = init_xfun;
    uint32_t mut_fun_max;
    uint32_t mut_xfun_max;
    uint64_t mut_i;
    struct mv_cdl_entry_t mut_cdl_entry;
    struct mv_cdl_t *pmut_mut_cdl;

    platform_expects(NULL != pmut_ioctl_args);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        goto ret;
    }

    pmut_mut_cdl = (struct mv_cdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_mut_cdl);

    /* Start by getting the largest function and largest extended function */
    pmut_mut_cdl->num_entries = ((uint64_t)2);
    pmut_mut_cdl->entries[0].fun = mut_fun;
    pmut_mut_cdl->entries[1].fun = mut_xfun;

    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    if (mv_pp_op_cpuid_get_supported_list(g_mut_hndl)) {
        bferror("mv_pp_op_cpuid_get_supported_list failed");
        goto release_shared_page;
    }

    if (pmut_mut_cdl->num_entries >= MV_CDL_MAX_ENTRIES) {
        bferror("num_entries exceeds MV_CDL_MAX_ENTRIES");
        return SHIM_FAILURE;
    }

    /* Calculate the new num_entries */
    mut_fun_max = pmut_mut_cdl->entries[0].eax;
    mut_xfun_max = pmut_mut_cdl->entries[1].eax;
    pmut_mut_cdl->num_entries = ((uint64_t)(mut_fun_max + mut_xfun_max - init_xfun));

    if (pmut_mut_cdl->num_entries >= MV_CDL_MAX_ENTRIES) {
        bferror("calculated num_entries exceeds MV_CDL_MAX_ENTRIES");
        goto release_shared_page;
    }

    if (pmut_mut_cdl->num_entries > ((uint64_t)pmut_ioctl_args->nent)) {
        bfdebug("CDL entries is larger than kvm_cpuid2 entries");
        pmut_ioctl_args->nent = ((uint32_t)pmut_mut_cdl->num_entries);
        mut_ret = SHIM_2BIG;
        goto release_shared_page;
    }

    mut_i = ((uint64_t)0);
    for (; mut_fun < mut_fun_max; ++mut_fun) {
        pmut_mut_cdl->entries[mut_i].fun = mut_fun;
        ++mut_i;
    }

    for (; mut_xfun < mut_xfun_max; ++mut_xfun) {
        pmut_mut_cdl->entries[mut_i].fun = mut_xfun;
        ++mut_i;
    }

    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    if (mv_pp_op_cpuid_get_supported_list(g_mut_hndl)) {
        bferror("mv_pp_op_cpuid_get_supported_list failed");
        mut_ret = SHIM_FAILURE;
        goto release_shared_page;
    }

    for (mut_i = ((uint64_t)0); mut_i < ((uint64_t)pmut_mut_cdl->num_entries); ++mut_i) {
        mut_cdl_entry = pmut_mut_cdl->entries[mut_i];
        pmut_ioctl_args->entries[mut_i].function = mut_cdl_entry.fun;
        pmut_ioctl_args->entries[mut_i].index = mut_cdl_entry.idx;
        pmut_ioctl_args->entries[mut_i].flags = mut_cdl_entry.flags;
        pmut_ioctl_args->entries[mut_i].eax = mut_cdl_entry.eax;
        pmut_ioctl_args->entries[mut_i].ebx = mut_cdl_entry.ebx;
        pmut_ioctl_args->entries[mut_i].ecx = mut_cdl_entry.ecx;
        pmut_ioctl_args->entries[mut_i].edx = mut_cdl_entry.edx;
    }
    pmut_ioctl_args->nent = ((uint32_t)pmut_mut_cdl->num_entries);

    mut_ret = SHIM_SUCCESS;

release_shared_page:
    release_shared_page_for_current_pp();

ret:
    return mut_ret;
}
