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
#include <kvm_msr_list.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_rdl_t.h>
#include <mv_types.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_check_extension.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_ioctl_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_system_kvm_get_msr_index_list(struct kvm_msr_list *const pmut_ioctl_args) NOEXCEPT
{
    int64_t mut_i;
    uint32_t mut_nmsrs = ((uint32_t)0);

    struct mv_rdl_t *const pmut_rdl = (struct mv_rdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_rdl);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }

    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);

    do {
        pmut_rdl->reg0 = MV_RDL_FLAG_ALL;
        pmut_rdl->num_entries = ((uint64_t)0);

        if (mv_pp_op_msr_get_supported_list(g_mut_hndl)) {
            bferror("mv_pp_op_msr_get_supported_list failed");
            return SHIM_FAILURE;
        }

        if (pmut_rdl->num_entries >= MV_RDL_MAX_ENTRIES) {
            bferror("the RDL's num_entries is no longer valid");
            return SHIM_FAILURE;
        }

        if (pmut_rdl->num_entries + ((uint64_t)mut_nmsrs) > ((uint64_t)pmut_ioctl_args->nmsrs)) {
            bferror("number of MSRs is larger than kvm_msr_list indices");
            return SHIM_FAILURE;
        }

        for (mut_i = ((int64_t)0); mut_i < ((int64_t)pmut_rdl->num_entries); ++mut_i) {
            pmut_ioctl_args->indices[mut_nmsrs] = ((uint32_t)pmut_rdl->entries[mut_i].reg);
            ++mut_nmsrs;
        }
    } while (((uint64_t)0) != pmut_rdl->reg1);

    pmut_ioctl_args->nmsrs = mut_nmsrs;

    return SHIM_SUCCESS;
}
