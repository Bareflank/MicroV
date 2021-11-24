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
#include <kvm_msr_entry.h>
#include <kvm_msrs.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_rdl_t.h>
#include <mv_types.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vcpu_t.h>
/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_get_msrs.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments received from private data
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_get_msrs(
    struct shim_vcpu_t const *const vcpu, struct kvm_msrs *const pmut_args) NOEXCEPT
{
    uint64_t mut_i;
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != vcpu);
    platform_expects(NULL != pmut_args);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicorV?");
        return SHIM_FAILURE;
    }

    struct mv_rdl_t *const pmut_rdl = (struct mv_rdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_rdl);

    pmut_rdl->num_entries = (uint64_t)pmut_args->nmsrs;

    for (mut_i = ((uint64_t)0); mut_i < pmut_rdl->num_entries; ++mut_i) {
        pmut_rdl->entries[mut_i].reg = (uint64_t)pmut_args->entries[mut_i].index;
    }

    if (mv_vs_op_msr_get_list(g_mut_hndl, vcpu->vsid)) {
        bferror("mv_vs_op_msr_get_list failed");
        return SHIM_FAILURE;
    }

    if (pmut_rdl->num_entries != (uint64_t)pmut_args->nmsrs) {
        bferror("The RDL's num_entries is no longer valid");
        return SHIM_FAILURE;
    }

    for (mut_i = ((uint64_t)0); mut_i < pmut_rdl->num_entries; ++mut_i) {
        pmut_args->entries[mut_i].data = pmut_rdl->entries[mut_i].val;
    }

    return SHIM_SUCCESS;
}
