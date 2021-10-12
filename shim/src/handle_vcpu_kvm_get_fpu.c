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
#include <kvm_fpu.h>
#include <mv_constants.h>
#include <mv_fpu_state_t.h>
#include <mv_hypercall.h>
#include <mv_types.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vcpu_t.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_get_fpu.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_ioctl_args the arguments provided by userspace
 *   @param  vcpu arguments received from private data
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_get_fpu(
    struct shim_vcpu_t const *const vcpu, struct kvm_fpu *const pmut_ioctl_args) NOEXCEPT
{
    struct mv_fpu_state_t *pmut_mut_fpu;

    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != vcpu);
    platform_expects(NULL != pmut_ioctl_args);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }

    pmut_mut_fpu = (struct mv_fpu_state_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_mut_fpu);

    if (mv_vs_op_fpu_get_all(g_mut_hndl, vcpu->vsid)) {
        bferror("mv_vs_op_reg_get_all failed");
        return SHIM_FAILURE;
    }

    platform_memcpy(pmut_ioctl_args->registers, pmut_mut_fpu->registers, NO_OF_REGISTERS_BYTES);
    pmut_ioctl_args->mxcsr = pmut_mut_fpu->mxcsr;
    platform_memcpy(pmut_ioctl_args->fpr, pmut_mut_fpu->fpr, TOTAL_NO_OF_FPR_BYTES);
    platform_memcpy(pmut_ioctl_args->xmm, pmut_mut_fpu->xmm, TOTAL_NO_OF_XMM_BYTES);

    return SHIM_SUCCESS;
}
