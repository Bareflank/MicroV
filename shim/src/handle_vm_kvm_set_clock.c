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
#include <kvm_clock_data.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <mv_types.h>
#include <platform.h>
#include <shim_vcpu_t.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_set_clock.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_ioctl_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vm_kvm_set_clock(const uint16_t vsid, struct kvm_clock_data *const pmut_ioctl_args) NOEXCEPT
{
    platform_expects(NULL != pmut_ioctl_args);
    
    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }

    if (mv_vs_op_clock_set(g_mut_hndl, vsid, pmut_ioctl_args->clock)) {
        bferror("mv_vs_op_reg_get_list failed");
        return SHIM_FAILURE;
    }

    return SHIM_SUCCESS;
}
