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
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <platform.h>
#include <shim_vcpu_t.h>
#include <shim_vm_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_create_vcpu.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vm the VM to add the VCPU to
 *   @param pmut_vcpu returns the resulting VCPU
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vm_kvm_create_vcpu(
    struct shim_vm_t *const pmut_vm, struct shim_vcpu_t **const pmut_vcpu) NOEXCEPT
{
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != pmut_vm);
    platform_expects(NULL != pmut_vcpu);

    if ((uint64_t)pmut_vm->num_vcpus >= MICROV_MAX_VCPUS) {
        bferror("the vm's max vcpu count has been reached");
        return SHIM_FAILURE;
    }

    *pmut_vcpu = &pmut_vm->vcpus[pmut_vm->num_vcpus];

    (*pmut_vcpu)->vpid = mv_vp_op_create_vp(g_mut_hndl, pmut_vm->vmid);
    if (MV_INVALID_ID == (int32_t)(*pmut_vcpu)->vpid) {
        bferror("mv_vp_op_create_vp failed");
        return SHIM_FAILURE;
    }

    (*pmut_vcpu)->vsid = mv_vs_op_create_vs(g_mut_hndl, (*pmut_vcpu)->vpid);
    if (MV_INVALID_ID == (int32_t)(*pmut_vcpu)->vsid) {
        bferror("mv_vs_op_create_vs failed");
        return SHIM_FAILURE;
    }

    (*pmut_vcpu)->id = (*pmut_vcpu)->vsid;
    ++pmut_vm->num_vcpus;

    return SHIM_SUCCESS;
}
