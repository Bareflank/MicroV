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
#include <mv_hypercall.h>
#include <platform.h>
#include <shim_vcpu_t.h>
#include <shim_vm_t.h>
#include <types.h>

/*Remove me */

static uint16_t
mv_vp_op_create_vp(uint16_t const vmid)
{
    (void)vmid;
    return 1;
}

/* Remove me */
static uint16_t
mv_vs_op_create_vs(uint16_t const vpid)
{
    (void)vpid;
    return 1;
}

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_create_vcpu.
 *
 * <!-- inputs/outputs -->
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
int64_t
handle_vm_kvm_create_vcpu(struct shim_vm_t *const vm, struct shim_vcpu_t *const vcpu)
{
    platform_expects(NULL != vcpu);
    platform_expects(NULL != vm);

    vcpu->vpid = mv_vp_op_create_vp(vm->vmid);
    if (MV_INVALID_ID == vcpu->vpid) {
        bferror("handle_vm_kvm_create_vcpu :: mv_vp_op_create_vp failed");
        return SHIM_FAILURE;
    }

    vcpu->vsid = mv_vs_op_create_vs(vcpu->vpid);
    if (MV_INVALID_ID == vcpu->vsid) {
        bferror("handle_vm_kvm_create_vcpu :: mv_vs_op_create_vs failed");
        return SHIM_FAILURE;
    }
    return SHIM_SUCCESS;
}
