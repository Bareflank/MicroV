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
#include <mv_types.h>
#include <platform.h>
#include <shim_vcpu_t.h>
#include <shim_vm_t.h>
#include <stdbool.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_create_irqchip.
 *
 * <!-- inputs/outputs -->
 *  @param pmut_vm the argument to hold vm details of type shim_vm_t
 *  @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vm_kvm_create_irqchip(struct shim_vm_t *const pmut_vm) NOEXCEPT
{
    //struct shim_vcpu_t mut_temp1={(uint16_t)0};
    struct shim_vcpu_t mut_temp1;
    struct shim_vcpu_t *pmut_mut_temp2 = &mut_temp1;
    struct shim_vcpu_t **pmut_mut_vcpu = &pmut_mut_temp2;
    uint64_t mut_i;
    int64_t mut_ret = SHIM_SUCCESS;

    platform_expects(NULL != pmut_vm);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }

    platform_mutex_lock(&pmut_vm->mutex);
    for (mut_i = ((uint64_t)0); mut_i < MICROV_MAX_VCPUS; ++mut_i) {
        *pmut_mut_vcpu = &pmut_vm->vcpus[mut_i];
        if (((uint64_t)0) != (*pmut_mut_vcpu)->fd) {
            bferror("VCPUs are already created. So IRQCHIP cannot be created!");
            mut_ret = SHIM_EXIST;
            goto unlock_irqchip_mutex;
        }

        mv_touch();
    }

    if (pmut_vm->is_irqchip_created) {
        bferror("The IRQCHIP is not created, Did you forget to create it?");
        mut_ret = SHIM_FAILURE;
        goto unlock_irqchip_mutex;
    }

    //NOTE: Below hypercalls to uncomment when they are implemented

    //platform_mutex_lock(&pmut_vm->mutex);
    // mv_status_t mut_pic_ret;
    // mv_status_t mut_iopic_ret;
    /** @brief for x86 create pic and iopic **/

    // mut_pic_ret = mv_vm_op_pic(pmut_vm->vmid);
    // if (mut_pic_ret) {
    //         mut_iopic_ret = mv_vm_op_ioapic_init(pmut_vm->vmid);
    //         if (mut_iopic_ret) {
    //                 platform_mutex_lock(&pmut_vm->slots_lock);
    //                 mv_vm_op_destroy_pic(pmut_vm->vmid);
    //                 platform_mutex_unlock(&pmut_vm->slots_lock);
    //                 goto create_irqchip_unlock;
    //         }
    // } else
    //         goto create_irqchip_unlock;

    // create_irqchip_unlock:
    //         platform_mutex_unlock(&pmut_vm->mutex);
    pmut_vm->is_irqchip_created = true;
unlock_irqchip_mutex:
    platform_mutex_unlock(&pmut_vm->mutex);
    return mut_ret;
}
