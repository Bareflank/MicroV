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
#include "kvm_irqchip.h"
#include "mv_types.h"
#include "platform.h"
#include "shim_vm_t.h"

#include <debug.h>
#include <detect_hypervisor.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_set_irqchip.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vm the argument for vm handle
 *   @param pmut_userargs the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vm_kvm_set_irqchip(
    struct shim_vm_t *const pmut_vm, struct kvm_irqchip *const pmut_userargs) NOEXCEPT
{
    platform_expects(NULL != pmut_vm);
    platform_expects(NULL != pmut_userargs);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }

    platform_mutex_lock(&pmut_vm->mutex);
    if (!pmut_vm->is_irqchip_created) {
        bferror("The IRQCHIP is not created, Did you forget to create it?");
        return SHIM_FAILURE;
    }
    platform_mutex_unlock(&pmut_vm->mutex);
    /*  
    //Set PIC status in hypercall "mv_vm_op_set_pic" 
    if (mv_vm_op_set_pic(pmut_vm, pmut_userargs)) {
        bferror("mv_vm_op_set_pic failed");
        return SHIM_FAILURE;
    }

    // Set PIC status in hypercall "mv_vm_op_set_iopic" 
    if (mv_vm_op_set_iopic(pmut_vm, pmut_userargs)) {
        bferror("mv_vm_op_set_iopic failed");
        return SHIM_FAILURE;
    }
    */

    return SHIM_SUCCESS;
}
