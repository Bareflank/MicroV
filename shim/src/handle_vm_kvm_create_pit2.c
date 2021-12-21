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
#include <kvm_pit_config.h>
#include <mv_constants.h>
#include <mv_types.h>
#include <platform.h>
#include <shim_vm_t.h>

/**
     * <!-- description -->
     *   @brief Handles the execution of mv_vp_op_create_pit2.
     *
     * <!-- inputs/outputs -->
     *   @param hndl the global handle
     *   @param vmid pointer of vm
     *   @param user_args the arguments provided by userspace
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
NODISCARD static inline mv_status_t
mv_vp_op_create_pit2(uint64_t const hndl, uint16_t const vmid, uint32_t const user_args)
{
    (void)hndl;
    (void)vmid;
    (void)user_args;
    return (uint64_t)0;
}
/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_create_pit2.
 *
 * <!-- inputs/outputs -->
 *   @param vm the VM to add the VCPU to
 *   @param pmut_ioctl_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vm_kvm_create_pit2(
    struct shim_vm_t const *const vm, struct kvm_pit_config *const pmut_ioctl_args) NOEXCEPT
{
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != vm);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }
    if ((uint32_t)1 != pmut_ioctl_args->flag) {
        bferror("The pit_config flag must be 1 (KVM_PIT_SPEAKER_DUMMY)");
        return SHIM_FAILURE;
    }

    if (mv_vp_op_create_pit2(g_mut_hndl, vm->vmid, pmut_ioctl_args->flag)) {
        bferror("mv_vp_op_create_pit2 failed");
        return SHIM_FAILURE;
    }
    return SHIM_SUCCESS;
}
