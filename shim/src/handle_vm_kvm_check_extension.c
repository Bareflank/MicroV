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
#include <kvm_constants.h>
#include <mv_constants.h>
#include <mv_types.h>
#include <platform.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_check_extension.
 *
 * <!-- inputs/outputs -->
 *   @param mut_userargs as a input from the user
 *   @param pmut_ret as a output to the user to check the extension is supported or not
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vm_kvm_check_extension(unsigned long mut_userargs, uint32_t *const pmut_ret) NOEXCEPT
{
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != pmut_ret);

    switch (mut_userargs) {
        case KVM_CAP_EXT_CPUID: {
            FALLTHROUGH;
        }
        case KVM_CAP_GET_TSC_KHZ: {
            FALLTHROUGH;
        }
        case KVM_CAP_TSC_DEADLINE_TIMER: {
            FALLTHROUGH;
        }
        case KVM_CAP_USER_MEMORY: {
            FALLTHROUGH;
        }
        case KVM_CAP_SET_TSS_ADDR: {
            FALLTHROUGH;
        }
        case KVM_CAP_MP_STATE: {
            FALLTHROUGH;
        }
        case KVM_CAP_DESTROY_MEMORY_REGION_WORKS: {
            FALLTHROUGH;
        }
        case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS: {
            FALLTHROUGH;
        }
        case KVM_CAP_IMMEDIATE_EXIT: {
            *pmut_ret = (uint32_t)1;
            break;
        }
        case KVM_CAP_NR_VCPUS: {
            *pmut_ret = (uint32_t)1;    //mv_pp_op_online_pps
            break;
        }
        case KVM_CAP_MAX_VCPUS: {
            *pmut_ret = (uint32_t)MICROV_MAX_VCPUS;
            break;
        }
        case KVM_CAP_NR_MEMSLOTS: {
            *pmut_ret = (uint32_t)MICROV_MAX_SLOTS;
            break;
        }
        case KVM_CAP_MAX_VCPU_ID: {
            *pmut_ret = (uint32_t)INT16_MAX;
            break;
        }
        case KVM_CAP_MCE: {
            *pmut_ret = (uint32_t)MICROV_MAX_MCE_BANKS;
            break;
        }
        default: {
            bfdebug_x64("Unsupported Extension userargs", mut_userargs);
            *pmut_ret = (uint32_t)0;
            break;
        }
    }

    return SHIM_SUCCESS;
}
