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
#include <kvm_constants.h>
#include <kvm_mp_state.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_mp_state_t.h>
#include <mv_types.h>
#include <platform.h>
#include <shim_vcpu_t.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_set_mp_state.
 *
 * <!-- inputs/outputs -->
 *   @param vcpu arguments recevied from the private data
 *   @param args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_set_mp_state(
    struct shim_vcpu_t const *const vcpu, struct kvm_mp_state const *const args) NOEXCEPT
{
    int32_t mut_mpstate;
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != vcpu);
    platform_expects(NULL != args);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start Microv?");
        return SHIM_FAILURE;
    }

    switch (args->mp_state) {
        case KVM_MP_STATE_UNINITIALIZED: {
            mut_mpstate = mv_mp_state_t_initial;
            break;
        }
        case KVM_MP_STATE_RUNNABLE: {
            mut_mpstate = mv_mp_state_t_running;
            break;
        }
        case KVM_MP_STATE_HALTED: {
            mut_mpstate = mv_mp_state_t_wait;
            break;
        }
        case KVM_MP_STATE_INIT_RECEIVED: {
            mut_mpstate = mv_mp_state_t_init;
            break;
        }
        case KVM_MP_STATE_SIPI_RECEIVED: {
            mut_mpstate = mv_mp_state_t_sipi;
            break;
        }
        default: {
            bferror_x32("Invalid value received in set mp state API", args->mp_state);
            return SHIM_FAILURE;
        }
    }

    if (mv_vs_op_mp_state_set(g_mut_hndl, vcpu->vsid, i32_to_mv_mp_state_t(mut_mpstate))) {
        bferror("mv_vs_op_mp_state_set failed");
        return SHIM_FAILURE;
    }

    return SHIM_SUCCESS;
}
