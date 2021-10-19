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

#ifndef HANDLE_VCPU_KVM_GET_MP_STATE_H
#define HANDLE_VCPU_KVM_GET_MP_STATE_H

#include <kvm_mp_state.h>
#include <mv_types.h>
#include <shim_vcpu_t.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * <!-- description -->
     *   @brief Handles the execution of kvm_get_mp_state.
     *
     * <!-- inputs/outputs -->
     *   @param vcpu to pass the vsid to hypercall
     *   @param pmut_args the arguments provided by userspace
     *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
     */
    NODISCARD int64_t handle_vcpu_kvm_get_mp_state(
        struct shim_vcpu_t const *const vcpu, struct kvm_mp_state *const pmut_args) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif
