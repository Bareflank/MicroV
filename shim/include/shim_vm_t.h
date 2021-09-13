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

#ifndef SHIM_VM_T_H
#define SHIM_VM_T_H

#include <constants.h>
#include <platform.h>
#include <shim_vcpu_t.h>
#include <stdint.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /**
     * @struct shim_vm_t
     *
     * <!-- description -->
     *   @brief Represents the shim's version of a VM, and stores all of the
     *     state that the shim needs to convert between KVM and MicroV
     *     with respect to a VM.
     */
    struct shim_vm_t
    {
        /** @brief stores the ID of this VM */
        uint16_t id;
        /** @brief stores file descriptor for this VM */
        uint64_t fd;
        /** @brief stores the mutex lock used to operate on this VM */
        platform_mutex mutex;

        /** @brief stores the ID of the MicroV VM associated with this VCPU */
        uint16_t vmid;

        /** @brief stores the VCPUs associated with this VM */
        struct shim_vcpu_t vcpus[MICROV_MAX_VCPUS];
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
