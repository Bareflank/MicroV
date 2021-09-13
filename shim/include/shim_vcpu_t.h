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

#ifndef SHIM_VCPU_T_H
#define SHIM_VCPU_T_H

#include <stdint.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /** prototype */
    struct shim_vm_t;

    /**
     * @struct shim_vcpu_t
     *
     * <!-- description -->
     *   @brief Represents the shim's version of a VCPU, and stores all of the
     *     state that the shim needs to convert between KVM and MicroV
     *     with respect to a VCPU.
     */
    struct shim_vcpu_t
    {
        /** @brief stores the ID of this VCPU */
        uint16_t id;
        /** @brief stores file descriptor for this VCPU */
        uint64_t fd;

        /** @brief stores the ID of the MicroV VP associated with this VCPU */
        uint16_t vpid;
        /** @brief stores the ID of the MicroV VS associated with this VCPU */
        uint16_t vsid;

        /** @brief stores a pointer to the parent VM */
        struct shim_vm_t *vm;
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
