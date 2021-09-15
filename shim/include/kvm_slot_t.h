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

#ifndef KVM_SLOT_T_H
#define KVM_SLOT_T_H

#include <stdint.h>

#define KVM_MEM_SLOTS_NUM 0x7FFF
#define KVM_USER_MEM_SLOTS 0x7FFF
// KVM_ADDRESS_SPACE_NUM needs some attention: defined as 1 in linux/hvm_host.h, 2 in asm/kvm_host.h
#define KVM_ADDRESS_SPACE_NUM 1

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * <!-- description -->
     *   @brief An internal representation of a kvm slot for book keeping
     */
    struct kvm_slot_t
    {
        /** @brief stores the id of this slot */
        int16_t id;
        /** @brief stores the address space id that this slot is a member of */
        uint16_t as_id;
        /** @brief stores the base of the guest frame number */
        uint64_t base_gfn;
        /** @brief stores the number of pages */
        uint32_t npages;
        /** @brief stores the userspace address */
        uint64_t userspace_addr;
        /** @brief stores the kvm flags for this slot */
        uint64_t flags;
    };

#ifdef __cplusplus
}
#endif

#endif
