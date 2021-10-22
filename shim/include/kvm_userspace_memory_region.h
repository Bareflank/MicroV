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

#ifndef KVM_USERSPACE_MEMORY_REGION_H
#define KVM_USERSPACE_MEMORY_REGION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

#define KVM_MEM_LOG_DIRTY_PAGES (1UL << 0)
#define KVM_MEM_READONLY (1UL << 1)

    /**
     * @struct kvm_userspace_memory_region
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_userspace_memory_region
    {
        /** @brief the guest physical memory slot */
        uint32_t slot;
        /** @brief the flags for this slot (log dirty pages or mem readonly) */
        uint32_t flags;
        /** @brief the guest physical address */
        uint64_t guest_phys_addr;
        /** @brief the memory size in bytes */
        uint64_t memory_size;
        /** @brief the start of the userspace allocated memory */
        uint64_t userspace_addr;
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
