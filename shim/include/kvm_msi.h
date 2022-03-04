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

#ifndef KVM_MSI_H
#define KVM_MSI_H

#include <stdint.h>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wold-style-cast"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)
/** @brief defines the padding size */
#define PAD_SIZE_MSI ((uint32_t)16)

    /**
     * @struct kvm_msi
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_msi
    {
        /** @brief  For PCI, this is a BFD identifier in the lower 16 bits. */
        uint32_t address_lo;
        /** @brief address_hi bits 31-8 provide bits 31-8 of the destination id.  Bits 7-0 of
                   address_hi must be zero. */
        uint32_t address_hi;
        /** @brief  a MSI message*/
        uint32_t data;
        /** @brief A Flag to indicate valid or invalid data */
        uint32_t flags;
        /** @brief TODO */
        uint8_t pad[PAD_SIZE_MSI];
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
