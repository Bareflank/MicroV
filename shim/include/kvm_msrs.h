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

#ifndef KVM_MSRS_H
#define KVM_MSRS_H

#include <kvm_msr_entry.h>
#include <mv_rdl_t.h>
#include <stdint.h>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wold-style-cast"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /**
     * @struct kvm_msrs
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_msrs
    {
        /** @brief number of msrs in entries */
        uint32_t nmsrs;
        /** @brief number of pad in entries */
        uint32_t pad;
        /** @brief defines array of entries*/
        struct kvm_msr_entry entries[MV_RDL_MAX_ENTRIES];
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
