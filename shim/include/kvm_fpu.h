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

#ifndef KVM_FPU_H
#define KVM_FPU_H

#include <stdint.h>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wold-style-cast"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

/** @brief defines the size of the padding1 field */
#define FPR_REGISTER_SIZE ((uint64_t)8)
/** @brief defines the no of FPR registers */
#define NO_OF_FPR_REGISTERS ((uint64_t)16)
/** @brief defines the size of XMM register size */
#define XMM_REGISTER_SIZE ((uint64_t)16)
/** @brief defines the no of XMM registers */
#define NO_OF_XMM_REGISTERS ((uint64_t)16)
/** @brief defines the no of Register bytes */
#define NO_OF_REGISTERS_BYTES ((uint64_t)32)
/** @brief defines the no of Register bytes */
#define REGISTER_SIZE ((uint64_t)1)
/** @brief defines the total no of Register bytes */
#define TOTAL_NO_REGISTER_SIZE (REGISTER_SIZE * NO_OF_REGISTERS_BYTES)
/** @brief defines the total no of FPR bytes */
#define TOTAL_NO_OF_FPR_BYTES (NO_OF_FPR_REGISTERS * FPR_REGISTER_SIZE)
/** @brief defines the total no of XMM bytes */
#define TOTAL_NO_OF_XMM_BYTES (NO_OF_XMM_REGISTERS * XMM_REGISTER_SIZE)

    /**
     * @struct kvm_fpu
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_fpu
    {
        /** @brief stores that value of the Floating pointer registers*/
        uint8_t fpr[TOTAL_NO_OF_FPR_BYTES];
        /** @brief stores that value of the registers*/
        uint8_t registers[TOTAL_NO_REGISTER_SIZE];
        /** @brief stores that value of the XMM registers*/
        uint8_t xmm[TOTAL_NO_OF_XMM_BYTES];
        /** @brief stores that value of mxscr*/
        uint32_t mxcsr;
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
