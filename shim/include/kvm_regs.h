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

#ifndef KVM_REGS_H
#define KVM_REGS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /**
     * @struct kvm_regs
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_regs
    {
        /** @brief rax stores register value */
        uint64_t rax;
        /** @brief rbx stores register value */
        uint64_t rbx;
        /** @brief rcx stores register value */
        uint64_t rcx;
        /** @brief rdx stores register value */
        uint64_t rdx;
        /** @brief rsi stores register value */
        uint64_t rsi;
        /** @brief rdi stores register value */
        uint64_t rdi;
        /** @brief rsp stores register value */
        uint64_t rsp;
        /** @brief rbp stores register value */
        uint64_t rbp;
        /** @brief r8 stores register value */
        uint64_t r8;
        /** @brief r9 stores register value */
        uint64_t r9;
        /** @brief r10 stores register value */
        uint64_t r10;
        /** @brief r11 stores register value */
        uint64_t r11;
        /** @brief r12 stores register value */
        uint64_t r12;
        /** @brief r13 stores register value */
        uint64_t r13;
        /** @brief r14 stores register value */
        uint64_t r14;
        /** @brief r15 stores register value */
        uint64_t r15;
        /** @brief rip stores register value */
        uint64_t rip;
        /** @brief rflags stores register value */
        uint64_t rflags;
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
