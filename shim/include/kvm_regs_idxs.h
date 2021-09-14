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

#ifndef KVM_REGS_IDXS_H
#define KVM_REGS_IDXS_H

#include <stdint.h>

#pragma pack(push, 1)

/** @brief index for RAX register */
#define RAX_IDX ((uint64_t)0)
/** @brief index for RBX register */
#define RBX_IDX ((uint64_t)1)
/** @brief index for RCX register */
#define RCX_IDX ((uint64_t)2)
/** @brief index for RDX register */
#define RDX_IDX ((uint64_t)3)
/** @brief index for RSI register */
#define RSI_IDX ((uint64_t)4)
/** @brief index for RDI register */
#define RDI_IDX ((uint64_t)5)
/** @brief index for RBP register */
#define RBP_IDX ((uint64_t)6)
/** @brief index for R8 register */
#define R8_IDX ((uint64_t)7)
/** @brief index for R9 register */
#define R9_IDX ((uint64_t)8)
/** @brief index for R10 register */
#define R10_IDX ((uint64_t)9)
/** @brief index for R11 register */
#define R11_IDX ((uint64_t)10)
/** @brief index for R12 register */
#define R12_IDX ((uint64_t)11)
/** @brief index for R13 register */
#define R13_IDX ((uint64_t)12)
/** @brief index for R14 register */
#define R14_IDX ((uint64_t)13)
/** @brief index for R15 register */
#define R15_IDX ((uint64_t)14)
/** @brief index for RSP register */
#define RSP_IDX ((uint64_t)15)
/** @brief index for RIP register */
#define RIP_IDX ((uint64_t)16)
/** @brief index for RFLAGS register */
#define RFLAGS_IDX ((uint64_t)17)

#pragma pack(pop)

#endif
