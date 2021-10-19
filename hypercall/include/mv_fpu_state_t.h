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
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

/** @brief defines the number of registers in fpu state */
#define MV_NO_OF_REGISTERS ((uint64_t)32)
/** @brief defines the number of xmm registers in fpu state */
#define MV_NO_OF_XMM_REGISTERS ((uint64_t)16)
/** @brief defines the xmm registers size in fpu state */
#define MV_XMM_REGISTER_SIZE ((uint64_t)16)
/** @brief defines the number of fpr registers in fpu state */
#define MV_NO_OF_FPR_REGISTERS ((uint64_t)8)
/** @brief defines the fpr registers size in fpu state */
#define MV_FPR_REGISTER_SIZE ((uint64_t)16)
/** @brief defines the calculate registers size */
#define MV_REGISTER_SIZE ((uint64_t)1)
/** @brief defines the total registers bytes size in fpu state */
#define MV_TOTAL_NO_OF_REGISTER_BYTES (MV_REGISTER_SIZE * MV_NO_OF_REGISTERS)
/** @brief defines the total fpr bytes size in fpu state */
#define MV_TOTAL_NO_OF_FPR_BYTES (MV_NO_OF_FPR_REGISTERS * MV_FPR_REGISTER_SIZE)
/** @brief defines the total xmm bytes size in fpu state */
#define MV_TOTAL_NO_OF_XMM_BYTES (MV_NO_OF_XMM_REGISTERS * MV_NO_OF_XMM_REGISTERS)

    /**
     * <!-- description -->
     *   @brief See mv_fpu_state_t for more details
     */
    struct mv_fpu_state_t
    {
        /** @brief stores registers */
        uint8_t registers[MV_TOTAL_NO_OF_REGISTER_BYTES];
        /** @brief stores mxscr registers */
        uint32_t mxcsr;
        /** @brief stores mxcsr mask registers */
        uint32_t mxcsr_mask;
        /** @brief stores fpr registers */
        uint8_t fpr[MV_TOTAL_NO_OF_FPR_BYTES];
        /** @brief stores xmm registers */
        uint8_t xmm[MV_TOTAL_NO_OF_XMM_BYTES];
        /** @brief stores the value read or to be written */
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif
