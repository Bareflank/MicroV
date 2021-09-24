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

#define MV_NO_OF_REGISTERS 32
#define MV_NO_OF_XMM_REGISTERS 16
#define MV_XMM_REGISTER_SIZE 16
#define MV_NO_OF_FPR_REGISTERS 8
#define MV_FPR_REGISTER_SIZE 16

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /**
     * <!-- description -->
     *   @brief See mv_rdl_t for more details
     */
    struct mv_fpu_state_t
    {
        /** @brief stores registers */
        uint8_t registers[MV_NO_OF_REGISTERS];

        /** @brief stores mxscr registers */
        uint32_t mxcsr;

        /** @brief stores mxcsr mask registers */
        uint32_t mxcsr_mask;

        /** @brief stores fpr registers */
        uint8_t fpr[MV_NO_OF_FPR_REGISTERS * MV_FPR_REGISTER_SIZE];

        /** @brief stores xmm registers */
        uint8_t xmm[MV_NO_OF_XMM_REGISTERS * MV_NO_OF_XMM_REGISTERS];
        /** @brief stores the value read or to be written */
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif
