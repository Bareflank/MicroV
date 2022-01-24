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

#ifndef MV_RUN_T
#define MV_RUN_T

#include <mv_rdl_entry_t.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

/** @brief defines the max number of reserved entries */
#define MV_RUN_MAX_RESERVED ((uint64_t)0xEC0)

    /**
     * <!-- description -->
     *   @brief TODO
     */
    struct mv_run_t
    {
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg0;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg1;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg2;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg3;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg4;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg5;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg6;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg7;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg8;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t reg9;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr0;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr1;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr2;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr3;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr4;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr5;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr6;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr7;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr8;
        /** @brief stores the mv_rdl_entry_t */
        mv_rdl_entry_t msr9;

        /** @brief reserved */
        uint8_t reserved[MV_RUN_MAX_RESERVED];
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
