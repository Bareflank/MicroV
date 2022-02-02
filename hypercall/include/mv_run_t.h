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

#include <mv_mdl_entry_t.h>
#include <mv_rdl_entry_t.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

/** @brief defines the max number of register entries */
#define MV_RUN_MAX_REG_ENTRIES ((uint64_t)0xA)
/** @brief defines the max number of MSR entries */
#define MV_RUN_MAX_MSR_ENTRIES ((uint64_t)0xA)
/** @brief defines the largest possible size for the memory region */
#define MV_RUN_MAX_MEM_REGION_SIZE ((uint64_t)0xE90)

    /**
     * <!-- description -->
     *   @brief TODO
     */
    struct mv_run_t
    {
        /** @brief stores the number of REG entries */
        uint64_t num_reg_entries;
        /** @brief stores the REG entries */
        struct mv_rdl_entry_t reg_entries[MV_RUN_MAX_REG_ENTRIES];

        /** @brief stores the number of MSR entries */
        uint64_t num_msr_entries;
        /** @brief stores the MSR entries */
        struct mv_rdl_entry_t msr_entries[MV_RUN_MAX_MSR_ENTRIES];

        /** @brief stores the MDL entry */
        struct mv_mdl_entry_t mdl_entry;
        /** @brief stores the memory region buffer */
        uint8_t mem[MV_RUN_MAX_MEM_REGION_SIZE];
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
