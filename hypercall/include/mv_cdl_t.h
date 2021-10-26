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

#ifndef MV_CDL_T_H
#define MV_CDL_T_H

#include <mv_cdl_entry_t.h>    // IWYU pragma: export
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

#ifdef __cplusplus
/** @brief defines the max number of entires in the CDL */
#define MV_CDL_MAX_ENTRIES (static_cast<uint64_t>(125))
#else
/** @brief defines the max number of entires in the CDL */
#define MV_CDL_MAX_ENTRIES ((uint64_t)125)
#endif

    /**
     * <!-- description -->
     *   @brief A CPUID descriptor list (CDL) describes a list of CPUID leaves
     *     that either need to be read or written. Each CDL consists of a list
     *     of entries with each entry describing one CPUID leaf to read/write.
     *     Like all structures used in this ABI, the CDL must be placed inside
     *     the shared page. Registers 0-7 in the mv_cdl_t are NOT entries, but
     *     instead input/output registers for the ABIs that need additional
     *     input and output registers. If any of these registers is not used by
     *     a specific ABI, it is REVI.
     */
    struct mv_cdl_t
    {
        /** @brief ABI dependent. REVI if unused */
        uint64_t reg0;
        /** @brief ABI dependent. REVI if unused */
        uint64_t reg1;
        /** @brief ABI dependent. REVI if unused */
        uint64_t reg2;
        /** @brief ABI dependent. REVI if unused */
        uint64_t reg3;
        /** @brief ABI dependent. REVI if unused */
        uint64_t reg4;
        /** @brief ABI dependent. REVI if unused */
        uint64_t reg5;
        /** @brief ABI dependent. REVI if unused */
        uint64_t reg6;
        /** @brief ABI dependent. REVI if unused */
        uint64_t reg7;
        /** @brief REVI */
        uint64_t reserved1;
        /** @brief REVI */
        uint64_t reserved2;
        /** @brief REVI */
        uint64_t reserved3;
        /** @brief stores the number of entries in the CDL */
        uint64_t num_entries;
        /** @brief stores each entry in the CDL */
        struct mv_cdl_entry_t entries[MV_CDL_MAX_ENTRIES];
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
