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

#ifndef MV_RDL_T_H
#define MV_RDL_T_H

#include <mv_rdl_entry_t.h>    // IWYU pragma: export
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief defines the max number of entires in the RDL */
#define MV_RDL_MAX_ENTRIES ((uint64_t)250)

    /**
     * <!-- description -->
     *   @brief A register descriptor list (RDL) describes a list of registers
     *     that either need to be read or written. Each RDL consists of a list
     *     of entries with each entry describing one register to read/write.
     *     Like all structures used in this ABI, the RDL must be placed inside
     *     the shared page. Not all registers require 64 bits for either the
     *     register index or the value itself. In all cases, unused bits are
     *     considered REVI. The meaning of the register and value fields is
     *     ABI dependent. For some ABIs, the reg field refers to a mv_reg_t
     *     while in other cases it refers to an architecture specific register
     *     like MSRs on x86 which have it's index type. The value field for
     *     some ABIs is the value read or the value to be written to the
     *     requested register. In other cases, it is a boolean, enum or bit
     *     field describing attributes about the register such as whether the
     *     register is supported, emulated or permissable. Registers 0-7 in the
     *     mv_rdl_t are NOT entries, but instead input/output registers for the
     *     ABIs that need additional input and output registers. If any of
     *     these registers is not used by a specific ABI, it is REVI.
     */
    struct mv_rdl_t
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
        /** @brief stores the number of entries in the RDL */
        uint64_t num_entries;
        /** @brief stores each entry in the RDL */
        struct mv_rdl_entry_t entries[MV_RDL_MAX_ENTRIES];
    };

#ifdef __cplusplus
}
#endif

#endif
