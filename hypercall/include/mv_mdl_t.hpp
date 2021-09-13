/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef MV_MDL_T_HPP
#define MV_MDL_T_HPP

#include <mv_mdl_entry_t.hpp>    // IWYU pragma: export

#include <bsl/cstdint.hpp>

namespace hypercall
{
    /// @brief defines the max number of entires in the MDL
    constexpr auto MV_MDL_MAX_ENTRIES{125_u64};

    /// <!-- description -->
    ///   @brief A memory descriptor list (MDL) describes a discontiguous
    ///     region of guest physical memory. Each MDL consists of a list of
    ///     entries with each entry describing one contiguous region of guest
    ///     physical memory. By combining multiple entries into a list, software
    ///     is capable of describing both contiguous and discontiguous regions
    ///     of guest physical memory. Like all structures used in this ABI, the
    ///     MDL must be placed inside the shared page. The meaning of the dst
    ///     and src fields is ABI dependent. Both the dst and src fields could
    ///     be GVAs, GLAs or GPAs (virtual, linear or physical). The bytes field
    ///     describes the total number of bytes in the contiguous memory region.
    ///     For some ABIs, this field must be page aligned. The flags field is
    ///     also ABI dependent. For example, for map hypercalls, this field
    ///     refers to map flags. Registers 0-7 in the mv_mdl_t are NOT entries,
    ///     but instead input/output registers for the ABIs that need additional
    ///     input and output registers. If any of these registers is not used by
    ///     a specific ABI, it is REVI.
    ///
    struct mv_mdl_t final
    {
        /// @brief ABI dependent. REVI if unused
        uint64_t reg0;
        /// @brief ABI dependent. REVI if unused
        uint64_t reg1;
        /// @brief ABI dependent. REVI if unused
        uint64_t reg2;
        /// @brief ABI dependent. REVI if unused
        uint64_t reg3;
        /// @brief ABI dependent. REVI if unused
        uint64_t reg4;
        /// @brief ABI dependent. REVI if unused
        uint64_t reg5;
        /// @brief ABI dependent. REVI if unused
        uint64_t reg6;
        /// @brief ABI dependent. REVI if unused
        uint64_t reg7;
        /// @brief REVI
        uint64_t reserved1;
        /// @brief REVI
        uint64_t reserved2;
        /// @brief REVI
        uint64_t reserved3;
        /// @brief stores the number of entries in the MDL
        uint64_t num_entries;
        /// @brief stores each entry in the MDL
        mv_mdl_entry_t entries[MV_MDL_MAX_ENTRIES];
    };
}

#endif
