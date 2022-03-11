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

#ifndef MV_RUN_T_HPP
#define MV_RUN_T_HPP

#include "mv_exit_io_t.hpp"
#include "mv_exit_mmio_t.hpp"
#include "mv_mdl_entry_t.hpp"
#include "mv_rdl_entry_t.hpp"    // IWYU pragma: export

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace hypercall
{
    /// @brief defines the max number of register entries
    constexpr auto MV_RUN_MAX_REG_ENTRIES{0xA_u64};
    /// @brief defines the max number of MSR entries
    constexpr auto MV_RUN_MAX_MSR_ENTRIES{0xA_u64};
    /// @brief defines the max number of entires in the MDL
    constexpr auto MV_RUN_MAX_IOMEM_SIZE{0xEA8_u64};

    /// <!-- description -->
    ///   @brief TODO
    ///
    struct mv_run_t final
    {
        /// @brief stores the number of REG entries
        uint64_t num_reg_entries;
        /// @brief stores the REG entries
        bsl::array<mv_rdl_entry_t, MV_RUN_MAX_REG_ENTRIES.get()> reg_entries;

        /// @brief stores the number of MSR entries
        uint64_t num_msr_entries;
        /// @brief stores the MSR entries
        bsl::array<mv_rdl_entry_t, MV_RUN_MAX_MSR_ENTRIES.get()> msr_entries;

        /// @brief stores the number of iomem
        uint64_t num_iomem;
        /// @brief stores the memory region buffer
        bsl::array<uint8_t, MV_RUN_MAX_IOMEM_SIZE.get()> iomem;
    };

    struct mv_run_return_t final
    {
        uint64_t rflags;
        uint64_t cr8;
        uint64_t apic_base;
        union
        {
            struct mv_exit_io_t mv_exit_io;
            struct mv_exit_mmio_t mv_exit_mmio;
        };
    };

}

#pragma pack(pop)

#endif
