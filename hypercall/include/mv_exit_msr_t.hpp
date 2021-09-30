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

#ifndef MV_EXIT_MMIO_T_HPP
#define MV_EXIT_MMIO_T_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace hypercall
{
    /// @brief mv_exit_mmio_t defines a read access
    constexpr auto MV_EXIT_MMIO_READ{0x0000000000000001_u64};
    /// @brief mv_exit_mmio_t defines a write access
    constexpr auto MV_EXIT_MMIO_WRITE{0x0000000000000002_u64};
    /// @brief mv_exit_mmio_t defines an execute access
    constexpr auto MV_EXIT_MMIO_EXECUTE{0x0000000000000004_u64};

    /// <!-- description -->
    ///   @brief See mv_vs_op_run for more details
    ///
    struct mv_exit_mmio_t final
    {
        /// @brief stores the GPA of the MMIO access
        bsl::uint64 gpa;
        /// @brief stores the MV_EXIT_MMIO flags
        bsl::uint64 flags;
    };
}

#pragma pack(pop)

#endif
