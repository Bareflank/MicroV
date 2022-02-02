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

#ifndef MV_EXIT_IO_T_HPP
#define MV_EXIT_IO_T_HPP

#include <mv_bit_size_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace hypercall
{
    /// @brief The mv_exit_io_t defines an input access
    constexpr auto MV_EXIT_IO_IN{0x0000000000000000_u64};
    /// @brief The mv_exit_io_t defines an output access
    constexpr auto MV_EXIT_IO_OUT{0x0000000000000001_u64};

    /// <!-- description -->
    ///   @brief See mv_vs_op_run for more details
    ///
    struct mv_exit_io_t final
    {
        /// @brief stores the address of the IO register
        bsl::uint64 addr;
        /// @brief stores the data to read/write
        bsl::uint64 data;
        /// @brief stores the number of repetitions to make
        bsl::uint64 reps;
        /// @brief stores MV_EXIT_IO flags
        bsl::uint64 type;
        /// @brief stores defines the bit size of the dst
        mv_bit_size_t size;
    };
}

#pragma pack(pop)

#endif
