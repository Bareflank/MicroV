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

#ifndef MV_EXIT_REASON_T_HPP
#define MV_EXIT_REASON_T_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// <!-- description -->
    ///   @brief Defines different bit sizes for address, operands, etc.
    ///
    enum class mv_exit_reason_t : bsl::int32
    {
        /// @brief returned on error
        mv_exit_reason_t_failure = 0,
        /// @brief an unknown/unsupported VMExit has occurred
        mv_exit_reason_t_unknown = 1,
        /// @brief a halt event has occurred
        mv_exit_reason_t_hlt = 2,
        /// @brief a IO event has occurred
        mv_exit_reason_t_io = 3,
        /// @brief a MMIO event has occurred
        mv_exit_reason_t_mmio = 4,
    };

    /// <!-- description -->
    ///   @brief return bsl::to_i32(static_cast<bsl::int32>(val))
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the mv_reg_t to convert
    ///   @return return bsl::to_i32(static_cast<bsl::int32>(val))
    ///
    [[nodiscard]] constexpr auto
    to_i32(mv_exit_reason_t const &val) noexcept -> bsl::safe_i32
    {
        return bsl::to_i32(static_cast<bsl::int32>(val));
    }

    /// @brief integer version of mv_exit_reason_t_failure
    constexpr auto EXIT_REASON_FAILURE{to_i32(mv_exit_reason_t::mv_exit_reason_t_failure)};
    /// @brief integer version of mv_exit_reason_t_unknown
    constexpr auto EXIT_REASON_UNKNOWN{to_i32(mv_exit_reason_t::mv_exit_reason_t_unknown)};
    /// @brief integer version of mv_exit_reason_t_hlt
    constexpr auto EXIT_REASON_HLT{to_i32(mv_exit_reason_t::mv_exit_reason_t_hlt)};
    /// @brief integer version of mv_exit_reason_t_io
    constexpr auto EXIT_REASON_IO{to_i32(mv_exit_reason_t::mv_exit_reason_t_io)};
    /// @brief integer version of mv_exit_reason_t_mmio
    constexpr auto EXIT_REASON_MMIO{to_i32(mv_exit_reason_t::mv_exit_reason_t_mmio)};
}

#endif
