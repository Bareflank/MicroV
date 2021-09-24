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

#ifndef MV_BIT_SIZE_T_HPP
#define MV_BIT_SIZE_T_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// <!-- description -->
    ///   @brief Defines different bit sizes for address, operands, etc.
    ///
    enum class mv_bit_size_t : bsl::int32
    {
        /// @brief indicates 8 bits
        mv_bit_size_t_8 = 0,
        /// @brief indicates 16 bits
        mv_bit_size_t_16 = 1,
        /// @brief indicates 32 bits
        mv_bit_size_t_32 = 2,
        /// @brief indicates 64 bits
        mv_bit_size_t_64 = 3,
    };

    /// <!-- description -->
    ///   @brief return bsl::to_i32(static_cast<bsl::int32>(val))
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the mv_reg_t to convert
    ///   @return return bsl::to_i32(static_cast<bsl::int32>(val))
    ///
    [[nodiscard]] constexpr auto
    to_i32(mv_bit_size_t const &val) noexcept -> bsl::safe_i32
    {
        return bsl::to_i32(static_cast<bsl::int32>(val));
    }

    /// @brief integer version of mv_bit_size_t_8
    constexpr auto BIT_SIZE_8{to_i32(mv_bit_size_t::mv_bit_size_t_8)};
    /// @brief integer version of mv_bit_size_t_16
    constexpr auto BIT_SIZE_16{to_i32(mv_bit_size_t::mv_bit_size_t_16)};
    /// @brief integer version of mv_bit_size_t_32
    constexpr auto BIT_SIZE_32{to_i32(mv_bit_size_t::mv_bit_size_t_32)};
    /// @brief integer version of mv_bit_size_t_64
    constexpr auto BIT_SIZE_64{to_i32(mv_bit_size_t::mv_bit_size_t_64)};
}

#endif
