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

#ifndef MV_CPUID_FLAG_T_HPP
#define MV_CPUID_FLAG_T_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// <!-- description -->
    ///   @brief Defines CPUID flags
    ///
    enum class mv_cpuid_flag_t : bsl::int32
    {
        /// @brief reserved
        mv_cpuid_flag_t_reserved = 0,
    };

    /// <!-- description -->
    ///   @brief return bsl::to_i32(static_cast<bsl::int32>(val))
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the mv_reg_t to convert
    ///   @return return bsl::to_i32(static_cast<bsl::int32>(val))
    ///
    [[nodiscard]] constexpr auto
    to_i32(mv_cpuid_flag_t const &val) noexcept -> bsl::safe_i32
    {
        return bsl::to_i32(static_cast<bsl::int32>(val));
    }

    /// @brief integer version of mv_cpuid_flag_t_reserved
    constexpr auto CPUID_FLAG_RESERVED{to_i32(mv_cpuid_flag_t::mv_cpuid_flag_t_reserved)};
}

#endif
