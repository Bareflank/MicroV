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

#ifndef MV_MP_STATE_T_HPP
#define MV_MP_STATE_T_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// <!-- description -->
    ///   @brief Defines the multiprocessor state of a VS
    ///
    enum class mv_mp_state_t : bsl::int32
    {
        /// @brief the initial state of the VS
        mv_mp_state_t_initial = 0,
        /// @brief the VS is running
        mv_mp_state_t_running = 1,
        /// @brief the VS is waiting for an interrupt
        mv_mp_state_t_wait = 2,
        /// @brief the VS is waiting for INIT (x86 only)
        mv_mp_state_t_init = 3,
        /// @brief the VS is waiting for SIPI (x86 only)
        mv_mp_state_t_sipi = 4,
    };

    /// <!-- description -->
    ///   @brief return bsl::to_i32(static_cast<bsl::int32>(val))
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the mv_reg_t to convert
    ///   @return return bsl::to_i32(static_cast<bsl::int32>(val))
    ///
    [[nodiscard]] constexpr auto
    to_i32(mv_mp_state_t const &val) noexcept -> bsl::safe_i32
    {
        return bsl::to_i32(static_cast<bsl::int32>(val));
    }

    /// @brief integer version of mv_mp_state_t_initial
    constexpr auto MP_STATE_INITIAL{to_i32(mv_mp_state_t::mv_mp_state_t_initial)};
    /// @brief integer version of mv_mp_state_t_running
    constexpr auto MP_STATE_RUNNING{to_i32(mv_mp_state_t::mv_mp_state_t_running)};
    /// @brief integer version of mv_mp_state_t_wait
    constexpr auto MP_STATE_WAIT{to_i32(mv_mp_state_t::mv_mp_state_t_wait)};
    /// @brief integer version of mv_mp_state_t_init
    constexpr auto MP_STATE_INIT{to_i32(mv_mp_state_t::mv_mp_state_t_init)};
    /// @brief integer version of mv_mp_state_t_sipi
    constexpr auto MP_STATE_SIPI{to_i32(mv_mp_state_t::mv_mp_state_t_sipi)};
}

#endif
