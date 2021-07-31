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

#ifndef EMULATED_CR_T_HPP
#define EMULATED_CR_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::emulated_cr_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's emulated CR handler.
    ///
    ///   @note IMPORTANT: This class is a per-VS class, and all accesses
    ///     to the control registers from a VM (root or guest) must come from
    ///     this class.
    ///
    ///   @note IMPORTANT: We only need to trap on CR accesses in the root
    ///     to ensure that certain bits are hidden, like the VT-x enable
    ///     bit on Intel. In the guest, we need to actually emulate each
    ///     control register. To start, I would not use a CR shadow. This
    ///     means that all reads/writes to the control registers are handled
    ///     here. Once these are working properly, shadow CRs can be added so
    ///     that only writes to the control registers are trapped.
    ///
    class emulated_cr_t final
    {
        /// @brief stores the ID of the VS associated with this emulated_cr_t
        bsl::safe_u16 m_assigned_vsid{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this emulated_cr_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_cr_t
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) noexcept
        {
            bsl::expects(this->assigned_vsid() == syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_vsid = ~vsid;
        }

        /// <!-- description -->
        ///   @brief Release the emulated_cr_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_vsid = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP associated with this
        ///     emulated_cr_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     emulated_cr_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vsid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vsid.is_valid_and_checked());
            return ~m_assigned_vsid;
        }
    };
}

#endif
