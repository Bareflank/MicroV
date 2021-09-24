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

#ifndef EMULATED_DR_T_HPP
#define EMULATED_DR_T_HPP

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
    /// @class microv::emulated_dr_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's emulated debug register handler.
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
    class emulated_dr_t final
    {
        /// @brief stores the ID of the VS associated with this emulated_dr_t
        bsl::safe_u16 m_assigned_vsid{};

        /// @brief stores the value of dr0;
        bsl::safe_u64 m_dr0{};
        /// @brief stores the value of dr1;
        bsl::safe_u64 m_dr1{};
        /// @brief stores the value of dr2;
        bsl::safe_u64 m_dr2{};
        /// @brief stores the value of dr3;
        bsl::safe_u64 m_dr3{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this emulated_dr_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_dr_t
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
        ///   @brief Release the emulated_dr_t.
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

            m_dr3 = {};
            m_dr2 = {};
            m_dr1 = {};
            m_dr0 = {};

            m_assigned_vsid = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP associated with this
        ///     emulated_dr_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     emulated_dr_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vsid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vsid.is_valid_and_checked());
            return ~m_assigned_vsid;
        }

        /// <!-- description -->
        ///   @brief Returns the emulated value of DR0
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the emulated value of DR0
        ///
        [[nodiscard]] constexpr auto
        get_dr0() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_dr0.is_valid_and_checked());
            return m_dr0;
        }

        /// <!-- description -->
        ///   @brief Sets the value of the emulated DR0
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set DR0 to
        ///
        constexpr void
        set_dr0(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());
            m_dr0 = val;
        }

        /// <!-- description -->
        ///   @brief Returns the emulated value of DR1
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the emulated value of DR1
        ///
        [[nodiscard]] constexpr auto
        get_dr1() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_dr1.is_valid_and_checked());
            return m_dr1;
        }

        /// <!-- description -->
        ///   @brief Sets the value of the emulated DR1
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set DR1 to
        ///
        constexpr void
        set_dr1(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());
            m_dr1 = val;
        }

        /// <!-- description -->
        ///   @brief Returns the emulated value of DR2
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the emulated value of DR2
        ///
        [[nodiscard]] constexpr auto
        get_dr2() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_dr2.is_valid_and_checked());
            return m_dr2;
        }

        /// <!-- description -->
        ///   @brief Sets the value of the emulated DR2
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set DR2 to
        ///
        constexpr void
        set_dr2(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());
            m_dr2 = val;
        }

        /// <!-- description -->
        ///   @brief Returns the emulated value of DR3
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the emulated value of DR3
        ///
        [[nodiscard]] constexpr auto
        get_dr3() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_dr3.is_valid_and_checked());
            return m_dr3;
        }

        /// <!-- description -->
        ///   @brief Sets the value of the emulated DR3
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set DR3 to
        ///
        constexpr void
        set_dr3(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());
            m_dr3 = val;
        }
    };
}

#endif
