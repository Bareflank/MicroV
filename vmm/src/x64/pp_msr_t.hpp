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

#ifndef PP_MSR_T_HPP
#define PP_MSR_T_HPP

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
    /// @class microv::pp_msr_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's physical processor MSR handler.
    ///
    class pp_msr_t final
    {
        /// @brief stores the ID of the PP associated with this pp_msr_t
        bsl::safe_u16 m_assigned_ppid{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this pp_msr_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param ppid the ID of the PP this pp_msr_t is assigned to
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &ppid) noexcept
        {
            bsl::expects(this->assigned_ppid() == syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_ppid = ~ppid;
        }

        /// <!-- description -->
        ///   @brief Release the pp_msr_t.
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

            m_assigned_ppid = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP associated with this
        ///     pp_msr_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     pp_msr_t
        ///
        [[nodiscard]] constexpr auto
        assigned_ppid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_ppid.is_valid_and_checked());
            return ~m_assigned_ppid;
        }

        /// NOTE:
        /// - supported(): Given the address of an MSR (32bit), returns
        ///   an mv_rdl_entry_t, with "reg" set to the provided address.
        ///   If the MSR is supported, "val" is set to 1. If the MSR is
        ///   not supported, "va1" is set to 0. By supported, if the
        ///   hardware HAS support for the MSR, and MicroV properly handles
        ///   the MSR, a 1 is returned. To determine if an MSR is supported,
        ///   a hardcoded switch statement should be created. A supported
        ///   MSR has a defined "case", and the MSR is read. If a failure
        ///   is encountered, which will cause the microkernel to have to
        ///   safely handle a GPF, an mv_rdl_entry_t with val set to 0 is
        ///   returned. Any MSR address that is not supported will hit the
        ///   default case an always return val set to 0. Val is only set
        ///   to 1 when the MSR is supported, and a read() does not report
        ///   a failure.
        ///
        ///   For now, the only MSRs that should be reported as supported
        ///   are MSRs that are in AMD's VMCB, and the APIC BASE. We can add
        ///   more later as needed.
        ///

        /// NOTE:
        /// - emulated(): Given the address of an MSR (32bit), returns
        ///   an mv_rdl_entry_t, with "reg" set to the provided address.
        ///   If the MSR is emulated, "val" is set to 1. If the MSR is
        ///   not emulated, "va1" is set to 0. By emulated, if the
        ///   hardware DOES NOT HAVE support for the MSR, and MicroV properly
        ///   handles the MSR anyways, a 1 is returned.
        ///
        ///   For now, we will always return 0, so no code is needed here
        ///

        /// NOTE:
        /// - permissable(): Given the address of an MSR (32bit), returns
        ///   an mv_rdl_entry_t, with "reg" set to the provided address.
        ///   If the MSR is allowed to be read by userspace, "val" is set to 1.
        ///   If the MSR is not allowed to be read by userspace, "va1" is set
        ///   to 0.
        ///
        ///   Ideally we would always return 0. We don't trust the root OS,
        ///   and therefore we don't want to give it more information about
        ///   the guest than it needs. To start however, we should simply
        ///   return whatever supported() returns. If it is supported(),
        ///   it is permissable(), and in the future we can restrict what
        ///   QEMU gets with a little research into what it actually needs.
        ///
    };
}

#endif
