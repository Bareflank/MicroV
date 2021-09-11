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

#ifndef EMULATED_CPUID_T_HPP
#define EMULATED_CPUID_T_HPP

#include <bf_syscall_t.hpp>
#include <cpuid_commands.hpp>
#include <errc_types.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::emulated_cpuid_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's emulated CPUID handler.
    ///
    ///   @note IMPORTANT: This class is a per-VS class, and all accesses
    ///     to CPUID from a VM (root or guest) must come from this class.
    ///
    class emulated_cpuid_t final
    {
        /// @brief stores the ID of the VS associated with this emulated_cpuid_t
        bsl::safe_u16 m_assigned_vsid{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this emulated_cpuid_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_cpuid_t
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
        ///   @brief Release the emulated_cpuid_t.
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
        ///     emulated_cpuid_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     emulated_cpuid_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vsid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vsid.is_valid_and_checked());
            return ~m_assigned_vsid;
        }

        /// <!-- description -->
        ///   @brief Reads CPUID on the physical processor using the values
        ///     stored in the eax, ebx, ecx, and edx registers provided by the
        ///     syscall layer and stores the results in the same registers.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise. If the PP was asked to promote the VS,
        ///     vmexit_success_promote is returned.
        ///
        [[nodiscard]] static constexpr auto
        get_root(syscall::bf_syscall_t &mut_sys, intrinsic_t const &intrinsic) noexcept
            -> bsl::errc_type
        {
            auto mut_rax{mut_sys.bf_tls_rax()};
            auto mut_rcx{mut_sys.bf_tls_rcx()};

            if (loader::CPUID_COMMAND_EAX == bsl::to_u32_unsafe(mut_rax)) {
                switch (bsl::to_u32_unsafe(mut_rcx).get()) {
                    case loader::CPUID_COMMAND_ECX_STOP.get(): {
                        bsl::debug() << bsl::rst << "about to"                         // --
                                     << bsl::red << " promote "                        // --
                                     << bsl::rst << "root OS on pp "                   // --
                                     << bsl::cyn << bsl::hex(mut_sys.bf_tls_ppid())    // --
                                     << bsl::rst << bsl::endl;                         // --

                        mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);
                        return vmexit_success_promote;
                    }

                    case loader::CPUID_COMMAND_ECX_REPORT_ON.get(): {
                        bsl::debug() << bsl::rst << "root OS had been"                 // --
                                     << bsl::grn << " demoted "                        // --
                                     << bsl::rst << "to vm "                           // --
                                     << bsl::cyn << bsl::hex(mut_sys.bf_tls_vmid())    // --
                                     << bsl::rst << " on pp "                          // --
                                     << bsl::cyn << bsl::hex(mut_sys.bf_tls_ppid())    // --
                                     << bsl::rst << bsl::endl;                         // --

                        mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);
                        return bsl::errc_success;
                    }

                    case loader::CPUID_COMMAND_ECX_REPORT_OFF.get(): {
                        mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);
                        return bsl::errc_success;
                    }

                    default: {
                        break;
                    }
                }

                bsl::error() << "unsupported cpuid command "    // --
                             << bsl::hex(mut_rcx)               // --
                             << bsl::endl                       // --
                             << bsl::here();                    // --

                mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_FAILURE);
                return bsl::errc_failure;
            }

            auto mut_rbx{mut_sys.bf_tls_rbx()};
            auto mut_rdx{mut_sys.bf_tls_rdx()};
            intrinsic.cpuid(mut_rax, mut_rbx, mut_rcx, mut_rdx);

            mut_sys.bf_tls_set_rax(mut_rax);
            mut_sys.bf_tls_set_rbx(mut_rbx);
            mut_sys.bf_tls_set_rcx(mut_rcx);
            mut_sys.bf_tls_set_rdx(mut_rdx);

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Reads CPUID on the physical processor using the values
        ///     stored in the eax, ebx, ecx, and edx registers provided by the
        ///     syscall layer and stores the results in the same registers.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise. If the PP was asked to promote the VS,
        ///     vmexit_success_promote is returned.
        ///
        [[nodiscard]] static constexpr auto
        get_guest(syscall::bf_syscall_t const &sys, intrinsic_t const &intrinsic) noexcept
            -> bsl::errc_type
        {
            bsl::discard(sys);
            bsl::discard(intrinsic);

            bsl::error() << "get_guest not implemented\n";
            return bsl::errc_failure;
        }
    };
}

#endif
