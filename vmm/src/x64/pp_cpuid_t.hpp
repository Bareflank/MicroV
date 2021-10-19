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

#ifndef PP_CPUID_T_HPP
#define PP_CPUID_T_HPP

#include <bf_syscall_t.hpp>
#include <cpuid.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_cdl_entry_t.hpp>
#include <mv_cdl_t.hpp>
#include <mv_constants.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::pp_cpuid_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's physical processor CPUID handler.
    ///
    class pp_cpuid_t final
    {
        /// @brief stores the ID of the PP associated with this pp_cpuid_t
        bsl::safe_u16 m_assigned_ppid{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this pp_cpuid_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param ppid the ID of the PP this pp_cpuid_t is assigned to
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
        ///   @brief Release the pp_cpuid_t.
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
        ///     pp_cpuid_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     pp_cpuid_t
        ///
        [[nodiscard]] constexpr auto
        assigned_ppid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_ppid.is_valid_and_checked());
            return ~m_assigned_ppid;
        }

        /// NOTE:
        /// - supported(): Given a function (EAX) and index (ECX)
        ///   returns a mv_cpuid_entry_t. Any feature that is supported
        ///   is enabled in the resulting values of eax, ebx, ecx and
        ///   edx. Any non-feature bits should be returned as 0. By
        ///   "supported", we mean that the hardware HAS this feature,
        ///   and MicroV allows the guest to use this feature. When
        ///   the guest calls CPUID, MicroV will return supported.
        ///

        /// NOTE:
        /// - emulated(): Given a function (EAX) and index (ECX)
        ///   returns a mv_cpuid_entry_t. Any feature that is emulated
        ///   is enabled in the resulting values of eax, ebx, ecx and
        ///   edx. Any non-feature bits should be returned as 0. By
        ///   "emulated", we mean that the hardware DOES NOT HAVE this
        ///   feature, but MicroV allows the guest to use this feature
        ///   anyway by means of emulated. When the guest calls CPUID,
        ///   MicroV will return supported. The best example is the
        ///   x2APIC. Since MicroV has to emulate this anyway, even if
        ///   the hardware doesn't support this feature, MicroV can
        ///   allow the guest to use it's emulated x2APIC which would
        ///   be faster than forcing the guest to use the x1APIC.
        ///

        /// NOTE:
        /// - permissable(): Given a function (EAX) and index (ECX)
        ///   returns a mv_cpuid_entry_t. For now, return supported().
        ///

        /// <!-- description -->
        ///   @brief  Given a function (EAX) and index (ECX)
        ///    returns a mv_cdl_entry_t. Any feature that is supported
        ///    is enabled in the resulting values of eax, ebx, ecx and
        ///    edx. Any non-feature bits should be returned as 0. By
        ///    "supported", we mean that the hardware HAS this feature,
        ///    and MicroV allows the guest to use this feature. When
        ///    the guest calls CPUID, MicroV will return supported.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param fun the CPUID function
        ///   @param idx the CPUID index
        ///   @return Returns mv_cdl_entry_t
        ///
        [[nodiscard]] constexpr auto
        supported(
            syscall::bf_syscall_t const &sys,
            bsl::safe_u32 const &fun,
            bsl::safe_u32 const &idx) const noexcept -> hypercall::mv_cdl_entry_t
        {
            bsl::expects(sys.bf_tls_ppid() == this->assigned_ppid());

            auto mut_eax{bsl::to_u64(fun)};
            bsl::safe_u64 mut_ebx{};
            auto mut_ecx{bsl::to_u64(idx)};
            bsl::safe_u64 mut_edx{};

            intrinsic_t::cpuid(mut_eax, mut_ebx, mut_ecx, mut_edx);

            switch (fun.get()) {
                case CPUID_FN0000_0000.get():
                    [[fallthrough]];
                case CPUID_FN8000_0000.get(): {
                    mut_ebx = bsl::safe_u64::magic_0();
                    mut_ecx = bsl::safe_u64::magic_0();
                    mut_edx = bsl::safe_u64::magic_0();
                    break;
                }

                case CPUID_FN0000_0001.get(): {
                    mut_eax = bsl::safe_u64::magic_0();
                    mut_ebx = bsl::safe_u64::magic_0();
                    mut_ecx &= CPUID_FN0000_0001_ECX;
                    mut_ecx |= CPUID_FN0000_0001_ECX_HYPERVISOR_BIT;
                    mut_edx &= CPUID_FN0000_0001_EDX;
                    break;
                }

                case CPUID_FN8000_0001.get(): {
                    mut_eax = bsl::safe_u64::magic_0();
                    mut_ebx = bsl::safe_u64::magic_0();
                    mut_ecx &= CPUID_FN8000_0001_ECX;
                    mut_edx &= CPUID_FN8000_0001_EDX;
                    break;
                }

                default: {
                    mut_eax = {};
                    mut_ebx = {};
                    mut_ecx = {};
                    mut_edx = {};
                    break;
                }
            }

            return {
                .fun = fun.get(),
                .idx = idx.get(),
                .eax = bsl::to_u32_unsafe(mut_eax).get(),
                .ebx = bsl::to_u32_unsafe(mut_ebx).get(),
                .ecx = bsl::to_u32_unsafe(mut_ecx).get(),
                .edx = bsl::to_u32_unsafe(mut_edx).get(),
            };
        }

        /// <!-- description -->
        ///   @brief Set the list of supported CPUIDs into the shared page using
        ///    a CDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_cdl the mv_cdl_t in which the supported MSR are set.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///    otherwise.
        ///
        [[nodiscard]] constexpr auto
        supported_list(syscall::bf_syscall_t const &sys, hypercall::mv_cdl_t &mut_cdl)
            const noexcept -> bsl::errc_type
        {
            bsl::expects(sys.bf_tls_ppid() == this->assigned_ppid());

            for (bsl::safe_idx mut_i{}; mut_i < mut_cdl.num_entries; ++mut_i) {
                auto *const pmut_entry{mut_cdl.entries.at_if(mut_i)};
                *pmut_entry =
                    supported(sys, bsl::to_u32(pmut_entry->fun), bsl::to_u32(pmut_entry->idx));
            }

            return bsl::errc_success;
        }
    };
}

#endif
