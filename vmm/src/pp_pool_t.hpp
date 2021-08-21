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

#ifndef PP_POOL_T_HPP
#define PP_POOL_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <pp_t.hpp>
#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/finally_assert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::pp_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines Microv's physical processor pool.
    ///
    class pp_pool_t final
    {
        /// @brief stores the pool of PPs
        bsl::array<pp_t, HYPERVISOR_MAX_PPS.get()> m_pool{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this pp_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::finally_assert mut_release_on_error{
                [this, &gs, &tls, &sys, &intrinsic]() noexcept -> void {
                    this->release(gs, tls, sys, intrinsic);
                }};

            for (bsl::safe_uintmax mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                auto const ret{
                    m_pool.at_if(mut_i)->initialize(gs, tls, sys, intrinsic, bsl::to_u16(mut_i))};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            mut_release_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the pp_pool_t.
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
            for (bsl::safe_uintmax mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                m_pool.at_if(mut_i)->release(gs, tls, sys, intrinsic);
            }
        }

        /// <!-- description -->
        ///   @brief Reads CPUID on the physical processor using the values
        ///     stored in the eax, ebx, ecx, and edx registers provided by the
        ///     syscall layer and stores the results in the same registers.
        ///
        /// <!-- notes -->
        ///   @note Uses the current PP
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        cpuid_get(gs_t const &gs, syscall::bf_syscall_t &mut_sys, intrinsic_t const &intrinsic)
            const noexcept -> bsl::errc_type
        {
            auto const *const pp{m_pool.at_if(bsl::to_umax(mut_sys.bf_tls_ppid()))};
            if (bsl::unlikely(nullptr == pp)) {
                bsl::error() << "the syscall layer returned an invalid ppid of "    // --
                             << bsl::hex(mut_sys.bf_tls_ppid())                     // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return bsl::errc_failure;
            }

            return pp->cpuid_get(gs, mut_sys, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Please see m_pp_mmio.map() for details as there are a
        ///     lot and they are important to understand.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type to map and return
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param spa the system physical address of the T * to return.
        ///   @return Returns the resulting T * given the SPA, or a nullptr
        ///     on error.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        map(syscall::bf_syscall_t &mut_sys, bsl::safe_uintmax const &spa) noexcept
            -> pp_unique_map_t<T>
        {
            auto *const pmut_pp{m_pool.at_if(bsl::to_umax(mut_sys.bf_tls_ppid()))};
            if (bsl::unlikely(nullptr == pmut_pp)) {
                bsl::error() << "the syscall layer returned an invalid ppid of "    // --
                             << bsl::hex(mut_sys.bf_tls_ppid())                     // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return pp_unique_map_t<T>{};
            }

            return pmut_pp->map<T>(mut_sys, spa);
        }
    };
}

#endif
