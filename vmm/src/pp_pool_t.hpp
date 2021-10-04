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
#include <page_pool_t.hpp>
#include <pp_t.hpp>
#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::pp_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's PP pool
    ///
    class pp_pool_t final
    {
        /// @brief stores the pool of pp_t objects
        bsl::array<pp_t, HYPERVISOR_MAX_PPS.get()> m_pool{};

        /// <!-- description -->
        ///   @brief Returns the pp_t associated with the provided ppid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ppid the ID of the pp_t to get
        ///   @return Returns the pp_t associated with the provided ppid.
        ///
        [[nodiscard]] constexpr auto
        get_pp(bsl::safe_u16 const &ppid) noexcept -> pp_t *
        {
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(ppid));
        }

        /// <!-- description -->
        ///   @brief Returns the pp_t associated with the provided ppid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ppid the ID of the pp_t to get
        ///   @return Returns the pp_t associated with the provided ppid.
        ///
        [[nodiscard]] constexpr auto
        get_pp(bsl::safe_u16 const &ppid) const noexcept -> pp_t const *
        {
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(ppid));
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this pp_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic) noexcept
        {
            for (bsl::safe_idx mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                m_pool.at_if(mut_i)->initialize(gs, tls, mut_sys, intrinsic, bsl::to_u16(mut_i));
            }
        }

        /// <!-- description -->
        ///   @brief Release the pp_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic) noexcept
        {
            for (auto &mut_pp : m_pool) {
                mut_pp.release(gs, tls, mut_sys, intrinsic);
            }
        }

        /// <!-- description -->
        ///   @brief Allocates a PP and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns ID of the newly allocated pp_t. Returns
        ///     bsl::safe_u16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            page_pool_t const &page_pool,
            intrinsic_t const &intrinsic) noexcept -> bsl::safe_u16
        {
            return this->get_pp(mut_sys.bf_tls_ppid())
                ->allocate(gs, tls, mut_sys, page_pool, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Clears the SPA of the shared page associated with the
        ///     requested pp_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///
        constexpr void
        clr_shared_page_spa(syscall::bf_syscall_t &mut_sys) noexcept
        {
            this->get_pp(mut_sys.bf_tls_ppid())->clr_shared_page_spa(mut_sys);
        }

        /// <!-- description -->
        ///   @brief Sets the SPA of the shared page associated with the
        ///     requested pp_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param spa the system physical address of the shared page
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_shared_page_spa(syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &spa) noexcept
            -> bsl::errc_type
        {
            return this->get_pp(mut_sys.bf_tls_ppid())->set_shared_page_spa(mut_sys, spa);
        }

        /// <!-- description -->
        ///   @brief Returns the PP's TSC frequency in KHz. If the TSC
        ///     frequency has not yet been set, bsl::safe_u64::failure is
        ///     returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @return Returns the PP's TSC frequency in KHz. If the TSC
        ///     frequency has not yet been set, bsl::safe_u64::failure is
        ///     returned.
        ///
        [[nodiscard]] constexpr auto
        tsc_khz_get(syscall::bf_syscall_t const &sys) const noexcept -> bsl::safe_u64
        {
            return this->get_pp(sys.bf_tls_ppid())->tsc_khz_get();
        }

        /// <!-- description -->
        ///   @brief Sets the PP's TSC frequency in KHz.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param tsc_khz the new TSC frequency
        ///
        constexpr void
        tsc_khz_set(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &tsc_khz) noexcept
        {
            this->get_pp(sys.bf_tls_ppid())->tsc_khz_set(tsc_khz);
        }

        /// <!-- description -->
        ///   @brief Returns a pp_unique_map_t<T> given an SPA to map. If an
        ///     error occurs, an invalid pp_unique_map_t<T> is returned.
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
        map(syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &spa) noexcept -> pp_unique_map_t<T>
        {
            return this->get_pp(mut_sys.bf_tls_ppid())->map<T>(mut_sys, spa);
        }

        /// <!-- description -->
        ///   @brief Returns a pp_unique_shared_page_t<T> if the shared page
        ///     is not currently in use. If an error occurs, returns an invalid
        ///     pp_unique_shared_page_t<T>.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of shared page to return
        ///   @param mut_sys the bf_syscall_t to use
        ///   @return Returns a pp_unique_shared_page_t<T> if the shared page
        ///     is not currently in use. If an error occurs, returns an invalid
        ///     pp_unique_shared_page_t<T>.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        shared_page(syscall::bf_syscall_t &mut_sys) noexcept -> pp_unique_shared_page_t<T>
        {
            return this->get_pp(mut_sys.bf_tls_ppid())->shared_page<T>(mut_sys);
        }

        /// <!-- description -->
        ///   @brief Set the list of supported CPUIDs of the requested pp_t into
        ///     a CDL shared page.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param ppid the ID of the pp_t to clear the SPA for
        ///   @param mut_cdl the mv_cdl_t in which the supported CPUID are set.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///    otherwise.
        ///
        [[nodiscard]] constexpr auto
        cpuid_get_supported_list(
            syscall::bf_syscall_t &mut_sys,
            bsl::safe_u16 const &ppid,
            hypercall::mv_cdl_t &mut_cdl) noexcept -> bsl::errc_type
        {
            return this->get_pp(ppid)->cpuid_get_supported_list(mut_sys, mut_cdl);
        }

        /// <!-- description -->
        ///   @brief Set the list of supported MSRs of the requested pp_t into
        ///     an RDL shared page.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param ppid the ID of the pp_t to clear the SPA for
        ///   @param mut_rdl the mv_rdl_t in which the supported MSR are set.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///    otherwise.
        ///
        [[nodiscard]] constexpr auto
        msr_get_supported_list(
            syscall::bf_syscall_t &mut_sys,
            bsl::safe_u16 const &ppid,
            hypercall::mv_rdl_t &mut_rdl) noexcept -> bsl::errc_type
        {
            return this->get_pp(ppid)->msr_get_supported_list(mut_sys, mut_rdl);
        }
    };
}

#endif
