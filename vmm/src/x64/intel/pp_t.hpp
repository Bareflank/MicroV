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

#ifndef PP_T_HPP
#define PP_T_HPP

#include <allocated_status_t.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <pp_cpuid_t.hpp>
#include <pp_lapic_t.hpp>
#include <pp_mmio_t.hpp>
#include <pp_msr_t.hpp>
#include <pp_mtrrs_t.hpp>
#include <pp_reg_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/ensures.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>

namespace microv
{
    /// @class microv::pp_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's notion of a PP
    ///
    class pp_t final
    {
        /// @brief stores the ID associated with this pp_t
        bsl::safe_u16 m_id{};

        /// @brief stores this pp_t's pp_cpuid_t
        pp_cpuid_t m_pp_cpuid{};
        /// @brief stores this pp_t's pp_lapic_t
        pp_lapic_t m_pp_lapic{};
        /// @brief stores this pp_t's pp_mmio_t
        pp_mmio_t m_pp_mmio{};
        /// @brief stores this pp_t's pp_msr_t
        pp_msr_t m_pp_msr{};
        /// @brief stores this pp_t's pp_mtrrs_t
        pp_mtrrs_t m_pp_mtrrs{};
        /// @brief stores this pp_t's pp_reg_t
        pp_reg_t m_pp_reg{};

        /// @brief stores the TSC frequency in KHz of this pp_t
        bsl::safe_u64 m_tsc_khz{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this pp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param i the ID for this pp_t
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &i) noexcept
        {
            bsl::expects(this->id() == syscall::BF_INVALID_ID);

            m_pp_cpuid.initialize(gs, tls, mut_sys, intrinsic, i);
            m_pp_lapic.initialize(gs, tls, mut_sys, intrinsic, i);
            m_pp_mmio.initialize(gs, tls, mut_sys, intrinsic, i);
            m_pp_msr.initialize(gs, tls, mut_sys, intrinsic, i);
            m_pp_mtrrs.initialize(gs, tls, mut_sys, intrinsic, i);
            m_pp_reg.initialize(gs, tls, mut_sys, intrinsic, i);

            m_id = ~i;
        }

        /// <!-- description -->
        ///   @brief Release the pp_t.
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
            m_pp_reg.release(gs, tls, mut_sys, intrinsic);
            m_pp_mtrrs.release(gs, tls, mut_sys, intrinsic);
            m_pp_msr.release(gs, tls, mut_sys, intrinsic);
            m_pp_mmio.release(gs, tls, mut_sys, intrinsic);
            m_pp_lapic.release(gs, tls, mut_sys, intrinsic);
            m_pp_cpuid.release(gs, tls, mut_sys, intrinsic);

            m_tsc_khz = {};
            m_id = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this pp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this pp_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_id.is_valid_and_checked());
            return ~m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates the pp_t and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns ID of this pp_t
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            page_pool_t const &page_pool,
            intrinsic_t const &intrinsic) const noexcept -> bsl::safe_u16
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(page_pool);
            bsl::discard(intrinsic);

            /// TODO:
            /// - We need to detect all of the features that we need
            ///   support for here and error out if the CPU does not
            ///   support the features that we need. This includes
            ///
            ///   - CPUID
            ///   - MSRs
            ///

            return this->id();
        }

        /// <!-- description -->
        ///   @brief Clears the SPA of the shared page associated with
        ///     this pp_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///
        constexpr void
        clr_shared_page_spa(syscall::bf_syscall_t &mut_sys) noexcept
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            m_pp_mmio.clr_shared_page_spa(mut_sys);
        }

        /// <!-- description -->
        ///   @brief Sets the SPA of the shared page associated with
        ///     this pp_t.
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
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            return m_pp_mmio.set_shared_page_spa(mut_sys, spa);
        }

        /// <!-- description -->
        ///   @brief Returns the pp_t's TSC frequency in KHz.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the pp_t's TSC frequency in KHz.
        ///
        [[nodiscard]] constexpr auto
        tsc_khz_get() const noexcept -> bsl::safe_u64
        {
            bsl::ensures(m_tsc_khz.is_valid_and_checked());
            return m_tsc_khz;
        }

        /// <!-- description -->
        ///   @brief Sets the pp_t's TSC frequency in KHz.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tsc_khz the new TSC frequency
        ///
        constexpr void
        tsc_khz_set(bsl::safe_u64 const &tsc_khz) noexcept
        {
            bsl::ensures(tsc_khz.is_valid_and_checked());
            bsl::ensures(tsc_khz.is_pos());

            bsl::debug<bsl::V>()                                   // --
                << "tsc frequency on pp "                          // --
                << bsl::cyn << bsl::hex(this->id()) << bsl::rst    // --
                << " is "                                          // --
                << bsl::grn << tsc_khz << "khz" << bsl::rst        // --
                << bsl::endl;                                      // --

            m_tsc_khz = tsc_khz;
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
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            return m_pp_mmio.map<T>(mut_sys, spa);
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
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            return m_pp_mmio.shared_page<T>(mut_sys);
        }

        /// <!-- description -->
        ///   @brief Set the list of supported CPUIDs into the shared page using
        ///     a CDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_cdl the mv_cdl_t in which the supported CPUID are set.
        ///   @return bsl::exit_success on success, bsl::exit_failure otherwise.
        ///
        [[nodiscard]] constexpr auto
        cpuid_get_supported_list(
            syscall::bf_syscall_t &mut_sys, hypercall::mv_cdl_t &mut_cdl) noexcept -> bsl::errc_type
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);

            return m_pp_cpuid.supported_list(mut_sys, mut_cdl);
        }

        /// <!-- description -->
        ///   @brief Set the list of supported MSRs into the shared page using an RDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_rdl the mv_rdl_t in which the supported MSR are set.
        ///   @return bsl::exit_success on success, bsl::exit_failure otherwise.
        ///
        [[nodiscard]] constexpr auto
        msr_get_supported_list(
            syscall::bf_syscall_t &mut_sys, hypercall::mv_rdl_t &mut_rdl) noexcept -> bsl::errc_type
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            return m_pp_msr.supported_list(mut_sys, mut_rdl);
        }
    };
}

#endif
