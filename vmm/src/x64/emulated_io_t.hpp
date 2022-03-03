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

#ifndef EMULATED_IO_T_HPP
#define EMULATED_IO_T_HPP

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
    /// @class microv::emulated_io_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's emulated IO handler.
    ///
    ///   @note IMPORTANT: This class is a per-VS class, and all accesses
    ///     to Port IO from a VM (root or guest) must come from this class.
    ///     Note that in most cases, we will not trap on root IO accesses.
    ///
    class emulated_io_t final
    {
        /// @brief stores the ID of the VS associated with this emulated_io_t
        bsl::safe_u16 m_assigned_vsid{};
        /// @brief stores the maximum number of storable SPAs
        static constexpr auto max_spa{2_u64};
        /// @brief stores the SPAs of a string IO read intercept
        bsl::array<bsl::safe_u64, max_spa.get()> m_mut_spas{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this emulated_io_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_io_t
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

            /// NOTE:
            /// - Since the IO permissions map is a global resource due to
            ///   the limited amount of physically contiguous memory that
            ///   is required, the initialization of the IO permission maps
            ///   is done in gs_initialize. Any IO ports that need to be
            ///   trapped, or passed through should be done there.
            ///

            m_assigned_vsid = ~vsid;
        }

        /// <!-- description -->
        ///   @brief Release the emulated_io_t.
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
        ///   @brief Allocates the emulated_cpuid_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_cpuid_t
        ///
        ///
        constexpr void
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            bsl::expects(vsid != syscall::BF_INVALID_ID);
            bsl::expects(vsid == this->assigned_vsid());

            for (auto &mut_spa: this->m_mut_spas) {
                mut_spa = bsl::safe_u64::failure();
            }
        }

        /// <!-- description -->
        ///   @brief Deallocates the emulated_cpuid_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_cpuid_t
        ///
        ///
        constexpr void
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) const noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            bsl::expects(vsid != syscall::BF_INVALID_ID);
            bsl::expects(vsid == this->assigned_vsid());
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP associated with this
        ///     emulated_io_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     emulated_io_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vsid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vsid.is_valid_and_checked());
            return ~m_assigned_vsid;
        }

        /// <!-- description -->
        ///   @brief Returns the SPA that was cached during the last string IO
        ///     intercepts. This is to prevent having to walk the page table a
        ///     second time prior to resuming a guest.
        ///
        /// <!-- inputs/outputs -->
        ///   @param idx the idx to set the spa into
        ///   @return Returns the cached SPA of the last string IO intercepts.
        ///
        [[nodiscard]] constexpr auto
        spa(bsl::safe_idx const &idx) const noexcept -> bsl::safe_u64
        {
            bsl::expects(m_assigned_vsid.is_valid_and_checked());
            bsl::expects(idx < max_spa);
            return *m_mut_spas.at_if(idx);
        }

        /// <!-- description -->
        ///   @brief Set and cache an SPA during a string IO intercepts. This is
        ///     to prevent having to walk the page table a second time prior to
        ///     resuming a guest.
        ///
        /// <!-- inputs/outputs -->
        ///   @param spa the spa to set
        ///   @param idx the idx to set the spa into
        ///
        constexpr void
        set_spa(bsl::safe_u64 const &spa, bsl::safe_idx const &idx) noexcept
        {
            bsl::expects(m_assigned_vsid.is_valid_and_checked());
            bsl::expects(idx < max_spa);
            *m_mut_spas.at_if(idx) = spa;
        }
    };
}

#endif
