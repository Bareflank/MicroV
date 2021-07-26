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

#ifndef VPS_POOL_T_HPP
#define VPS_POOL_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vps_t.hpp>

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
    /// @class microv::vps_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines Microv's virtual processor state pool.
    ///
    class vps_pool_t final
    {
        /// @brief stores the pool of VPSs
        bsl::array<vps_t, HYPERVISOR_MAX_VPSS.get()> m_pool{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vps_pool_t
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
        ///   @brief Release the vps_pool_t.
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
        ///   @brief Allocates a vps_t and returns it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the newly created VPS to
        ///   @param vpid the ID of the VP to assign the newly created VPS to
        ///   @param ppid the ID of the PP to assign the newly created VPS to
        ///   @return Returns the ID of the newly created VPS on
        ///     success, or bsl::safe_uint16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vmid,
            bsl::safe_uint16 const &vpid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::safe_uint16
        {
            auto const vpsid{mut_sys.bf_vps_op_create_vps(vpid, ppid)};
            if (bsl::unlikely(!vpsid)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            bsl::finally mut_destroy_vps_on_error{[&mut_sys, &vpsid]() noexcept -> void {
                bsl::discard(mut_sys.bf_vps_op_destroy_vps(vpsid));
            }};

            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error() << "vpsid "                                                   // --
                             << bsl::hex(vpsid)                                            // --
                             << " provided by the microkernel is invalid"                  // --
                             << " or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                             << bsl::hex(HYPERVISOR_MAX_VPSS)                              // --
                             << bsl::endl                                                  // --
                             << bsl::here();                                               // --

                return bsl::safe_uint16::failure();
            }

            auto const ret{pmut_vps->allocate(gs, tls, mut_sys, intrinsic, vmid, vpid, ppid)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            mut_destroy_vps_on_error.ignore();
            return vpsid;
        }

        /// <!-- description -->
        ///   @brief Deallocates a vps_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vpsid the ID of the VM to deallocate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vpsid) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_failure;
            }

            bsl::finally mut_zombify_vps_on_error{[&pmut_vps]() noexcept -> void {
                pmut_vps->zombify();
            }};

            mut_ret = pmut_vps->deallocate(gs, tls, mut_sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_sys.bf_vps_op_destroy_vps(vpsid);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_zombify_vps_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vps_t is a root VPS.
        ///     Returns false if the requested vps_t is not a root VPS or
        ///     an error occurs.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid the ID of the VPS to query
        ///   @return Returns true if the requested vps_t is a root VPS.
        ///     Returns false if the requested vps_t is not a root VPS or
        ///     an error occurs.
        ///
        [[nodiscard]] constexpr auto
        is_root_vps(bsl::safe_uint16 const &vpsid) const noexcept -> bool
        {
            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return false;
            }

            return vps->is_root_vps();
        }

        /// <!-- description -->
        ///   @brief RReturns true if the requested vps_t is a guest VPS.
        ///     Returns false if the requested vps_t is not a guest VPS or
        ///     an error occurs.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid the ID of the VPS to query
        ///   @return Returns true if the requested vps_t is a guest VPS.
        ///     Returns false if the requested vps_t is not a guest VPS or
        ///     an error occurs.
        ///
        [[nodiscard]] constexpr auto
        is_guest_vps(bsl::safe_uint16 const &vpsid) const noexcept -> bool
        {
            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return false;
            }

            return vps->is_guest_vps();
        }
    };
}

#endif
