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

#ifndef VP_POOL_T_HPP
#define VP_POOL_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vp_t.hpp>

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
    /// @class microv::vp_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines Microv's virtual processor pool.
    ///
    class vp_pool_t final
    {
        /// @brief stores the pool of VPs
        bsl::array<vp_t, HYPERVISOR_MAX_VPS.get()> m_pool{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vp_pool_t
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
        ///   @brief Release the vp_pool_t.
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
        ///   @brief Allocates a vp_t and returns it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the newly created VP to
        ///   @param ppid the ID of the PP to assign the newly created VP to
        ///   @return Returns the ID of the newly created VP on
        ///     success, or bsl::safe_uint16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vmid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::safe_uint16
        {
            auto const vpid{mut_sys.bf_vp_op_create_vp(vmid, ppid)};
            if (bsl::unlikely(!vpid)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            bsl::finally mut_destroy_vp_on_error{[&mut_sys, &vpid]() noexcept -> void {
                bsl::discard(mut_sys.bf_vp_op_destroy_vp(vpid));
            }};

            auto *const pmut_vp{m_pool.at_if(bsl::to_umax(vpid))};
            if (bsl::unlikely(nullptr == pmut_vp)) {
                bsl::error() << "vpid "                                                   // --
                             << bsl::hex(vpid)                                            // --
                             << " provided by the microkernel is invalid"                 // --
                             << " or greater than or equal to the HYPERVISOR_MAX_VPS "    // --
                             << bsl::hex(HYPERVISOR_MAX_VPS)                              // --
                             << bsl::endl                                                 // --
                             << bsl::here();                                              // --

                return bsl::safe_uint16::failure();
            }

            auto const ret{pmut_vp->allocate(gs, tls, mut_sys, intrinsic, vmid, ppid)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            mut_destroy_vp_on_error.ignore();
            return vpid;
        }

        /// <!-- description -->
        ///   @brief Deallocates a vp_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vpid the ID of the VM to deallocate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vpid) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            auto *const pmut_vp{m_pool.at_if(bsl::to_umax(vpid))};
            if (bsl::unlikely(nullptr == pmut_vp)) {
                bsl::error()
                    << "vpid "                                                              // --
                    << bsl::hex(vpid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPS)                                         // --
                    << bsl::endl                                                            // --
                    << bsl::here();                                                         // --

                return bsl::errc_failure;
            }

            bsl::finally mut_zombify_vp_on_error{[&pmut_vp]() noexcept -> void {
                pmut_vp->zombify();
            }};

            mut_ret = pmut_vp->deallocate(gs, tls, mut_sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_sys.bf_vp_op_destroy_vp(vpid);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_zombify_vp_on_error.ignore();
            return bsl::errc_success;
        }
    };
}

#endif
