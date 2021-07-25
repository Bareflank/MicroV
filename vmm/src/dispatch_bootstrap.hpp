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

#ifndef DISPATCH_BOOTSTRAP_HPP
#define DISPATCH_BOOTSTRAP_HPP

#include <bf_constants.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_initialize.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Dispatches the bootstrap process as needed. Note that
    ///     the bootstrap callback is only called when starting the
    ///     hypervisor on root VPs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vps_pool the vps_pool_t to use
    ///   @param ppid the ID of the PP to bootstrap
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_bootstrap(
        gs_t const &gs,
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        vp_pool_t &mut_vp_pool,
        vps_pool_t &mut_vps_pool,
        bsl::safe_uint16 const &ppid) noexcept -> bsl::errc_type
    {
        auto const ret{tls_initialize(mut_tls, mut_sys, intrinsic)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        auto const vpid{
            mut_vp_pool.allocate(gs, mut_tls, mut_sys, intrinsic, syscall::BF_ROOT_VMID, ppid)};
        if (bsl::unlikely(!vpid)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        auto const vpsid{mut_vps_pool.allocate(
            gs, mut_tls, mut_sys, intrinsic, syscall::BF_ROOT_VMID, vpid, ppid)};
        if (bsl::unlikely(!vpsid)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        return mut_sys.bf_vps_op_run(syscall::BF_ROOT_VMID, vpid, vpsid);
    }
}

#endif
