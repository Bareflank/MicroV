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

#ifndef DISPATCH_BOOTSTRAP
#define DISPATCH_BOOTSTRAP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <pp_pool_t.hpp>
#include <tls_initialize.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
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
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] static constexpr auto
    dispatch_bootstrap(
        gs_t const &gs,
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t &mut_pp_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool) noexcept -> bsl::errc_type
    {
        constexpr auto vmid{syscall::BF_ROOT_VMID};

        auto const ret{tls_initialize(mut_tls, mut_sys, mut_page_pool, intrinsic)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        auto const ppid{mut_pp_pool.allocate(gs, mut_tls, mut_sys, mut_page_pool, intrinsic)};
        if (bsl::unlikely(ppid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        auto const vpid{mut_vp_pool.allocate(gs, mut_tls, mut_sys, mut_page_pool, intrinsic, vmid)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        auto const vsid{mut_vs_pool.allocate(
            gs,
            mut_tls,
            mut_sys,
            mut_page_pool,
            intrinsic,
            vmid,
            vpid,
            ppid,
            mut_vm_pool.slpt_spa(vmid))};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        mut_vm_pool.set_active(mut_tls, vmid);
        mut_vp_pool.set_active(mut_tls, vpid);
        mut_vs_pool.set_active(mut_tls, intrinsic, vsid);

        return mut_sys.bf_vs_op_run(vmid, vpid, vsid);
    }
}

#endif
