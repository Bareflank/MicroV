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

#ifndef DISPATCH_FAIL
#define DISPATCH_FAIL

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <pp_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Dispatches the fail as needed, or returns an error so
    ///     that the microkernel can halt the PP.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param pp_pool the pp_pool_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS that generated the fail
    ///   @param fail_reason the exit reason associated with the fail
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] static constexpr auto
    dispatch_fail(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t const &sys,
        intrinsic_t const &intrinsic,
        pp_pool_t const &pp_pool,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        vs_pool_t const &vs_pool,
        bsl::safe_u16 const &vsid,
        bsl::safe_u64 const &fail_reason) noexcept -> bsl::errc_type
    {
        bsl::expects(vsid.is_valid_and_checked());
        bsl::expects(fail_reason.is_valid_and_checked());

        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(sys);
        bsl::discard(intrinsic);
        bsl::discard(pp_pool);
        bsl::discard(vm_pool);
        bsl::discard(vp_pool);
        bsl::discard(vs_pool);

        return bsl::errc_failure;
    }
}

#endif
