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

#ifndef GS_INITIALIZE_HPP
#define GS_INITIALIZE_HPP

#include <alloc_bitmap.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Initializes the Global Storage (GS).
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_gs the gs_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    gs_initialize(
        gs_t &mut_gs,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t const &page_pool,
        intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
    {
        bsl::discard(page_pool);
        bsl::discard(intrinsic);

        mut_gs.root_iopm = alloc_bitmap(mut_sys, IOPM_SIZE, mut_gs.root_iopm_spa);
        if (bsl::unlikely(mut_gs.root_iopm.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        mut_gs.guest_iopm = alloc_bitmap(mut_sys, IOPM_SIZE, mut_gs.guest_iopm_spa);
        if (bsl::unlikely(mut_gs.guest_iopm.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        mut_gs.root_msrpm = alloc_bitmap(mut_sys, MSRPM_SIZE, mut_gs.root_msrpm_spa);
        if (bsl::unlikely(mut_gs.root_msrpm.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        mut_gs.guest_msrpm = alloc_bitmap(mut_sys, MSRPM_SIZE, mut_gs.guest_msrpm_spa);
        if (bsl::unlikely(mut_gs.guest_msrpm.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        for (auto &mut_elem : mut_gs.guest_iopm) {
            mut_elem = bsl::safe_u8::max_value().get();
        }

        for (auto &mut_elem : mut_gs.guest_msrpm) {
            mut_elem = bsl::safe_u8::max_value().get();
        }

        return bsl::errc_success;
    }
}

#endif
