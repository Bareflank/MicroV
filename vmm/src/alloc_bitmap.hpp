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

#ifndef ALLOC_BITMAP_HPP
#define ALLOC_BITMAP_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/span.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Allocates a bitmap and returns a resulting bsl::span. If
    ///     this function fails, an invalid bsl::span is returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param size the total number of bytes in the bitmap
    ///   @param mut_spa where to store the SPA of the bitmap
    ///   @return Returns a bsl::span containing the bitmap
    ///
    [[nodiscard]] constexpr auto
    alloc_bitmap(
        syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &size, bsl::safe_u64 &mut_spa) noexcept
        -> bsl::span<bsl::uint8>
    {
        bsl::uint8 *pmut_mut_ptr{};

        bsl::expects(size.is_valid_and_checked());
        bsl::expects(size.is_pos());
        bsl::expects(syscall::bf_is_page_aligned(size));
        bsl::expects(mut_spa.is_valid_and_checked());

        if (size == HYPERVISOR_PAGE_SIZE) {
            pmut_mut_ptr = mut_sys.bf_mem_op_alloc_page<bsl::uint8>(mut_spa);
        }
        else {
            pmut_mut_ptr = mut_sys.bf_mem_op_alloc_huge<bsl::uint8>(size, mut_spa);
        }

        if (bsl::unlikely(nullptr == pmut_mut_ptr)) {
            bsl::error() << "failed to allocate bitmap\n" << bsl::here();
            return {};
        }

        return {pmut_mut_ptr, size};
    }
}

#endif
