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

#ifndef PAGE_POOL_HELPERS_HPP
#define PAGE_POOL_HELPERS_HPP

#include <basic_page_pool_node_t.hpp>
#include <bf_syscall_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>

namespace helpers
{
    /// <!-- description -->
    ///   @brief Adds more pages to the page_pool_t and returns the new head.
    ///     If no pages can be added to the pool, a nullptr is returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @return Returns the new head of the page_pool_t on success. On failure,
    ///     a nullptr is returned.
    ///
    [[nodiscard]] constexpr auto
    add_to_page_pool(syscall::bf_syscall_t &mut_sys) noexcept -> lib::basic_page_pool_node_t *
    {
        /// TODO:
        /// - This should be speed up, but pre-allocating more than just a
        ///   single page on demand. To do that, we should add a syscall to
        ///   the microkernel to return a linked list of pages. If done
        ///   correctly, nothing about this function changes, other than
        ///   the syscall, asking for XYZ number of pages instead of
        ///   just one. It will return a page node that, instead of pointing
        ///   to nothing, points to the linked list, but using the extensions
        ///   address space instead of the kernel's. This means that the
        ///   extension can just return the result like it is, and MicroV's
        ///   page pool will now have several pages in it's linked list
        ///   instead of just one.
        /// - Think of it like transfering a group of links from one page
        ///   pool to another, with the only modification that has to be
        ///   made is going from the microkernel's direct map address
        ///   space, to the extension's direct map address space.
        /// - Also, don't forget that the page still needs to be mapped by
        ///   the microkernel, otherwise the extension's memory map will
        ///   not have the page table entries to support the virtual
        ///   addresses that it needs for these pages.
        ///

        auto *const pmut_ptr{mut_sys.bf_mem_op_alloc_page<lib::basic_page_pool_node_t>()};
        if (bsl::unlikely(nullptr == pmut_ptr)) {
            bsl::print<bsl::V>() << bsl::here();
            return pmut_ptr;
        }

        return pmut_ptr;
    }
}

#endif
