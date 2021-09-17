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

#ifndef SECOND_LEVEL_PAGE_TABLE_T_HPP
#define SECOND_LEVEL_PAGE_TABLE_T_HPP

#include <basic_root_page_table_t.hpp>
#include <bf_syscall_t.hpp>
#include <intrinsic_t.hpp>
#include <l0e_t.hpp>
#include <l1e_t.hpp>
#include <l2e_t.hpp>
#include <l3e_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>

namespace microv
{
    /// @brief defines the second_level_page_table_t used by the microkernel
    using second_level_page_table_t = lib::basic_root_page_table_t<
        tls_t,
        syscall::bf_syscall_t,
        page_pool_t,
        intrinsic_t,
        l3e_t,
        l2e_t,
        l1e_t,
        l0e_t>;
}

#endif
