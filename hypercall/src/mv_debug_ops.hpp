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

#ifndef MV_DEBUG_OPS_HPP
#define MV_DEBUG_OPS_HPP

#include <mv_hypercall_impl.hpp>

#include <bsl/is_constant_evaluated.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// <!-- description -->
    ///   @brief This hypercall tells MicroV to output reg0 and reg1 to the
    ///     console device MicroV is currently using for debugging. The purpose
    ///     of this hypercall is to provide a simple means for debugging issues
    ///     with the guest and can be used by a VM from both userspace and the
    ///     kernel, even when the operating system is not fully bootstrapped or
    ///     is in a failure state.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val1 The first value to output to MicroV's console
    ///   @param val2 The second value to output to MicroV's console
    ///
    constexpr void
    mv_debug_op_out(bsl::safe_u64 const &val1, bsl::safe_u64 const &val2) noexcept
    {
        if (bsl::is_constant_evaluated()) {
            return;
        }

        mv_debug_op_out_impl(val1.get(), val2.get());
    }
}

#endif
