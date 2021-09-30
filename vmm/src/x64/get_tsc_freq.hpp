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

#ifndef GET_TSC_FREQ_HPP
#define GET_TSC_FREQ_HPP

#include <intrinsic_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Returns the invariant (not stable) TSC frequency of the
    ///     CPU. By invariant, we mean fixed frequency. By stable, we mean
    ///     consistent between each core, which is more rare, and likely
    ///     not a thing with BIG.little.
    ///
    /// <!-- inputs/outputs -->
    ///   @param intrinsic the intrinsic_t to use
    ///   @return Returns the invariant (not stable) TSC frequency of the
    ///     CPU on success. Returns bsl::safe_u64::failure() on failure.
    ///
    [[nodiscard]] constexpr auto
    get_tsc_freq(intrinsic_t const &intrinsic) noexcept -> bsl::safe_u64
    {
        constexpr auto khz{1000_u64};
        bsl::safe_u64 mut_rax{};
        bsl::safe_u64 mut_rbx{};
        bsl::safe_u64 mut_rcx{};
        bsl::safe_u64 mut_rdx{};

        /// NOTE:
        /// - If we are on VMWare, 0x40000010 can be used to get the
        ///   invariant TSC information.
        ///

        constexpr auto vmware_tsc_leaf{0x40000010_u64};
        mut_rax = vmware_tsc_leaf;
        mut_rbx = {};
        mut_rcx = {};
        mut_rdx = {};
        intrinsic.cpuid(mut_rax, mut_rbx, mut_rcx, mut_rdx);

        if (mut_rax.is_pos()) {
            return (mut_rax / khz).checked();
        }

        /// NOTE:
        /// - If we got here, it means that we are not in a VMWare VM
        ///   which means that we need to get this information from
        ///   CPUID, assuming it is there.
        ///

        constexpr auto hw_tsc_leaf{0x15_u64};
        mut_rax = hw_tsc_leaf;
        mut_rbx = {};
        mut_rcx = {};
        mut_rdx = {};
        intrinsic.cpuid(mut_rax, mut_rbx, mut_rcx, mut_rdx);

        /// TODO:
        /// - There are some systems that do not report TSC information
        ///   even though they have an invariant TSC. The code to handle
        ///   this is here:
        ///   https://github.com/Bareflank/boxy/blob/762d989fcf4ad54eb1e2da4361c7258a712e34ad/bfsdk/include/bftsc.h
        ///
        /// - This code just needs to be translated to AUTOSAR happy
        ///   code, which will require a fair number of constants.
        ///

        mut_rcx = (mut_rcx / khz).checked();

        if (bsl::unlikely(mut_rax.is_zero())) {
            return bsl::safe_u64::failure();
        }

        if (bsl::unlikely(mut_rbx.is_zero())) {
            return bsl::safe_u64::failure();
        }

        if (bsl::unlikely(mut_rcx.is_zero())) {
            return bsl::safe_u64::failure();
        }

        return ((mut_rcx * mut_rbx) / mut_rax).checked();
    }
}

#endif
