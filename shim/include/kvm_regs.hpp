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

#ifndef KVM_REGS_HPP
#define KVM_REGS_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// @struct kvm_regs
    ///
    /// <!-- description -->
    ///   @brief see /include/uapi/linux/kvm.h in Linux for more details.
    ///
    struct kvm_regs final
    {
        /// @brief stores that value of the rax register
        bsl::uint64 rax;
        /// @brief stores that value of the rbx register
        bsl::uint64 rbx;
        /// @brief stores that value of the rcx register
        bsl::uint64 rcx;
        /// @brief stores that value of the rdx register
        bsl::uint64 rdx;
        /// @brief stores that value of the rsi register
        bsl::uint64 rsi;
        /// @brief stores that value of the rdi register
        bsl::uint64 rdi;
        /// @brief stores that value of the rsp register
        bsl::uint64 rsp;
        /// @brief stores that value of the rbp register
        bsl::uint64 rbp;
        /// @brief stores that value of the r8 register
        bsl::uint64 r8;
        /// @brief stores that value of the r9 register
        bsl::uint64 r9;
        /// @brief stores that value of the r10 register
        bsl::uint64 r10;
        /// @brief stores that value of the r11 register
        bsl::uint64 r11;
        /// @brief stores that value of the r12 register
        bsl::uint64 r12;
        /// @brief stores that value of the r13 register
        bsl::uint64 r13;
        /// @brief stores that value of the r14 register
        bsl::uint64 r14;
        /// @brief stores that value of the r15 register
        bsl::uint64 r15;
        /// @brief stores that value of the rip register
        bsl::uint64 rip;
        /// @brief stores that value of the rflags register
        bsl::uint64 rflags;
    };
}

#pragma pack(pop)

#endif
