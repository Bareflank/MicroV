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

#ifndef KVM_DTABLE_HPP
#define KVM_DTABLE_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// <!-- description -->
    ///   @brief TODO
    ///
    struct kvm_dtable final
    {
        /// @brief stores that value of the base dtable
        bsl::uint64 base;
        /// @brief stores that value of the limit dtable
        bsl::uint16 limit;
        /// @brief padding for alignment
        bsl::uint16 padding1;
        /// @brief padding for alignment
        bsl::uint16 padding2;
        /// @brief padding for alignment
        bsl::uint16 padding3;
    };
}

#pragma pack(pop)

#endif
