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

#ifndef KVM_SEGMENT_HPP
#define KVM_SEGMENT_HPP

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// <!-- description -->
    ///   @brief TODO
    ///
    struct kvm_segment final
    {
        /// @brief stores that value of the base segment register
        bsl::uint64 base;
        /// @brief stores that value of the limit segment register
        bsl::uint32 limit;
        /// @brief stores that value of the selector segment register
        bsl::uint16 selector;
        /// @brief stores that value of the type segment register
        bsl::uint8 type;
        /// @brief stores that value of the present segment register
        bsl::uint8 present;
        /// @brief stores that value of the dpl segment register
        bsl::uint8 dpl;
        /// @brief stores that value of the db segment register
        bsl::uint8 db;
        /// @brief stores that value of the s segment register
        bsl::uint8 s;
        /// @brief stores that value of the l segment register
        bsl::uint8 l;
        /// @brief stores that value of the g segment register
        bsl::uint8 g;
        /// @brief stores that value of the avl segment register
        bsl::uint8 avl;
        /// @brief stores that value of the unusable segment register
        bsl::uint8 unusable;
        /// @brief stores that value of the padding segment register
        bsl::uint8 padding;
    };
}

#pragma pack(pop)

#endif
