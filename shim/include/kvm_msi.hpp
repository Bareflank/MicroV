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

#ifndef KVM_MSI_HPP
#define KVM_MSI_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// @brief defines the size of the padding field
    constexpr auto PAD_SIZE_MSI{16_umx};
    /// @struct kvm_msi
    ///
    /// <!-- description -->
    ///   @brief see /include/uapi/linux/kvm.h in Linux for more details.
    ///
    struct kvm_msi final
    {
        /** @brief  For PCI, this is a BFD identifier in the lower 16 bits. */
        bsl::uint32 address_lo;
        /** @brief address_hi bits 31-8 provide bits 31-8 of the destination id.  Bits 7-0 of
                   address_hi must be zero. */
        bsl::uint32 address_hi;
        /** @brief  a MSI message*/
        bsl::uint32 data;
        /** @brief A Flag to indicate valid or invalid data */
        bsl::uint32 flags;
        /** @brief TODO */
        bsl::array<bsl::uint8, PAD_SIZE_MSI.get()> pad;
    };
}

#pragma pack(pop)

#endif