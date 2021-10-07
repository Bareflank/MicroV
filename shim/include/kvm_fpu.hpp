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

#ifndef KVM_FPU_HPP
#define KVM_FPU_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// @brief defines the size of the FPR
    constexpr auto FPR_REGISTER_SIZE{8_umx};
    /// @brief defines the total no of the FPR registers
    constexpr auto NO_OF_FPR_REGISTERS{16_umx};
    /// @brief defines the total size of the REGISTER bytes
    constexpr auto REGISTER_SIZE{1_umx};
    /// @brief defines the total size of the number of REGISTER bytes
    constexpr auto NO_OF_REGISTER_SIZE{32_umx};
    /// @brief defines the no of XMM registers
    constexpr auto NO_OF_XMM_REGISTERS{16_umx};
    /// @brief defines the size of the XMM REGISTER
    constexpr auto XMM_REGISTER_SIZE{16_umx};
    /// @brief defines the total no of register bytes
    constexpr auto TOTAL_NO_OF_REGISTER_BYTES{(REGISTER_SIZE * NO_OF_REGISTER_SIZE).checked()};
    /// @brief defines the total no of FPR bytes
    constexpr auto TOTAL_NO_OF_FPR_BYTES{(NO_OF_FPR_REGISTERS * FPR_REGISTER_SIZE).checked()};
    /// @brief defines the total no of XMM bytes
    constexpr auto TOTAL_NO_OF_XMM_BYTES{(NO_OF_XMM_REGISTERS * XMM_REGISTER_SIZE).checked()};

    /// @struct kvm_fpu
    ///
    /// <!-- description -->
    ///   @brief see /include/uapi/linux/kvm.h in Linux for more details.
    ///
    struct kvm_fpu final
    {
        /** @brief stores that value of the Floating pointer registers*/
        bsl::array<bsl::uint8, TOTAL_NO_OF_FPR_BYTES.get()> fpr;
        /** @brief stores that value of the registers*/
        bsl::array<bsl::uint8, TOTAL_NO_OF_REGISTER_BYTES.get()> registers;
        /** @brief stores that value of the XMM registers*/
        bsl::array<bsl::uint8, TOTAL_NO_OF_XMM_BYTES.get()> xmm;
        /** @brief stores that value of mxscr*/
        bsl::uint32 mxcsr;
    };

}

#pragma pack(pop)

#endif
