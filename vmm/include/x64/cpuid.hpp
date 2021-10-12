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

#ifndef CPUID_HPP
#define CPUID_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace microv
{
    /// @brief the vendor-id and largest standard function CPUID
    constexpr auto CPUID_FN0000_0000{0x00000000_u32};
    /// @brief the feature information CPUID
    constexpr auto CPUID_FN0000_0001{0x00000001_u32};
    /// @brief the largest extended function CPUID
    constexpr auto CPUID_FN8000_0000{0x80000000_u32};
    /// @brief the extended feature bits
    constexpr auto CPUID_FN8000_0001{0x80000001_u32};
    /// @brief the processor brand string
    constexpr auto CPUID_FN8000_0002{0x80000002_u32};
    /// @brief the processor brand string
    constexpr auto CPUID_FN8000_0003{0x80000003_u32};
    /// @brief the processor brand string
    constexpr auto CPUID_FN8000_0004{0x80000004_u32};

    /// @brief the ECX mask for CPUID Fn0000_0001
    constexpr auto CPUID_FN0000_0001_ECX{0x21FC3203_u64};
    /// @brief the ECX enable bit for CPUID Fn0000_0001
    constexpr auto CPUID_FN0000_0001_ECX_HYPERVISOR_BIT{0x80000000_u64};
    /// @brief the EDX mask for CPUID Fn0000_0001
    constexpr auto CPUID_FN0000_0001_EDX{0x1FCBFBFB_u64};
    /// @brief the ECX mask for CPUID Fn8000_0001
    constexpr auto CPUID_FN8000_0001_ECX{0x00000121_u64};
    /// @brief the EDX mask for CPUID Fn8000_0001
    constexpr auto CPUID_FN8000_0001_EDX{0x24100800_u64};
}

#endif
