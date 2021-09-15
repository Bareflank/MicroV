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

#ifndef GS_T_HPP
#define GS_T_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>

namespace microv
{
    /// @brief stores the size of the IO permissions map
    constexpr auto IOPM_SIZE{0x3000_umx};
    /// @brief stores the size of the MSR permissions map
    constexpr auto MSRPM_SIZE{0x2000_umx};

    /// @class microv::gs_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's Global Storage (GS).
    ///
    struct gs_t final
    {
        /// @brief stores the IO permissions map for the root VM
        bsl::span<bsl::uint8> root_iopm;
        /// @brief stores the SPA of the IO permissions map for the root VM
        bsl::safe_u64 root_iopm_spa;

        /// @brief stores the IO permissions map for guest VMs
        bsl::span<bsl::uint8> guest_iopm;
        /// @brief stores the SPA of the IO permissions map for guest VMs
        bsl::safe_u64 guest_iopm_spa;

        /// @brief stores the MSR permissions map for root the VM
        bsl::span<bsl::uint8> root_msrpm;
        /// @brief stores the SPA of the MSR permissions map for root the VM
        bsl::safe_u64 root_msrpm_spa;

        /// @brief stores the MSR permissions map for guest VMs
        bsl::span<bsl::uint8> guest_msrpm;
        /// @brief stores the SPA of the MSR permissions map for guest VMs
        bsl::safe_u64 guest_msrpm_spa;
    };
}

#endif
