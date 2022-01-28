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

#ifndef KVM_RUN_IO_HPP
#define KVM_RUN_IO_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// @brief n/a
    constexpr auto KVM_EXIT_IO_IN{0x00_u8};
    /// @brief n/a
    constexpr auto KVM_EXIT_IO_OUT{0x01_u8};
    /// @brief n/a
    constexpr auto KVM_EXIT_IO_MAX_DATA_SIZE{0x270_umx};

    /// <!-- description -->
    ///   @brief TODO
    ///
    struct kvm_run_io final
    {
        /// @brief TODO
        bsl::uint8 direction;
        /// @brief TODO
        bsl::uint8 size;
        /// @brief TODO
        bsl::uint16 port;
        /// @brief TODO
        bsl::uint32 count;
        /// @brief TODO
        bsl::uint64 data_offset;

        /**
         * <!-- description -->
         *   @brief TODO
         */
        // NOLINTNEXTLINE(bsl-decl-forbidden)
        union
        {
            /// @brief stores the data
            bsl::array<bsl::uint8, KVM_EXIT_IO_MAX_DATA_SIZE.get()> data;
            /// @brief stores the data from the target register
            bsl::uint64 reg0;
        };
    };
}

#pragma pack(pop)

#endif
