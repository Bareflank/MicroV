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

#ifndef KVM_RUN_HPP
#define KVM_RUN_HPP

#include <kvm_run_ex.hpp>
#include <kvm_run_fail_entry.hpp>
#include <kvm_run_hw.hpp>
#include <kvm_run_io.hpp>
#include <kvm_run_mmio.hpp>
#include <kvm_run_system_event.hpp>
#include <kvm_run_tpr_access.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// @brief defines the size of the padding1 field
    constexpr auto KVM_RUN_PADDING1_SIZE{6_umx};
    /// @brief defines the size of the padding2 field
    constexpr auto KVM_RUN_PADDING2_SIZE{256_umx};
    /// @brief defines the size of the padding3 field
    constexpr auto KVM_RUN_PADDING3_SIZE{2048_umx};

    /// @struct kvm_run
    ///
    /// <!-- description -->
    ///   @brief see /include/uapi/linux/kvm.h in Linux for more details.
    ///
    struct kvm_run
    {
        /// @brief TODO
        bsl::uint8 request_interrupt_window;
        /// @brief TODO
        bsl::uint8 immediate_exit;
        /// @brief TODO
        bsl::array<bsl::uint8, KVM_RUN_PADDING1_SIZE.get()> padding1;

        /// @brief TODO
        bsl::uint32 exit_reason;
        /// @brief TODO
        bsl::uint8 ready_for_interrupt_injection;
        /// @brief TODO
        bsl::uint8 if_flag;
        /// @brief TODO
        bsl::uint16 flags;

        /// @brief TODO
        bsl::uint64 cr8;
        /// @brief TODO
        bsl::uint64 apic_base;

        /// <!-- description -->
        ///   @brief TODO
        ///
        // NOLINTNEXTLINE(bsl-decl-forbidden)
        union
        {
            /// @brief TODO
            struct kvm_run_hw hw;
            /// @brief TODO
            struct kvm_run_fail_entry fail_entry;
            /// @brief TODO
            struct kvm_run_ex ex;
            /// @brief TODO
            struct kvm_run_io io;
            /// @brief TODO
            struct kvm_run_mmio mmio;
            /// @brief TODO
            struct kvm_run_tpr_access tpr_access;
            /// @brief TODO
            struct kvm_run_system_event system_event;

            /// @brief TODO
            bsl::array<bsl::uint8, KVM_RUN_PADDING2_SIZE.get()> padding2;
        };

        /// @brief TODO
        bsl::uint64 kvm_valid_regs;
        /// @brief TODO
        bsl::uint64 kvm_dirty_regs;

        /// @brief TODO
        bsl::array<bsl::uint8, KVM_RUN_PADDING3_SIZE.get()> padding3;
    };
}

#pragma pack(pop)

#endif
