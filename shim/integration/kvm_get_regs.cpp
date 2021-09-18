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

#include <integration_utils.hpp>
#include <ioctl.hpp>
#include <kvm_regs.hpp>
#include <shim_platform_interface.hpp>

#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace
{
    /// @brief defines the expected value for rax
    constexpr auto RAX_EXPECTED_VAL{0xF0F0F0F0BFBFBFB1_u64};
    /// @brief defines the expected value for rbx
    constexpr auto RBX_EXPECTED_VAL{0xF0F0F0F0BFBFBFB2_u64};
    /// @brief defines the expected value for rcx
    constexpr auto RCX_EXPECTED_VAL{0xF0F0F0F0BFBFBFB3_u64};
    /// @brief defines the expected value for rdx
    constexpr auto RDX_EXPECTED_VAL{0xF0F0F0F0BFBFBFB4_u64};
    /// @brief defines the expected value for rbp
    constexpr auto RBP_EXPECTED_VAL{0xF0F0F0F0BFBFBFB5_u64};
    /// @brief defines the expected value for rsi
    constexpr auto RSI_EXPECTED_VAL{0xF0F0F0F0BFBFBFB6_u64};
    /// @brief defines the expected value for rdi
    constexpr auto RDI_EXPECTED_VAL{0xF0F0F0F0BFBFBFB7_u64};
    /// @brief defines the expected value for r8
    constexpr auto R8_EXPECTED_VAL{0xF0F0F0F0BFBFBFB8_u64};
    /// @brief defines the expected value for r9
    constexpr auto R9_EXPECTED_VAL{0xF0F0F0F0BFBFBFB9_u64};
    /// @brief defines the expected value for r10
    constexpr auto R10_EXPECTED_VAL{0xF0F0F0F0BFBFBF10_u64};
    /// @brief defines the expected value for r11
    constexpr auto R11_EXPECTED_VAL{0xF0F0F0F0BFBFBF11_u64};
    /// @brief defines the expected value for r12
    constexpr auto R12_EXPECTED_VAL{0xF0F0F0F0BFBFBF12_u64};
    /// @brief defines the expected value for r13
    constexpr auto R13_EXPECTED_VAL{0xF0F0F0F0BFBFBF13_u64};
    /// @brief defines the expected value for r14
    constexpr auto R14_EXPECTED_VAL{0xF0F0F0F0BFBFBF14_u64};
    /// @brief defines the expected value for r15
    constexpr auto R15_EXPECTED_VAL{0xF0F0F0F0BFBFBF15_u64};
    /// @brief defines the expected value for rsp
    constexpr auto RSP_EXPECTED_VAL{0xF0F0F0F0BFBFBF16_u64};
    /// @brief defines the expected value for rip
    constexpr auto RIP_EXPECTED_VAL{0xF0F0F0F0BFBFBF17_u64};
    /// @brief defines the expected value for rflags
    constexpr auto RFLAGS_EXPECTED_VAL{0xF0F0F0F0BFBFBF18_u64};
}

/// <!-- description -->
///   @brief Provides the main entry point for this application.
///
/// <!-- inputs/outputs -->
///   @return bsl::exit_success on success, bsl::exit_failure otherwise.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::enable_color();
    lib::ioctl mut_system_ctl{shim::DEVICE_NAME};

    /// Verify that get/set works
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        lib::ioctl mut_vm{bsl::to_i32(vmfd)};

        auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        lib::ioctl mut_vcpu{bsl::to_i32(vcpufd)};

        shim::kvm_regs mut_regs{
            RAX_EXPECTED_VAL.get(),
            RBX_EXPECTED_VAL.get(),
            RCX_EXPECTED_VAL.get(),
            RDX_EXPECTED_VAL.get(),
            RSI_EXPECTED_VAL.get(),
            RDI_EXPECTED_VAL.get(),
            RSP_EXPECTED_VAL.get(),
            RBP_EXPECTED_VAL.get(),
            R8_EXPECTED_VAL.get(),
            R9_EXPECTED_VAL.get(),
            R10_EXPECTED_VAL.get(),
            R11_EXPECTED_VAL.get(),
            R12_EXPECTED_VAL.get(),
            R13_EXPECTED_VAL.get(),
            R14_EXPECTED_VAL.get(),
            R15_EXPECTED_VAL.get(),
            RIP_EXPECTED_VAL.get(),
            RFLAGS_EXPECTED_VAL.get()};

        integration::verify(mut_vcpu.write(shim::KVM_SET_REGS, &mut_regs).is_zero());
        mut_regs = {};
        integration::verify(mut_vcpu.write(shim::KVM_GET_REGS, &mut_regs).is_zero());

        integration::verify(RAX_EXPECTED_VAL == mut_regs.rax);
        integration::verify(RBX_EXPECTED_VAL == mut_regs.rbx);
        integration::verify(RCX_EXPECTED_VAL == mut_regs.rcx);
        integration::verify(RDX_EXPECTED_VAL == mut_regs.rdx);
        integration::verify(RSI_EXPECTED_VAL == mut_regs.rsi);
        integration::verify(RDI_EXPECTED_VAL == mut_regs.rdi);
        integration::verify(RSP_EXPECTED_VAL == mut_regs.rsp);
        integration::verify(RBP_EXPECTED_VAL == mut_regs.rbp);
        integration::verify(R8_EXPECTED_VAL == mut_regs.r8);
        integration::verify(R9_EXPECTED_VAL == mut_regs.r9);
        integration::verify(R10_EXPECTED_VAL == mut_regs.r10);
        integration::verify(R11_EXPECTED_VAL == mut_regs.r11);
        integration::verify(R12_EXPECTED_VAL == mut_regs.r12);
        integration::verify(R13_EXPECTED_VAL == mut_regs.r13);
        integration::verify(R14_EXPECTED_VAL == mut_regs.r14);
        integration::verify(R15_EXPECTED_VAL == mut_regs.r15);
        integration::verify(RIP_EXPECTED_VAL == mut_regs.rip);
        integration::verify(RFLAGS_EXPECTED_VAL == mut_regs.rflags);

        mut_vcpu.close();
        mut_vm.close();
    }

    // Try a bunch of times
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        lib::ioctl mut_vm{bsl::to_i32(vmfd)};

        auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        lib::ioctl mut_vcpu{bsl::to_i32(vcpufd)};

        shim::kvm_regs mut_regs{
            RAX_EXPECTED_VAL.get(),
            RBX_EXPECTED_VAL.get(),
            RCX_EXPECTED_VAL.get(),
            RDX_EXPECTED_VAL.get(),
            RSI_EXPECTED_VAL.get(),
            RDI_EXPECTED_VAL.get(),
            RSP_EXPECTED_VAL.get(),
            RBP_EXPECTED_VAL.get(),
            R8_EXPECTED_VAL.get(),
            R9_EXPECTED_VAL.get(),
            R10_EXPECTED_VAL.get(),
            R11_EXPECTED_VAL.get(),
            R12_EXPECTED_VAL.get(),
            R13_EXPECTED_VAL.get(),
            R14_EXPECTED_VAL.get(),
            R15_EXPECTED_VAL.get(),
            RIP_EXPECTED_VAL.get(),
            RFLAGS_EXPECTED_VAL.get()};

        constexpr auto num_loops{0x1000_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            integration::verify(mut_vcpu.write(shim::KVM_SET_REGS, &mut_regs).is_zero());
            mut_regs = {};
            integration::verify(mut_vcpu.write(shim::KVM_GET_REGS, &mut_regs).is_zero());
        }

        integration::verify(RAX_EXPECTED_VAL == mut_regs.rax);
        integration::verify(RBX_EXPECTED_VAL == mut_regs.rbx);
        integration::verify(RCX_EXPECTED_VAL == mut_regs.rcx);
        integration::verify(RDX_EXPECTED_VAL == mut_regs.rdx);
        integration::verify(RSI_EXPECTED_VAL == mut_regs.rsi);
        integration::verify(RDI_EXPECTED_VAL == mut_regs.rdi);
        integration::verify(RSP_EXPECTED_VAL == mut_regs.rsp);
        integration::verify(RBP_EXPECTED_VAL == mut_regs.rbp);
        integration::verify(R8_EXPECTED_VAL == mut_regs.r8);
        integration::verify(R9_EXPECTED_VAL == mut_regs.r9);
        integration::verify(R10_EXPECTED_VAL == mut_regs.r10);
        integration::verify(R11_EXPECTED_VAL == mut_regs.r11);
        integration::verify(R12_EXPECTED_VAL == mut_regs.r12);
        integration::verify(R13_EXPECTED_VAL == mut_regs.r13);
        integration::verify(R14_EXPECTED_VAL == mut_regs.r14);
        integration::verify(R15_EXPECTED_VAL == mut_regs.r15);
        integration::verify(RIP_EXPECTED_VAL == mut_regs.rip);
        integration::verify(RFLAGS_EXPECTED_VAL == mut_regs.rflags);

        mut_vcpu.close();
        mut_vm.close();
    }

    return bsl::exit_success;
}
