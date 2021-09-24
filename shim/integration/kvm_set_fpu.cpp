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
#include <kvm_fpu.hpp>
#include <shim_platform_interface.hpp>

#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace
{
    /// @brief defines the Expected for mxcsr
    constexpr auto EXPECTED{0x12345678_u32};

    /// @brief defines the Expected for registers
    constexpr auto EXPECTED_REG{0x12_u8};

    /// @brief defines the expected regs information
    constexpr shim::kvm_fpu FPU_TEST{
        {},
        {EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(),
         EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(),
         EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(),
         EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(),
         EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(),
         EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(),
         EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(),
         EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get(), EXPECTED_REG.get()},
        {},
        EXPECTED.get()};

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
    shim::kvm_fpu mut_regs{FPU_TEST};

    bsl::enable_color();
    lib::ioctl mut_system_ctl{shim::DEVICE_NAME};

    /// Verify that get/set works
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        lib::ioctl mut_vm{bsl::to_i32(vmfd)};

        auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        lib::ioctl mut_vcpu{bsl::to_i32(vcpufd)};

        integration::verify(mut_vcpu.write(shim::KVM_SET_FPU, &mut_regs).is_zero());
        mut_regs = {};
        integration::verify(mut_vcpu.write(shim::KVM_GET_FPU, &mut_regs).is_zero());

        integration::verify(EXPECTED == mut_regs.mxcsr);

        for (const auto &reg : mut_regs.registers) {
            integration::verify(EXPECTED_REG == reg);
        }
    }

    // Try a bunch of times
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        lib::ioctl mut_vm{bsl::to_i32(vmfd)};

        auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        lib::ioctl mut_vcpu{bsl::to_i32(vcpufd)};

        constexpr auto num_loops{0x1000_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            integration::verify(mut_vcpu.write(shim::KVM_SET_FPU, &mut_regs).is_zero());
        }
    }

    return bsl::exit_success;
}
