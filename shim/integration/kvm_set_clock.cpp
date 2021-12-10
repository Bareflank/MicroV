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
#include <ioctl_t.hpp>
#include <kvm_constants.hpp>
#include <shim_platform_interface.hpp>

#include <bsl/debug.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_integral.hpp>

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
    integration::ioctl_t mut_system_ctl{shim::DEVICE_NAME};
    auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
    integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

    auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
    integration::ioctl_t mut_vcpu{bsl::to_i32(vcpufd)};

    shim::kvm_clock_data mut_clock_data{};
    constexpr auto deadbeef{0xDEADBEEF_u64};
    mut_clock_data.clock = deadbeef.get();
    mut_clock_data.flags = bsl::safe_u32::magic_2().get();
    integration::verify(mut_vcpu.write(shim::KVM_SET_CLOCK, &mut_clock_data).is_zero());

    return bsl::exit_success;
}
