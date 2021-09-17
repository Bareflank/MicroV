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

#include <ifmap.hpp>
#include <integration_utils.hpp>
#include <ioctl.hpp>
#include <kvm_userspace_memory_region.hpp>
#include <shim_platform_interface.hpp>

#include <bsl/convert.hpp>
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
    lib::ioctl mut_system_ctl{shim::DEVICE_NAME};

    lib::ifmap vm_image{"vm_cross_compile/bin/16bit_io_test"};
    integration::verify(!vm_image.empty());

    /// TODO:
    /// - We need to add tests for the KVM flags.
    ///

    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        lib::ioctl mut_vm{bsl::to_i32(vmfd)};

        shim::kvm_userspace_memory_region region{};
        region.slot = {};
        region.flags = {};
        region.guest_phys_addr = {};
        region.memory_size = vm_image.size().get();
        region.userspace_addr = vm_image.data();

        auto const ret{mut_vm.write(shim::KVM_SET_USER_MEMORY_REGION, &region)};
        integration::verify(ret.is_zero());

        mut_vm.close();
    }

    return bsl::exit_success;
}
