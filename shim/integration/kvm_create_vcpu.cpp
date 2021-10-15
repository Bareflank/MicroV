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
#include <shim_platform_interface.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
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

    /// Destroy in order or creation
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        auto const vcpu1fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu2fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu3fd{mut_vm.send(shim::KVM_CREATE_VCPU)};

        integration::verify(vcpu1fd.is_pos());
        integration::verify(vcpu2fd.is_pos());
        integration::verify(vcpu3fd.is_pos());

        integration::ioctl_t mut_vcpu1{bsl::to_i32(vcpu1fd)};
        integration::ioctl_t mut_vcpu2{bsl::to_i32(vcpu2fd)};
        integration::ioctl_t mut_vcpu3{bsl::to_i32(vcpu3fd)};

        mut_vcpu1.close();
        mut_vcpu2.close();
        mut_vcpu3.close();
        mut_vm.close();
    }

    /// Destroy in reverse order
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        auto const vcpu1fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu2fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu3fd{mut_vm.send(shim::KVM_CREATE_VCPU)};

        integration::verify(vcpu1fd.is_pos());
        integration::verify(vcpu2fd.is_pos());
        integration::verify(vcpu3fd.is_pos());

        integration::ioctl_t mut_vcpu1{bsl::to_i32(vcpu1fd)};
        integration::ioctl_t mut_vcpu2{bsl::to_i32(vcpu2fd)};
        integration::ioctl_t mut_vcpu3{bsl::to_i32(vcpu3fd)};

        mut_vcpu3.close();
        mut_vcpu2.close();
        mut_vcpu1.close();
        mut_vm.close();
    }

    // Destroy in a random order
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        auto const vcpu1fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu2fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu3fd{mut_vm.send(shim::KVM_CREATE_VCPU)};

        integration::verify(vcpu1fd.is_pos());
        integration::verify(vcpu2fd.is_pos());
        integration::verify(vcpu3fd.is_pos());

        integration::ioctl_t mut_vcpu1{bsl::to_i32(vcpu1fd)};
        integration::ioctl_t mut_vcpu2{bsl::to_i32(vcpu2fd)};
        integration::ioctl_t mut_vcpu3{bsl::to_i32(vcpu3fd)};

        mut_vcpu2.close();
        mut_vcpu3.close();
        mut_vcpu1.close();
        mut_vm.close();
    }

    // Destroy the VM first
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        auto const vcpu1fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu2fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu3fd{mut_vm.send(shim::KVM_CREATE_VCPU)};

        integration::verify(vcpu1fd.is_pos());
        integration::verify(vcpu2fd.is_pos());
        integration::verify(vcpu3fd.is_pos());

        integration::ioctl_t mut_vcpu1{bsl::to_i32(vcpu1fd)};
        integration::ioctl_t mut_vcpu2{bsl::to_i32(vcpu2fd)};
        integration::ioctl_t mut_vcpu3{bsl::to_i32(vcpu3fd)};

        mut_vm.close();
        mut_vcpu3.close();
        mut_vcpu2.close();
        mut_vcpu1.close();
    }

    // Create VCPUs until we run out, remove some, then recreate
    {
        bsl::array<integration::ioctl_t, MICROV_MAX_VCPUS.get()> mut_vcpus{};

        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        for (auto &mut_vcpu : mut_vcpus) {
            auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
            integration::verify(vcpufd.is_pos());

            mut_vcpu = integration::ioctl_t{bsl::to_i32(vcpufd)};
        }

        mut_vcpus.front().close();

        auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        integration::verify(vcpufd.is_pos());

        mut_vcpus.front() = integration::ioctl_t{bsl::to_i32(vcpufd)};
    }

    // Create VCPUs until we run out and let the kernel clean up the mess
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        for (bsl::safe_idx mut_i{}; mut_i < MICROV_MAX_VCPUS; ++mut_i) {
            auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
            integration::verify(vcpufd.is_pos());
        }
    }

    // Make sure we can still create VCPUs. MAX_VPS and MAX_VSS must be
    // larger than MICROV_MAX_VCPUS for this to work
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        auto const vcpu1fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu2fd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        auto const vcpu3fd{mut_vm.send(shim::KVM_CREATE_VCPU)};

        integration::verify(vcpu1fd.is_pos());
        integration::verify(vcpu2fd.is_pos());
        integration::verify(vcpu3fd.is_pos());

        integration::ioctl_t mut_vcpu1{bsl::to_i32(vcpu1fd)};
        integration::ioctl_t mut_vcpu2{bsl::to_i32(vcpu2fd)};
        integration::ioctl_t mut_vcpu3{bsl::to_i32(vcpu3fd)};

        mut_vcpu3.close();
        mut_vcpu2.close();
        mut_vcpu1.close();
        mut_vm.close();
    }

    return bsl::exit_success;
}
