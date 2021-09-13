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

#include <ioctl.hpp>
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

    // Destroy in order of creation
    {
        auto const vm1fd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        auto const vm2fd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        auto const vm3fd{mut_system_ctl.send(shim::KVM_CREATE_VM)};

        lib::ioctl mut_vm1{bsl::to_i32(vm1fd)};
        lib::ioctl mut_vm2{bsl::to_i32(vm2fd)};
        lib::ioctl mut_vm3{bsl::to_i32(vm3fd)};

        mut_vm1.close();
        mut_vm2.close();
        mut_vm3.close();
    }

    // Destroy in reverse order
    {
        auto const vm1fd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        auto const vm2fd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        auto const vm3fd{mut_system_ctl.send(shim::KVM_CREATE_VM)};

        lib::ioctl mut_vm1{bsl::to_i32(vm1fd)};
        lib::ioctl mut_vm2{bsl::to_i32(vm2fd)};
        lib::ioctl mut_vm3{bsl::to_i32(vm3fd)};

        mut_vm3.close();
        mut_vm2.close();
        mut_vm1.close();
    }

    // Destroy in random order
    {
        auto const vm1fd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        auto const vm2fd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        auto const vm3fd{mut_system_ctl.send(shim::KVM_CREATE_VM)};

        lib::ioctl mut_vm1{bsl::to_i32(vm1fd)};
        lib::ioctl mut_vm2{bsl::to_i32(vm2fd)};
        lib::ioctl mut_vm3{bsl::to_i32(vm3fd)};

        mut_vm2.close();
        mut_vm1.close();
        mut_vm3.close();
    }

    // Create VMs until we run out and let the kernel clean up the mess
    {
        bsl::safe_i64 mut_fd{};
        while (!mut_fd.is_neg()) {
            mut_fd = mut_system_ctl.send(shim::KVM_CREATE_VM);
        }
    }

    return bsl::exit_success;
}
