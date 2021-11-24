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
#include <kvm_msr_entry.hpp>
#include <kvm_msrs.hpp>
#include <shim_platform_interface.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace
{
    /// @brief defines the number of MSRS we expect
    constexpr auto EXPECTED_NMSRS{0x01_u32};
    /// @brief defines the PAD we expect
    constexpr auto EXPECTED_PAD{0x00_u32};
    /// @brief defines the size for entries in RDL
    constexpr auto MYSIZE_ENTRIES{1_u64};
    /// @brief defines the register index we expect
    constexpr auto EXPECTED_INDEX{0x00_u32};
    /// @brief defines the register data we expect
    constexpr auto EXPECTED_DATA{0x42_u64};
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
    shim::kvm_msrs mut_msrs{};

    mut_msrs.nmsrs = EXPECTED_NMSRS.get();
    mut_msrs.pad = EXPECTED_PAD.get();

    for (bsl::safe_idx mut_i{}; mut_i < MYSIZE_ENTRIES.get(); ++mut_i) {
        mut_msrs.entries.at_if(mut_i)->index = EXPECTED_INDEX.get();
        mut_msrs.entries.at_if(mut_i)->data = EXPECTED_DATA.get();
    }

    bsl::enable_color();
    integration::ioctl_t mut_system_ctl{shim::DEVICE_NAME};

    /// Verify that get/set works
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        integration::ioctl_t mut_vcpu{bsl::to_i32(vcpufd)};

        integration::verify(mut_vcpu.write(shim::KVM_SET_MSRS, &mut_msrs).is_zero());
        mut_msrs = {};
        auto const ret{bsl::to_u32(mut_vcpu.read(shim::KVM_GET_MSRS, &mut_msrs))};

        integration::verify(ret == EXPECTED_NMSRS.get());
        integration::verify(EXPECTED_NMSRS == mut_msrs.nmsrs);
        integration::verify(EXPECTED_PAD == mut_msrs.pad);
        for (bsl::safe_idx mut_i{}; mut_i < MYSIZE_ENTRIES.get(); ++mut_i) {
            mut_msrs.entries.at_if(mut_i)->index = EXPECTED_INDEX.get();
            mut_msrs.entries.at_if(mut_i)->data = EXPECTED_DATA.get();
        }
    }

    // Try a bunch of times
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        integration::ioctl_t mut_vcpu{bsl::to_i32(vcpufd)};

        constexpr auto num_loops{0x1000_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            integration::verify(mut_vcpu.write(shim::KVM_SET_MSRS, &mut_msrs).is_zero());
        }
    }

    return bsl::exit_success;
}
