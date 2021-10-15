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

#include <ifmap_t.hpp>
#include <integration_utils.hpp>
#include <ioctl_t.hpp>
#include <kvm_regs.hpp>
#include <kvm_run.hpp>
#include <kvm_run_io.hpp>
#include <kvm_segment.hpp>
#include <kvm_sregs.hpp>
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
    bsl::safe_i64 mut_ret{};

    bsl::enable_color();
    integration::ioctl_t mut_system_ctl{shim::DEVICE_NAME};

    auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
    integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

    integration::ifmap_t const vm_image{"vm_cross_compile/bin/16bit_io_test"};
    integration::verify(!vm_image.empty());

    shim::kvm_userspace_memory_region mut_region{};
    mut_region.memory_size = vm_image.size().get();
    mut_region.userspace_addr = vm_image.data();

    mut_ret = mut_vm.write(shim::KVM_SET_USER_MEMORY_REGION, &mut_region);
    integration::verify(mut_ret.is_zero());

    auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
    integration::ioctl_t mut_vcpu{bsl::to_i32(vcpufd)};

    auto const kvm_run_size{mut_system_ctl.send(shim::KVM_GET_VCPU_MMAP_SIZE)};
    integration::verify(kvm_run_size.is_pos());
    integration::verify(bsl::to_umx(kvm_run_size) == sizeof(shim::kvm_run));

    shim::kvm_run *const pmut_run{static_cast<shim::kvm_run *>(mmap(
        nullptr,
        bsl::to_u64(kvm_run_size).get(),
        PROT_READ | PROT_WRITE,    // NOLINT
        MAP_SHARED,
        bsl::to_i32(vcpufd).get(),
        bsl::safe_i64::magic_0().get()))};

    integration::verify(nullptr != pmut_run);

    shim::kvm_regs mut_regs{};
    integration::verify(mut_vcpu.read(shim::KVM_GET_REGS, &mut_regs).is_zero());
    mut_regs.rip = {};
    integration::verify(mut_vcpu.write(shim::KVM_SET_REGS, &mut_regs).is_zero());

    shim::kvm_sregs mut_sregs{};
    integration::verify(mut_vcpu.read(shim::KVM_GET_SREGS, &mut_sregs).is_zero());
    mut_sregs.cs.selector = {};
    mut_sregs.cs.base = {};
    integration::verify(mut_vcpu.write(shim::KVM_SET_SREGS, &mut_sregs).is_zero());

    // while (!mut_vcpu.send(shim::KVM_RUN).is_neg()) {
    //     bsl::print() << "IO port: "                                              // --
    //                  << bsl::cyn << bsl::hex(pmut_run->io.port) << bsl::rst      // --
    //                  << ", data: "                                               // --
    //                  << bsl::blu << bsl::hex(pmut_run->io.data16) << bsl::rst    // --
    //                  << bsl::endl;                                               // --
    // }

    mut_ret = mut_vcpu.send(shim::KVM_RUN);
    integration::verify(!mut_ret.is_neg());
    mut_ret = mut_vcpu.send(shim::KVM_RUN);
    integration::verify(!mut_ret.is_neg());
    mut_ret = mut_vcpu.send(shim::KVM_RUN);
    integration::verify(!mut_ret.is_neg());

    constexpr auto expected_direction{0x01_u8};
    constexpr auto expected_size{0x02_u8};
    constexpr auto expected_port{0x10_u16};
    constexpr auto expected_count{0x00_u32};
    constexpr auto expected_data{0x02_u16};

    integration::verify(expected_direction == pmut_run->io.direction);
    integration::verify(expected_size == pmut_run->io.size);
    integration::verify(expected_port == pmut_run->io.port);
    integration::verify(expected_count == pmut_run->io.count);
    integration::verify(expected_data == pmut_run->io.data16);

    mut_vcpu.close();
    mut_vm.close();

    return bsl::exit_success;
}
