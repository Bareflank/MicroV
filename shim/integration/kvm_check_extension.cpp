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

#include <bsl/array.hpp>
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
    integration::ioctl_t mut_system_ctl{shim::DEVICE_NAME};
    bsl::safe_i64 mut_ret{};
    auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
    integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};
    bsl::array<integration::ioctl_t *, 2UL> mut_ioctls{&mut_system_ctl, &mut_vm};
    for (auto *const pmut_ctl : mut_ioctls) {
        {
            constexpr auto capdestroymem_args{21_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capdestroymem_args);
            integration::verify(mut_ret == shim::KVM_CAP_DESTROY_MEMORY_REGION_WORKS);

            constexpr auto capjoinmem_args{30_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capjoinmem_args);
            integration::verify(mut_ret == shim::KVM_CAP_JOIN_MEMORY_REGIONS_WORKS);

            constexpr auto capusermem_args{3_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capusermem_args);
            integration::verify(mut_ret == shim::KVM_CAP_USER_MEMORY);

            constexpr auto captss_args{4_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, captss_args);
            integration::verify(mut_ret == shim::KVM_CAP_SET_TSS_ADDR);

            constexpr auto capextcpuid_args{7_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capextcpuid_args);
            integration::verify(mut_ret == shim::KVM_CAP_EXT_CPUID);

            constexpr auto capnrvcpus_args{9_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capnrvcpus_args);
            integration::verify(mut_ret == shim::KVM_CAP_NR_VCPUS);

            constexpr auto capnrmemslots_args{10_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capnrmemslots_args);
            integration::verify(mut_ret == shim::KVM_CAP_NR_MEMSLOTS);

            constexpr auto capmpstate_args{14_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capmpstate_args);
            integration::verify(mut_ret == shim::KVM_CAP_MP_STATE);

            constexpr auto capmce_args{31_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capmce_args);
            integration::verify(mut_ret == shim::KVM_CAP_MCE);

            constexpr auto captsckhz_args{61_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, captsckhz_args);
            integration::verify(mut_ret == shim::KVM_CAP_GET_TSC_KHZ);

            constexpr auto capmaxvcpus_args{66_i64};
            bsl::safe_i64 mut_ret1{};
            mut_ret1 = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capmaxvcpus_args);
            integration::verify(mut_ret1 == shim::KVM_CAP_MAX_VCPUS);

            constexpr auto capdeadlinetimer_args{72_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capdeadlinetimer_args);
            integration::verify(mut_ret == shim::KVM_CAP_TSC_DEADLINE_TIMER);

            constexpr auto capimmexit_args{136_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capimmexit_args);
            integration::verify(mut_ret == shim::KVM_CAP_IMMEDIATE_EXIT);

            constexpr auto capmaxvcpuid_args{128_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, capmaxvcpuid_args);
            integration::verify(mut_ret == shim::KVM_CAP_MAX_VCPU_ID);
        }
        {
            constexpr auto unsupported_args{100_i64};
            mut_ret = pmut_ctl->write(shim::KVM_CHECK_EXTENSION, unsupported_args);
            integration::verify(mut_ret == shim::KVM_CAP_UNSUPPORTED);
        }
    }
    {
        constexpr auto capdestroymem_args{21_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capdestroymem_args);
        integration::verify(mut_ret == shim::KVM_CAP_DESTROY_MEMORY_REGION_WORKS);

        constexpr auto capjoinmem_args{30_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capjoinmem_args);
        integration::verify(mut_ret == shim::KVM_CAP_JOIN_MEMORY_REGIONS_WORKS);

        constexpr auto capusermem_args{3_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capusermem_args);
        integration::verify(mut_ret == shim::KVM_CAP_USER_MEMORY);

        constexpr auto captss_args{4_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, captss_args);
        integration::verify(mut_ret == shim::KVM_CAP_SET_TSS_ADDR);

        constexpr auto capextcpuid_args{7_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capextcpuid_args);
        integration::verify(mut_ret == shim::KVM_CAP_EXT_CPUID);

        constexpr auto capnrvcpus_args{9_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capnrvcpus_args);
        integration::verify(mut_ret == shim::KVM_CAP_NR_VCPUS);

        constexpr auto capnrmemslots_args{10_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capnrmemslots_args);
        integration::verify(mut_ret == shim::KVM_CAP_NR_MEMSLOTS);

        constexpr auto capmpstate_args{14_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capmpstate_args);
        integration::verify(mut_ret == shim::KVM_CAP_MP_STATE);

        constexpr auto capmce_args{31_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capmce_args);
        integration::verify(mut_ret == shim::KVM_CAP_MCE);

        constexpr auto captsckhz_args{61_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, captsckhz_args);
        integration::verify(mut_ret == shim::KVM_CAP_GET_TSC_KHZ);

        constexpr auto capmaxvcpus_args{66_i64};
        bsl::safe_i64 mut_ret1{};
        mut_ret1 = mut_vm.write(shim::KVM_CHECK_EXTENSION, capmaxvcpus_args);
        integration::verify(mut_ret1 == shim::KVM_CAP_MAX_VCPUS);

        constexpr auto capdeadlinetimer_args{72_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capdeadlinetimer_args);
        integration::verify(mut_ret == shim::KVM_CAP_TSC_DEADLINE_TIMER);

        constexpr auto capimmexit_args{136_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capimmexit_args);
        integration::verify(mut_ret == shim::KVM_CAP_IMMEDIATE_EXIT);

        constexpr auto capmaxvcpuid_args{128_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, capmaxvcpuid_args);
        integration::verify(mut_ret == shim::KVM_CAP_MAX_VCPU_ID);
    }
    {
        constexpr auto unsupported_args{100_i64};
        mut_ret = mut_vm.write(shim::KVM_CHECK_EXTENSION, unsupported_args);
        integration::verify(mut_ret == shim::KVM_CAP_UNSUPPORTED);
    }

    return bsl::exit_success;
}
