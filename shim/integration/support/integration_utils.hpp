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

#ifndef INTEGRATION_UTILS_HPP
#define INTEGRATION_UTILS_HPP

#include <cstdlib>
#include <ifmap.hpp>
#include <ioctl.hpp>
#include <kvm_regs.hpp>
#include <kvm_run.hpp>
#include <kvm_segment.hpp>
#include <kvm_sregs.hpp>
#include <kvm_userspace_memory_region.hpp>
#include <shim_platform_interface.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace integration
{
    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///
    constexpr void
    verify(bool const test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            exit(1);
        }
        else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///
    constexpr void
    verify(bsl::errc_type const test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            exit(1);
        }
        else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of bsl::safe_integral to test.
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///
    template<typename T>
    constexpr void
    verify(
        bsl::safe_integral<T> const &test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            exit(1);
        }
        else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Initializes a VM for a 16bit test
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_vm the VM to initialize
    ///   @param filename the filename of the VM image to load
    ///
    constexpr void
    initialize_16bit_vm(lib::ioctl &mut_vm, bsl::string_view const &filename) noexcept
    {
        lib::ifmap const vm_image{filename};
        integration::verify(!vm_image.empty());

        shim::kvm_userspace_memory_region region{};
        region.memory_size = vm_image.size().get();
        region.userspace_addr = vm_image.data();

        auto const ret{mut_vm.write(shim::KVM_SET_USER_MEMORY_REGION, &region)};
        integration::verify(ret.is_zero());
    }

    /// <!-- description -->
    ///   @brief Initializes a VCPU for a 16bit test
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_vcpu the VCPU to initialize
    ///   @return Returns the KVM_RUN struct associated with the VCPU
    ///
    [[maybe_unused]] constexpr auto
    initialize_16bit_vcpu(lib::ioctl &mut_vcpu) noexcept -> shim::kvm_run *
    {
        shim::kvm_run *const pmut_run{static_cast<shim::kvm_run *>(mmap(
            nullptr,
            sizeof(shim::kvm_run),
            PROT_READ | PROT_WRITE,    // NOLINT
            MAP_SHARED,
            mut_vcpu.handle().get(),
            {}))};

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

        return pmut_run;
    }
}

#endif
