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
#include <kvm_cpuid2.h>
#include <kvm_cpuid_entry2.h>
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
    constexpr auto init_nent{0x20_u32};
    constexpr auto cpuid_fn0000_0001{0x00000001_u32};
    shim::kvm_cpuid2 mut_cpuid2{};

    bsl::enable_color();
    integration::ioctl_t mut_system_ctl{shim::DEVICE_NAME};

    {
        mut_cpuid2.nent = init_nent.get();

        integration::verify(
            mut_system_ctl.write(shim::KVM_GET_SUPPORTED_CPUID, &mut_cpuid2).is_zero());

        auto nent{bsl::to_u32(mut_cpuid2.nent)};
        integration::verify(nent > bsl::safe_u32::magic_0());
    }

    // Valid registers should be present
    {
        // Fn0000_0001h[0][EDX][ 5]: RDMSR and WRMSR support
        bool found_rdmsr_support{};
        constexpr auto rdmsr_bit{0x20_u32};
        constexpr shim::kvm_cpuid_entry2 rdmsr_support{
            .function = cpuid_fn0000_0001.get(), .index = 0U, .edx = rdmsr_bit.get()};
        auto mut_nent{bsl::to_idx(mut_cpuid2.nent)};
        shim::kvm_cpuid_entry2 mut_entry{};

        for (bsl::safe_idx mut_i{}; mut_i < mut_nent; ++mut_i) {
            mut_entry = *mut_cpuid2.entries.at_if(mut_i);
            if ((mut_entry.function == rdmsr_support.function) &&                // NOLINT
                (mut_entry.index == rdmsr_support.index) &&                      // NOLINT
                ((mut_entry.edx & rdmsr_support.edx) == rdmsr_support.edx)) {    // NOLINT
                found_rdmsr_support = true;
            }
        }
        integration::verify(found_rdmsr_support);
    }

    // Try a bunch of times
    {
        constexpr auto num_loops{0x1000_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            integration::verify(
                mut_system_ctl.write(shim::KVM_GET_SUPPORTED_CPUID, &mut_cpuid2).is_zero());
        }
    }

    return bsl::exit_success;
}
