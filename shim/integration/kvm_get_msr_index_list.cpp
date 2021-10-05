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
#include <kvm_msr_list.hpp>
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
    shim::kvm_msr_list mut_msr_list{};
    constexpr auto star_val{0xC0000081_u32};
    constexpr auto pat_val{0x00000277_u32};
    constexpr auto apic_base_val{0x0000001B_u32};
    constexpr auto init_nmsrs{0x10_u32};

    bsl::enable_color();
    integration::ioctl_t mut_system_ctl{shim::DEVICE_NAME};
    bsl::array<bsl::uint32, bsl::uintmx(init_nmsrs.get())> mut_msr_indices{};

    // nmsrs is too big
    {
        mut_msr_list.nmsrs = HYPERVISOR_PAGE_SIZE.get();
        mut_msr_list.nmsrs++;
        mut_msr_list.indices = mut_msr_indices.front_if();

        integration::verify(
            mut_system_ctl.write(shim::KVM_GET_MSR_INDEX_LIST, &mut_msr_list).is_neg());
    }

    {
        mut_msr_list.nmsrs = init_nmsrs.get();
        mut_msr_list.indices = mut_msr_indices.front_if();

        integration::verify(
            mut_system_ctl.write(shim::KVM_GET_MSR_INDEX_LIST, &mut_msr_list).is_zero());

        auto mut_nmsrs{bsl::to_u32(mut_msr_list.nmsrs)};
        integration::verify(mut_nmsrs > bsl::safe_u32::magic_0());
    }

    // Valid registers should be present
    {
        bool mut_found_star{false};
        bool mut_found_pat{false};
        bool mut_found_apic_base{false};
        auto mut_nmsrs{bsl::to_idx(mut_msr_list.nmsrs)};

        for (bsl::safe_idx mut_i{}; mut_i < mut_nmsrs; ++mut_i) {
            if (star_val == mut_msr_list.indices[mut_i.get()]) {
                mut_found_star = true;
            }
            else if (pat_val == mut_msr_list.indices[mut_i.get()]) {
                mut_found_pat = true;
            }
            else if (apic_base_val == mut_msr_list.indices[mut_i.get()]) {
                mut_found_apic_base = true;
            }
        }

        integration::verify(mut_found_star);
        integration::verify(mut_found_pat);
        integration::verify(mut_found_apic_base);
    }

    // Try a bunch of times
    {
        constexpr auto num_loops{0x1000_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            integration::verify(
                mut_system_ctl.write(shim::KVM_GET_MSR_INDEX_LIST, &mut_msr_list).is_zero());
        }
    }

    return bsl::exit_success;
}
