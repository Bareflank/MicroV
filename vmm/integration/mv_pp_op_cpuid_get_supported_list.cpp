/// @copyright
/// Copyright (C) 2021 Assured Information Security, Inc.
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

#include "cpuid_printer_t.hpp"

#include <integration_utils.hpp>
#include <mv_cdl_t.hpp>
#include <mv_constants.hpp>
#include <mv_hypercall_impl.hpp>
#include <mv_hypercall_t.hpp>
#include <mv_types.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstring.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

// #define INTEGRATION_MOCK
namespace hypercall
{
    /// <!-- description -->
    ///   @brief Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        mv_status_t mut_ret{};

        constexpr auto cpuid_fn0000_0000{0x00000000_u32};
        constexpr auto cpuid_fn0000_0001{0x00000001_u32};
        constexpr auto cpuid_fn8000_0000{0x80000000_u32};

        integration::initialize_globals();
        auto *const pmut_rdl0{to_0<mv_cdl_t>()};
        auto *const pmut_rdl1{to_1<mv_cdl_t>()};

        // No shared paged
        mut_ret = mv_pp_op_cpuid_get_supported_list_impl(hndl.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        integration::initialize_shared_pages();

        // Get the largest standard function and the largest extended function
        bsl::builtin_memset(pmut_rdl0, '\0', bsl::to_umx(sizeof(*pmut_rdl0)));
        pmut_rdl0->num_entries = (2_u64).get();
        pmut_rdl0->entries.at_if(0_idx)->fun = cpuid_fn0000_0000.get();
        pmut_rdl0->entries.at_if(1_idx)->fun = cpuid_fn8000_0000.get();
        mut_ret = mv_pp_op_cpuid_get_supported_list_impl(hndl.get());
        integration::verify(mut_ret == MV_STATUS_SUCCESS);
        integration::verify((2_u64).get() == pmut_rdl0->num_entries);
        integration::verify(pmut_rdl0->entries.at_if(0_idx)->eax > 0_u32);
        integration::verify(pmut_rdl0->entries.at_if(1_idx)->eax > 0_u32);

        // Get the list of all supported CPUIDs
        {
            auto const fun_max{bsl::to_u32(pmut_rdl0->entries.at_if(0_idx)->eax)};
            auto const xfun_max{bsl::to_u32(pmut_rdl0->entries.at_if(1_idx)->eax)};
            auto const num_entries{
                bsl::to_u64(fun_max + (xfun_max - cpuid_fn8000_0000).checked()).checked()};
            integration::verify(num_entries < MV_CDL_MAX_ENTRIES);
            pmut_rdl0->num_entries = num_entries.get();

            auto mut_fun{cpuid_fn0000_0000};
            auto mut_i{bsl::safe_idx::magic_0()};
            for (; mut_fun <= fun_max; mut_fun = (++mut_fun).checked()) {
                pmut_rdl0->entries.at_if(mut_i)->fun = mut_fun.get();
                ++mut_i;
            }
            auto mut_xfun{cpuid_fn8000_0000};
            for (; mut_xfun <= xfun_max; mut_xfun = (++mut_xfun).checked()) {
                pmut_rdl0->entries.at_if(mut_i)->fun = mut_xfun.get();
                ++mut_i;
            }
            mut_ret = mv_pp_op_cpuid_get_supported_list_impl(hndl.get());
            integration::verify(mut_ret == MV_STATUS_SUCCESS);
            integration::verify(pmut_rdl0->num_entries == num_entries);

            bsl::safe_u64 mut_flags{};
            // mut_flags |= integration::CPUID_PRINTER_FLAG_PRINT_SUPPORTED;
            // mut_flags |= integration::CPUID_PRINTER_FLAG_PRINT_UNSUPPORTED;
            mut_flags |= integration::CPUID_PRINTER_FLAG_PRINT_ERROR;
            integration::cpuid_printer_t mut_cpuid_printer{};
            mut_cpuid_printer.print_features(pmut_rdl0, mut_flags);
            integration::verify(mut_cpuid_printer.succeeded());
        }

        // Valid registers should be present
        {
            // Fn0000_0001h[0][EDX][ 5]: RDMSR and WRMSR support
            bool mut_found_rdmsr_support{};
            constexpr auto rdmsr_bit{0x20_u32};
            constexpr mv_cdl_entry_t rdmsr_support{
                .fun = cpuid_fn0000_0001.get(), .idx = 0U, .edx = rdmsr_bit.get()};

            for (auto const &entry : pmut_rdl0->entries) {
                if ((entry.fun == rdmsr_support.fun) &&                          // NOLINT
                    (entry.idx == rdmsr_support.idx) &&                          // NOLINT
                    ((entry.edx & rdmsr_support.edx) == rdmsr_support.edx)) {    // NOLINT
                    mut_found_rdmsr_support = true;
                }
            }
            integration::verify(mut_found_rdmsr_support);
        }

        // CPU affinity test (requires more than one core)
        {
            bsl::builtin_memset(pmut_rdl0, '\0', bsl::to_umx(sizeof(*pmut_rdl0)));
            pmut_rdl0->num_entries = (2_u64).get();
            pmut_rdl0->entries.at_if(0_idx)->fun = cpuid_fn0000_0000.get();
            pmut_rdl0->entries.at_if(1_idx)->fun = cpuid_fn8000_0000.get();

            pmut_rdl1->num_entries = (2_u64).get();
            pmut_rdl1->entries.at_if(0_idx)->fun = cpuid_fn0000_0000.get();
            pmut_rdl1->entries.at_if(1_idx)->fun = cpuid_fn8000_0000.get();

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_pp_op_cpuid_get_supported_list());
            integration::set_affinity(core1);
            integration::verify(mut_hvc.mv_pp_op_cpuid_get_supported_list());
            integration::set_affinity(core0);
        }

        return 0;
    }
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
    bsl::enable_color();
    return hypercall::tests();
}
