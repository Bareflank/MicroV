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
#include <mv_cdl_t.hpp>
#include <mv_constants.hpp>
#include <mv_hypercall_impl.hpp>
#include <mv_hypercall_t.hpp>
#include <mv_types.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstring.hpp>
#include <bsl/debug.hpp>    // IWYU pragma: keep
#include <bsl/enable_color.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// @brief the standard feature information CPUID
    constexpr auto CPUID_FN0000_0001{0x00000001_u32};
    /// @brief the extended feature information CPUID
    constexpr auto CPUID_FN8000_0001{0x80000001_u32};

    /// <!-- description -->
    ///   @brief Get the CPUID supported list into the shared page
    ///
    constexpr void
    cpuid_get_supported_list() noexcept
    {
        auto *const pmut_cdl0{to_0<mv_cdl_t>()};

        // Get the list of supported CPUID features

        bsl::builtin_memset(pmut_cdl0, '\0', bsl::to_umx(sizeof(*pmut_cdl0)));

        pmut_cdl0->num_entries = (2_u64).get();
        pmut_cdl0->entries.at_if(0_idx)->fun = CPUID_FN0000_0001.get();
        pmut_cdl0->entries.at_if(1_idx)->fun = CPUID_FN8000_0001.get();

        integration::verify(mut_hvc.mv_pp_op_cpuid_get_supported_list());
        integration::verify(pmut_cdl0->num_entries == bsl::safe_u64::magic_2());
    }

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

        integration::initialize_globals();
        auto *const pmut_cdl0{to_0<mv_cdl_t>()};
        auto *const pmut_cdl1{to_1<mv_cdl_t>()};

        // invalid VSID #1
        mut_ret = mv_vs_op_cpuid_set_list_impl(hndl.get(), MV_INVALID_ID.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // invalid VSID #2
        mut_ret = mv_vs_op_cpuid_set_list_impl(hndl.get(), MV_SELF_ID.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // invalid VSID #3
        mut_ret = mv_vs_op_cpuid_set_list_impl(hndl.get(), vsid0.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // invalid VSID #4
        mut_ret = mv_vs_op_cpuid_set_list_impl(hndl.get(), vsid1.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID out of range
        auto const oor{bsl::to_u16(HYPERVISOR_MAX_VSS + bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_cpuid_set_list_impl(hndl.get(), oor.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID not yet created
        auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VSS - bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_cpuid_set_list_impl(hndl.get(), nyc.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // No shared paged
        mut_ret = mv_vs_op_cpuid_set_list_impl(hndl.get(), self.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        integration::initialize_shared_pages();
        pmut_cdl0->num_entries = bsl::safe_u64::magic_1().get();

        // register unsupported
        constexpr auto unsupported_cpuid{0xFFFFFFFF_u32};
        pmut_cdl0->entries.front().fun = unsupported_cpuid.get();
        mut_ret = mv_vs_op_cpuid_set_list_impl(hndl.get(), self.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // empty CDL
        {
            pmut_cdl0->num_entries = {};

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::verify(!mut_hvc.mv_vs_op_cpuid_set_list(vsid));

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // CDL num entries out of range
        {
            pmut_cdl0->num_entries =
                (MV_CDL_MAX_ENTRIES + bsl::safe_u64::magic_1()).checked().get();

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::verify(!mut_hvc.mv_vs_op_cpuid_set_list(vsid));

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Enable unsupported CPUID features
        {
            bsl::builtin_memset(pmut_cdl0, '\0', bsl::to_umx(sizeof(*pmut_cdl0)));

            cpuid_get_supported_list();

            auto &mut_entry_fn0000_0001{*pmut_cdl0->entries.at_if(bsl::safe_idx::magic_0())};
            integration::verify(mut_entry_fn0000_0001.fun == CPUID_FN0000_0001);
            integration::verify(mut_entry_fn0000_0001.idx == bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn0000_0001.ecx != bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn0000_0001.edx != bsl::safe_u32::magic_0());
            auto &mut_entry_fn8000_0001{*pmut_cdl0->entries.at_if(bsl::safe_idx::magic_1())};
            integration::verify(mut_entry_fn8000_0001.fun == CPUID_FN8000_0001);
            integration::verify(mut_entry_fn8000_0001.idx == bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn8000_0001.ecx != bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn8000_0001.edx != bsl::safe_u32::magic_0());

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            auto const fn0000_0001_entry_copy{mut_entry_fn0000_0001};
            auto const fn8000_0001_entry_copy{mut_entry_fn8000_0001};

            // Try to enable all possible features
            mut_entry_fn0000_0001.ecx = bsl::safe_u32::max_value().get();
            mut_entry_fn8000_0001.ecx = bsl::safe_u32::max_value().get();

            integration::verify(mut_hvc.mv_vs_op_cpuid_set_list(vsid));
            integration::verify(mut_entry_fn0000_0001.fun == CPUID_FN0000_0001);
            integration::verify(mut_entry_fn0000_0001.idx == bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn8000_0001.fun == CPUID_FN8000_0001);
            integration::verify(mut_entry_fn8000_0001.idx == bsl::safe_u32::magic_0());

            mut_entry_fn0000_0001.eax = {};
            mut_entry_fn0000_0001.ebx = {};
            mut_entry_fn0000_0001.ecx = {};
            mut_entry_fn0000_0001.edx = {};

            mut_entry_fn8000_0001.eax = {};
            mut_entry_fn8000_0001.ebx = {};
            mut_entry_fn8000_0001.ecx = {};
            mut_entry_fn8000_0001.edx = {};

            // Enabled features should not have changed
            integration::verify(mut_hvc.mv_vs_op_cpuid_get_list(vsid));
            integration::verify(mut_entry_fn0000_0001.fun == CPUID_FN0000_0001);
            integration::verify(mut_entry_fn0000_0001.idx == bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn8000_0001.fun == CPUID_FN8000_0001);
            integration::verify(mut_entry_fn8000_0001.idx == bsl::safe_u32::magic_0());

            integration::verify(mut_entry_fn0000_0001.ecx == fn0000_0001_entry_copy.ecx);
            integration::verify(mut_entry_fn8000_0001.ecx == fn8000_0001_entry_copy.ecx);

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Disable CPUID features
        {
            bsl::builtin_memset(pmut_cdl0, '\0', bsl::to_umx(sizeof(*pmut_cdl0)));

            cpuid_get_supported_list();

            auto &mut_entry_fn0000_0001{*pmut_cdl0->entries.at_if(bsl::safe_idx::magic_0())};
            integration::verify(mut_entry_fn0000_0001.fun == CPUID_FN0000_0001);
            integration::verify(mut_entry_fn0000_0001.idx == bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn0000_0001.ecx != bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn0000_0001.edx != bsl::safe_u32::magic_0());
            auto &mut_entry_fn8000_0001{*pmut_cdl0->entries.at_if(bsl::safe_idx::magic_1())};
            integration::verify(mut_entry_fn8000_0001.fun == CPUID_FN8000_0001);
            integration::verify(mut_entry_fn8000_0001.idx == bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn8000_0001.ecx != bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn8000_0001.edx != bsl::safe_u32::magic_0());

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            // Disable features
            mut_entry_fn0000_0001.ecx = bsl::safe_u32::magic_0().get();
            mut_entry_fn8000_0001.ecx = bsl::safe_u32::magic_0().get();

            integration::verify(mut_hvc.mv_vs_op_cpuid_set_list(vsid));
            integration::verify(mut_entry_fn0000_0001.fun == CPUID_FN0000_0001);
            integration::verify(mut_entry_fn0000_0001.idx == bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn8000_0001.fun == CPUID_FN8000_0001);
            integration::verify(mut_entry_fn8000_0001.idx == bsl::safe_u32::magic_0());

            mut_entry_fn0000_0001.eax = {};
            mut_entry_fn0000_0001.ebx = {};
            mut_entry_fn0000_0001.ecx = {};
            mut_entry_fn0000_0001.edx = {};

            mut_entry_fn8000_0001.eax = {};
            mut_entry_fn8000_0001.ebx = {};
            mut_entry_fn8000_0001.ecx = {};
            mut_entry_fn8000_0001.edx = {};

            // Features should now be disabled
            integration::verify(mut_hvc.mv_vs_op_cpuid_get_list(vsid));
            integration::verify(mut_entry_fn0000_0001.fun == CPUID_FN0000_0001);
            integration::verify(mut_entry_fn0000_0001.idx == bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn8000_0001.fun == CPUID_FN8000_0001);
            integration::verify(mut_entry_fn8000_0001.idx == bsl::safe_u32::magic_0());

            integration::verify(mut_entry_fn0000_0001.ecx == bsl::safe_u32::magic_0());
            integration::verify(mut_entry_fn8000_0001.ecx == bsl::safe_u32::magic_0());

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // CPU affinity test (requires more than one core)
        {
            bsl::builtin_memset(pmut_cdl0, '\0', bsl::to_umx(sizeof(*pmut_cdl0)));

            pmut_cdl0->num_entries = bsl::safe_u64::magic_1().get();
            pmut_cdl0->entries.front().fun = CPUID_FN0000_0001.get();
            pmut_cdl0->entries.front().idx = {};
            pmut_cdl0->entries.front().eax = {};
            pmut_cdl0->entries.front().ebx = {};
            pmut_cdl0->entries.front().ecx = {};
            pmut_cdl0->entries.front().edx = {};

            pmut_cdl1->num_entries = bsl::safe_u64::magic_1().get();
            pmut_cdl1->entries.front().fun = CPUID_FN0000_0001.get();
            pmut_cdl1->entries.front().idx = {};
            pmut_cdl1->entries.front().eax = {};
            pmut_cdl1->entries.front().ebx = {};
            pmut_cdl1->entries.front().ecx = {};
            pmut_cdl1->entries.front().edx = {};

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_cpuid_set_list(vsid));
            integration::set_affinity(core1);
            integration::verify(mut_hvc.mv_vs_op_cpuid_set_list(vsid));
            integration::set_affinity(core0);

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        return bsl::exit_success;
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
