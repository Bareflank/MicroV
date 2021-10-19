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

#include <integration_utils.hpp>
#include <mv_constants.hpp>
#include <mv_hypercall_impl.hpp>
#include <mv_hypercall_t.hpp>
#include <mv_rdl_t.hpp>
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
        mv_rdl_entry_t const star{.reg = 0xC0000081UL, .val = bsl::safe_u64::magic_1().get()};
        mv_rdl_entry_t const pat{.reg = 0x00000277UL, .val = bsl::safe_u64::magic_1().get()};
        mv_rdl_entry_t const apic_base{.reg = 0x0000001BUL, .val = bsl::safe_u64::magic_1().get()};

        integration::initialize_globals();
        auto *const pmut_rdl0{to_0<mv_rdl_t>()};
        auto *const pmut_rdl1{to_1<mv_rdl_t>()};

        // No shared paged
        mut_ret = mv_pp_op_msr_get_supported_list_impl(hndl.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        integration::initialize_shared_pages();

        // Setting mv_rdl_t.reg1 should fail when MV_RDL_FLAG_ALL is not set
        pmut_rdl0->reg0 = bsl::safe_u64::magic_0().get();
        pmut_rdl0->reg1 = bsl::safe_u64::magic_1().get();
        mut_ret = mv_pp_op_msr_get_supported_list_impl(hndl.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);
        pmut_rdl0->reg1 = bsl::safe_u64::magic_0().get();

        // Setting unknown flags in reg0 should fail
        pmut_rdl0->reg0 = bsl::safe_u64::max_value().get();
        mut_ret = mv_pp_op_msr_get_supported_list_impl(hndl.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // Setting num_entries should fail when MV_RDL_FLAG_ALL is set
        pmut_rdl0->reg0 = MV_RDL_FLAG_ALL.get();
        pmut_rdl0->num_entries = bsl::safe_u64::magic_1().get();
        mut_ret = mv_pp_op_msr_get_supported_list_impl(hndl.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);
        pmut_rdl0->num_entries = bsl::safe_u64::magic_0().get();

        // Get the list of all supported MSRs with MV_RDL_FLAG_ALL successfully
        pmut_rdl0->reg0 = MV_RDL_FLAG_ALL.get();
        mut_ret = mv_pp_op_msr_get_supported_list_impl(hndl.get());
        integration::verify(mut_ret == MV_STATUS_SUCCESS);
        integration::verify(pmut_rdl0->num_entries > bsl::safe_u64::magic_0());
        integration::verify(pmut_rdl0->num_entries <= MV_RDL_MAX_ENTRIES);

        // Valid registers should be present
        {
            bool mut_found_star{false};
            bool mut_found_pat{false};
            bool mut_found_apic_base{false};
            for (bsl::safe_idx mut_i{}; mut_i < pmut_rdl0->num_entries; ++mut_i) {
                if (pmut_rdl0->entries.at_if(mut_i)->reg == star.reg) {
                    integration::verify(1UL == pmut_rdl0->entries.at_if(mut_i)->val);
                    mut_found_star = true;
                }
                else if (pmut_rdl0->entries.at_if(mut_i)->reg == pat.reg) {
                    integration::verify(1UL == pmut_rdl0->entries.at_if(mut_i)->val);
                    mut_found_pat = true;
                }
                else if (pmut_rdl0->entries.at_if(mut_i)->reg == apic_base.reg) {
                    integration::verify(1UL == pmut_rdl0->entries.at_if(mut_i)->val);
                    mut_found_apic_base = true;
                }
            }
            integration::verify(mut_found_star);
            integration::verify(mut_found_pat);
            integration::verify(mut_found_apic_base);
        }

        // CPU affinity test (requires more than one core)
        {
            bsl::builtin_memset(pmut_rdl0, '\0', bsl::to_umx(sizeof(*pmut_rdl0)));
            pmut_rdl0->num_entries = bsl::safe_u64::magic_0().get();
            pmut_rdl0->reg0 = MV_RDL_FLAG_ALL.get();

            pmut_rdl1->num_entries = bsl::safe_u64::magic_0().get();
            pmut_rdl1->reg0 = MV_RDL_FLAG_ALL.get();

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_pp_op_msr_get_supported_list());
            integration::set_affinity(core1);
            integration::verify(mut_hvc.mv_pp_op_msr_get_supported_list());
            integration::set_affinity(core0);
        }

        // When a single page is not enough to fit all MSRs, mv_rdl_t.reg1 is set
        {
#ifdef INTEGRATION_MOCK
            bsl::safe_idx mut_i{};
            constexpr auto total_supported_msrs{610_umx};
            bsl::array<hypercall::mv_rdl_entry_t, total_supported_msrs.get()> supported_msrs{};
            for (auto &entry : supported_msrs) {
                entry.reg = mut_i.get();
                entry.val = 1UL;
                ++mut_i;
            }
            supported_msrs.at_if(0_idx)->reg = star.reg;
            supported_msrs.at_if(1_idx)->reg = pat.reg;
            supported_msrs.at_if(2_idx)->reg = apic_base.reg;
#endif

            bsl::builtin_memset(pmut_rdl0, '\0', bsl::to_umx(sizeof(*pmut_rdl0)));
            pmut_rdl0->reg0 |= MV_RDL_FLAG_ALL.get();    // NOLINT
            integration::verify(mut_hvc.mv_pp_op_msr_get_supported_list());
            integration::verify(pmut_rdl0->num_entries > bsl::safe_u64::magic_0());
            integration::verify(pmut_rdl0->num_entries <= MV_RDL_MAX_ENTRIES);

#ifdef INTEGRATION_MOCK
            for (mut_i = 0UL; mut_i < pmut_rdl0->num_entries; ++mut_i) {
                integration::verify(
                    supported_msrs.at_if(mut_i)->reg == pmut_rdl0->entries.at_if(mut_i)->reg);
            }
#endif

            auto mut_idx{MV_RDL_MAX_ENTRIES};
            while (pmut_rdl0->reg1 != bsl::safe_u64::magic_0()) {
                pmut_rdl0->reg1 = mut_idx.get();
                pmut_rdl0->num_entries = 0UL;
                integration::verify(mut_hvc.mv_pp_op_msr_get_supported_list());
                integration::verify(pmut_rdl0->num_entries > bsl::safe_u64::magic_0());
                integration::verify(pmut_rdl0->num_entries <= MV_RDL_MAX_ENTRIES);
#ifdef INTEGRATION_MOCK
                for (mut_i = 0_idx; mut_i < pmut_rdl0->num_entries; ++mut_i) {
                    integration::verify(
                        supported_msrs.at_if(mut_idx.get() + mut_i)->reg ==
                        pmut_rdl0->entries.at_if(mut_i)->reg);
                }
#endif
                mut_idx = (mut_idx + MV_RDL_MAX_ENTRIES).checked();
            }
        }

        // Overflow reg1
        bsl::builtin_memset(pmut_rdl0, '\0', bsl::to_umx(sizeof(*pmut_rdl0)));
        pmut_rdl0->reg0 |= MV_RDL_FLAG_ALL.get();    // NOLINT
        pmut_rdl0->reg1 = bsl::safe_u64::max_value().get();
        integration::verify(mv_pp_op_msr_get_supported_list_impl(hndl.get()) != MV_STATUS_SUCCESS);

        // Requests with mv_rdl_t.reg0 = 0 should filter our existing list
        bsl::builtin_memset(pmut_rdl0, '\0', bsl::to_umx(sizeof(*pmut_rdl0)));
        pmut_rdl0->entries.at_if(0_idx)->reg = bsl::to_u64(bsl::safe_u32::max_value()).get();
        pmut_rdl0->entries.at_if(1_idx)->reg = star.reg;
        pmut_rdl0->entries.at_if(2_idx)->reg = pat.reg;
        pmut_rdl0->entries.at_if(3_idx)->reg = apic_base.reg;
        pmut_rdl0->num_entries = 4UL;
        integration::verify(mv_pp_op_msr_get_supported_list_impl(hndl.get()) == MV_STATUS_SUCCESS);
        integration::verify(pmut_rdl0->entries.at_if(0_idx)->val == bsl::safe_u64::magic_0());
        integration::verify(pmut_rdl0->entries.at_if(1_idx)->val == bsl::safe_u64::magic_1());
        integration::verify(pmut_rdl0->entries.at_if(2_idx)->val == bsl::safe_u64::magic_1());
        integration::verify(pmut_rdl0->entries.at_if(3_idx)->val == bsl::safe_u64::magic_1());

        // An MSR register is a 32 bit address
        bsl::builtin_memset(pmut_rdl0, '\0', bsl::to_umx(sizeof(*pmut_rdl0)));
        pmut_rdl0->entries.at_if(0_idx)->reg = bsl::to_u64(bsl::safe_u64::max_value()).get();
        pmut_rdl0->num_entries = 1UL;
        integration::verify(mv_pp_op_msr_get_supported_list_impl(hndl.get()) != MV_STATUS_SUCCESS);
        integration::verify(pmut_rdl0->entries.at_if(0_idx)->val == bsl::safe_u64::magic_0());

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
