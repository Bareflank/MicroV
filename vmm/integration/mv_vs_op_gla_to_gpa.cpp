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
#include <mv_constants.hpp>
#include <mv_hypercall_impl.hpp>
#include <mv_hypercall_t.hpp>
#include <mv_translation_t.hpp>
#include <mv_types.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

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
        integration::initialize_globals();

        auto const gla{to_u64(&g_shared_page0)};
        bsl::safe_u64 mut_gpa{};

        // invalid VSID
        auto const iid{MV_INVALID_ID};
        mut_ret = mv_vs_op_gla_to_gpa_impl(hndl.get(), iid.get(), gla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID out of range
        auto const oor{bsl::to_u16(HYPERVISOR_MAX_VSS + bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_gla_to_gpa_impl(hndl.get(), oor.get(), gla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID not yet created
        auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VSS - bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_gla_to_gpa_impl(hndl.get(), nyc.get(), gla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // GLA that is not paged aligned
        constexpr auto ugla{42_u64};
        mut_ret = mv_vs_op_gla_to_gpa_impl(hndl.get(), self.get(), ugla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // NULL GLA
        constexpr auto ngla{0_u64};
        mut_ret = mv_vs_op_gla_to_gpa_impl(hndl.get(), self.get(), ngla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // GLA that is not present (i.e. not paged in)
        constexpr auto npgla{0x1000_u64};
        mut_ret = mv_vs_op_gla_to_gpa_impl(hndl.get(), self.get(), npgla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID that has been created, but has not been initialized
        {
            auto const vmid1{mut_hvc.mv_vm_op_create_vm()};
            auto const vm1_vpid0{mut_hvc.mv_vp_op_create_vp(vmid1)};
            auto const vm1_vp0_vsid0{mut_hvc.mv_vs_op_create_vs(vm1_vpid0)};

            auto const trns{mut_hvc.mv_vs_op_gla_to_gpa(vm1_vp0_vsid0, gla)};
            integration::verify(!trns.is_valid);

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vm1_vp0_vsid0));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vm1_vpid0));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid1));
        }

        // VSID that has been created, but is not locally assigned.
        {
            auto const vmid1{mut_hvc.mv_vm_op_create_vm()};
            auto const vm1_vpid0{mut_hvc.mv_vp_op_create_vp(vmid1)};
            auto const vm1_vp0_vsid0{mut_hvc.mv_vs_op_create_vs(vm1_vpid0)};

            integration::set_affinity(core1);

            auto const trns{mut_hvc.mv_vs_op_gla_to_gpa(vm1_vp0_vsid0, gla)};
            integration::verify(!trns.is_valid);

            integration::set_affinity(core0);

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vm1_vp0_vsid0));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vm1_vpid0));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid1));
        }

        // Get a valid GPA a lot to make sure mapping/unmapping works
        constexpr auto num_loops{0x100_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            auto const trns{mut_hvc.mv_vs_op_gla_to_gpa(self, gla)};
            integration::verify(trns.is_valid);
        }

        // Get the gpa and print the results for manual inspection
        {
            auto const trns{mut_hvc.mv_vs_op_gla_to_gpa(self, gla)};
            integration::verify(trns.is_valid);

            bsl::debug() << "the result is:\n"
                         << "  - vaddr: " << bsl::hex(trns.vaddr) << bsl::endl
                         << "  - laddr: " << bsl::hex(trns.laddr) << bsl::endl
                         << "  - paddr: " << bsl::hex(trns.paddr) << bsl::endl
                         << "  - flags: " << bsl::hex(trns.flags) << bsl::endl
                         << "  - is_valid: " << trns.is_valid << bsl::endl
                         << bsl::endl;
        }

        /// TODO:
        /// - Add a migration test. To do that, we will actually need to
        ///   start a VS that is running with a functional set of page
        ///   tables.
        ///

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
