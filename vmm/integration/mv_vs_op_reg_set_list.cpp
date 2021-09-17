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
#include <mv_rdl_t.hpp>
#include <mv_reg_t.hpp>
#include <mv_translation_t.hpp>
#include <mv_types.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// @brief defines the shared page used for this test
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    alignas(HYPERVISOR_PAGE_SIZE.get()) mv_rdl_t g_mut_rdl{};

    /// @brief stores the list of general purpose registers
    constexpr bsl::array GPR_REG_LIST{
        mv_reg_t::mv_reg_t_rax,
        mv_reg_t::mv_reg_t_rbx,
        mv_reg_t::mv_reg_t_rcx,
        mv_reg_t::mv_reg_t_rdx,
        mv_reg_t::mv_reg_t_rbp,
        mv_reg_t::mv_reg_t_rsi,
        mv_reg_t::mv_reg_t_rdi,
        mv_reg_t::mv_reg_t_r8,
        mv_reg_t::mv_reg_t_r9,
        mv_reg_t::mv_reg_t_r10,
        mv_reg_t::mv_reg_t_r11,
        mv_reg_t::mv_reg_t_r12,
        mv_reg_t::mv_reg_t_r13,
        mv_reg_t::mv_reg_t_r14,
        mv_reg_t::mv_reg_t_r15,
    };

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
        mv_hypercall_t mut_hvc{};

        constexpr auto self{MV_SELF_ID};

        /// NOTE:
        /// - Touch g_mut_page. This ensures that g_mut_page is paged in.
        ///

        g_mut_rdl = {};

        /// TODO:
        /// - Currently we assume that the GVA and GLA or g_mut_test are the
        ///   same. In most cases (if not all), this is true, but we really
        ///   should call gva_to_gla to get the GLA instead of making this
        ///   assumption.
        ///

        integration::verify(mut_hvc.initialize());
        auto const hndl{mut_hvc.handle()};

        auto const translation{mut_hvc.mv_vs_op_gla_to_gpa(self, to_umx(&g_mut_rdl))};
        integration::verify(translation.is_valid);

        auto const gpa{translation.paddr};
        integration::verify(gpa.is_valid_and_checked());

        // invalid VSID
        mut_ret = mv_vs_op_reg_set_list_impl(hndl.get(), MV_INVALID_ID.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID out of range
        auto const oor{bsl::to_u16(HYPERVISOR_MAX_VSS + bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_reg_set_list_impl(hndl.get(), oor.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID not yet created
        auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VSS - bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_reg_set_list_impl(hndl.get(), nyc.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // No shared paged
        mut_ret = mv_vs_op_reg_set_list_impl(hndl.get(), self.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        integration::verify(mut_hvc.mv_pp_op_clr_shared_page_gpa());
        integration::verify(mut_hvc.mv_pp_op_set_shared_page_gpa(gpa));

        g_mut_rdl.num_entries = bsl::safe_u64::magic_1().get();

        // register unsupported
        g_mut_rdl.entries.front().reg = to_u64(mv_reg_t::mv_reg_t_unsupported).get();
        mut_ret = mv_vs_op_reg_set_list_impl(hndl.get(), self.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // register invalid
        g_mut_rdl.entries.front().reg = to_u64(mv_reg_t::mv_reg_t_invalid).get();
        mut_ret = mv_vs_op_reg_set_list_impl(hndl.get(), self.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // register out of range
        g_mut_rdl.entries.front().reg = ~to_u64(mv_reg_t::mv_reg_t_invalid).get();
        mut_ret = mv_vs_op_reg_set_list_impl(hndl.get(), self.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // empty RDL
        {
            g_mut_rdl.num_entries = {};

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vs_op_reg_set_list(vsid));

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Verify the general purpose registers
        {
            g_mut_rdl.num_entries = GPR_REG_LIST.size().get();
            for (bsl::safe_idx mut_i{}; mut_i < GPR_REG_LIST.size(); ++mut_i) {
                g_mut_rdl.entries.at_if(mut_i)->reg = to_u64(*GPR_REG_LIST.at_if(mut_i)).get();
            }

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            for (bsl::safe_idx mut_i{}; mut_i < GPR_REG_LIST.size(); ++mut_i) {
                g_mut_rdl.entries.at_if(mut_i)->val = mut_i.get();
            }

            integration::verify(mut_hvc.mv_vs_op_reg_set_list(vsid));

            for (bsl::safe_idx mut_i{}; mut_i < GPR_REG_LIST.size(); ++mut_i) {
                g_mut_rdl.entries.at_if(mut_i)->val = {};
            }

            integration::verify(mut_hvc.mv_vs_op_reg_get_list(vsid));

            for (bsl::safe_idx mut_i{}; mut_i < GPR_REG_LIST.size(); ++mut_i) {
                integration::verify(g_mut_rdl.entries.at_if(mut_i)->val == mut_i);
            }

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        /// TODO:
        /// - Finish the other registers
        /// - Verify that RDL registers that should be ignored are ignored
        /// - Verify that unused entries are not modified
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
