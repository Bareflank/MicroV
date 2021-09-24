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
#include <mv_reg_t.hpp>
#include <mv_types.hpp>

#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
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
        constexpr auto reg{mv_reg_t::mv_reg_t_rax};
        constexpr auto val{0x1234567890ABCDEF_u64};

        integration::initialize_globals();

        // invalid VSID
        mut_ret = mv_vs_op_reg_set_impl(hndl.get(), MV_INVALID_ID.get(), reg, val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID out of range
        auto const oor{bsl::to_u16(HYPERVISOR_MAX_VSS + bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_reg_set_impl(hndl.get(), oor.get(), reg, val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID not yet created
        auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VSS - bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_reg_set_impl(hndl.get(), nyc.get(), reg, val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // register unsupported
        constexpr auto ureg{mv_reg_t::mv_reg_t_unsupported};
        mut_ret = mv_vs_op_reg_set_impl(hndl.get(), self.get(), ureg, val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // register invalid
        constexpr auto ireg{mv_reg_t::mv_reg_t_invalid};
        mut_ret = mv_vs_op_reg_set_impl(hndl.get(), self.get(), ireg, val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // register out of range
        constexpr auto oreg{static_cast<mv_reg_t>(0xFFFFFFFFU)};
        mut_ret = mv_vs_op_reg_set_impl(hndl.get(), self.get(), oreg, val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // Verify the general purpose registers
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rax, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rax));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rbx, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rbx));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rcx, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rcx));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rdx, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rdx));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rbp, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rbp));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rsi, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rsi));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rdi, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rdi));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_r8, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_r8));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_r9, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_r9));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_r10, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_r10));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_r11, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_r11));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_r12, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_r12));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_r13, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_r13));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_r14, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_r14));
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_r15, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_r15));

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Verify the general purpose registers
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rax, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rax));
            integration::set_affinity(core1);
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rax, val));
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rax));

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rax, val));
            integration::set_affinity(core1);
            integration::verify(val == mut_hvc.mv_vs_op_reg_get(vsid, mv_reg_t::mv_reg_t_rax));
            integration::set_affinity(core0);

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        /// TODO:
        /// - Finish the other registers
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
