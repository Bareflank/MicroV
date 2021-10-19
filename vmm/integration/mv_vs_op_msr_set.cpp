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
        constexpr auto msr_pat{0x277_u32};
        constexpr auto msr_sysenter_cs{0x174_u32};
        constexpr auto msr_sysenter_esp{0x175_u32};
        constexpr auto msr_sysenter_eip{0x176_u32};
        constexpr auto msr_efer{0xC0000080_u32};
        constexpr auto msr_star{0xC0000081_u32};
        constexpr auto msr_lstar{0xC0000082_u32};
        constexpr auto msr_cstar{0xC0000083_u32};
        constexpr auto msr_fmask{0xC0000084_u32};
        constexpr auto msr_fs_base{0xC0000100_u32};
        constexpr auto msr_gs_base{0xC0000101_u32};
        constexpr auto msr_kernel_gs_base{0xC0000102_u32};
        constexpr auto msr_apic_base{0x0000001B_u32};

        mv_status_t mut_ret{};
        constexpr auto val{0x87654321_u64};

        integration::initialize_globals();

        // invalid VSID #1
        mut_ret = mv_vs_op_msr_set_impl(hndl.get(), MV_INVALID_ID.get(), msr_star.get(), val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // invalid VSID #2
        mut_ret = mv_vs_op_msr_set_impl(hndl.get(), MV_SELF_ID.get(), msr_star.get(), val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // invalid VSID #3
        mut_ret = mv_vs_op_msr_set_impl(hndl.get(), vsid0.get(), msr_star.get(), val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // invalid VSID #4
        mut_ret = mv_vs_op_msr_set_impl(hndl.get(), vsid1.get(), msr_star.get(), val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID out of range
        auto const oor{bsl::to_u16(HYPERVISOR_MAX_VSS + bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_msr_set_impl(hndl.get(), oor.get(), msr_star.get(), val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID not yet created
        auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VSS - bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_msr_set_impl(hndl.get(), nyc.get(), msr_star.get(), val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // register unsupported
        constexpr auto ureg{0xFFFFFFFF_u32};
        mut_ret = mv_vs_op_msr_set_impl(hndl.get(), self.get(), ureg.get(), val.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // Verify the model specific registers
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_pat, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_pat));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_sysenter_cs, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_sysenter_cs));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_sysenter_esp, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_sysenter_esp));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_sysenter_eip, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_sysenter_eip));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_efer, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_efer));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_star, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_star));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_lstar, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_lstar));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_cstar, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_cstar));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_fmask, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_fmask));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_fs_base, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_fs_base));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_gs_base, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_gs_base));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_kernel_gs_base, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_kernel_gs_base));
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_apic_base, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_apic_base));

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Verify the model specific registers
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_star, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_star));
            integration::set_affinity(core1);
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_star, val));
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_star));

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_msr_set(vsid, msr_star, val));
            integration::set_affinity(core1);
            integration::verify(val == mut_hvc.mv_vs_op_msr_get(vsid, msr_star));
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
