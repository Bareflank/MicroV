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
#include <bsl/errc_type.hpp>
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
        mv_hypercall_t mut_hvc{};

        /// TODO:
        /// - Need to implement at test for attempting to destroy an
        ///   active VP.
        ///

        integration::verify(mut_hvc.initialize());
        auto const hndl{mut_hvc.handle()};

        // invalid VPID
        mut_ret = mv_vp_op_destroy_vp_impl(hndl.get(), MV_INVALID_ID.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VPID out of range
        auto const oor{bsl::to_u16(HYPERVISOR_MAX_VPS + bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vp_op_destroy_vp_impl(hndl.get(), oor.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VPID not yet created
        auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VPS - bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vp_op_destroy_vp_impl(hndl.get(), nyc.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // root VP
        mut_ret = mv_vp_op_destroy_vp_impl(hndl.get(), {});
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // Still assigned
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(!mut_hvc.mv_vp_op_destroy_vp(vpid));

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Destroy in order of creation
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};

            auto const vpid1{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vpid2{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vpid3{mut_hvc.mv_vp_op_create_vp(vmid)};

            integration::verify(vpid1.is_valid_and_checked());
            integration::verify(vpid2.is_valid_and_checked());
            integration::verify(vpid1.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid1));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid2));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid3));

            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Destroy in reverse order
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};

            auto const vpid1{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vpid2{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vpid3{mut_hvc.mv_vp_op_create_vp(vmid)};

            integration::verify(vpid1.is_valid_and_checked());
            integration::verify(vpid2.is_valid_and_checked());
            integration::verify(vpid1.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid3));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid2));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid1));

            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Destroy in random order
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};

            auto const vpid1{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vpid2{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vpid3{mut_hvc.mv_vp_op_create_vp(vmid)};

            integration::verify(vpid1.is_valid_and_checked());
            integration::verify(vpid2.is_valid_and_checked());
            integration::verify(vpid1.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid2));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid3));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid1));

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
