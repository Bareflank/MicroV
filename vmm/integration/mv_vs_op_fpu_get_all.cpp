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

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// @brief stores the size of the FPU portion of the shared page
    constexpr auto FPU_SIZE{0x200_umx};
    /// @brief stores the size of the padding portion of the shared page
    constexpr auto PADDING_SIZE{0xE00_umx};

    /// <!-- description -->
    ///   @brief A test shared page for the FPU.
    ///
    struct my_fpu_t final    // NOLINT
    {
        /// @brief store the FPU portion of the shared page
        bsl::array<bool, FPU_SIZE.get()> fpu;
        /// @brief store the padding portion of the shared page
        bsl::array<bool, PADDING_SIZE.get()> padding;
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

        integration::initialize_globals();
        auto *const pmut_fpu0{to_0<my_fpu_t>()};

        // invalid VSID
        mut_ret = mv_vs_op_fpu_get_all_impl(hndl.get(), MV_INVALID_ID.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID out of range
        auto const oor{bsl::to_u16(HYPERVISOR_MAX_VSS + bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_fpu_get_all_impl(hndl.get(), oor.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID not yet created
        auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VSS - bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_fpu_get_all_impl(hndl.get(), nyc.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // No shared paged
        mut_ret = mv_vs_op_fpu_get_all_impl(hndl.get(), self.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        integration::initialize_shared_pages();

        // Success test
        {
            for (bool &mut_elem : pmut_fpu0->fpu) {
                mut_elem = true;
            }

            for (bool &mut_elem : pmut_fpu0->padding) {
                mut_elem = false;
            }

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_fpu_set_all(vsid));

            for (bool &mut_elem : pmut_fpu0->fpu) {
                mut_elem = false;
            }

            for (bool &mut_elem : pmut_fpu0->padding) {
                mut_elem = true;
            }

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_fpu_get_all(vsid));

            for (bool const &elem : pmut_fpu0->fpu) {
                integration::verify(elem);
            }

            for (bool const &elem : pmut_fpu0->padding) {
                integration::verify(elem);
            }

            for (bool &mut_elem : pmut_fpu0->fpu) {
                mut_elem = false;
            }

            for (bool &mut_elem : pmut_fpu0->padding) {
                mut_elem = false;
            }

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_fpu_get_all(vsid));

            for (bool const &elem : pmut_fpu0->fpu) {
                integration::verify(elem);
            }

            for (bool const &elem : pmut_fpu0->padding) {
                integration::verify(!elem);
            }

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // CPU affinity test
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_fpu_get_all(vsid));
            integration::set_affinity(core1);
            integration::verify(mut_hvc.mv_vs_op_fpu_get_all(vsid));
            integration::set_affinity(core0);
            integration::verify(mut_hvc.mv_vs_op_fpu_get_all(vsid));

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Stress test
        {
            integration::set_affinity(core0);

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            constexpr auto num_loops{0x1000_umx};
            for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
                integration::verify(mut_hvc.mv_vs_op_fpu_get_all(vsid));
            }

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
