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
#include <mv_mdl_t.hpp>
#include <mv_types.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/errc_type.hpp>
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
        bsl::safe_u16 mut_src{};
        bsl::safe_u16 mut_dst{};

        integration::initialize_globals();
        auto *const pmut_mdl0{to_0<mv_mdl_t>()};

        auto const vmid{mut_hvc.mv_vm_op_create_vm()};

        // invalid source VMID
        mut_dst = vmid;
        mut_src = MV_INVALID_ID;
        mut_ret = mv_vm_op_mmio_map_impl(hndl.get(), mut_dst.get(), mut_src.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // source VMID out of range
        mut_dst = vmid;
        mut_src = bsl::to_u16(HYPERVISOR_MAX_VMS + bsl::safe_u64::magic_1()).checked();
        mut_ret = mv_vm_op_mmio_map_impl(hndl.get(), mut_dst.get(), mut_src.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // source VMID not yet created
        mut_dst = vmid;
        mut_src = bsl::to_u16(HYPERVISOR_MAX_VMS - bsl::safe_u64::magic_1()).checked();
        mut_ret = mv_vm_op_mmio_map_impl(hndl.get(), mut_dst.get(), mut_src.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // source VMID must be the root VM for now
        mut_dst = vmid;
        mut_src = vmid;
        mut_ret = mv_vm_op_mmio_map_impl(hndl.get(), mut_dst.get(), mut_src.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // invalid destination VMID
        mut_dst = MV_INVALID_ID;
        mut_src = self;
        mut_ret = mv_vm_op_mmio_map_impl(hndl.get(), mut_dst.get(), mut_src.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // destination VMID out of range
        mut_dst = bsl::to_u16(HYPERVISOR_MAX_VMS + bsl::safe_u64::magic_1()).checked();
        mut_src = self;
        mut_ret = mv_vm_op_mmio_map_impl(hndl.get(), mut_dst.get(), mut_src.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // destination VMID not yet created
        mut_dst = bsl::to_u16(HYPERVISOR_MAX_VMS - bsl::safe_u64::magic_1()).checked();
        mut_src = self;
        mut_ret = mv_vm_op_mmio_map_impl(hndl.get(), mut_dst.get(), mut_src.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // destination VMID cannot be the root VM for now
        mut_dst = self;
        mut_src = self;
        mut_ret = mv_vm_op_mmio_map_impl(hndl.get(), mut_dst.get(), mut_src.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // No shared paged
        mut_dst = vmid;
        mut_src = self;
        mut_ret = mv_vm_op_mmio_map_impl(hndl.get(), mut_dst.get(), mut_src.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        integration::initialize_shared_pages();

        // empty MDL
        {
            pmut_mdl0->num_entries = {};
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        // MDL num entries out of range
        {
            pmut_mdl0->num_entries =
                (MV_MDL_MAX_ENTRIES + bsl::safe_u64::magic_1()).checked().get();
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        pmut_mdl0->num_entries = bsl::safe_u64::magic_1().get();

        // source GPA is not page aligned
        {
            constexpr auto gpa{0x42_u64};
            pmut_mdl0->entries.front().dst = {};
            pmut_mdl0->entries.front().src = gpa.get();
            pmut_mdl0->entries.front().bytes = HYPERVISOR_PAGE_SIZE.get();
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        // source GPA is out of range
        {
            constexpr auto gpa{0xFFFFFFFFFFFFF000_u64};
            pmut_mdl0->entries.front().dst = {};
            pmut_mdl0->entries.front().src = gpa.get();
            pmut_mdl0->entries.front().bytes = HYPERVISOR_PAGE_SIZE.get();
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        // destination GPA is not page aligned
        {
            constexpr auto gpa{0x42_u64};
            pmut_mdl0->entries.front().dst = gpa.get();
            pmut_mdl0->entries.front().src = {};
            pmut_mdl0->entries.front().bytes = HYPERVISOR_PAGE_SIZE.get();
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        // destination GPA is out of range
        {
            constexpr auto gpa{0xFFFFFFFFFFFFF000_u64};
            pmut_mdl0->entries.front().dst = gpa.get();
            pmut_mdl0->entries.front().src = {};
            pmut_mdl0->entries.front().bytes = HYPERVISOR_PAGE_SIZE.get();
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        // bytes is 0
        {
            pmut_mdl0->entries.front().dst = {};
            pmut_mdl0->entries.front().src = {};
            pmut_mdl0->entries.front().bytes = {};
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        // bytes is unaligned
        {
            constexpr auto bytes{0x42_u64};
            pmut_mdl0->entries.front().dst = {};
            pmut_mdl0->entries.front().src = {};
            pmut_mdl0->entries.front().bytes = bytes.get();
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        // bytes is out of range
        {
            constexpr auto bytes{0xFFFFFFFFFFFFF000_u64};
            pmut_mdl0->entries.front().dst = {};
            pmut_mdl0->entries.front().src = {};
            pmut_mdl0->entries.front().bytes = bytes.get();
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        // we currently do not support compressed MDLs
        {
            constexpr auto bytes{(HYPERVISOR_PAGE_SIZE * bsl::safe_u64::magic_2()).checked()};
            pmut_mdl0->entries.front().dst = {};
            pmut_mdl0->entries.front().src = {};
            pmut_mdl0->entries.front().bytes = bytes.get();
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
        }

        // Already mapped
        {
            pmut_mdl0->num_entries = bsl::safe_u64::magic_1().get();

            pmut_mdl0->entries.front().dst = {};
            pmut_mdl0->entries.front().src = {};
            pmut_mdl0->entries.front().bytes = HYPERVISOR_PAGE_SIZE.get();
            integration::verify(mut_hvc.mv_vm_op_mmio_map(vmid, self));
            integration::verify(!mut_hvc.mv_vm_op_mmio_map(vmid, self));
            integration::verify(mut_hvc.mv_vm_op_mmio_unmap(vmid));
        }

        // success (single)
        {
            pmut_mdl0->num_entries = bsl::safe_u64::magic_1().get();

            pmut_mdl0->entries.front().dst = {};
            pmut_mdl0->entries.front().src = {};
            pmut_mdl0->entries.front().bytes = HYPERVISOR_PAGE_SIZE.get();
            integration::verify(mut_hvc.mv_vm_op_mmio_map(vmid, self));
            integration::verify(mut_hvc.mv_vm_op_mmio_unmap(vmid));
        }

        // success (full MDL)
        {
            pmut_mdl0->num_entries = MV_MDL_MAX_ENTRIES.get();

            for (bsl::safe_idx mut_i{}; mut_i < MV_MDL_MAX_ENTRIES; ++mut_i) {
                auto const gpa{(HYPERVISOR_PAGE_SIZE * bsl::to_u64(mut_i)).checked()};
                pmut_mdl0->entries.at_if(mut_i)->dst = gpa.get();
                pmut_mdl0->entries.at_if(mut_i)->src = gpa.get();
                pmut_mdl0->entries.at_if(mut_i)->bytes = HYPERVISOR_PAGE_SIZE.get();
            }

            integration::verify(mut_hvc.mv_vm_op_mmio_map(vmid, self));
            integration::verify(mut_hvc.mv_vm_op_mmio_unmap(vmid));
        }

        // success multiple (full MDL)
        {
            pmut_mdl0->num_entries = MV_MDL_MAX_ENTRIES.get();

            for (bsl::safe_idx mut_i{}; mut_i < MV_MDL_MAX_ENTRIES; ++mut_i) {
                auto const gpa{(HYPERVISOR_PAGE_SIZE * bsl::to_u64(mut_i)).checked()};
                pmut_mdl0->entries.at_if(mut_i)->dst = gpa.get();
                pmut_mdl0->entries.at_if(mut_i)->src = gpa.get();
                pmut_mdl0->entries.at_if(mut_i)->bytes = HYPERVISOR_PAGE_SIZE.get();
            }

            integration::verify(mut_hvc.mv_vm_op_mmio_map(vmid, self));

            for (bsl::safe_idx mut_i{}; mut_i < MV_MDL_MAX_ENTRIES; ++mut_i) {
                auto const gpa{
                    (HYPERVISOR_PAGE_SIZE * (bsl::to_u64(mut_i) + MV_MDL_MAX_ENTRIES)).checked()};
                pmut_mdl0->entries.at_if(mut_i)->dst = gpa.get();
                pmut_mdl0->entries.at_if(mut_i)->src = gpa.get();
                pmut_mdl0->entries.at_if(mut_i)->bytes = HYPERVISOR_PAGE_SIZE.get();
            }

            integration::verify(mut_hvc.mv_vm_op_mmio_map(vmid, self));
            integration::verify(mut_hvc.mv_vm_op_mmio_unmap(vmid));

            for (bsl::safe_idx mut_i{}; mut_i < MV_MDL_MAX_ENTRIES; ++mut_i) {
                auto const gpa{(HYPERVISOR_PAGE_SIZE * bsl::to_u64(mut_i)).checked()};
                pmut_mdl0->entries.at_if(mut_i)->dst = gpa.get();
                pmut_mdl0->entries.at_if(mut_i)->src = gpa.get();
                pmut_mdl0->entries.at_if(mut_i)->bytes = HYPERVISOR_PAGE_SIZE.get();
            }

            integration::verify(mut_hvc.mv_vm_op_mmio_unmap(vmid));
        }

        // Repeat a lot
        {
            pmut_mdl0->num_entries = bsl::safe_u64::magic_1().get();

            constexpr auto num_loops{0x100_umx};
            for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
                pmut_mdl0->entries.front().dst = {};
                pmut_mdl0->entries.front().src = {};
                pmut_mdl0->entries.front().bytes = HYPERVISOR_PAGE_SIZE.get();
                integration::verify(mut_hvc.mv_vm_op_mmio_map(vmid, self));
                integration::verify(mut_hvc.mv_vm_op_mmio_unmap(vmid));
            }
        }

        /// TODO:
        /// - Need add support for, and test compressed MDLs
        /// - Add tests with randomized MDLs
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
