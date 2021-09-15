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

#ifndef DISPATCH_VMCALL_MV_VM_OP_HPP
#define DISPATCH_VMCALL_MV_VM_OP_HPP

#include <bf_syscall_t.hpp>
#include <dispatch_abi_helpers.hpp>
#include <dispatch_vmcall_helpers.hpp>
#include <errc_types.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_constants.hpp>
#include <mv_types.hpp>
#include <page_pool_t.hpp>
#include <pp_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Implements the mv_vm_op_create_vm hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vm_op_create_vm(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        vm_pool_t &mut_vm_pool) noexcept -> bsl::errc_type
    {
        auto const vmid{mut_vm_pool.allocate(gs, tls, mut_sys, mut_page_pool, intrinsic)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, bsl::merge_umx_with_u16(get_reg0(mut_sys), vmid));
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vm_op_destroy_vm hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vm_op_destroy_vm(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t const &vp_pool) noexcept -> bsl::errc_type
    {
        auto const vmid{get_allocated_vmid(mut_sys, get_reg1(mut_sys), mut_vm_pool)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const vm_destroyable{is_vm_destroyable(tls, mut_sys, mut_vm_pool, vp_pool, vmid)};
        if (bsl::unlikely(!vm_destroyable)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_vm_pool.deallocate(gs, tls, mut_sys, mut_page_pool, intrinsic, vmid);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vm_op_vmid hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vm_op_vmid(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
    {
        set_reg0(mut_sys, bsl::merge_umx_with_u16(get_reg0(mut_sys), mut_sys.bf_tls_vmid()));
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vm_op_mmio_map hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vm_op_mmio_map(
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        pp_pool_t &mut_pp_pool,
        vm_pool_t &mut_vm_pool) noexcept -> bsl::errc_type
    {
        /// TODO:
        /// - We need to add support for the dst and src to be any VMID. This
        ///   will be needed for device domain support in the future.
        ///

        auto const dst_vmid{get_allocated_guest_vmid(mut_sys, get_reg1(mut_sys), mut_vm_pool)};
        if (bsl::unlikely(dst_vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const src_vmid{get_allocated_root_vmid(mut_sys, get_reg2(mut_sys), mut_vm_pool)};
        if (bsl::unlikely(src_vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG2);
            return vmexit_failure_advance_ip_and_run;
        }

        auto mut_mdl{mut_pp_pool.shared_page<hypercall::mv_mdl_t>(mut_sys)};
        if (bsl::unlikely(mut_mdl.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const mdl_safe{is_mdl_safe(*mut_mdl, false)};
        if (bsl::unlikely(!mdl_safe)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const ret{mut_vm_pool.mmio_map(tls, mut_sys, mut_page_pool, *mut_mdl, dst_vmid)};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vm_op_mmio_unmap hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vm_op_mmio_unmap(
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        pp_pool_t &mut_pp_pool,
        vm_pool_t &mut_vm_pool) noexcept -> bsl::errc_type
    {
        /// TODO:
        /// - We need to add support for the dst to be any VMID. This
        ///   will be needed for device domain support in the future.
        ///

        auto const dst_vmid{get_allocated_guest_vmid(mut_sys, get_reg1(mut_sys), mut_vm_pool)};
        if (bsl::unlikely(dst_vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto mut_mdl{mut_pp_pool.shared_page<hypercall::mv_mdl_t>(mut_sys)};
        if (bsl::unlikely(mut_mdl.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const mdl_safe{is_mdl_safe(*mut_mdl, true)};
        if (bsl::unlikely(!mdl_safe)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const ret{mut_vm_pool.mmio_unmap(tls, mut_sys, mut_page_pool, *mut_mdl, dst_vmid)};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Dispatches virtual machine VMCalls.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_vmcall_mv_vm_op(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t &mut_pp_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t const &vp_pool,
        vs_pool_t const &vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::discard(vs_pool);
        bsl::discard(vsid);

        if (bsl::unlikely(!verify_handle(mut_sys))) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        if (bsl::unlikely(!verify_root_vm(mut_sys))) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        switch (hypercall::mv_hypercall_index(get_reg_hypercall(mut_sys)).get()) {
            case hypercall::MV_VM_OP_CREATE_VM_IDX_VAL.get(): {
                auto const ret{handle_mv_vm_op_create_vm(
                    gs, tls, mut_sys, mut_page_pool, intrinsic, mut_vm_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VM_OP_DESTROY_VM_IDX_VAL.get(): {
                auto const ret{handle_mv_vm_op_destroy_vm(
                    gs, tls, mut_sys, mut_page_pool, intrinsic, mut_vm_pool, vp_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VM_OP_VMID_IDX_VAL.get(): {
                auto const ret{handle_mv_vm_op_vmid(mut_sys)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VM_OP_MMIO_MAP_IDX_VAL.get(): {
                auto const ret{handle_mv_vm_op_mmio_map(
                    tls, mut_sys, mut_page_pool, mut_pp_pool, mut_vm_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VM_OP_MMIO_UNMAP_IDX_VAL.get(): {
                auto const ret{handle_mv_vm_op_mmio_unmap(
                    tls, mut_sys, mut_page_pool, mut_pp_pool, mut_vm_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            default: {
                break;
            }
        }

        return report_hypercall_unknown_unsupported(mut_sys);
    }
}

#endif
