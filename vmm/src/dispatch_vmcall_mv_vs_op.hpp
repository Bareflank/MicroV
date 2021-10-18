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

#ifndef DISPATCH_VMCALL_MV_VS_OP_HPP
#define DISPATCH_VMCALL_MV_VS_OP_HPP

#include <bf_syscall_t.hpp>
#include <dispatch_abi_helpers.hpp>
#include <dispatch_vmcall_helpers.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_constants.hpp>
#include <mv_translation_t.hpp>
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
    ///   @brief Implements the mv_vs_op_create_vs hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param pp_pool the pp_pool_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_create_vs(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t const &pp_pool,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        vs_pool_t &mut_vs_pool) noexcept -> bsl::errc_type
    {
        auto const vpid{get_allocated_non_self_vpid(mut_sys, get_reg1(mut_sys), vp_pool)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const tsc_khz{pp_pool.tsc_khz_get(mut_sys)};
        if (bsl::unlikely(!is_tsc_khz_set(mut_sys, tsc_khz))) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const vmid{vp_pool.assigned_vm(vpid)};
        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(vmid != syscall::BF_INVALID_ID);

        auto const vsid{mut_vs_pool.allocate(
            gs,
            tls,
            mut_sys,
            mut_page_pool,
            intrinsic,
            vmid,
            vpid,
            tls.ppid,
            tsc_khz,
            vm_pool.slpt_spa(vmid))};

        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, bsl::merge_umx_with_u16(get_reg0(mut_sys), vsid));
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_destroy_vs hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_destroy_vs(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        vs_pool_t &mut_vs_pool) noexcept -> bsl::errc_type
    {
        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const vs_destroyable{is_vs_destroyable(mut_sys, mut_vs_pool, vsid)};
        if (bsl::unlikely(!vs_destroyable)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_vs_pool.deallocate(gs, tls, mut_sys, mut_page_pool, intrinsic, vsid);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_vmid hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_vmid(syscall::bf_syscall_t &mut_sys, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        auto const vsid{get_vsid(mut_sys, get_reg1(mut_sys))};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const assigned_vmid{mut_vs_pool.assigned_vm(vsid)};
        if (bsl::unlikely(assigned_vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, bsl::merge_umx_with_u16(get_reg0(mut_sys), assigned_vmid));
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_vpid hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_vpid(syscall::bf_syscall_t &mut_sys, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        auto const vsid{get_vsid(mut_sys, get_reg1(mut_sys))};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const assigned_vpid{mut_vs_pool.assigned_vp(vsid)};
        if (bsl::unlikely(assigned_vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, bsl::merge_umx_with_u16(get_reg0(mut_sys), assigned_vpid));
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_vsid hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_vsid(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
    {
        set_reg0(mut_sys, bsl::merge_umx_with_u16(get_reg0(mut_sys), mut_sys.bf_tls_vsid()));
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_gla_to_gpa hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_gla_to_gpa(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        bsl::safe_u16 mut_vsid{};
        if constexpr (BSL_RELEASE_MODE) {
            mut_vsid = get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool);
        }
        else {
            mut_vsid = get_allocated_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool);
        }

        if (bsl::unlikely(mut_vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const gla{get_gla(get_reg2(mut_sys))};
        if (bsl::unlikely(gla.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG2);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const translation{mut_vs_pool.gla_to_gpa(mut_sys, mut_pp_pool, gla, mut_vsid)};
        if (bsl::unlikely(!translation.is_valid)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, translation.paddr | translation.flags);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_run hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_run(
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool) noexcept -> bsl::errc_type
    {
        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const ret{
            run_guest(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, vsid)};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_reg_get hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_reg_get(syscall::bf_syscall_t &mut_sys, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const val{mut_vs_pool.reg_get(mut_sys, get_reg2(mut_sys), vsid)};
        if (bsl::unlikely(val.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, val);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_reg_set hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_reg_set(syscall::bf_syscall_t &mut_sys, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        bsl::errc_type mut_ret{};

        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_ret = mut_vs_pool.reg_set(mut_sys, get_reg2(mut_sys), get_reg3(mut_sys), vsid);
        if (bsl::unlikely(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_reg_get_list hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_reg_get_list(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        bsl::errc_type mut_ret{};

        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto mut_rdl{mut_pp_pool.shared_page<hypercall::mv_rdl_t>(mut_sys)};
        if (bsl::unlikely(mut_rdl.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const rdl_safe{is_rdl_safe(*mut_rdl)};
        if (bsl::unlikely(!rdl_safe)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_ret = mut_vs_pool.reg_get_list(mut_sys, *mut_rdl, vsid);
        if (bsl::unlikely(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_reg_set_list hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_reg_set_list(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        bsl::errc_type mut_ret{};

        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const rdl{mut_pp_pool.shared_page<hypercall::mv_rdl_t>(mut_sys)};
        if (bsl::unlikely(rdl.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const rdl_safe{is_rdl_safe(*rdl)};
        if (bsl::unlikely(!rdl_safe)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_ret = mut_vs_pool.reg_set_list(mut_sys, *rdl, vsid);
        if (bsl::unlikely(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_msr_get hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_msr_get(syscall::bf_syscall_t &mut_sys, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const val{mut_vs_pool.msr_get(mut_sys, get_reg2(mut_sys), vsid)};
        if (bsl::unlikely(val.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, val);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_msr_set hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_msr_set(syscall::bf_syscall_t &mut_sys, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        bsl::errc_type mut_ret{};

        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_ret = mut_vs_pool.msr_set(mut_sys, get_reg2(mut_sys), get_reg3(mut_sys), vsid);
        if (bsl::unlikely(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_msr_get_list hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_msr_get_list(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        bsl::errc_type mut_ret{};

        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto mut_rdl{mut_pp_pool.shared_page<hypercall::mv_rdl_t>(mut_sys)};
        if (bsl::unlikely(mut_rdl.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const rdl_safe{is_rdl_safe(*mut_rdl)};
        if (bsl::unlikely(!rdl_safe)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_ret = mut_vs_pool.msr_get_list(mut_sys, *mut_rdl, vsid);
        if (bsl::unlikely(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_msr_set_list hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_msr_set_list(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        bsl::errc_type mut_ret{};

        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const rdl{mut_pp_pool.shared_page<hypercall::mv_rdl_t>(mut_sys)};
        if (bsl::unlikely(rdl.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const rdl_safe{is_rdl_safe(*rdl)};
        if (bsl::unlikely(!rdl_safe)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_ret = mut_vs_pool.msr_set_list(mut_sys, *rdl, vsid);
        if (bsl::unlikely(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_fpu_get_all hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_fpu_get_all(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto mut_page{mut_pp_pool.shared_page<page_4k_t>(mut_sys)};
        if (bsl::unlikely(mut_page.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_vs_pool.fpu_get_all(mut_sys, *mut_page, vsid);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_fpu_set_all hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_fpu_set_all(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const page{mut_pp_pool.shared_page<page_4k_t>(mut_sys)};
        if (bsl::unlikely(page.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_vs_pool.fpu_set_all(mut_sys, *page, vsid);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_mp_state_get hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_mp_state_get(syscall::bf_syscall_t &mut_sys, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, hypercall::to_u64(mut_vs_pool.mp_state_get(vsid)));
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_mp_state_set hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_mp_state_set(syscall::bf_syscall_t &mut_sys, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        bsl::errc_type mut_ret{};

        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const mp_state{get_mp_state(get_reg2(mut_sys))};
        if (bsl::unlikely(mp_state == hypercall::mv_mp_state_t::mv_mp_state_t_invalid)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG2);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_ret = mut_vs_pool.mp_state_set(mut_sys, mp_state, vsid);
        if (bsl::unlikely(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_vs_op_tsc_get_khz hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_vs_op_tsc_get_khz(syscall::bf_syscall_t &mut_sys, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::errc_type
    {
        auto const vsid{get_allocated_non_self_vsid(mut_sys, get_reg1(mut_sys), mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, mut_vs_pool.tsc_khz_get(vsid));
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Dispatches virtual processor state VMCalls.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_vmcall_mv_vs_op(
        gs_t const &gs,
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t &mut_pp_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::discard(vsid);

        if (bsl::unlikely(!verify_handle(mut_sys))) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG0);
            return vmexit_failure_advance_ip_and_run;
        }

        if (bsl::unlikely(!verify_root_vm(mut_sys))) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_PERM_DENIED);
            return vmexit_failure_advance_ip_and_run;
        }

        switch (hypercall::mv_hypercall_index(get_reg_hypercall(mut_sys)).get()) {
            case hypercall::MV_VS_OP_CREATE_VS_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_create_vs(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_DESTROY_VS_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_destroy_vs(
                    gs, mut_tls, mut_sys, mut_page_pool, intrinsic, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_VMID_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_vmid(mut_sys, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_VPID_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_vpid(mut_sys, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_VSID_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_vsid(mut_sys)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_GLA_TO_GPA_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_gla_to_gpa(mut_sys, mut_pp_pool, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_RUN_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_run(
                    mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_REG_GET_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_reg_get(mut_sys, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_REG_SET_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_reg_set(mut_sys, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_REG_GET_LIST_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_reg_get_list(mut_sys, mut_pp_pool, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_REG_SET_LIST_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_reg_set_list(mut_sys, mut_pp_pool, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_MSR_GET_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_msr_get(mut_sys, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_MSR_SET_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_msr_set(mut_sys, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_MSR_GET_LIST_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_msr_get_list(mut_sys, mut_pp_pool, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_MSR_SET_LIST_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_msr_set_list(mut_sys, mut_pp_pool, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_FPU_GET_ALL_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_fpu_get_all(mut_sys, mut_pp_pool, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_FPU_SET_ALL_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_fpu_set_all(mut_sys, mut_pp_pool, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_MP_STATE_GET_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_mp_state_get(mut_sys, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_MP_STATE_SET_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_mp_state_set(mut_sys, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_TSC_GET_KHZ_IDX_VAL.get(): {
                auto const ret{handle_mv_vs_op_tsc_get_khz(mut_sys, mut_vs_pool)};
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
