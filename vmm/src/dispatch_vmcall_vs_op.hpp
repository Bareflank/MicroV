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

#ifndef DISPATCH_VMCALL_VS_OP_HPP
#define DISPATCH_VMCALL_VS_OP_HPP

#include <bf_syscall_t.hpp>
#include <dispatch_vmcall_abi_helpers.hpp>
#include <dispatch_vmcall_helpers.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_constants.hpp>
#include <mv_translation_t.hpp>
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
    ///   @param intrinsic the intrinsic_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    hypercall_vs_op_create_vs(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        vp_pool_t const &vp_pool,
        vs_pool_t &mut_vs_pool) noexcept -> bsl::errc_type
    {
        auto const vpid{get_allocated_vpid(get_reg1(mut_sys), vp_pool)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const vmid{vp_pool.assigned_vm(vpid)};
        bsl::expects(vmid.is_valid_and_checked());
        bsl::expects(vmid != syscall::BF_INVALID_ID);

        auto const vsid{mut_vs_pool.allocate(gs, tls, mut_sys, intrinsic, vmid, vpid, tls.ppid)};
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
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    hypercall_vs_op_destroy_vs(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        vs_pool_t &mut_vs_pool) noexcept -> bsl::errc_type
    {
        auto const vsid{get_allocated_vsid(get_reg1(mut_sys), mut_vs_pool)};
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

        mut_vs_pool.deallocate(gs, tls, mut_sys, intrinsic, vsid);
        return vmexit_success_advance_ip_and_run;
    }

    // /// <!-- description -->
    // ///   @brief Implements the mv_vs_op_gla_to_gpa hypercall
    // ///
    // /// <!-- inputs/outputs -->
    // ///   @param mut_sys the bf_syscall_t to use
    // ///   @param mut_pp_pool the pp_pool_t to use
    // ///   @param vs_pool the vs_pool_t to use
    // ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    // ///     and friends otherwise
    // ///
    // [[nodiscard]] constexpr auto
    // hypercall_vs_op_gla_to_gpa(
    //     syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vs_pool_t const &vs_pool) noexcept
    //     -> bsl::errc_type
    // {
    //     auto const vsid{get_vsid(get_reg1(mut_sys))};
    //     if (bsl::unlikely(!vsid)) {
    //         bsl::print<bsl::V>() << bsl::here();
    //         set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
    //         return vmexit_failure_advance_ip_and_run;
    //     }

    //     auto const gla{get_reg2(mut_sys)};
    //     if (bsl::unlikely(!is_valid_gla(gla))) {
    //         bsl::print<bsl::V>() << bsl::here();
    //         set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG2);
    //         return vmexit_failure_advance_ip_and_run;
    //     }

    //     auto const translation{vs_pool.gla_to_gpa(mut_sys, mut_pp_pool, gla, vsid)};
    //     if (bsl::unlikely(!translation.is_valid)) {
    //         bsl::print<bsl::V>() << bsl::here();
    //         set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
    //         return vmexit_failure_advance_ip_and_run;
    //     }

    //     set_reg0(mut_sys, translation.paddr | translation.flags);
    //     return vmexit_success_advance_ip_and_run;
    // }

    // /// <!-- description -->
    // ///   @brief Implements the mv_vs_op_gva_to_gla hypercall
    // ///
    // /// <!-- inputs/outputs -->
    // ///   @param mut_sys the bf_syscall_t to use
    // ///   @param mut_pp_pool the pp_pool_t to use
    // ///   @param vs_pool the vs_pool_t to use
    // ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    // ///     and friends otherwise
    // ///
    // [[nodiscard]] constexpr auto
    // hypercall_vs_op_gva_to_gla(
    //     syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vs_pool_t const &vs_pool) noexcept
    //     -> bsl::errc_type
    // {
    //     bsl::discard(mut_sys);
    //     bsl::discard(mut_pp_pool);
    //     bsl::discard(vs_pool);

    //     bsl::error() << "mv_vs_op_gva_to_gla is reserved and not supported\n" << bsl::here();

    //     set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNSUPPORTED);
    //     return vmexit_failure_advance_ip_and_run;
    // }

    /// <!-- description -->
    ///   @brief Dispatches virtual processor state VMCalls.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_vmcall_vs_op(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        pp_pool_t &mut_pp_pool,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        vs_pool_t &mut_vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::discard(mut_pp_pool);
        bsl::discard(vm_pool);
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
            case hypercall::MV_VS_OP_CREATE_VS_IDX_VAL.get(): {
                auto const ret{
                    hypercall_vs_op_create_vs(gs, tls, mut_sys, intrinsic, vp_pool, mut_vs_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_VS_OP_DESTROY_VS_IDX_VAL.get(): {
                auto const ret{
                    hypercall_vs_op_destroy_vs(gs, tls, mut_sys, intrinsic, mut_vs_pool)};
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
