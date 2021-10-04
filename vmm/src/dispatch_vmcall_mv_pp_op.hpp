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

#ifndef DISPATCH_VMCALL_MV_PP_OP_HPP
#define DISPATCH_VMCALL_MV_PP_OP_HPP

#include <bf_syscall_t.hpp>
#include <dispatch_abi_helpers.hpp>
#include <dispatch_vmcall_helpers.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_cdl_t.hpp>
#include <mv_constants.hpp>
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
    ///   @brief Implements the mv_pp_op_ppid hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_pp_op_ppid(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
    {
        set_reg0(mut_sys, bsl::merge_umx_with_u16(get_reg0(mut_sys), mut_sys.bf_tls_ppid()));
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_pp_op_clr_shared_page_gpa hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_pp_op_clr_shared_page_gpa(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool) noexcept -> bsl::errc_type
    {
        mut_pp_pool.clr_shared_page_spa(mut_sys);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_pp_op_set_shared_page_gpa hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_pp_op_set_shared_page_gpa(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, vm_pool_t const &vm_pool) noexcept
        -> bsl::errc_type
    {
        auto const gpa{get_pos_gpa(get_reg1(mut_sys))};
        if (bsl::unlikely(gpa.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const spa{vm_pool.gpa_to_spa(mut_sys, gpa, mut_sys.bf_tls_vmid())};
        if (bsl::unlikely(spa.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        /// TODO:
        /// - We need to detect if the SPA is being used on another PP. An
        ///   SPA can only be used once per PP, otherwise unmaps, and other
        ///   TLB related issues will occur.
        ///

        auto const ret{mut_pp_pool.set_shared_page_spa(mut_sys, spa)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_pp_op_cpuid_get_supported_list hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_pp_op_cpuid_get_supported_list(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool) noexcept -> bsl::errc_type
    {
        auto mut_cdl{mut_pp_pool.shared_page<hypercall::mv_cdl_t>(mut_sys)};

        if (bsl::unlikely(mut_cdl.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const cdl_safe{is_cdl_safe(*mut_cdl)};
        if (bsl::unlikely(!cdl_safe)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const ret{
            mut_pp_pool.cpuid_get_supported_list(mut_sys, mut_sys.bf_tls_ppid(), *mut_cdl)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_pp_op_msr_get_supported_list hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_pp_op_msr_get_supported_list(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool) noexcept -> bsl::errc_type
    {
        auto mut_rdl{mut_pp_pool.shared_page<hypercall::mv_rdl_t>(mut_sys)};

        if (bsl::unlikely(mut_rdl.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        bool const mdl_safe{is_rdl_msr_safe(*mut_rdl)};
        if (bsl::unlikely(!mdl_safe)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const ret{
            mut_pp_pool.msr_get_supported_list(mut_sys, mut_sys.bf_tls_ppid(), *mut_rdl)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_pp_op_tsc_get_khz hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_pp_op_tsc_get_khz(syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool) noexcept
        -> bsl::errc_type
    {
        auto const tsc_khz{mut_pp_pool.tsc_khz_get(mut_sys)};
        if (bsl::unlikely(tsc_khz.is_zero())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, tsc_khz);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_pp_op_tsc_set_khz hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_mv_pp_op_tsc_set_khz(syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool) noexcept
        -> bsl::errc_type
    {
        auto const tsc_khz{get_tsc_khz(get_reg1(mut_sys))};
        if (bsl::unlikely(tsc_khz.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        mut_pp_pool.tsc_khz_set(mut_sys, tsc_khz);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Dispatches physical processor VMCalls.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_vmcall_mv_pp_op(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t const &page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t &mut_pp_pool,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        vs_pool_t const &vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(page_pool);
        bsl::discard(intrinsic);
        bsl::discard(vp_pool);
        bsl::discard(vs_pool);
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

            case hypercall::MV_PP_OP_PPID_IDX_VAL.get(): {
                auto const ret{handle_mv_pp_op_ppid(mut_sys)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_PP_OP_CLR_SHARED_PAGE_GPA_IDX_VAL.get(): {
                auto const ret{handle_mv_pp_op_clr_shared_page_gpa(mut_sys, mut_pp_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_PP_OP_SET_SHARED_PAGE_GPA_IDX_VAL.get(): {
                auto const ret{handle_mv_pp_op_set_shared_page_gpa(mut_sys, mut_pp_pool, vm_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_PP_OP_CPUID_GET_SUPPORTED_LIST_IDX_VAL.get(): {
                auto const ret{handle_mv_pp_op_cpuid_get_supported_list(mut_sys, mut_pp_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_PP_OP_MSR_GET_SUPPORTED_LIST_IDX_VAL.get(): {
                auto const ret{handle_mv_pp_op_msr_get_supported_list(mut_sys, mut_pp_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_PP_OP_TSC_GET_KHZ_IDX_VAL.get(): {
                auto const ret{handle_mv_pp_op_tsc_get_khz(mut_sys, mut_pp_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_PP_OP_TSC_SET_KHZ_IDX_VAL.get(): {
                auto const ret{handle_mv_pp_op_tsc_set_khz(mut_sys, mut_pp_pool)};
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
