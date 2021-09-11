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

#ifndef DISPATCH_VMCALL_PP_OP_HPP
#define DISPATCH_VMCALL_PP_OP_HPP

#include <bf_syscall_t.hpp>
#include <dispatch_vmcall_abi_helpers.hpp>
#include <dispatch_vmcall_helpers.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_constants.hpp>
#include <pp_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>

/// NOTE:
/// - Since all mv_pp_ops must be executed on the root VM, an SPA is
///   the same thing as a GPA.
///

namespace microv
{
    /// <!-- description -->
    ///   @brief Returns true if the provided GPA is valid.  Otherwise, this
    ///     function returns false.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam VERIFY_PAGE_ALIGNMENT if true, the GPA must be page aligned
    ///   @param gpa the gpa to validate
    ///   @return Returns true if the provided GPA is valid.  Otherwise, this
    ///     function returns false.
    ///
    template<bool VERIFY_PAGE_ALIGNMENT = true>
    [[nodiscard]] constexpr auto
    is_valid_gpa(bsl::safe_u64 const &gpa) noexcept -> bool
    {
        if constexpr (VERIFY_PAGE_ALIGNMENT) {
            if (bsl::unlikely(!hypercall::mv_is_page_aligned(gpa))) {
                bsl::error() << "the provided gpa "                          // --
                             << bsl::hex(gpa)                                // --
                             << " is not page aligned and cannot be used"    // --
                             << bsl::endl                                    // --
                             << bsl::here();                                 // --

                return false;
            }

            bsl::touch();
        }

        if (bsl::unlikely(gpa.is_zero())) {
            bsl::error() << "the provided gpa "                    // --
                         << bsl::hex(gpa)                          // --
                         << " is a NULL GPA and cannot be used"    // --
                         << bsl::endl                              // --
                         << bsl::here();                           // --

            return false;
        }

        return true;
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
    hypercall_pp_op_clr_shared_page_gpa(
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
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    hypercall_pp_op_set_shared_page_gpa(
        syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool) noexcept -> bsl::errc_type
    {
        auto const gpa{get_reg1(mut_sys)};
        if (bsl::unlikely(!is_valid_gpa(gpa))) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_INPUT_REG1);
            return vmexit_failure_advance_ip_and_run;
        }

        auto const ret{mut_pp_pool.set_shared_page_spa(mut_sys, gpa)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Dispatches physical processor VMCalls.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
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
    dispatch_vmcall_pp_op(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        pp_pool_t &mut_pp_pool,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        vs_pool_t const &vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(mut_sys);
        bsl::discard(intrinsic);
        bsl::discard(mut_pp_pool);
        bsl::discard(vm_pool);
        bsl::discard(vp_pool);
        bsl::discard(vs_pool);
        bsl::discard(vsid);

        // if (bsl::unlikely(hypercall::MV_HANDLE_VAL != get_reg0(mut_sys))) {
        //     bsl::error() << "invalid handle "              // --
        //                  << bsl::hex(get_reg0(mut_sys))    // --
        //                  << bsl::endl                      // --
        //                  << bsl::here();                   // --

        //     set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_INVALID_HANDLE);
        //     return vmexit_failure_advance_ip_and_run;
        // }

        // if (bsl::unlikely(hypercall::MV_ROOT_VMID != mut_sys.bf_tls_vmid())) {
        //     bsl::error() << "mv_pp_ops can only be executed from the root VM"    // --
        //                  << bsl::endl                                            // --
        //                  << bsl::here();                                         // --

        //     set_reg_return(mut_sys, hypercall::MV_STATUS_INVALID_PERM_DENIED);
        //     return vmexit_failure_advance_ip_and_run;
        // }

        // switch (hypercall::mv_hypercall_index(get_reg_hypercall(mut_sys)).get()) {
        //     case hypercall::MV_PP_OP_GET_SHARED_PAGE_GPA_IDX_VAL.get(): {
        //         auto const ret{hypercall_pp_op_get_shared_page_gpa(mut_sys, mut_pp_pool)};
        //         if (bsl::unlikely(!ret)) {
        //             bsl::print<bsl::V>() << bsl::here();
        //             return ret;
        //         }

        //         return ret;
        //     }

        //     case hypercall::MV_PP_OP_CLR_SHARED_PAGE_GPA_IDX_VAL.get(): {
        //         auto const ret{hypercall_pp_op_clr_shared_page_gpa(mut_sys, mut_pp_pool)};
        //         if (bsl::unlikely(!ret)) {
        //             bsl::print<bsl::V>() << bsl::here();
        //             return ret;
        //         }

        //         return ret;
        //     }

        //     case hypercall::MV_PP_OP_SET_SHARED_PAGE_GPA_IDX_VAL.get(): {
        //         auto const ret{hypercall_pp_op_set_shared_page_gpa(mut_sys, mut_pp_pool)};
        //         if (bsl::unlikely(!ret)) {
        //             bsl::print<bsl::V>() << bsl::here();
        //             return ret;
        //         }

        //         return ret;
        //     }

        //     default: {
        //         break;
        //     }
        // }

        return report_hypercall_unknown_unsupported(mut_sys);
    }
}

#endif
