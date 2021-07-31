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
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam SELF_IS_ALLOWED if true, MV_SELF_ID is allowed, otherwise
    ///     it is not.
    ///   @param reg the register to get the vsid from.
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    template<bool SELF_IS_ALLOWED = true>
    [[nodiscard]] constexpr auto
    get_vsid(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u16
    {
        auto const vsid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(hypercall::MV_INVALID_ID == vsid)) {
            bsl::error() << "the provided vsid "                      // --
                         << bsl::hex(vsid)                            // --
                         << " is MV_INVALID_ID and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (hypercall::MV_SELF_ID == vsid) {
            if constexpr (SELF_IS_ALLOWED) {
                return vsid;
            }
            else {
                return bsl::safe_u16::failure();
            }
        }
        else {
            bsl::touch();
        }

        if (bsl::unlikely(bsl::to_umx(vsid) >= HYPERVISOR_MAX_VSS)) {
            bsl::error() << "the provided vsid "                      // --
                         << bsl::hex(vsid)                            // --
                         << " is out of bounds and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Returns true if the provided GLA is valid.  Otherwise, this
    ///     function returns false.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam VERIFY_PAGE_ALIGNMENT if true, the GLA must be page aligned
    ///   @param gla the gla to validate
    ///   @return Returns true if the provided GLA is valid.  Otherwise, this
    ///     function returns false.
    ///
    template<bool VERIFY_PAGE_ALIGNMENT = true>
    [[nodiscard]] constexpr auto
    is_valid_gla(bsl::safe_u64 const &gla) noexcept -> bool
    {
        if constexpr (VERIFY_PAGE_ALIGNMENT) {
            if (bsl::unlikely(!hypercall::mv_is_page_aligned(gla))) {
                bsl::error() << "the provided gla "                          // --
                             << bsl::hex(gla)                                // --
                             << " is not page aligned and cannot be used"    // --
                             << bsl::endl                                    // --
                             << bsl::here();                                 // --

                return false;
            }

            bsl::touch();
        }

        if (bsl::unlikely(gla.is_zero())) {
            bsl::error() << "the provided gla "                    // --
                         << bsl::hex(gla)                          // --
                         << " is a NULL GLA and cannot be used"    // --
                         << bsl::endl                              // --
                         << bsl::here();                           // --

            return false;
        }

        return true;
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
    ///   @param vs_pool the vs_pool_t to use
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

        // switch (hypercall::mv_hypercall_index(get_reg_hypercall(mut_sys)).get()) {
        //     case hypercall::MV_VS_OP_GLA_TO_GPA_IDX_VAL.get(): {
        //         auto const ret{hypercall_vs_op_gla_to_gpa(mut_sys, mut_pp_pool, vs_pool)};
        //         if (bsl::unlikely(!ret)) {
        //             bsl::print<bsl::V>() << bsl::here();
        //             return ret;
        //         }

        //         return ret;
        //     }

        //     case hypercall::MV_VS_OP_GVA_TO_GLA_IDX_VAL.get(): {
        //         auto const ret{hypercall_vs_op_gva_to_gla(mut_sys, mut_pp_pool, vs_pool)};
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
