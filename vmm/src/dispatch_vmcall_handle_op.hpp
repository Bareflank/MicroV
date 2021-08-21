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

#ifndef DISPATCH_VMCALL_HANDLE_OP_HPP
#define DISPATCH_VMCALL_HANDLE_OP_HPP

#include <abi_helpers.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_constants.hpp>
#include <pp_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Implements the mv_handle_op_open_handle hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    hypercall_handle_op_open_handle(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
    {
        if (bsl::unlikely(bsl::to_u32(get_reg0(mut_sys)) != hypercall::MV_SPEC_ID1_VAL)) {
            bsl::error() << "unsupported hypercall ABI "                //--
                         << bsl::hex(bsl::to_u32(get_reg0(mut_sys)))    //--
                         << bsl::endl                                   //--
                         << bsl::here();                                //--

            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        set_reg0(mut_sys, hypercall::MV_HANDLE_VAL);
        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Implements the mv_handle_op_close_handle hypercall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    hypercall_handle_op_close_handle(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
    {
        if (bsl::unlikely(get_reg0(mut_sys) != hypercall::MV_HANDLE_VAL)) {
            bsl::error() << "invalid handle "              // --
                         << bsl::hex(get_reg0(mut_sys))    //--
                         << bsl::endl                      //--
                         << bsl::here();                   //--

            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Dispatches handle VMCalls.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param pp_pool the pp_pool_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vps_pool the vps_pool_t to use
    ///   @param vpsid the ID of the VPS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_vmcall_handle_op(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        pp_pool_t const &pp_pool,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        vps_pool_t const &vps_pool,
        bsl::safe_uint16 const &vpsid) noexcept -> bsl::errc_type
    {
        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(intrinsic);
        bsl::discard(pp_pool);
        bsl::discard(vm_pool);
        bsl::discard(vp_pool);
        bsl::discard(vps_pool);
        bsl::discard(vpsid);

        switch (hypercall::mv_hypercall_index(get_reg_hypercall(mut_sys)).get()) {
            case hypercall::MV_HANDLE_OP_OPEN_HANDLE_IDX_VAL.get(): {
                auto const ret{hypercall_handle_op_open_handle(mut_sys)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case hypercall::MV_HANDLE_OP_CLOSE_HANDLE_IDX_VAL.get(): {
                auto const ret{hypercall_handle_op_close_handle(mut_sys)};
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

        bsl::error() << "unknown hypercall "                    //--
                     << bsl::hex(get_reg_hypercall(mut_sys))    //--
                     << bsl::endl                               //--
                     << bsl::here();                            //--

        set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
        return vmexit_failure_advance_ip_and_run;
    }
}

#endif
