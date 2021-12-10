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

#ifndef DISPATCH_VMEXIT_CR_HPP
#define DISPATCH_VMEXIT_CR_HPP

#include <bf_syscall_t.hpp>
#include <cr_access_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
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
    ///   @brief Helper function for vcpu register.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param reg_idx the safe_u64 to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///
    [[nodiscard]] constexpr auto
    helper_vcpu_reg(syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &reg_idx) noexcept
        -> bsl::safe_u64
    {
        constexpr auto rax_idx{0_u64};
        constexpr auto rcx_idx{1_u64};
        // constexpr auto rdx_idx{2_u64};
        constexpr auto rbx_idx{3_u64};
        // constexpr auto rsp_idx{4_u64};
        // constexpr auto rbp_idx{5_u64};
        constexpr auto rsi_idx{6_u64};
        constexpr auto rdi_idx{7_u64};
        constexpr auto r8_idx{8_u64};
        constexpr auto r9_idx{9_u64};
        constexpr auto r10_idx{10_u64};
        constexpr auto r11_idx{11_u64};
        constexpr auto r12_idx{12_u64};
        // constexpr auto r13_idx{13_u64};
        // constexpr auto r14_idx{14_u64};
        // constexpr auto r15_idx{15_u64};
        // constexpr auto rip_idx{16_u64};
        // constexpr auto num_reg_idxs{17_u64};

        switch (reg_idx.get()) {
            case rax_idx.get(): {
                return mut_sys.bf_tls_rax();
            }
            case rcx_idx.get(): {
                return mut_sys.bf_tls_rcx();
            }
            case rbx_idx.get(): {
                return mut_sys.bf_tls_rbx();
            }
            // case rsp_idx.get(): {
            //     return mut_sys.bf_tls_rsp();
            // }
            // case rbp_idx.get(): {
            //     return mut_sys.bf_tls_rbp();
            // }
            case rsi_idx.get(): {
                return mut_sys.bf_tls_rsi();
            }
            case rdi_idx.get(): {
                return mut_sys.bf_tls_rdi();
            }
            case r8_idx.get(): {
                return mut_sys.bf_tls_r8();
            }
            case r9_idx.get(): {
                return mut_sys.bf_tls_r9();
            }
            case r10_idx.get(): {
                return mut_sys.bf_tls_r10();
            }
            case r11_idx.get(): {
                return mut_sys.bf_tls_r11();
            }
            case r12_idx.get(): {
                return mut_sys.bf_tls_r12();
            }
                // case r13_idx.get(): {
                //     return mut_sys.bf_tls_13();
                // }
                // case r14_idx.get(): {
                //     return mut_sys.bf_tls_14();
                // }
                // case r15_idx.get(): {
                //     return mut_sys.bf_tls_15();
                // }
                // case rip_idx.get(): {
                //     return mut_sys.bf_tls_rip();
                // }

            default: {
                break;
            }
        }
        bsl::error() << "incorrect register index "    // --
                     << bsl::hex(reg_idx)              // --
                     << bsl::endl;                     // --

        return bsl::safe_u64::failure();
    }

    /// <!-- description -->
    ///   @brief Dispatches control register VMExits.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param pp_pool the pp_pool_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vs_pool the vs_pool_t to use
    ///   @param cr_access the type of control register access
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_vmexit_cr(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t const &page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t const &pp_pool,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        vs_pool_t const &vs_pool,
        cr_access_t const cr_access,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        constexpr auto gpr_mask{0x00000000FFFFFFFF_u64};
        constexpr auto reg_mask{0xF_u64};

        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(page_pool);
        bsl::discard(intrinsic);
        bsl::discard(pp_pool);
        bsl::discard(vm_pool);
        bsl::discard(vp_pool);
        bsl::discard(vs_pool);
        bsl::discard(cr_access);

        bsl::expects(!mut_sys.is_the_active_vm_the_root_vm());

        auto const exitinfo1{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_exitinfo1)};
        bsl::expects(exitinfo1.is_valid());

        auto const cr0_idx{syscall::bf_reg_t::bf_reg_t_cr0};

        auto const cr0_val_old{mut_sys.bf_vs_op_read(vsid, cr0_idx)};
        bsl::expects(cr0_val_old.is_valid());

        auto const cr0_val{gpr_mask & helper_vcpu_reg(mut_sys, exitinfo1 & reg_mask)};
        bsl::expects(cr0_val.is_valid());

        bsl::expects(mut_sys.bf_vs_op_write(vsid, cr0_idx, cr0_val));
        bsl::expects(mut_sys.bf_vm_op_tlb_flush(mut_sys.bf_tls_vmid()));

        return vmexit_success_advance_ip_and_run;
    }
}

#endif
