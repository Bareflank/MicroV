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

#ifndef DISPATCH_VMEXIT_HPP
#define DISPATCH_VMEXIT_HPP

#include <bf_debug_ops.hpp>
#include <bf_syscall_t.hpp>
#include <dispatch_vmexit_cpuid.hpp>
#include <dispatch_vmexit_cr.hpp>
#include <dispatch_vmexit_dr.hpp>
#include <dispatch_vmexit_hlt.hpp>
#include <dispatch_vmexit_init.hpp>
#include <dispatch_vmexit_intr.hpp>
#include <dispatch_vmexit_intr_window.hpp>
#include <dispatch_vmexit_io.hpp>
#include <dispatch_vmexit_npf.hpp>
#include <dispatch_vmexit_mmio.hpp>
#include <dispatch_vmexit_nmi.hpp>
#include <dispatch_vmexit_rdmsr.hpp>
#include <dispatch_vmexit_sipi.hpp>
#include <dispatch_vmexit_triple_fault.hpp>
#include <dispatch_vmexit_unknown.hpp>
#include <dispatch_vmexit_vmcall.hpp>
#include <dispatch_vmexit_wrmsr.hpp>
#include <errc_types.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <pp_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>
#include <mv_exit_mmio_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>

namespace microv
{
    /// @brief defines the INTR exit reason code
    constexpr auto EXIT_REASON_INTR{0x60_u64};
    /// @brief defines the NMI exit reason code
    constexpr auto EXIT_REASON_NMI{0x61_u64};
    /// @brief defines the INTR Window exit reason code
    constexpr auto EXIT_REASON_INTR_WINDOW{0x64_u64};
    /// @brief defines the NMI exit reason code
    constexpr auto EXIT_REASON_CR0_SPECIAL{0x65_u64};
    /// @brief defines the CPUID exit reason code
    constexpr auto EXIT_REASON_CPUID{0x72_u64};
    /// @brief defines the IO exit reason code
    constexpr auto EXIT_REASON_IO{0x7B_u64};
    /// @brief defines the RDMSR/WRMSR access exit reason code
    constexpr auto EXIT_REASON_MSR{0x7C_u64};
    /// @brief defines the SHUTDOWN exit reason code
    constexpr auto EXIT_REASON_SHUTDOWN{0x7f_u64};
    /// @brief defines the VMCALL exit reason code
    constexpr auto EXIT_REASON_VMCALL{0x81_u64};
    /// @brief defines the Nested Page Fault (NPF) exit reason code
    constexpr auto EXIT_REASON_NPF{0x400_u64};


 /// <!-- description -->
    ///   @brief Dispatches Nested Page Fault (NPF) VMExits.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param page_pool the page_pool_t to use
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
    dispatch_vmexit_npf(
        gs_t const &gs,
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t const &page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t &mut_pp_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        /// TODO:
        /// - Need to properly handle string instructions (INS/OUTS)
        ///

        bsl::expects(!mut_sys.is_the_active_vm_the_root_vm());

        bsl::discard(gs);
        bsl::discard(page_pool);
        bsl::discard(vsid);

        // ---------------------------------------------------------------------
        // Context: Guest VM
        // ---------------------------------------------------------------------

        auto const exitinfo1{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_exitinfo1)};
        bsl::expects(exitinfo1.is_valid());

        auto const exitinfo2{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_exitinfo2)};
        bsl::expects(exitinfo2.is_valid());

        //FIXME: do we need to save any guest register values here??

        constexpr auto rw_mask{0x02_u64};
        constexpr auto rw_shift{1_u64};
//FIXME: Just for reference
// struct {
//             __u64 phys_addr;
//             __u8  data[8];
//             __u32 len;
//             __u8  is_write;
//         } mmio;
        auto const phys_addr{(exitinfo2)};
        auto const is_write{(exitinfo1 & rw_mask) >> rw_shift};

        // FIXME: how are we going to get these properly? Hard code for now
        auto const len{4_u32};
        auto const data{0_u64};

        bsl::debug() << __FUNCTION__ << bsl::endl;
        bsl::debug() << "          exitinfo1 = " << bsl::hex(exitinfo1) << bsl::endl;
        bsl::debug() << "          exitinfo2 = " << bsl::hex(exitinfo2) << bsl::endl;
        bsl::debug() << "          phys_addr = " << bsl::hex(phys_addr) << bsl::endl;
        bsl::debug() << "          is_write = " << bsl::hex(is_write) << bsl::endl;

        // ---------------------------------------------------------------------
        // Context: Change To Root VM
        // ---------------------------------------------------------------------

        switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, true);

        // ---------------------------------------------------------------------
        // Context: Root VM
        // ---------------------------------------------------------------------

        auto mut_exit_mmio{mut_pp_pool.shared_page<hypercall::mv_exit_mmio_t>(mut_sys)};
        bsl::expects(mut_exit_mmio.is_valid());

        mut_exit_mmio->gpa = phys_addr.get();
        if(is_write.is_zero()) {
            mut_exit_mmio->flags = hypercall::MV_EXIT_MMIO_READ.get();
        } else {
            mut_exit_mmio->flags = hypercall::MV_EXIT_MMIO_WRITE.get();
        }

        set_reg_return(mut_sys, hypercall::MV_STATUS_SUCCESS);
        set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_MMIO));

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Dispatches the VMExit.
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
    ///   @param exit_reason the exit reason associated with the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_vmexit(
        gs_t const &gs,
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t &mut_pp_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        bsl::safe_u16 const &vsid,
        bsl::safe_u64 const &exit_reason) noexcept -> bsl::errc_type
    {
        bsl::errc_type mut_ret{};

        switch (exit_reason.get()) {
            case EXIT_REASON_INTR.get(): {
                mut_ret = dispatch_vmexit_intr(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    vsid);
                break;
            }

            case EXIT_REASON_NMI.get(): {
                mut_ret = dispatch_vmexit_nmi(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    vsid);
                break;
            }

            case EXIT_REASON_INTR_WINDOW.get(): {
                mut_ret = dispatch_vmexit_intr_window(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    vsid);
                break;
            }

            case EXIT_REASON_CR0_SPECIAL.get(): {
                mut_ret = dispatch_vmexit_cr(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    cr_access_t::cr0_write,
                    vsid);
                break;
            }

            case EXIT_REASON_CPUID.get(): {
                mut_ret = dispatch_vmexit_cpuid(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    vsid);
                break;
            }

            case EXIT_REASON_IO.get(): {
                mut_ret = dispatch_vmexit_io(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    vsid);
                break;
            }

            case EXIT_REASON_NPF.get(): {
                mut_ret = dispatch_vmexit_npf(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    vsid);
                break;
            }

            case EXIT_REASON_SHUTDOWN.get(): {
                mut_ret = dispatch_vmexit_triple_fault(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    vsid);
                break;
            }

            case EXIT_REASON_VMCALL.get(): {
                mut_ret = dispatch_vmexit_vmcall(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    vsid);
                break;
            }

            case EXIT_REASON_MSR.get(): {
                bsl::debug() << __FILE__ << " EXIT_REASON_MSR " << bsl::endl;
                auto const exitinfo1{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_exitinfo1)};

                // exitinfo1 = 0 means read; 1 = write
                if(exitinfo1.is_zero()) {
                    mut_ret = dispatch_vmexit_rdmsr(
                        gs,
                        mut_tls,
                        mut_sys,
                        mut_page_pool,
                        intrinsic,
                        mut_pp_pool,
                        mut_vm_pool,
                        mut_vp_pool,
                        mut_vs_pool,
                        vsid);
                } else {
                    mut_ret = dispatch_vmexit_wrmsr(
                            gs,
                            mut_tls,
                            mut_sys,
                            mut_page_pool,
                            intrinsic,
                            mut_pp_pool,
                            mut_vm_pool,
                            mut_vp_pool,
                            mut_vs_pool,
                            vsid);                
                }
                break;
            }

            default: {
                mut_ret = dispatch_vmexit_unknown(
                    gs,
                    mut_tls,
                    mut_sys,
                    mut_page_pool,
                    intrinsic,
                    mut_pp_pool,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    vsid,
                    exit_reason);
                break;
            }
        }

        return return_from_vmexit(
            mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, vsid, mut_ret);
    }
}

#endif
