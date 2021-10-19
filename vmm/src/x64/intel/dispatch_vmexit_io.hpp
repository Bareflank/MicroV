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

#ifndef DISPATCH_VMEXIT_IO_HPP
#define DISPATCH_VMEXIT_IO_HPP

#include <bf_syscall_t.hpp>
#include <dispatch_abi_helpers.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_exit_io_t.hpp>
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
    ///   @brief Dispatches IO VMExits.
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
    dispatch_vmexit_io(
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
        /// - Need to properly handle IN instructions
        ///

        bsl::expects(!mut_sys.is_the_active_vm_the_root_vm());

        bsl::discard(gs);
        bsl::discard(page_pool);
        bsl::discard(vsid);

        // ---------------------------------------------------------------------
        // Context: Guest VM
        // ---------------------------------------------------------------------

        constexpr auto exitqual_idx{syscall::bf_reg_t::bf_reg_t_exit_qualification};
        auto const exitqual{mut_sys.bf_vs_op_read(vsid, exitqual_idx)};

        auto const rax{mut_sys.bf_tls_rax()};
        auto const rcx{mut_sys.bf_tls_rcx()};
        auto const rdx{mut_sys.bf_tls_rdx()};

        // ---------------------------------------------------------------------
        // Context: Change To Root VM
        // ---------------------------------------------------------------------

        switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, true);

        // ---------------------------------------------------------------------
        // Context: Root VM
        // ---------------------------------------------------------------------

        auto mut_exit_io{mut_pp_pool.shared_page<hypercall::mv_exit_io_t>(mut_sys)};
        bsl::expects(mut_exit_io.is_valid());

        constexpr auto size_mask{0x00000007_u64};
        constexpr auto size_shft{0_u64};
        constexpr auto type_mask{0x00000008_u64};
        constexpr auto type_shft{3_u64};
        constexpr auto reps_mask{0x00000020_u64};
        constexpr auto reps_shft{5_u64};
        constexpr auto oper_mask{0x00000040_u64};
        constexpr auto oper_shft{6_u64};
        constexpr auto port_mask{0xFFFF0000_u64};
        constexpr auto port_shft{16_u64};

        if (((exitqual & oper_mask) >> oper_shft).is_zero()) {
            constexpr auto addr_mask{0x000000000000FFFF_u64};
            mut_exit_io->addr = (addr_mask & rdx).get();
        }
        else {
            mut_exit_io->addr = ((exitqual & port_mask) >> port_shft).get();
        }

        if (((exitqual & type_mask) >> type_shft).is_zero()) {
            mut_exit_io->type = hypercall::MV_EXIT_IO_OUT.get();
        }
        else {
            bsl::error() << "MV_EXIT_IO_IN not implemented\n" << bsl::here();
            return bsl::errc_failure;
        }

        constexpr auto bytes1{0_u64};
        constexpr auto bytes2{1_u64};
        constexpr auto bytes4{3_u64};

        if (bytes4 == ((exitqual & size_mask) >> size_shft)) {
            constexpr auto data_mask{0x00000000FFFFFFFF_u64};
            mut_exit_io->size = hypercall::mv_bit_size_t::mv_bit_size_t_32;
            mut_exit_io->data = (data_mask & rax).get();
        }
        else {
            bsl::touch();
        }

        if (bytes2 == ((exitqual & size_mask) >> size_shft)) {
            constexpr auto data_mask{0x000000000000FFFF_u64};
            mut_exit_io->size = hypercall::mv_bit_size_t::mv_bit_size_t_16;
            mut_exit_io->data = (data_mask & rax).get();
        }
        else {
            bsl::touch();
        }

        if (bytes1 == ((exitqual & size_mask) >> size_shft)) {
            constexpr auto data_mask{0x00000000000000FF_u64};
            mut_exit_io->size = hypercall::mv_bit_size_t::mv_bit_size_t_8;
            mut_exit_io->data = (data_mask & rax).get();
        }
        else {
            bsl::touch();
        }

        if (((exitqual & reps_mask) >> reps_shft).is_pos()) {
            mut_exit_io->reps = rcx.get();
        }
        else {
            mut_exit_io->reps = {};
        }

        set_reg_return(mut_sys, hypercall::MV_STATUS_SUCCESS);
        set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_IO));

        return vmexit_success_advance_ip_and_run;
    }
}

#endif
