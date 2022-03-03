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
#include <dispatch_vmcall_helpers.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_run_t.hpp>
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
#include <bsl/span.hpp>

namespace microv
{
    constexpr auto PAGE_MASK{0xFFFFFFFFFFFFFFFF_u64 << HYPERVISOR_PAGE_SHIFT};

    constexpr auto PORT_MASK{0xFFFF0000_u64};
    constexpr auto PORT_SHFT{16_u64};
    constexpr auto REPS_MASK{0x00000008_u64};
    constexpr auto REPS_SHFT{3_u64};
    constexpr auto TYPE_MASK{0x00000001_u64};
    constexpr auto TYPE_SHFT{0_u64};
    constexpr auto STRN_MASK{0x00000004_u64};
    constexpr auto STRN_SHFT{2_u64};

    constexpr auto SZ32_MASK{0x00000040_u64};
    constexpr auto SZ32_SHFT{6_u64};
    constexpr auto SZ16_MASK{0x00000020_u64};
    constexpr auto SZ16_SHFT{5_u64};
    constexpr auto SZ08_MASK{0x00000010_u64};
    constexpr auto SZ08_SHFT{4_u64};

    /// <!-- description -->
    ///   @brief Dispatches IO VMExits.
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
    dispatch_vmexit_io_string(
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
        bsl::safe_u64 const &exitinfo1,
        bsl::safe_u64 const &addr,
        enum hypercall::mv_bit_size_t const &mut_size,
        bsl::safe_u64 const &mut_reps,
        bsl::safe_u64 const &mut_bytes,
        bsl::safe_u64 const &mut_type) noexcept -> bsl::errc_type
    {
        using page_t = bsl::array<uint8_t, HYPERVISOR_PAGE_SIZE.get()>;

        bsl::expects(!mut_sys.is_the_active_vm_the_root_vm());

        // ---------------------------------------------------------------------
        // Context: Guest VM
        // ---------------------------------------------------------------------

        bsl::safe_u64 mut_string_addr{};

        if (((exitinfo1 & TYPE_MASK) >> TYPE_SHFT).is_zero()) {
            // OUT instruction
            mut_string_addr = mut_sys.bf_tls_rsi();
        }
        else {
            // IN instruction
            mut_string_addr = mut_sys.bf_tls_rdi();
        }

        auto const end_addr{(mut_string_addr + mut_bytes).checked()};
        auto const gfn_beg{mut_string_addr >> HYPERVISOR_PAGE_SHIFT};
        auto const gfn_end{end_addr >> HYPERVISOR_PAGE_SHIFT};

        auto const num_pages{(bsl::safe_u64::magic_1() + (gfn_end - gfn_beg).checked()).checked()};
        if (num_pages > bsl::safe_u64::magic_2()) {
            bsl::error()
                << "FIXME: Too many pages requested: " << num_pages    // --
                << bsl::endl                                           // --
                << bsl::here;                                          // --
            switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, true);
            return vmexit_failure_advance_ip_and_run;
        }

        for (auto mut_i{0_idx}; mut_i < num_pages; ++mut_i) {
            bsl::safe_u64 mut_spa{};
            bsl::safe_u64 mut_gpa{};
            if (mut_i != bsl::safe_idx::magic_0()) {
                mut_string_addr = ((mut_string_addr & PAGE_MASK) + (bsl::to_umx(mut_i) * HYPERVISOR_PAGE_SIZE).checked()).checked();
            }
            //
            //FIXME: This doesn't consider 16-bit segment base values!!
            //
            auto const translation{mut_vs_pool.gla_to_gpa(mut_sys, mut_tls, mut_page_pool, mut_pp_pool, mut_vm_pool, mut_string_addr, vsid)};
            if (bsl::unlikely(!translation.is_valid)) {
                bsl::error()
                    << "gla to gpa translation failed for gla "    // --
                    << bsl::hex(mut_string_addr)                   // --
                    << bsl::endl                                   // --
                    << bsl::here();
                switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, true);
                return vmexit_failure_advance_ip_and_run;
            }
            mut_gpa = translation.paddr;
            mut_spa = mut_vm_pool.gpa_to_spa(mut_tls, mut_sys, mut_page_pool, mut_gpa, mut_sys.bf_tls_vmid());
            mut_vs_pool.io_set_spa(mut_sys, vsid, mut_spa, mut_i);
        }

        // ---------------------------------------------------------------------
        // Context: Change To Root VM
        // ---------------------------------------------------------------------

        switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, true);

        // ---------------------------------------------------------------------
        // Context: Root VM
        // ---------------------------------------------------------------------

        if (bsl::unlikely(mut_bytes > hypercall::MV_EXIT_IO_MAX_DATA)) {
            bsl::error()
                << "FIXME: The requested size of "    // --
                << bsl::hex(mut_bytes)                // --
                << " is too large."                   // --
                << bsl::endl                          // --
                << bsl::here();                       // --

            return vmexit_failure_advance_ip_and_run;
        }
        else {
            bsl::touch();
        }

        bsl::safe_idx mut_i{};
        bsl::safe_u64 mut_spa{mut_vs_pool.io_spa(mut_sys, vsid, mut_i)};

        if (bsl::unlikely(mut_spa.is_invalid())) {
            bsl::error() << bsl::here();
            return vmexit_failure_advance_ip_and_run;
        }

        auto const idx{mut_spa & ~PAGE_MASK};
        if (bsl::unlikely(hypercall::MV_RUN_MAX_IOMEM_SIZE < mut_bytes)) {
            bsl::error()
                << "FIXME: mv_run_t.iomem will overflow:"    // --
                << " mut_bytes = " << bsl::hex(mut_bytes)    // --
                << bsl::endl                                 // --
                << bsl::here();                              // --
            return vmexit_failure_advance_ip_and_run;
        }
        else if (bsl::unlikely(hypercall::MV_EXIT_IO_MAX_DATA < mut_bytes)) {
            bsl::error()
                << "FIXME: mv_exit_io_t.data will overflow:"    // --
                << " mut_bytes = "                              // --
                << bsl::hex(mut_bytes)                          // --
                << bsl::endl                                    // --
                << bsl::here();                                 // --
            return vmexit_failure_advance_ip_and_run;
        }
        else {
            bsl::touch();
        }

        auto mut_run_return{mut_pp_pool.shared_page<hypercall::mv_run_return_t>(mut_sys)};
        bsl::expects(mut_run_return.is_valid());
        auto mut_exit_io{&mut_run_return->mv_exit_io};

        auto const bytes_cur_page{(HYPERVISOR_PAGE_SIZE - idx).checked()};

        {
            auto const size{bytes_cur_page.min(mut_bytes)};
            auto const page{mut_pp_pool.map<page_t>(mut_sys, mut_spa & PAGE_MASK)};
            auto const data{page.span(idx, size)};
            if (bsl::unlikely(data.is_invalid())) {
                bsl::error()
                    << "data is invalid"    // --
                    << bsl::endl            // --
                    << bsl::here();         // --

                return vmexit_failure_advance_ip_and_run;
            }
            else {
                bsl::touch();
            }

            bsl::builtin_memcpy(mut_exit_io->data.data(), data.data(), data.size_bytes());
        }

        if (bsl::unlikely(bytes_cur_page < mut_bytes)) {
            bsl::debug() << "Handling page boudary" << bsl::endl;

            auto const size{(mut_bytes - bytes_cur_page).checked()};
            mut_spa = mut_vs_pool.io_spa(mut_sys, vsid, ++mut_i);
            if (bsl::unlikely(mut_spa.is_invalid())) {
                bsl::error()
                    << "SPA for second page is invalid"    // --
                    << bsl::endl    // --
                    << bsl::here();    // --
                return vmexit_failure_advance_ip_and_run;
            }
            else if (bsl::unlikely((mut_spa & ~PAGE_MASK).is_pos())) {
                bsl::error()
                    << "SPA should be page aligned but is "    // --
                    << bsl::hex(mut_spa)
                    << bsl::endl    // --
                    << bsl::here();    // --
                return vmexit_failure_advance_ip_and_run;
            }

            auto const page{mut_pp_pool.map<page_t>(mut_sys, mut_spa)};
            auto const data{page.span({}, size)};
            bsl::expects((bytes_cur_page + data.size_bytes()).checked() == mut_bytes);
            // bsl::debug() << "bytes_cur_page " << bytes_cur_page << " size_bytes " << data.size_bytes() << " mut_bytes " << mut_bytes << " size " << size << bsl::endl;
            // return vmexit_failure_advance_ip_and_run;
            bsl::builtin_memcpy(mut_exit_io->data.at_if(bsl::to_idx(bytes_cur_page)), data.data(), data.size_bytes());
        }
        else {
            bsl::touch();
        }

        mut_exit_io->addr = addr.get();
        mut_exit_io->size = mut_size;
        mut_exit_io->reps = mut_reps.get();
        mut_exit_io->type = mut_type.get();

        set_reg_return(mut_sys, hypercall::MV_STATUS_SUCCESS);
        set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_IO));

        return vmexit_success_advance_ip_and_run;
    }

    /// <!-- description -->
    ///   @brief Dispatches IO VMExits.
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
    dispatch_vmexit_io(
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
        bsl::expects(!mut_sys.is_the_active_vm_the_root_vm());

        bsl::discard(gs);

        // ---------------------------------------------------------------------
        // Context: Guest VM
        // ---------------------------------------------------------------------

        auto const exitinfo1{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_exitinfo1)};
        bsl::expects(exitinfo1.is_valid());

        auto const rax{mut_sys.bf_tls_rax()};
        auto const rcx{mut_sys.bf_tls_rcx()};
        auto const addr{(exitinfo1 & PORT_MASK) >> PORT_SHFT};

        auto mut_type{0_u64};
        enum hypercall::mv_bit_size_t mut_size{};
        auto mut_reps{1_u64};
        auto mut_bytes{0_u64};

        if (((exitinfo1 & REPS_MASK) >> REPS_SHFT).is_pos()) {
            mut_reps = rcx.get();
        }
        else {
            mut_reps = bsl::safe_u64::magic_1().get();
        }

        if (((exitinfo1 & SZ32_MASK) >> SZ32_SHFT).is_pos()) {
            mut_size = hypercall::mv_bit_size_t::mv_bit_size_t_32;
            constexpr auto four{4_u64};
            mut_bytes = (four * mut_reps).checked();
        }
        else if (((exitinfo1 & SZ16_MASK) >> SZ16_SHFT).is_pos()) {
            mut_size = hypercall::mv_bit_size_t::mv_bit_size_t_16;
            mut_bytes = (bsl::safe_u64::magic_2() * mut_reps).checked();
        }
        else if (((exitinfo1 & SZ08_MASK) >> SZ08_SHFT).is_pos()) {
            mut_size = hypercall::mv_bit_size_t::mv_bit_size_t_8;
            mut_bytes = mut_reps;
        }
        else {
            bsl::touch();
        }

        if (((exitinfo1 & TYPE_MASK) >> TYPE_SHFT).is_zero()) {
            mut_type = hypercall::MV_EXIT_IO_OUT;
        }
        else {
            mut_type = hypercall::MV_EXIT_IO_IN;
        }

        if (((exitinfo1 & STRN_MASK) >> STRN_SHFT).is_pos()) {
            return dispatch_vmexit_io_string(gs, mut_tls, mut_sys, mut_page_pool, intrinsic,
                mut_pp_pool, mut_vm_pool, mut_vp_pool, mut_vs_pool, vsid, exitinfo1, addr, mut_size,
                mut_reps, mut_bytes, mut_type);
        }

        // ---------------------------------------------------------------------
        // Context: Change To Root VM
        // ---------------------------------------------------------------------

        switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, true);

        // ---------------------------------------------------------------------
        // Context: Root VM
        // ---------------------------------------------------------------------

        auto mut_run_return{mut_pp_pool.shared_page<hypercall::mv_run_return_t>(mut_sys)};
        bsl::expects(mut_run_return.is_valid());
        auto mut_exit_io{&mut_run_return->mv_exit_io};

        mut_exit_io->addr = addr.get();
        mut_exit_io->size = mut_size;
        mut_exit_io->reps = bsl::safe_u64::magic_1().get();
        mut_exit_io->type = mut_type.get();
        hypercall::io_to_u64(mut_exit_io->data) = rax.get();

        set_reg_return(mut_sys, hypercall::MV_STATUS_SUCCESS);
        set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_IO));

        return vmexit_success_advance_ip_and_run;
    }
}

#endif
