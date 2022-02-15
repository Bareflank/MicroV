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

#ifndef DISPATCH_VMEXIT_MMIO_HPP
#define DISPATCH_VMEXIT_MMIO_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <pp_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>
#include <mv_reg_t.hpp>
#include <mv_exit_mmio_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>

namespace microv
{
    constexpr auto OPCODE_REG_USE_IMMEDIATE{0xBEEFBEEF_u64};
    [[nodiscard]] constexpr auto
    instruction_decode(
        bsl::uint64 const &opcodes0,
        bsl::uint64 const &opcodes1,
        bsl::uint64 const &cpu_mode,
        bsl::uint64 *mut_instr_len,
        bsl::uint64 *mut_register,
        bsl::uint64 *memory_access_size,
        bsl::uint64 *immediate_value) noexcept -> bsl::errc_type
    {
        constexpr auto mask_2bytes{0xFFFF_u64};
        constexpr auto mask_3bytes{0xFFFFFF_u64};
        constexpr auto mask_6bytes{0xFFFFFFFFFFFF_u64};
        constexpr auto mask_7bytes{0xFFFFFFFFFFFFFF_u64};

        constexpr auto instr__mov_eax_PTRebx{0x038b_u64};
        constexpr auto instr__mov_PTRebx_esi{0x3389_u64};
        constexpr auto instr__mov_PTRebx_eax{0x0389_u64};
        constexpr auto instr__mov_esi_PTReax{0x308b_u64};
        constexpr auto instr__mov_eax_PTRIDXecx{0xb0000000818b_u64};
        constexpr auto instr__mov_ecx_PTRIDXedi{0xb00000008f8b_u64};
        constexpr auto instr__mov_ecx_PTRIDXebx{0xb00000008b8b_u64};
        constexpr auto instr__mov_ebx_PTRIDXebx{0xb00000009b8b_u64};
        constexpr auto instr__mov_bl_PTRIDXebx{0xb00000009b8a_u64};
        constexpr auto instr__mov_bl_PTRIDXedi{0xb00000009f8a_u64};
        constexpr auto instr__mov_eax_PTRIDXebx{0xb0000000838b_u64};
        constexpr auto instr__mov_PTRIDXebx_eax{0xb00000008389_u64};
        constexpr auto instr__mov_PTRIDXebx_al{0xb00000008388_u64};
        constexpr auto instr__mov_ax_PTRIDXebx{0xb0000000838b66_u64};
        constexpr auto instr__mov_PTRIDXebx_di{0xb0000000bb8966_u64};
        constexpr auto instr__mov_dx_PTResi{0x168b66_u64};
        constexpr auto instr__mov_edx_PTResi{0x168b_u64};
        constexpr auto instr__mov_PTResi_edx{0x1689_u64};
        constexpr auto instr__mov_dl_PTResi{0x168a_u64};
        constexpr auto instr__mov_PTResi_cl{0x0e88_u64};
        constexpr auto instr__mov_PTResi_dx{0x168966_u64};
        constexpr auto instr__mov_PTRIDXecx_bl{0xb00000009988_u64};
        constexpr auto instr__mov_edx_PTReax{0x08508B_u64};
        constexpr auto instr__mov_edx_PTRedx{0x08528B_u64};
        constexpr auto instr__mov_edx_PTRebx{0x0c538B_u64};
        constexpr auto instr__mov_PTReax_edx{0x1089_u64};
        constexpr auto instr__mov_PTReax_edi{0x3889_u64};
        constexpr auto instr__mov_ecx_PTRedx{0x000054008A8B_u64};
        constexpr auto instr__mov_eax_PTRedx{0x00005404828B_u64};
        constexpr auto instr__mov_PTRedx_ecx{0x0a89_u64};
        constexpr auto instr__mov_PTRedx_IMM{0x0000000002c7_u64};


        // bsl::debug() << __FUNCTION__ << bsl::endl;

        //FIXME: We assume 32-bit mode for now...

        // Initialize the immediate value to 0
        *immediate_value = 0;

        if( (opcodes0 & mask_2bytes) == (instr__mov_eax_PTRebx) ) {
            // mov eax, dword ptr [ebx]
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rax)};
            bsl::debug() << " mov eax, dword ptr [ebx]" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_PTRebx_esi) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rsi)};
            // mov dword ptr [ebx], esi
            bsl::debug() << " mov dword ptr [ebx], esi" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_PTRebx_eax) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rax)};
            // mov dword ptr [ebx], eax
            bsl::debug() << " mov dword ptr [ebx], eax" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_esi_PTReax) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rsi)};
            bsl::debug() << " mov esi, dword ptr [eax]" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_eax_PTRIDXecx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rax)};
            // mov eax, -0x50000000(ecx)
            bsl::debug() << " mov eax, -0x50000000(ecx)" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_ecx_PTRIDXedi) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rcx)};
            // mov ecx, -0x50000000(edi)
            bsl::debug() << " mov ecx, -0x50000000(edi)" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_ecx_PTRIDXebx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rcx)};
            // mov ecx, -0x50000000(ebx)
            bsl::debug() << " mov ecx, -0x50000000(ebx)" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_ebx_PTRIDXebx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rbx)};
            bsl::debug() << " mov ebx, -0x50000000(ebx)" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_bl_PTRIDXebx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rbx)};
            // mov bl, -0x50000000(ebx)
            bsl::debug() << " mov bl, -0x50000000(ebx)" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 1;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_bl_PTRIDXedi) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rbx)};
            // mov bl, -0x50000000(edi)
            bsl::debug() << " mov bl, -0x50000000(edi)" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 1;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_eax_PTRIDXebx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rax)};
            // mov eax, -0x50000000(ebx)
            bsl::debug() << " mov eax, -0x50000000(ebx)" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_PTRIDXebx_eax) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rax)};
            // mov -0x50000000(ebx), eax
            bsl::debug() << " mov -0x50000000(ebx), eax" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_PTRIDXebx_al) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rax)};
            // mov -0x50000000(ebx), eax
            bsl::debug() << " mov byte ptr[ebx-0x50000000], al" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 1;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_7bytes) == (instr__mov_ax_PTRIDXebx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rax)};
            // mov ax, -0x50000000(ebx)
            bsl::debug() << " mov ax, -0x50000000(ebx)" << bsl::endl;
            *mut_instr_len = 7;
            *memory_access_size = 2;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_7bytes) == (instr__mov_PTRIDXebx_di) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdi)};
            // mov -0x50000000(ebx), di
            bsl::debug() << " mov -0x50000000(ebx), di" << bsl::endl;
            *mut_instr_len = 7;
            *memory_access_size = 2;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_3bytes) == (instr__mov_dx_PTResi) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdx)};
            // mov dx, word ptr[esi]
            bsl::debug() << " mov dx, word ptr[esi]" << bsl::endl;
            *mut_instr_len = 3;
            *memory_access_size = 2;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_edx_PTResi) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdx)};
            bsl::debug() << " mov edx, dword ptr[esi]" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_PTResi_edx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdx)};
            bsl::debug() << " mov dword ptr[esi], edx" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_dl_PTResi) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdx)};
            // mov dl, byte ptr[esi]
            bsl::debug() << " mov dl, byte ptr[esi]" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 1;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_PTResi_cl) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rcx)};
            // mov byte ptr[esi], cl
            bsl::debug() << " mov byte ptr[esi], cl" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 1;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_3bytes) == (instr__mov_PTResi_dx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdx)};
            // mov byte ptr[esi], cl
            bsl::debug() << " mov byte ptr[esi], dx" << bsl::endl;
            *mut_instr_len = 3;
            *memory_access_size = 2;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_PTRIDXecx_bl) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rbx)};
            bsl::debug() << " mov byte ptr[ebx-0x50000000], bl" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 1;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_3bytes) == (instr__mov_edx_PTReax) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdx)};
            bsl::debug() << " mov    edx,DWORD PTR [eax+0x8]" << bsl::endl;
            *mut_instr_len = 3;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_3bytes) == (instr__mov_edx_PTRedx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdx)};
            bsl::debug() << " mov    edx,DWORD PTR [edx+0x8]" << bsl::endl;
            *mut_instr_len = 3;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_3bytes) == (instr__mov_edx_PTRebx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdx)};
            bsl::debug() << " mov    ecx,DWORD PTR [ebx+0xc]" << bsl::endl;
            *mut_instr_len = 3;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_PTReax_edx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdx)};
            bsl::debug() << " mov    DWORD PTR [eax],edx" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_PTRedx_ecx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rcx)};
            bsl::debug() << " mov    DWORD PTR [edx],ecx" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_2bytes) == (instr__mov_PTReax_edi) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rdi)};
            bsl::debug() << " mov    DWORD PTR [eax],edi" << bsl::endl;
            *mut_instr_len = 2;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_ecx_PTRedx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rcx)};
            bsl::debug() << " mov    ecx,DWORD PTR [edx+0x5400]" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_eax_PTRedx) ) {
            bsl::uint64 reg {bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rax)};
            bsl::debug() << " mov    eax,DWORD PTR [edx+0x5404]" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 4;
            *mut_register = reg;
            return bsl::errc_success;
        } else if( (opcodes0 & mask_6bytes) == (instr__mov_PTRedx_IMM) ) {
            bsl::debug() << " mov    DWORD PTR [edx], 0xb0000000" << bsl::endl;
            *mut_instr_len = 6;
            *memory_access_size = 4;
            *mut_register = OPCODE_REG_USE_IMMEDIATE.get();
            *immediate_value = 0;
            return bsl::errc_success;
        } else {
            bsl::debug() << __FUNCTION__ << " UNSUPPORTED OPCODE" << bsl::endl;            
            bsl::debug() << "    opcodes0 " << bsl::hex(opcodes0) << bsl::endl;
            bsl::debug() << "    opcodes1 " << bsl::hex(opcodes1) << bsl::endl;
            bsl::debug() << "    cpu_mode " << bsl::hex(cpu_mode) << bsl::endl;
            return bsl::errc_unsupported;
        }

        return bsl::errc_success;
    }


    /// <!-- description -->
    ///   @brief Dispatches MMIO VMExits.
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
    dispatch_vmexit_mmio(
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

        auto const op_bytes{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_number_of_bytes_fetched)};
        auto const opcodes0{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_guest_instruction_bytes0)};
        auto const opcodes1{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_guest_instruction_bytes1)};
        auto rip{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_rip)};

        constexpr auto rw_mask{0x02_u64};
        constexpr auto rw_shift{1_u64};

        auto const phys_addr{(exitinfo2)};
        auto const is_write{(exitinfo1 & rw_mask) >> rw_shift};

        // bsl::debug() << __FUNCTION__ << bsl::endl;
        // bsl::debug() << "          exitinfo1 = " << bsl::hex(exitinfo1) << bsl::endl;
        // bsl::debug() << "          exitinfo2 = " << bsl::hex(exitinfo2) << bsl::endl;
        // bsl::debug() << "          phys_addr = " << bsl::hex(phys_addr) << bsl::endl;
        // bsl::debug() << "          is_write = " << bsl::hex(is_write) << bsl::endl;
        // bsl::debug() << "          op_bytes = " << bsl::hex(op_bytes) << bsl::endl;
        // bsl::debug() << "          rip = " << bsl::hex(rip) << bsl::endl;
        // bsl::debug() << "          opcodes0 = " << bsl::hex(opcodes0) << bsl::endl;
        // bsl::debug() << "          opcodes1 = " << bsl::hex(opcodes1) << bsl::endl;

        // Disassemble the triggering opcode
        bsl::uint64 mut_instr_len{0};
        bsl::uint64 memory_access_size{0};
        bsl::uint64 mut_register{bsl::uint64(hypercall::mv_reg_t::mv_reg_t_rax)};
        bsl::uint64 immediate_value{0};
        auto decode_ret{ instruction_decode(opcodes0.get(), opcodes1.get(), 0U, &mut_instr_len, &mut_register, &memory_access_size, &immediate_value) };
        if (bsl::unlikely(!decode_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, true);
            set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_UNKNOWN));
            set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
            return vmexit_failure_advance_ip_and_run;
        }

        bsl::uint64 nrip{ rip.get() + mut_instr_len };
        bsl::uint64 data{ 0 };

        if(mut_register == OPCODE_REG_USE_IMMEDIATE.get()) {
            data = immediate_value;
        } else {
            data = mut_vs_pool.reg_get(mut_sys, bsl::make_safe(mut_register), vsid).get();
        }

        // bsl::debug() << "          mut_instr_len = " << bsl::hex(mut_instr_len) << bsl::endl;
        // bsl::debug() << "          mut_register = " << bsl::hex(bsl::make_safe(static_cast<bsl::uint64>(mut_register))) << bsl::endl;
        // bsl::debug() << "          memory_access_size = " << bsl::hex(memory_access_size) << bsl::endl;
        // bsl::debug() << "          nrip = " << bsl::hex(nrip) << bsl::endl;
        // bsl::debug() << "          data = " << bsl::hex(data) << bsl::endl;

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

        mut_exit_mmio->nrip = nrip;
        mut_exit_mmio->target_reg = static_cast<bsl::uint64>(mut_register);
        mut_exit_mmio->memory_access_size = memory_access_size;
        mut_exit_mmio->data = data;

        set_reg_return(mut_sys, hypercall::MV_STATUS_SUCCESS);
        set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_MMIO));

        return vmexit_success_advance_ip_and_run;
    }
}

#endif
