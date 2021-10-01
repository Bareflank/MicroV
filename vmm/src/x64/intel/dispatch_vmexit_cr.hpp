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

#include <arch_helpers.hpp>
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
    /// NOTE:
    /// - Intel handles CR emulation for CR0/CR4 different from AMD. On
    ///   Intel, if you want to trap on a read/write to CR0/CR4, you have
    ///   to set bits in the CR0/CR4 guest/host mask. Any bit set in this
    ///   mask will generate a VMExit when the guest attempts to change
    ///   that bit. So you will not get a VMExit for any bit that is set
    ///   to 0, or if the guest does not actually change the bit.
    ///
    /// - In addition, just to make this more interesting, any bit set in
    ///   the mask is read/from the read shadow. So in the VMCS, there
    ///   are two CR0s and two CR4s. The real one, and the read shadow.
    ///   Whatever is in the read shadow is what is read by the guest, but
    ///   only the bits set in the mask. All writes go directly to CR0/CR4
    ///   if the mask is clear, or trap when the mask bit is 1.
    ///
    /// - So, what we do here is just set all of the bits to 1 in the mask.
    ///   If this ends up being a performance issue in the future, we can
    ///   always get a bit more fancy with this. By setting all of the mask
    ///   bits to 0, all writes to CR0/CR4 that change a bit will trap, and
    ///   all bits read will always come from the shadow, making life a ton
    ///   easier here.
    ///
    /// - Unlike AMD as well, Intel requires that certain CRO/CR4 bits are
    ///   always enabled, or always disabled. AMD does not have this same
    ///   limitation. Which bits can be 1 and which bits can be 0 come from
    ///   the fixed CR0/CR4 MSRs. And of course it is not that simple, as
    ///   once you turn unrestricted guest mode on, PG and PE can be
    ///   enabled/disabled, to the fixed CR0/CR4 MSRs lie WRT to PG/PE
    ///   when this mode is changed. Thankfully, the Microkernel handles all
    ///   of this for us. So MicroV has it pretty easy here.
    ///
    /// - MicroV requires EPT and unrestricted mode, so these are always
    ///   turned on. And, the Microkernel handles the rest. So, any write
    ///   from CR0/CR4, we simply write to CR0/CR4 in the VMCS. The Microkernel
    ///   will make sure that the bits that must be on/off are handled. All
    ///   we need to do next is also write CR0/CR4 to the read shadow. This
    ///   way, what the guest reads from CR0/CR4 is what it wrote. Just know
    ///   that if you see the output of a VS, CR0/CR4 might not match what
    ///   the guest wrote. This is because the Microkernel is adding bits
    ///   based on what Intel requires. But the read shadow should always
    ///   match what the guest wrote.
    ///
    /// - Sadly, this story is not over for Intel. For god knows what reason,
    ///   Intel has this thing called the ia32e_mode in the entry controls.
    ///   If this mode is enabled, the guest must be in 64bit mode. If this
    ///   control is disabled, the guest must be in 32bit mode. So, what this
    ///   means is that we need to watch changes to CR0/CR4, and then read
    ///   the EFER MSR for the guest. This will tell us when we need to handle
    ///   modifications to this entry control so that we ensure the guest
    ///   can actually be in the mode that it wants to be.
    ///
    /// - And finally, like AMD, we need to worry about TLB flushes. Certain
    ///   modifications to CR0/CR4 require a TLB flush. Not that big of a
    ///   deal, but it must be done. The list includes:
    ///   - CR0.PG, CR0.WP, CR0.CD, CR0.NW
    ///   - CR4.PGE, CR4.PAE, CR4.PSE
    ///   - EFER.NXE, EFER.LMA, EFER.LME
    ///

    /// <!-- description -->
    ///   @brief Handles CR0 VMExits
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @param type 1 = read, 0 = write
    ///   @param rnum which GPR to read/write from
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_vmexit_cr0(
        syscall::bf_syscall_t &mut_sys,
        bsl::safe_u16 const &vsid,
        bsl::safe_u64 const &type,
        bsl::safe_u64 const &rnum) noexcept -> bsl::errc_type
    {
        constexpr auto type_write{0_u64};
        if (type == type_write) {
            auto const cr0_val{get_gpr(mut_sys, vsid, rnum)};
            auto const cr0_idx{syscall::bf_reg_t::bf_reg_t_cr0};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, cr0_idx, cr0_val));

            constexpr auto cr0_shadow_idx{syscall::bf_reg_t::bf_reg_t_cr0_read_shadow};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, cr0_shadow_idx, cr0_val));

            return vmexit_success_advance_ip_and_run;
        }

        bsl::error() << "reads from cr0 on Intel are impossible\n" << bsl::here();
        return bsl::errc_failure;
    }

    /// <!-- description -->
    ///   @brief Handles CR4 VMExits
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @param type 1 = read, 0 = write
    ///   @param rnum which GPR to read/write from
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_vmexit_cr4(
        syscall::bf_syscall_t &mut_sys,
        bsl::safe_u16 const &vsid,
        bsl::safe_u64 const &type,
        bsl::safe_u64 const &rnum) noexcept -> bsl::errc_type
    {
        constexpr auto type_write{0_u64};
        if (type == type_write) {
            auto const cr4_val{get_gpr(mut_sys, vsid, rnum)};
            auto const cr4_idx{syscall::bf_reg_t::bf_reg_t_cr4};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, cr4_idx, cr4_val));

            constexpr auto cr4_shadow_idx{syscall::bf_reg_t::bf_reg_t_cr4_read_shadow};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, cr4_shadow_idx, cr4_val));

            return vmexit_success_advance_ip_and_run;
        }

        bsl::error() << "reads from cr4 on Intel are impossible\n" << bsl::here();
        return bsl::errc_failure;
    }

    /// <!-- description -->
    ///   @brief Handles CR8 VMExits
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @param type 1 = read, 0 = write
    ///   @param rnum which GPR to read/write from
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    handle_vmexit_cr8(
        syscall::bf_syscall_t &mut_sys,
        bsl::safe_u16 const &vsid,
        bsl::safe_u64 const &type,
        bsl::safe_u64 const &rnum) noexcept -> bsl::errc_type
    {
        /// TODO:
        /// - CR8 (also called the TPR) should be written to the emulated
        ///   LAPIC code so that it has it, as the TPR will be needed to
        ///   determine which interrupts take priority. Just make a get/set
        ///   TPR function in the vs_t/vs_pool_t and get/set it's value
        ///

        constexpr auto type_read{1_u64};
        if (type == type_read) {
            auto const cr8_idx{syscall::bf_reg_t::bf_reg_t_cr8};
            auto const cr8_val{mut_sys.bf_vs_op_read(vsid, cr8_idx)};
            bsl::expects(set_gpr(mut_sys, vsid, rnum, cr8_val));

            return vmexit_success_advance_ip_and_run;
        }

        constexpr auto type_write{0_u64};
        if (type == type_write) {
            auto const cr8_val{get_gpr(mut_sys, vsid, rnum)};
            auto const cr8_idx{syscall::bf_reg_t::bf_reg_t_cr8};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, cr8_idx, cr8_val));

            return vmexit_success_advance_ip_and_run;
        }

        bsl::error() << "unknown type\n" << bsl::here();
        return bsl::errc_failure;
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
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        /// TODO:
        /// - Need to properly handle CLTS and LMSW
        ///

        bsl::discard(gs);
        bsl::discard(tls);
        bsl::discard(page_pool);
        bsl::discard(intrinsic);
        bsl::discard(pp_pool);
        bsl::discard(vm_pool);
        bsl::discard(vp_pool);
        bsl::discard(vs_pool);

        bsl::expects(!mut_sys.is_the_active_vm_the_root_vm());

        constexpr auto exitqual_idx{syscall::bf_reg_t::bf_reg_t_exit_qualification};
        auto const exitqual{mut_sys.bf_vs_op_read(vsid, exitqual_idx)};

        constexpr auto cnum_mask{0x0000000F_u64};
        constexpr auto cnum_shft{0_u64};
        constexpr auto type_mask{0x00000030_u64};
        constexpr auto type_shft{4_u64};
        constexpr auto rnum_mask{0x00000700_u64};
        constexpr auto rnum_shft{8_u64};

        auto const cnum{((exitqual & cnum_mask) >> cnum_shft)};
        auto const type{((exitqual & type_mask) >> type_shft)};
        auto const rnum{((exitqual & rnum_mask) >> rnum_shft)};

        constexpr auto type_clts{2_u64};
        if (bsl::unlikely(type_clts == type)) {
            bsl::error() << "support for CLTS is currently not implemented\n" << bsl::here();
            return bsl::errc_failure;
        }

        constexpr auto type_lmsw{2_u64};
        if (bsl::unlikely(type_lmsw == type)) {
            bsl::error() << "support for LMSW is currently not implemented\n" << bsl::here();
            return bsl::errc_failure;
        }

        constexpr auto cnum_cr0{0_u64};
        constexpr auto cnum_cr4{4_u64};
        constexpr auto cnum_cr8{8_u64};

        switch (cnum.get()) {
            case cnum_cr0.get(): {
                return handle_vmexit_cr0(mut_sys, vsid, type, rnum);
            }

            case cnum_cr4.get(): {
                return handle_vmexit_cr4(mut_sys, vsid, type, rnum);
            }

            case cnum_cr8.get(): {
                return handle_vmexit_cr8(mut_sys, vsid, type, rnum);
            }

            default: {
                break;
            }
        }

        bsl::error() << "unknown CR related VMExit\n" << bsl::here();
        return bsl::errc_failure;
    }
}

#endif
