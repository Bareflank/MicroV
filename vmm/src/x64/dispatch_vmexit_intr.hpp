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

#ifndef DISPATCH_VMEXIT_INTR_HPP
#define DISPATCH_VMEXIT_INTR_HPP

#include <bf_debug_ops.hpp>
#include <bf_syscall_t.hpp>
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
    ///   @brief Dispatches INTR VMExits.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param pp_pool the pp_pool_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_vmexit_intr(
        gs_t const &gs,
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t const &page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t const &pp_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::discard(gs);
        bsl::discard(page_pool);
        bsl::discard(pp_pool);
        bsl::discard(vsid);

        bsl::expects(!mut_sys.is_the_active_vm_the_root_vm());

        /// NOTE:
        /// - The CPU has a physical INTR pin that tells the CPU that an
        ///   external interrupt has fired. The PIC or LAPIC will keep this
        ///   line high until the interrupt is serviced (usually indicated
        ///   by an EOI).
        /// - On AMD, even though this exit has occurred, the INTR pin is
        ///   still high because nothing has given the LAPIC an EOI. MicroV
        ///   itself has no way of servicing this interrupt, that is something
        ///   that the root VM has to do. So all we need to do is return to
        ///   the root VM. Interrupts will be enabled in the root VM, and as
        ///   a result, INTR will be able to be serviced, which will cause
        ///   the CPU to fetch which vector needs servicing, and then call
        ///   the IDT in the root VM as needed.
        /// - On Intel, this depends on the setting of ack on exit. If ack
        ///   on exit is turned on, the VMExit will also send an EOI to the
        ///   LAPIC, which will cause INTR to drop. When this is the case,
        ///   you will have to read the vector from the VMCS and injected it
        ///   into the root VM. If ack on exit is disabled, the AMD approach
        ///   works, allowing us to simply return to the root VM and let it
        ///   handle the interrupt the same way AMD would.
        ///

        // ---------------------------------------------------------------------
        // Context: Change To Root VM
        // ---------------------------------------------------------------------

        switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, false);

        // ---------------------------------------------------------------------
        // Context: Root VM
        // ---------------------------------------------------------------------

        set_reg_return(mut_sys, hypercall::MV_STATUS_SUCCESS);
        set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_INTERRUPT));

        return vmexit_success_advance_ip_and_run;
    }
}

#endif
