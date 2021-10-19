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

#ifndef EMULATED_MMIO_T_HPP
#define EMULATED_MMIO_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <l1e_t.hpp>
#include <map_page_flags.hpp>
#include <mv_mdl_t.hpp>
#include <mv_translation_t.hpp>
#include <page_2m_t.hpp>
#include <second_level_page_table_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::emulated_mmio_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's emulated MMIO handler.
    ///
    ///   @note IMPORTANT: This class is a per-VM class. Any MMIO accesses
    ///     made by a VM must come through here.
    ///
    class emulated_mmio_t final
    {
        /// @brief stores the ID of the VM associated with this emulated_mmio_t
        bsl::safe_u16 m_assigned_vmid{};
        /// @brief stores the second level page tables for this emulated_mmio_t
        second_level_page_table_t m_slpt{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this emulated_mmio_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM associated with this emulated_mmio_t
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid) noexcept
        {
            bsl::expects(this->assigned_vmid() == syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_vmid = ~vmid;
        }

        /// <!-- description -->
        ///   @brief Release the emulated_mmio_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_vmid = {};
        }

        /// <!-- description -->
        ///   @brief Allocates the vm_t and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[maybe_unused]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            page_pool_t &mut_page_pool,
            intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            bsl::discard(gs);
            bsl::discard(intrinsic);

            mut_ret = m_slpt.initialize(tls, mut_page_pool, mut_sys);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            // constexpr auto max_gpa{bsl::to_u64(0x8000000000U)};
            // constexpr auto gpa_inc{bsl::to_idx(PAGE_2M_T_SIZE)};

            // if (mut_sys.is_vm_the_root_vm(this->assigned_vmid())) {
            //     for (bsl::safe_idx mut_i{}; mut_i < max_gpa; mut_i += gpa_inc) {
            //         auto const spa{bsl::to_u64(mut_i)};
            //         auto const gpa{bsl::to_u64(mut_i)};

            //         mut_ret = m_slpt.map_page<l1e_t>(
            //             tls, mut_page_pool, gpa, spa, MAP_PAGE_RWE, false, mut_sys);
            //         if (bsl::unlikely(!mut_ret)) {
            //             bsl::print<bsl::V>() << bsl::here();
            //             return mut_ret;
            //         }

            //         bsl::touch();
            //     }
            // }
            // else {
            //     bsl::touch();
            // }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Deallocates the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            page_pool_t &mut_page_pool,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(gs);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_slpt.release(tls, mut_page_pool);
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP associated with this
        ///     emulated_mmio_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     emulated_mmio_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vmid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vmid.is_valid_and_checked());
            return ~m_assigned_vmid;
        }

        /// <!-- description -->
        ///   @brief Returns the system physical address of the second level
        ///     page tables used by this VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the system physical address of the second level
        ///     page tables used by this VM.
        ///
        [[nodiscard]] constexpr auto
        slpt_spa() const noexcept -> bsl::safe_u64
        {
            return m_slpt.spa();
        }

        /// <!-- description -->
        ///   @brief Maps memory into this VM using instructions from the
        ///     provided MDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mdl the MDL containing the memory to map into the VM
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        map(tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            page_pool_t &mut_page_pool,
            hypercall::mv_mdl_t const &mdl) noexcept -> bsl::errc_type
        {
            bsl::expects(mut_sys.is_the_active_vm_the_root_vm());
            bsl::expects(!mut_sys.is_vm_the_root_vm(this->assigned_vmid()));

            for (bsl::safe_idx mut_i{}; mut_i < mdl.num_entries; ++mut_i) {
                auto const *const entry{mdl.entries.at_if(mut_i)};

                auto const gpa{bsl::to_u64(entry->dst)};
                auto const spa{this->gpa_to_spa(mut_sys, bsl::to_u64(entry->src))};

                /// TODO:
                /// - Add support for entries that have a size greater than
                ///   4k. For now we only support 4k pages.
                /// - Add support for the flags field. For now, everything
                ///   is mapped as RWE.
                /// - We need to undo the any maps that succeeded on failure.
                ///   Right now, we do not do that, which is an issue
                ///   because guest software will not attempt to undo a
                ///   failed map operation.
                ///
                auto const ret{
                    m_slpt.map(tls, mut_page_pool, gpa, spa, MAP_PAGE_RWE, false, mut_sys)};

                if (bsl::unlikely(ret == bsl::errc_already_exists)) {
                    bsl::error() << "mdl entry "                   // --
                                 << mut_i                          // --
                                 << " for dst "                    // --
                                 << bsl::hex(gpa)                  // --
                                 << " has already been mapped "    // --
                                 << bsl::endl                      // --
                                 << bsl::here();                   // --

                    return ret;
                }

                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Unmaps memory from this VM using instructions from the
        ///     provided MDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mdl the MDL containing the memory to map from the VM
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        unmap(
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            page_pool_t &mut_page_pool,
            hypercall::mv_mdl_t const &mdl) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            bsl::expects(mut_sys.is_the_active_vm_the_root_vm());
            bsl::expects(!mut_sys.is_vm_the_root_vm(this->assigned_vmid()));

            for (bsl::safe_idx mut_i{}; mut_i < mdl.num_entries; ++mut_i) {
                auto const *const entry{mdl.entries.at_if(mut_i)};
                auto const gpa{bsl::to_u64(entry->dst)};

                /// TODO:
                /// - Add support for entries that have a size greater than
                ///   4k. For now we only support 4k pages.
                ///

                mut_ret = m_slpt.unmap(tls, mut_page_pool, gpa);
                if (bsl::unlikely(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                bsl::touch();
            }

            /// TODO:
            /// - This needs to be a broadcast TLB flush. To do that, every
            ///   PP that the VM has touched (means we will have to track
            ///   this in the vm_t), we need to flush the TLB for. So likely
            ///   this should just return a bsl::errc_type that is something
            ///   like flush_tlb. Then the vm_t that called this, can loop
            ///   though all of the PPs and IPI the PPs that need to be
            ///   flushed, and the call below is what they would call.
            ///
            /// - On AMD, we can use the broadcast function instead, but the
            ///   microkernel will need a an intrinsic for this. I would not
            ///   make this a VM or VS opcode in the Microkernel because this
            ///   is an AMD specific thing that does not require the use of
            ///   IPIs. If it was a VM, VS thing, any CPU that doesn't have
            ///   this kind of function would have to implement IPIs internal
            ///   to the Microkernel which should be avoided at all costs.
            ///   Instead, making this an intrinsic op means that it can be
            ///   specific to AMD, and you can literally just pass whatever
            ///   the instruction needs. The microkernel would just sanitize
            ///   this input and then call the instruction.
            ///
            /// - On Intel, IPIs will be needed. The pp_lapic_t can be used
            ///   for this. Just implement an IPI API in the pp_lapic_t,
            ///   which will have to have support for both the x1 and x2
            ///   versions, and the MMIO and MSR APIs for this already exist
            ///   in the Microkernel. The code for how to do this is already
            ///   in MicroV/mono, but basically, trap on all INIT calls, and
            ///   then repurpose INIT for IPIs with a mailbox. You will
            ///   have to add an INIT message, so that if a VS executes a
            ///   real INIT, you can send it to the proper PP and handle
            ///   it as needed. But this will allow you to create additional
            ///   messages, including one that performs an tlb flush.
            ///
            /// - On AMD with VMWare, the IPI method will be needed, unless you
            ///   can figure out what VMWare's APIs are for performing a
            ///   remote TLB flush (I know that HyperV has them, not sure
            ///   about VMWare). With AMD, the INIT trick works as well, you
            ///   just need to catch them with an exception, but in general
            ///   they are basically the same.
            ///
            /// - So TL;DR, return `flush_tlb` as a bsl::errc_type instead
            ///   of calling tlb_flush. The vm_t code that called this can
            ///   look for this, and when it sees this, it will flush the
            ///   TLB. To do that, first, add PP tracking to the VM. Each
            ///   time a VS is mirgrated to a PP, it will call the vm_t
            ///   and tell it that it has dirtied the TLB on a given PP.
            ///   This way, when you need to flush the TLB, you can loop
            ///   through this array, and flush the TLB for each PP that the
            ///   VM has touched. Next, add an IPI API to the pp_lapic_t
            ///   and then add a mailbox (locked of course) API to the
            ///   pp_t. The pp_t will lock the mailbox, add the message,
            ///   and then IPI using it's pp_lapic_t, to tell send the
            ///   message. The vm_t will call this pp_t API with a message
            ///   to flush the TLB. To implement the IPI, send an INIT.
            ///   This means that you will have to trap on INIT exits, and
            ///   the LAPIC to see when a guest VM attempts to send an INIT.
            ///   If a guest VM attempts to send an INIT, send it using the
            ///   mailbox. This way you can tell the difference between a
            ///   real INIT and something else like a TLB flush. Finally,
            ///   on VMExit, for INIT, if it is the root VM, just puke as
            ///   this should never happen, and you are not trapping on
            ///   INIT writes to the root VM LAPICs so you have no way to
            ///   make sense of this (but again, it should not happen as it
            ///   would result in a CPU reset). If you get a VMExit INIT for
            ///   a guest VM, if the message is INIT, emulate INIT. If the
            ///   message is flush the TLB, flush the TLB.
            ///

            return mut_sys.bf_vm_op_tlb_flush(this->assigned_vmid());
        }

        /// <!-- description -->
        ///   @brief Returns a system physical address given a guest physical
        ///     address using MMIO second level paging from this VM to
        ///     perform the translation.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param gpa the GPA to translate to a SPA
        ///   @return Returns a system physical address given a guest physical
        ///     address using MMIO second level paging from this VM to
        ///     perform the translation.
        ///
        [[nodiscard]] constexpr auto
        gpa_to_spa(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &gpa) const noexcept
            -> bsl::safe_u64
        {
            bsl::expects(this->assigned_vmid() != syscall::BF_INVALID_ID);
            bsl::expects(sys.is_the_active_vm_the_root_vm());

            /// TODO:
            /// - Right now we assume that the only VM that can run this is
            ///   the root VM. We will have to drop the above check, and
            ///   actually perform a second-level paging translation. If
            ///   the root VM remains such that, maps cannot occur, for the
            ///   root VM, we can continue to return the GPA as an SPA.
            ///
            /// - For guest VMs, we will definitely need to perform a
            ///   translation, which is just running the "entries" function
            ///   while will do the translation.
            ///
            /// - If the root VM eventually supports mapping memory that is
            ///   not 1:1, we will also need to perform this translation
            ///   on the root VM as well.
            ///

            return gpa;
        }
    };
}

#endif
