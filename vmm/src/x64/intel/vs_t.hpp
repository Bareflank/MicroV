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

#ifndef VS_T_HPP
#define VS_T_HPP

#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <bf_syscall_t.hpp>
#include <emulated_cpuid_t.hpp>
#include <emulated_cr_t.hpp>
#include <emulated_decoder_t.hpp>
#include <emulated_io_t.hpp>
#include <emulated_lapic_t.hpp>
#include <emulated_mmio_t.hpp>
#include <emulated_msr_t.hpp>
#include <emulated_tlb_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_translation_t.hpp>
#include <pp_pool_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Returns the masked version of the VMCS control fields
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value of the control fields read from the MSRs
    ///   @return The masked version of the control fields.
    ///
    [[nodiscard]] constexpr auto
    ctls_mask(bsl::safe_u64 const &val) noexcept -> bsl::safe_u64
    {
        constexpr auto mask{0x00000000FFFFFFFF_u64};
        constexpr auto shift{32_u64};
        return ((val & mask) & (val >> shift)).checked();
    };

    /// @class microv::vs_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's notion of a VS
    ///
    class vs_t final
    {
        /// @brief stores the ID associated with this vs_t
        bsl::safe_u16 m_id{};
        /// @brief stores whether or not this vs_t is allocated.
        allocated_status_t m_allocated{};
        /// @brief stores the ID of the VM this vs_t is assigned to
        bsl::safe_u16 m_assigned_vmid{};
        /// @brief stores the ID of the VP this vs_t is assigned to
        bsl::safe_u16 m_assigned_vpid{};
        /// @brief stores the ID of the PP this vs_t is assigned to
        bsl::safe_u16 m_assigned_ppid{};
        /// @brief stores the ID of the PP this vs_t is active on
        bsl::safe_u16 m_active_ppid{};

        /// @brief stores this vs_t's emulated_cpuid_t
        emulated_cpuid_t m_emulated_cpuid{};
        /// @brief stores this vs_t's emulated_cr_t
        emulated_cr_t m_emulated_cr{};
        /// @brief stores this vs_t's emulated_decoder_t
        emulated_decoder_t m_emulated_decoder{};
        /// @brief stores this vs_t's emulated_io_t
        emulated_io_t m_emulated_io{};
        /// @brief stores this vs_t's emulated_lapic_t
        emulated_lapic_t m_emulated_lapic{};
        /// @brief stores this vs_t's emulated_mmio_t
        emulated_mmio_t m_emulated_mmio{};
        /// @brief stores this vs_t's emulated_msr_t
        emulated_msr_t m_emulated_msr{};
        /// @brief stores this vs_t's emulated_tlb_t
        emulated_tlb_t m_emulated_tlb{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param i the ID for this vs_t
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &i) noexcept
        {
            bsl::expects(this->id() == syscall::BF_INVALID_ID);

            bsl::expects(i.is_valid_and_checked());
            bsl::expects(i != syscall::BF_INVALID_ID);

            m_emulated_cpuid.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_cr.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_decoder.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_io.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_lapic.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_mmio.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_msr.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_tlb.initialize(gs, tls, sys, intrinsic, i);

            m_id = ~i;
        }

        /// <!-- description -->
        ///   @brief Release the vs_t.
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
            this->deallocate(gs, tls, sys, intrinsic);

            m_emulated_tlb.release(gs, tls, sys, intrinsic);
            m_emulated_msr.release(gs, tls, sys, intrinsic);
            m_emulated_mmio.release(gs, tls, sys, intrinsic);
            m_emulated_lapic.release(gs, tls, sys, intrinsic);
            m_emulated_io.release(gs, tls, sys, intrinsic);
            m_emulated_decoder.release(gs, tls, sys, intrinsic);
            m_emulated_cr.release(gs, tls, sys, intrinsic);
            m_emulated_cpuid.release(gs, tls, sys, intrinsic);

            m_id = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vs_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_id.is_valid_and_checked());
            return ~m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates the vs_t and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the vs_t to
        ///   @param vpid the ID of the VP to assign the vs_t to
        ///   @param ppid the ID of the PP to assign the vs_t to
        ///   @return Returns ID of this vs_t
        ///
        [[maybe_unused]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::safe_u16
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            bsl::expects(allocated_status_t::deallocated == m_allocated);

            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != syscall::BF_INVALID_ID);
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != syscall::BF_INVALID_ID);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            auto const vsid{this->id()};
            if (mut_sys.is_vs_a_root_vs(vsid)) {
                bsl::expects(mut_sys.bf_vs_op_init_as_root(vsid));
            }
            else {
                bsl::touch();
            }

            auto const vmcs_vpid_val{(bsl::to_u64(vmid) + bsl::safe_u64::magic_1()).checked()};
            constexpr auto vmcs_vpid_idx{syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier};
            bsl::expects(mut_sys.bf_vs_op_write(this->id(), vmcs_vpid_idx, vmcs_vpid_val));

            constexpr auto vmcs_link_ptr_val{0xFFFFFFFFFFFFFFFF_u64};
            constexpr auto vmcs_link_ptr_idx{syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer};
            bsl::expects(mut_sys.bf_vs_op_write(this->id(), vmcs_link_ptr_idx, vmcs_link_ptr_val));

            constexpr auto ia32_vmx_true_pinbased_ctls{0x48D_u32};
            constexpr auto ia32_vmx_true_procbased_ctls{0x48E_u32};
            constexpr auto ia32_vmx_true_exit_ctls{0x48F_u32};
            constexpr auto ia32_vmx_true_entry_ctls{0x490_u32};
            constexpr auto ia32_vmx_true_procbased_ctls2{0x48B_u32};

            bsl::safe_umx mut_ctls{};
            syscall::bf_reg_t mut_idx{};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_pinbased_ctls);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_idx = syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(this->id(), mut_idx, ctls_mask(mut_ctls)));

            constexpr auto enable_msr_bitmaps{0x10000000_u64};
            constexpr auto enable_procbased_ctls2{0x80000000_u64};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_procbased_ctls);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_ctls |= enable_msr_bitmaps;
            mut_ctls |= enable_procbased_ctls2;

            mut_idx = syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(this->id(), mut_idx, ctls_mask(mut_ctls)));

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_exit_ctls);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_idx = syscall::bf_reg_t::bf_reg_t_vmexit_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(this->id(), mut_idx, ctls_mask(mut_ctls)));

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_entry_ctls);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_idx = syscall::bf_reg_t::bf_reg_t_vmentry_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(this->id(), mut_idx, ctls_mask(mut_ctls)));

            constexpr auto enable_vpid{0x00000020_u64};
            constexpr auto enable_rdtscp{0x00000008_u64};
            constexpr auto enable_invpcid{0x00001000_u64};
            constexpr auto enable_xsave{0x00100000_u64};
            constexpr auto enable_uwait{0x04000000_u64};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_procbased_ctls2);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_ctls |= enable_vpid;
            mut_ctls |= enable_rdtscp;
            mut_ctls |= enable_invpcid;
            mut_ctls |= enable_xsave;
            mut_ctls |= enable_uwait;

            mut_idx = syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(this->id(), mut_idx, ctls_mask(mut_ctls)));

            constexpr auto msr_bitmaps_idx{syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps};
            bsl::expects(mut_sys.bf_vs_op_write(this->id(), msr_bitmaps_idx, gs.msr_bitmap_phys));

            m_assigned_vpid = ~vpid;
            m_assigned_ppid = ~ppid;
            m_allocated = allocated_status_t::allocated;

            if (!mut_sys.is_vs_a_root_vs(this->id())) {
                bsl::debug<bsl::V>()                                   // --
                    << "vs "                                           // --
                    << bsl::grn << bsl::hex(this->id()) << bsl::rst    // --
                    << " was created"                                  // --
                    << bsl::endl;                                      // --
            }
            else {
                bsl::touch();
            }

            return vsid;
        }

        /// <!-- description -->
        ///   @brief Deallocates the vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::expects(this->is_active().is_invalid());

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            m_assigned_ppid = {};
            m_assigned_vpid = {};
            m_assigned_vmid = {};
            m_allocated = allocated_status_t::deallocated;

            if (!sys.is_vs_a_root_vs(this->id())) {
                bsl::debug<bsl::V>()                                   // --
                    << "vs "                                           // --
                    << bsl::red << bsl::hex(this->id()) << bsl::rst    // --
                    << " was destroyed"                                // --
                    << bsl::endl;                                      // --
            }
            else {
                bsl::touch();
            }
        }

        /// <!-- description -->
        ///   @brief Returns true if this vs_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vs_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vs_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vs_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Sets this vs_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        set_active(tls_t &mut_tls) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vsid);

            m_active_ppid = ~bsl::to_u16(mut_tls.ppid);
            mut_tls.active_vsid = this->id().get();
        }

        /// <!-- description -->
        ///   @brief Sets this vs_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        set_inactive(tls_t &mut_tls) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(this->id() == mut_tls.active_vsid);

            m_active_ppid = {};
            mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vs_t is active on. If the
        ///     vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vs_t is active on. If the
        ///     vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        [[nodiscard]] constexpr auto
        is_active() const noexcept -> bsl::safe_u16
        {
            if (m_active_ppid.is_pos()) {
                return ~m_active_ppid;
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Returns true if this vs_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vs_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_this_pp(tls_t const &tls) const noexcept -> bool
        {
            return tls.ppid == ~m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VM this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vm() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vmid.is_valid_and_checked());
            return ~m_assigned_vmid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VP this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vpid.is_valid_and_checked());
            return ~m_assigned_vpid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_pp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_ppid.is_valid_and_checked());
            return ~m_assigned_ppid;
        }

        /// <!-- description -->
        ///   @brief Reads CPUID for this vs_t and returns the results
        ///     in the appropriate bf_syscall_t TLS registers.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        cpuid_get(syscall::bf_syscall_t &mut_sys, intrinsic_t const &intrinsic) const noexcept
            -> bsl::errc_type
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);

            if (mut_sys.is_the_active_vm_the_root_vm()) {
                return m_emulated_cpuid.get_root(mut_sys, intrinsic);
            }

            return m_emulated_cpuid.get_guest(mut_sys, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Translates a GLA to a GPA using the paging configuration
        ///     of this vs_t stored in CR0, CR3 and CR4.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_pp_pool the pp_pool_t to use
        ///   @param gla the GLA to translate to a GPA
        ///   @return Returns mv_translation_t containing the results of the
        ///     translation.
        ///
        [[nodiscard]] constexpr auto
        gla_to_gpa(syscall::bf_syscall_t &mut_sys, pp_pool_t &mut_pp_pool, bsl::safe_u64 const &gla)
            const noexcept -> hypercall::mv_translation_t
        {
            auto const vsid{this->id()};
            bsl::expects(allocated_status_t::allocated == m_allocated);

            auto const cr0{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_guest_cr0)};
            bsl::expects(cr0.is_valid_and_checked());

            if (bsl::unlikely(cr0.is_zero())) {
                bsl::error() << "gla_to_gpa failed for gla "                // --
                             << bsl::hex(gla)                               // --
                             << " because the value of cr0 is invalid: "    // --
                             << bsl::hex(cr0)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return {};
            }

            auto const cr3{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_guest_cr3)};
            bsl::expects(cr3.is_valid_and_checked());
            bsl::expects(cr3.is_pos());

            if (bsl::unlikely(cr3.is_zero())) {
                bsl::error() << "gla_to_gpa failed for gla "                // --
                             << bsl::hex(gla)                               // --
                             << " because the value of cr3 is invalid: "    // --
                             << bsl::hex(cr3)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return {};
            }

            auto const cr4{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_guest_cr4)};
            bsl::expects(cr4.is_valid_and_checked());
            bsl::expects(cr4.is_pos());

            if (bsl::unlikely(cr4.is_zero())) {
                bsl::error() << "gla_to_gpa failed for gla "                // --
                             << bsl::hex(gla)                               // --
                             << " because the value of cr4 is invalid: "    // --
                             << bsl::hex(cr4)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return {};
            }

            return m_emulated_tlb.gla_to_gpa(mut_sys, mut_pp_pool, gla, cr0, cr3, cr4);
        }
    };
}

#endif
