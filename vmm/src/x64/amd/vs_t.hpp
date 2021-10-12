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
#include <emulated_decoder_t.hpp>
#include <emulated_dr_t.hpp>
#include <emulated_io_t.hpp>
#include <emulated_lapic_t.hpp>
#include <emulated_msr_t.hpp>
#include <emulated_tlb_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_exit_reason_t.hpp>
#include <mv_mp_state_t.hpp>
#include <mv_rdl_t.hpp>
#include <mv_reg_t.hpp>
#include <mv_run_t.hpp>
#include <mv_translation_t.hpp>
#include <page_4k_t.hpp>
#include <page_pool_t.hpp>
#include <pp_pool_t.hpp>
#include <queue.hpp>
#include <running_status_t.hpp>
#include <tls_t.hpp>

#include <bsl/cstring.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @brief defines the PAT MSR
    constexpr auto MSR_PAT{0x277_u32};
    /// @brief defines the SYSENTER_CS MSR
    constexpr auto MSR_SYSENTER_CS{0x174_u32};
    /// @brief defines the SYSENTER_ESP MSR
    constexpr auto MSR_SYSENTER_ESP{0x175_u32};
    /// @brief defines the SYSENTER_EIP MSR
    constexpr auto MSR_SYSENTER_EIP{0x176_u32};
    /// @brief defines the EFER MSR
    constexpr auto MSR_EFER{0xC0000080_u32};
    /// @brief defines the STAR MSR
    constexpr auto MSR_STAR{0xC0000081_u32};
    /// @brief defines the LSTAR MSR
    constexpr auto MSR_LSTAR{0xC0000082_u32};
    /// @brief defines the CSTAR MSR
    constexpr auto MSR_CSTAR{0xC0000083_u32};
    /// @brief defines the FMASK MSR
    constexpr auto MSR_FMASK{0xC0000084_u32};
    /// @brief defines the FS_BASE MSR
    constexpr auto MSR_FS_BASE{0xC0000100_u32};
    /// @brief defines the GS_BASE MSR
    constexpr auto MSR_GS_BASE{0xC0000101_u32};
    /// @brief defines the KERNEL_GS_BASE MSR
    constexpr auto MSR_KERNEL_GS_BASE{0xC0000102_u32};

    /// @brief stores the APIC_BASE MSR address
    constexpr auto MSR_APIC_BASE{0x0000001B_u32};

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
        /// @brief stores the running state of this vs_t
        running_status_t m_status{};
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
        /// @brief stores this vs_t's emulated_decoder_t
        emulated_decoder_t m_emulated_decoder{};
        /// @brief stores this vs_t's emulated_dr_t
        emulated_dr_t m_emulated_dr{};
        /// @brief stores this vs_t's emulated_io_t
        emulated_io_t m_emulated_io{};
        /// @brief stores this vs_t's emulated_lapic_t
        emulated_lapic_t m_emulated_lapic{};
        /// @brief stores this vs_t's emulated_msr_t
        emulated_msr_t m_emulated_msr{};
        /// @brief stores this vs_t's emulated_tlb_t
        emulated_tlb_t m_emulated_tlb{};

        /// @brief stores the xsave region for this vs_t
        page_4k_t *m_xsave{};
        /// @brief stores multiprocessor state of this vs_t
        hypercall::mv_mp_state_t m_mp_state{};
        /// @brief stores the TSC frequency in KHz of this vs_t
        bsl::safe_u64 m_tsc_khz{};

        /// @brief stores a queue of interrupts that need to be injected
        queue<bsl::safe_u64, MICROV_INTERRUPT_QUEUE_SIZE.get()> m_interrupt_queue{};

        /// <!-- description -->
        ///   @brief Initializes the VS to start as a 16bit guest.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///
        constexpr void
        init_as_16bit_guest(syscall::bf_syscall_t &mut_sys) noexcept
        {
            auto const vsid{this->id()};
            using mk = syscall::bf_reg_t;

            // -----------------------------------------------------------------
            // General Purpose Registers
            // -----------------------------------------------------------------

            constexpr auto rip_val{0x0000FFF0_u64};
            constexpr auto rdx_val{0x00000600_u64};

            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rax, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rbx, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rcx, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rdx, rdx_val));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rbp, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rsi, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rdi, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_r8, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_r9, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_r10, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_r11, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_r12, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_r13, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_r14, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_r15, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rip, rip_val));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rsp, {}));

            // -----------------------------------------------------------------
            // General Purpose Registers
            // -----------------------------------------------------------------

            constexpr auto rflags_val{0x00000002_u64};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_rflags, rflags_val));

            // -----------------------------------------------------------------
            // ES
            // -----------------------------------------------------------------

            constexpr auto es_selector_val{0x0_u64};
            constexpr auto es_selector_idx{mk::bf_reg_t_es_selector};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, es_selector_idx, es_selector_val));

            constexpr auto es_base_val{0x0_u64};
            constexpr auto es_base_idx{mk::bf_reg_t_es_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, es_base_idx, es_base_val));

            constexpr auto es_limit_val{0xFFFF_u64};
            constexpr auto es_limit_idx{mk::bf_reg_t_es_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, es_limit_idx, es_limit_val));

            constexpr auto es_attrib_val{0x93_u64};
            constexpr auto es_attrib_idx{mk::bf_reg_t_es_attrib};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, es_attrib_idx, es_attrib_val));

            // -----------------------------------------------------------------
            // CS
            // -----------------------------------------------------------------

            constexpr auto cs_selector_val{0xF000_u64};
            constexpr auto cs_selector_idx{mk::bf_reg_t_cs_selector};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, cs_selector_idx, cs_selector_val));

            constexpr auto cs_base_val{0xFFFF0000_u64};
            constexpr auto cs_base_idx{mk::bf_reg_t_cs_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, cs_base_idx, cs_base_val));

            constexpr auto cs_limit_val{0xFFFF_u64};
            constexpr auto cs_limit_idx{mk::bf_reg_t_cs_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, cs_limit_idx, cs_limit_val));

            constexpr auto cs_attrib_val{0x9B_u64};
            constexpr auto cs_attrib_idx{mk::bf_reg_t_cs_attrib};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, cs_attrib_idx, cs_attrib_val));

            // -----------------------------------------------------------------
            // SS
            // -----------------------------------------------------------------

            constexpr auto ss_selector_val{0x0_u64};
            constexpr auto ss_selector_idx{mk::bf_reg_t_ss_selector};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ss_selector_idx, ss_selector_val));

            constexpr auto ss_base_val{0x0_u64};
            constexpr auto ss_base_idx{mk::bf_reg_t_ss_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ss_base_idx, ss_base_val));

            constexpr auto ss_limit_val{0xFFFF_u64};
            constexpr auto ss_limit_idx{mk::bf_reg_t_ss_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ss_limit_idx, ss_limit_val));

            constexpr auto ss_attrib_val{0x93_u64};
            constexpr auto ss_attrib_idx{mk::bf_reg_t_ss_attrib};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ss_attrib_idx, ss_attrib_val));

            // -----------------------------------------------------------------
            // DS
            // -----------------------------------------------------------------

            constexpr auto ds_selector_val{0x0_u64};
            constexpr auto ds_selector_idx{mk::bf_reg_t_ds_selector};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ds_selector_idx, ds_selector_val));

            constexpr auto ds_base_val{0x0_u64};
            constexpr auto ds_base_idx{mk::bf_reg_t_ds_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ds_base_idx, ds_base_val));

            constexpr auto ds_limit_val{0xFFFF_u64};
            constexpr auto ds_limit_idx{mk::bf_reg_t_ds_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ds_limit_idx, ds_limit_val));

            constexpr auto ds_attrib_val{0x93_u64};
            constexpr auto ds_attrib_idx{mk::bf_reg_t_ds_attrib};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ds_attrib_idx, ds_attrib_val));

            // -----------------------------------------------------------------
            // FS
            // -----------------------------------------------------------------

            constexpr auto fs_selector_val{0x0_u64};
            constexpr auto fs_selector_idx{mk::bf_reg_t_fs_selector};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, fs_selector_idx, fs_selector_val));

            constexpr auto fs_base_val{0x0_u64};
            constexpr auto fs_base_idx{mk::bf_reg_t_fs_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, fs_base_idx, fs_base_val));

            constexpr auto fs_limit_val{0xFFFF_u64};
            constexpr auto fs_limit_idx{mk::bf_reg_t_fs_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, fs_limit_idx, fs_limit_val));

            constexpr auto fs_attrib_val{0x93_u64};
            constexpr auto fs_attrib_idx{mk::bf_reg_t_fs_attrib};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, fs_attrib_idx, fs_attrib_val));

            // -----------------------------------------------------------------
            // GS
            // -----------------------------------------------------------------

            constexpr auto gs_selector_val{0x0_u64};
            constexpr auto gs_selector_idx{mk::bf_reg_t_gs_selector};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, gs_selector_idx, gs_selector_val));

            constexpr auto gs_base_val{0x0_u64};
            constexpr auto gs_base_idx{mk::bf_reg_t_gs_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, gs_base_idx, gs_base_val));

            constexpr auto gs_limit_val{0xFFFF_u64};
            constexpr auto gs_limit_idx{mk::bf_reg_t_gs_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, gs_limit_idx, gs_limit_val));

            constexpr auto gs_attrib_val{0x93_u64};
            constexpr auto gs_attrib_idx{mk::bf_reg_t_gs_attrib};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, gs_attrib_idx, gs_attrib_val));

            // -----------------------------------------------------------------
            // LDTR
            // -----------------------------------------------------------------

            constexpr auto ldtr_selector_val{0x0_u64};
            constexpr auto ldtr_selector_idx{mk::bf_reg_t_ldtr_selector};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ldtr_selector_idx, ldtr_selector_val));

            constexpr auto ldtr_base_val{0x0_u64};
            constexpr auto ldtr_base_idx{mk::bf_reg_t_ldtr_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ldtr_base_idx, ldtr_base_val));

            constexpr auto ldtr_limit_val{0xFFFF_u64};
            constexpr auto ldtr_limit_idx{mk::bf_reg_t_ldtr_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ldtr_limit_idx, ldtr_limit_val));

            constexpr auto ldtr_attrib_val{0x82_u64};
            constexpr auto ldtr_attrib_idx{mk::bf_reg_t_ldtr_attrib};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ldtr_attrib_idx, ldtr_attrib_val));

            // -----------------------------------------------------------------
            // TR
            // -----------------------------------------------------------------

            constexpr auto tr_selector_val{0x0_u64};
            constexpr auto tr_selector_idx{mk::bf_reg_t_tr_selector};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, tr_selector_idx, tr_selector_val));

            constexpr auto tr_base_val{0x0_u64};
            constexpr auto tr_base_idx{mk::bf_reg_t_tr_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, tr_base_idx, tr_base_val));

            constexpr auto tr_limit_val{0xFFFF_u64};
            constexpr auto tr_limit_idx{mk::bf_reg_t_tr_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, tr_limit_idx, tr_limit_val));

            constexpr auto tr_attrib_val{0x8B_u64};
            constexpr auto tr_attrib_idx{mk::bf_reg_t_tr_attrib};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, tr_attrib_idx, tr_attrib_val));

            // -----------------------------------------------------------------
            // GDTR
            // -----------------------------------------------------------------

            constexpr auto gdtr_base_val{0x0_u64};
            constexpr auto gdtr_base_idx{mk::bf_reg_t_gdtr_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, gdtr_base_idx, gdtr_base_val));

            constexpr auto gdtr_limit_val{0xFFFF_u64};
            constexpr auto gdtr_limit_idx{mk::bf_reg_t_gdtr_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, gdtr_limit_idx, gdtr_limit_val));

            // -----------------------------------------------------------------
            // IDTR
            // -----------------------------------------------------------------

            // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
            constexpr auto idtr_base_val{0x0_u64};
            // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
            constexpr auto idtr_base_idx{mk::bf_reg_t_idtr_base};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, idtr_base_idx, idtr_base_val));

            // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
            constexpr auto idtr_limit_val{0xFFFF_u64};
            // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
            constexpr auto idtr_limit_idx{mk::bf_reg_t_idtr_limit};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, idtr_limit_idx, idtr_limit_val));

            // -----------------------------------------------------------------
            // Control Registers
            // -----------------------------------------------------------------

            constexpr auto cr0_val{0x60000010_u64};

            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_cr0, cr0_val));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_cr2, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_cr3, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_cr4, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_cr8, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_xcr0, {}));

            // -----------------------------------------------------------------
            // Debug Registers
            // -----------------------------------------------------------------

            constexpr auto dr7_val{0x00000400_u64};

            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_dr0, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_dr1, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_dr2, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_dr3, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_dr6, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_dr7, dr7_val));

            // -----------------------------------------------------------------
            // MSRs
            // -----------------------------------------------------------------

            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_efer, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_fs_base, {}));
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mk::bf_reg_t_gs_base, {}));

            constexpr auto apic_base{0xFEE00900_u64};
            m_emulated_lapic.set_apic_base(apic_base);
        }

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
            m_emulated_decoder.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_dr.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_io.initialize(gs, tls, sys, intrinsic, i);
            m_emulated_lapic.initialize(gs, tls, sys, intrinsic, i);
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
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            page_pool_t &mut_page_pool,
            intrinsic_t const &intrinsic) noexcept
        {
            this->deallocate(gs, tls, sys, mut_page_pool, intrinsic);

            m_emulated_tlb.release(gs, tls, sys, intrinsic);
            m_emulated_msr.release(gs, tls, sys, intrinsic);
            m_emulated_lapic.release(gs, tls, sys, intrinsic);
            m_emulated_io.release(gs, tls, sys, intrinsic);
            m_emulated_dr.release(gs, tls, sys, intrinsic);
            m_emulated_decoder.release(gs, tls, sys, intrinsic);
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
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the vs_t to
        ///   @param vpid the ID of the VP to assign the vs_t to
        ///   @param ppid the ID of the PP to assign the vs_t to
        ///   @param tsc_khz the starting TSC frequency of the vs_t
        ///   @param slpt_spa the system physical address of the second level
        ///     page tables to use.
        ///   @return Returns ID of this vs_t
        ///
        [[maybe_unused]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            page_pool_t &mut_page_pool,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid,
            bsl::safe_u64 const &tsc_khz,
            bsl::safe_u64 const &slpt_spa) noexcept -> bsl::safe_u16
        {
            auto const vsid{this->id()};

            bsl::expects(vsid != syscall::BF_INVALID_ID);
            bsl::expects(allocated_status_t::deallocated == m_allocated);
            bsl::expects(running_status_t::initial == m_status);

            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != syscall::BF_INVALID_ID);
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != syscall::BF_INVALID_ID);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);
            bsl::expects(tsc_khz.is_valid_and_checked());
            bsl::expects(tsc_khz.is_pos());
            bsl::expects(slpt_spa.is_valid_and_checked());
            bsl::expects(slpt_spa.is_pos());

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            m_xsave = mut_page_pool.allocate<page_4k_t>(tls, mut_sys);
            if (bsl::unlikely(nullptr == m_xsave)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            auto const guest_asid_val{(bsl::to_u64(vmid) + bsl::safe_u64::magic_1()).checked()};
            constexpr auto guest_asid_idx{syscall::bf_reg_t::bf_reg_t_guest_asid};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, guest_asid_idx, guest_asid_val));

            if (mut_sys.is_vs_a_root_vs(vsid)) {
                constexpr auto intercept1_val{0x00040000_u64};
                constexpr auto intercept1_idx{syscall::bf_reg_t::bf_reg_t_intercept_instruction1};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept1_idx, intercept1_val));

                constexpr auto intercept2_val{0x00000003_u64};
                constexpr auto intercept2_idx{syscall::bf_reg_t::bf_reg_t_intercept_instruction2};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept2_idx, intercept2_val));

                constexpr auto iopm_base_pa_idx{syscall::bf_reg_t::bf_reg_t_iopm_base_pa};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, iopm_base_pa_idx, gs.root_iopm_spa));

                constexpr auto msrpm_base_pa_idx{syscall::bf_reg_t::bf_reg_t_msrpm_base_pa};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, msrpm_base_pa_idx, gs.root_msrpm_spa));

                intrinsic.xsave(m_xsave);
                bsl::expects(mut_sys.bf_vs_op_init_as_root(vsid));
            }
            else {
                // constexpr auto intercept_crr_val{0xFFFF_u64};
                // constexpr auto intercept_crr_idx{syscall::bf_reg_t::bf_reg_t_intercept_cr_read};
                // bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept_crr_idx, intercept_crr_val));

                // constexpr auto intercept_crw_val{0xFFFF_u64};
                // constexpr auto intercept_crw_idx{syscall::bf_reg_t::bf_reg_t_intercept_cr_write};
                // bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept_crw_idx, intercept_crw_val));

                constexpr auto intercept_drr_val{0xFFFF_u64};
                constexpr auto intercept_drr_idx{syscall::bf_reg_t::bf_reg_t_intercept_dr_read};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept_drr_idx, intercept_drr_val));

                constexpr auto intercept_drw_val{0xFFFF_u64};
                constexpr auto intercept_drw_idx{syscall::bf_reg_t::bf_reg_t_intercept_dr_write};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept_drw_idx, intercept_drw_val));

                constexpr auto intercept1_val{0x9F24003B_u64};
                constexpr auto intercept1_idx{syscall::bf_reg_t::bf_reg_t_intercept_instruction1};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept1_idx, intercept1_val));

                constexpr auto intercept2_val{0x0000007F_u64};
                constexpr auto intercept2_idx{syscall::bf_reg_t::bf_reg_t_intercept_instruction2};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept2_idx, intercept2_val));

                constexpr auto vint_a_val{0x01000000_u64};
                constexpr auto vint_a_idx{syscall::bf_reg_t::bf_reg_t_virtual_interrupt_a};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, vint_a_idx, vint_a_val));

                constexpr auto ctls1_val{0x1_u64};
                constexpr auto ctls1_idx{syscall::bf_reg_t::bf_reg_t_ctls1};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, ctls1_idx, ctls1_val));

                constexpr auto n_cr3_idx{syscall::bf_reg_t::bf_reg_t_n_cr3};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, n_cr3_idx, slpt_spa));

                constexpr auto iopm_base_pa_idx{syscall::bf_reg_t::bf_reg_t_iopm_base_pa};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, iopm_base_pa_idx, gs.guest_iopm_spa));

                constexpr auto msrpm_base_pa_idx{syscall::bf_reg_t::bf_reg_t_msrpm_base_pa};
                bsl::expects(mut_sys.bf_vs_op_write(vsid, msrpm_base_pa_idx, gs.guest_msrpm_spa));

                this->init_as_16bit_guest(mut_sys);
            }

            m_assigned_vmid = ~vmid;
            m_assigned_vpid = ~vpid;
            m_assigned_ppid = ~ppid;
            m_tsc_khz = tsc_khz;
            m_allocated = allocated_status_t::allocated;

            if (!mut_sys.is_vs_a_root_vs(vsid)) {
                bsl::debug<bsl::V>()                             // --
                    << "vs "                                     // --
                    << bsl::grn << bsl::hex(vsid) << bsl::rst    // --
                    << " was created"                            // --
                    << bsl::endl;                                // --
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
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(this->is_active().is_invalid());

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            mut_page_pool.deallocate(tls, m_xsave);

            m_tsc_khz = {};
            m_mp_state = {};
            m_assigned_ppid = {};
            m_assigned_vpid = {};
            m_assigned_vmid = {};
            m_allocated = allocated_status_t::deallocated;
            m_status = running_status_t::initial;

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
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        set_active(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vsid);

            intrinsic.xrstr(m_xsave);

            m_active_ppid = ~bsl::to_u16(mut_tls.ppid);
            mut_tls.active_vsid = this->id();
        }

        /// <!-- description -->
        ///   @brief Sets this vs_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        set_inactive(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(this->id() == mut_tls.active_vsid);

            intrinsic.xsave(m_xsave);

            m_active_ppid = {};
            mut_tls.active_vsid = syscall::BF_INVALID_ID;
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
        ///   @brief Migrates this vs_t to the current PP. If this vs_t
        ///     is already assigned to the current PP, this function
        ///     does nothing.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        migrate(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);

            auto const ppid{mut_sys.bf_tls_ppid()};
            if (ppid == this->assigned_pp()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(mut_sys.is_vs_a_root_vs(this->id()))) {
                bsl::error() << "vs "                                            // --
                             << bsl::hex(this->id())                             // --
                             << " is a root vs and cannot be migrated to pp "    // --
                             << bsl::hex(ppid)                                   // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(running_status_t::running == m_status)) {
                bsl::error() << "vs "                               // --
                             << bsl::hex(this->id())                // --
                             << " is running on "                   // --
                             << bsl::hex(this->assigned_pp())       // --
                             << " and cannot be migrated to pp "    // --
                             << bsl::hex(ppid)                      // --
                             << bsl::endl                           // --
                             << bsl::here();                        // --

                return bsl::errc_failure;
            }

            auto const ret{mut_sys.bf_vs_op_migrate(this->id(), ppid)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_assigned_ppid = ~ppid;
            return bsl::errc_success;
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
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(mut_sys.bf_tls_ppid() == this->assigned_pp());

            auto const cr0{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_cr0)};
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

            auto const cr3{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_cr3)};
            bsl::expects(cr3.is_valid_and_checked());

            if (bsl::unlikely(cr3.is_zero())) {
                bsl::error() << "gla_to_gpa failed for gla "                // --
                             << bsl::hex(gla)                               // --
                             << " because the value of cr3 is invalid: "    // --
                             << bsl::hex(cr3)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return {};
            }

            auto const cr4{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_cr4)};
            bsl::expects(cr4.is_valid_and_checked());

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
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(mut_sys.bf_tls_ppid() == this->assigned_pp());

            if (mut_sys.is_the_active_vm_the_root_vm()) {
                return m_emulated_cpuid.get_root(mut_sys, intrinsic);
            }

            return m_emulated_cpuid.get(mut_sys, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Returns the value of the requested register
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param reg the register to get
        ///   @return Returns the value of the requested register
        ///
        [[nodiscard]] constexpr auto
        reg_get(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &reg) const noexcept
            -> bsl::safe_u64
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(sys.bf_tls_ppid() == this->assigned_pp());

            bsl::expects(reg.is_valid_and_checked());

            using mk = syscall::bf_reg_t;
            using mv = hypercall::mv_reg_t;

            switch (hypercall::to_mv_reg_t(reg)) {
                case mv::mv_reg_t_unsupported: {
                    break;
                }

                case mv::mv_reg_t_rax: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rax);
                }

                case mv::mv_reg_t_rbx: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rbx);
                }

                case mv::mv_reg_t_rcx: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rcx);
                }

                case mv::mv_reg_t_rdx: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rdx);
                }

                case mv::mv_reg_t_rbp: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rbp);
                }

                case mv::mv_reg_t_rsi: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rsi);
                }

                case mv::mv_reg_t_rdi: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rdi);
                }

                case mv::mv_reg_t_r8: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_r8);
                }

                case mv::mv_reg_t_r9: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_r9);
                }

                case mv::mv_reg_t_r10: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_r10);
                }

                case mv::mv_reg_t_r11: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_r11);
                }

                case mv::mv_reg_t_r12: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_r12);
                }

                case mv::mv_reg_t_r13: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_r13);
                }

                case mv::mv_reg_t_r14: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_r14);
                }

                case mv::mv_reg_t_r15: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_r15);
                }

                case mv::mv_reg_t_rsp: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rsp);
                }

                case mv::mv_reg_t_rip: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rip);
                }

                case mv::mv_reg_t_rflags: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_rflags);
                }

                case mv::mv_reg_t_es_selector: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_es_selector);
                }

                case mv::mv_reg_t_es_attrib: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_es_attrib);
                }

                case mv::mv_reg_t_es_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_es_limit);
                }

                case mv::mv_reg_t_es_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_es_base);
                }

                case mv::mv_reg_t_cs_selector: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cs_selector);
                }

                case mv::mv_reg_t_cs_attrib: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cs_attrib);
                }

                case mv::mv_reg_t_cs_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cs_limit);
                }

                case mv::mv_reg_t_cs_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cs_base);
                }

                case mv::mv_reg_t_ss_selector: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ss_selector);
                }

                case mv::mv_reg_t_ss_attrib: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ss_attrib);
                }

                case mv::mv_reg_t_ss_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ss_limit);
                }

                case mv::mv_reg_t_ss_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ss_base);
                }

                case mv::mv_reg_t_ds_selector: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ds_selector);
                }

                case mv::mv_reg_t_ds_attrib: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ds_attrib);
                }

                case mv::mv_reg_t_ds_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ds_limit);
                }

                case mv::mv_reg_t_ds_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ds_base);
                }

                case mv::mv_reg_t_fs_selector: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_fs_selector);
                }

                case mv::mv_reg_t_fs_attrib: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_fs_attrib);
                }

                case mv::mv_reg_t_fs_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_fs_limit);
                }

                case mv::mv_reg_t_fs_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_fs_base);
                }

                case mv::mv_reg_t_gs_selector: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_gs_selector);
                }

                case mv::mv_reg_t_gs_attrib: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_gs_attrib);
                }

                case mv::mv_reg_t_gs_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_gs_limit);
                }

                case mv::mv_reg_t_gs_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_gs_base);
                }

                case mv::mv_reg_t_ldtr_selector: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ldtr_selector);
                }

                case mv::mv_reg_t_ldtr_attrib: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ldtr_attrib);
                }

                case mv::mv_reg_t_ldtr_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ldtr_limit);
                }

                case mv::mv_reg_t_ldtr_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_ldtr_base);
                }

                case mv::mv_reg_t_tr_selector: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_tr_selector);
                }

                case mv::mv_reg_t_tr_attrib: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_tr_attrib);
                }

                case mv::mv_reg_t_tr_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_tr_limit);
                }

                case mv::mv_reg_t_tr_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_tr_base);
                }

                case mv::mv_reg_t_gdtr_selector: {
                    break;
                }

                case mv::mv_reg_t_gdtr_attrib: {
                    break;
                }

                case mv::mv_reg_t_gdtr_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_gdtr_limit);
                }

                case mv::mv_reg_t_gdtr_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_gdtr_base);
                }

                case mv::mv_reg_t_idtr_selector: {
                    break;
                }

                case mv::mv_reg_t_idtr_attrib: {
                    break;
                }

                case mv::mv_reg_t_idtr_limit: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_idtr_limit);
                }

                case mv::mv_reg_t_idtr_base: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_idtr_base);
                }

                case mv::mv_reg_t_dr0: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_dr0);
                }

                case mv::mv_reg_t_dr1: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_dr1);
                }

                case mv::mv_reg_t_dr2: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_dr2);
                }

                case mv::mv_reg_t_dr3: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_dr3);
                }

                case mv::mv_reg_t_dr6: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_dr6);
                }

                case mv::mv_reg_t_dr7: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_dr7);
                }

                case mv::mv_reg_t_cr0: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cr0);
                }

                case mv::mv_reg_t_cr2: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cr2);
                }

                case mv::mv_reg_t_cr3: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cr3);
                }

                case mv::mv_reg_t_cr4: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cr4);
                }

                case mv::mv_reg_t_cr8: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cr8);
                }

                case mv::mv_reg_t_xcr0: {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_xcr0);
                    break;
                }

                case mv::mv_reg_t_invalid:
                    [[fallthrough]];
                default: {
                    break;
                }
            }

            bsl::error() << "mv_reg_t "      // --
                         << bsl::hex(reg)    // --
                         << " is either unsupported/invalid or not yet implemented"
                         << bsl::endl       // --
                         << bsl::here();    // --

            return bsl::safe_u64::failure();
        }

        /// <!-- description -->
        ///   @brief Sets the value of the requested register
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param reg the register to set
        ///   @param val the value to set the register to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        reg_set(
            syscall::bf_syscall_t &mut_sys,
            bsl::safe_u64 const &reg,
            bsl::safe_u64 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(mut_sys.bf_tls_ppid() == this->assigned_pp());

            bsl::expects(reg.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            using mk = syscall::bf_reg_t;
            using mv = hypercall::mv_reg_t;

            switch (hypercall::to_mv_reg_t(reg)) {
                case mv::mv_reg_t_unsupported: {
                    break;
                }

                case mv::mv_reg_t_rax: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rax, val);
                }

                case mv::mv_reg_t_rbx: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rbx, val);
                }

                case mv::mv_reg_t_rcx: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rcx, val);
                }

                case mv::mv_reg_t_rdx: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rdx, val);
                }

                case mv::mv_reg_t_rbp: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rbp, val);
                }

                case mv::mv_reg_t_rsi: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rsi, val);
                }

                case mv::mv_reg_t_rdi: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rdi, val);
                }

                case mv::mv_reg_t_r8: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_r8, val);
                }

                case mv::mv_reg_t_r9: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_r9, val);
                }

                case mv::mv_reg_t_r10: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_r10, val);
                }

                case mv::mv_reg_t_r11: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_r11, val);
                }

                case mv::mv_reg_t_r12: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_r12, val);
                }

                case mv::mv_reg_t_r13: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_r13, val);
                }

                case mv::mv_reg_t_r14: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_r14, val);
                }

                case mv::mv_reg_t_r15: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_r15, val);
                }

                case mv::mv_reg_t_rsp: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rsp, val);
                }

                case mv::mv_reg_t_rip: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rip, val);
                }

                case mv::mv_reg_t_rflags: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_rflags, val);
                }

                case mv::mv_reg_t_es_selector: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_es_selector, val);
                }

                case mv::mv_reg_t_es_attrib: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_es_attrib, val);
                }

                case mv::mv_reg_t_es_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_es_limit, val);
                }

                case mv::mv_reg_t_es_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_es_base, val);
                }

                case mv::mv_reg_t_cs_selector: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cs_selector, val);
                }

                case mv::mv_reg_t_cs_attrib: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cs_attrib, val);
                }

                case mv::mv_reg_t_cs_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cs_limit, val);
                }

                case mv::mv_reg_t_cs_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cs_base, val);
                }

                case mv::mv_reg_t_ss_selector: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ss_selector, val);
                }

                case mv::mv_reg_t_ss_attrib: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ss_attrib, val);
                }

                case mv::mv_reg_t_ss_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ss_limit, val);
                }

                case mv::mv_reg_t_ss_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ss_base, val);
                }

                case mv::mv_reg_t_ds_selector: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ds_selector, val);
                }

                case mv::mv_reg_t_ds_attrib: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ds_attrib, val);
                }

                case mv::mv_reg_t_ds_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ds_limit, val);
                }

                case mv::mv_reg_t_ds_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ds_base, val);
                }

                case mv::mv_reg_t_fs_selector: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_fs_selector, val);
                }

                case mv::mv_reg_t_fs_attrib: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_fs_attrib, val);
                }

                case mv::mv_reg_t_fs_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_fs_limit, val);
                }

                case mv::mv_reg_t_fs_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_fs_base, val);
                }

                case mv::mv_reg_t_gs_selector: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_gs_selector, val);
                }

                case mv::mv_reg_t_gs_attrib: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_gs_attrib, val);
                }

                case mv::mv_reg_t_gs_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_gs_limit, val);
                }

                case mv::mv_reg_t_gs_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_gs_base, val);
                }

                case mv::mv_reg_t_ldtr_selector: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ldtr_selector, val);
                }

                case mv::mv_reg_t_ldtr_attrib: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ldtr_attrib, val);
                }

                case mv::mv_reg_t_ldtr_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ldtr_limit, val);
                }

                case mv::mv_reg_t_ldtr_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_ldtr_base, val);
                }

                case mv::mv_reg_t_tr_selector: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_tr_selector, val);
                }

                case mv::mv_reg_t_tr_attrib: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_tr_attrib, val);
                }

                case mv::mv_reg_t_tr_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_tr_limit, val);
                }

                case mv::mv_reg_t_tr_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_tr_base, val);
                }

                case mv::mv_reg_t_gdtr_selector: {
                    break;
                }

                case mv::mv_reg_t_gdtr_attrib: {
                    break;
                }

                case mv::mv_reg_t_gdtr_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_gdtr_limit, val);
                }

                case mv::mv_reg_t_gdtr_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_gdtr_base, val);
                }

                case mv::mv_reg_t_idtr_selector: {
                    break;
                }

                case mv::mv_reg_t_idtr_attrib: {
                    break;
                }

                case mv::mv_reg_t_idtr_limit: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_idtr_limit, val);
                }

                case mv::mv_reg_t_idtr_base: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_idtr_base, val);
                }

                case mv::mv_reg_t_dr0: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_dr0, val);
                }

                case mv::mv_reg_t_dr1: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_dr1, val);
                }

                case mv::mv_reg_t_dr2: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_dr2, val);
                }

                case mv::mv_reg_t_dr3: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_dr3, val);
                }

                case mv::mv_reg_t_dr6: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_dr6, val);
                }

                case mv::mv_reg_t_dr7: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_dr7, val);
                }

                case mv::mv_reg_t_cr0: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cr0, val);
                }

                case mv::mv_reg_t_cr2: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cr2, val);
                }

                case mv::mv_reg_t_cr3: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cr3, val);
                }

                case mv::mv_reg_t_cr4: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cr4, val);
                }

                case mv::mv_reg_t_cr8: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cr8, val);
                }

                case mv::mv_reg_t_xcr0: {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_xcr0, val);
                    break;
                }

                case mv::mv_reg_t_invalid:
                    [[fallthrough]];
                default: {
                    break;
                }
            }

            bsl::error() << "mv_reg_t "      // --
                         << bsl::hex(reg)    // --
                         << " is either unsupported/invalid or not yet implemented"
                         << bsl::endl       // --
                         << bsl::here();    // --

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Returns the value of the requested registers from
        ///     the provided RDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_rdl the RDL to store the requested register values
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        reg_get_list(syscall::bf_syscall_t const &sys, hypercall::mv_rdl_t &mut_rdl) const noexcept
            -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(sys.bf_tls_ppid() == this->assigned_pp());
            bsl::expects(mut_rdl.num_entries <= mut_rdl.entries.size());

            for (bsl::safe_idx mut_i{}; mut_i < mut_rdl.num_entries; ++mut_i) {
                auto const reg{bsl::to_u64(mut_rdl.entries.at_if(mut_i)->reg)};
                auto const val{this->reg_get(sys, reg)};
                if (bsl::unlikely(val.is_invalid())) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                mut_rdl.entries.at_if(mut_i)->val = val.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the value of the requested registers given
        ///     the provided RDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param rdl the RDL to get the requested register values from
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        reg_set_list(syscall::bf_syscall_t &mut_sys, hypercall::mv_rdl_t const &rdl) noexcept
            -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(mut_sys.bf_tls_ppid() == this->assigned_pp());
            bsl::expects(rdl.num_entries <= rdl.entries.size());

            for (bsl::safe_idx mut_i{}; mut_i < rdl.num_entries; ++mut_i) {
                auto const reg{bsl::to_u64(rdl.entries.at_if(mut_i)->reg)};
                auto const val{bsl::to_u64(rdl.entries.at_if(mut_i)->val)};

                auto const ret{this->reg_set(mut_sys, reg, val)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns this vs_t's FPU state in the provided "page".
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_page the shared page to store the FPU state.
        ///
        constexpr void
        fpu_get_all(syscall::bf_syscall_t const &sys, page_4k_t &mut_page) const noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(sys.bf_tls_ppid() == this->assigned_pp());

            constexpr auto fpu_size{512_umx};
            bsl::builtin_memcpy(&mut_page, m_xsave, fpu_size);
        }

        /// <!-- description -->
        ///   @brief Sets this vs_t's FPU state to the provided
        ///     contents stored in "page".
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param page the shared page containing the state to set this
        ///     vs_t's FPU state to.
        ///
        constexpr void
        fpu_set_all(syscall::bf_syscall_t const &sys, page_4k_t const &page) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(sys.bf_tls_ppid() == this->assigned_pp());

            constexpr auto fpu_size{512_umx};
            bsl::builtin_memcpy(m_xsave, &page, fpu_size);
        }

        /// <!-- description -->
        ///   @brief Returns this vs_t's multiprocessor state.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns this vs_t's multiprocessor state
        ///
        [[nodiscard]] constexpr auto
        mp_state_get() const noexcept -> hypercall::mv_mp_state_t
        {
            bsl::ensures(m_mp_state != hypercall::mv_mp_state_t::mv_mp_state_t_invalid);
            return m_mp_state;
        }

        /// <!-- description -->
        ///   @brief Sets this vs_t's multiprocessor state.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mp_state the new MP state
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        mp_state_set(
            syscall::bf_syscall_t &mut_sys, hypercall::mv_mp_state_t const mp_state) noexcept
            -> bsl::errc_type
        {
            using mp = hypercall::mv_mp_state_t;

            /// TODO:
            /// - For both UEFI and SMP, we need to handle the MP state
            ///   properly. Specifically, when a processor is put into INIT,
            ///   we need to set the guest activity state on Intel (see
            ///   Bareflank v2.1 INIT/SIPI vmexit handlers for more an
            ///   example of what to do as some of the logic is already
            ///   implemented here, but some is still missing like the
            ///   activity state).
            ///
            /// - We also need to watch for INIT/SIPI exits and make sure
            ///   that the MP state is switch automatically properly.
            ///

            switch (mp_state) {
                case mp::mv_mp_state_t_initial: {
                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_init)) {
                        bsl::error()
                            << "setting the mp state of vs_t "                          // --
                            << bsl::hex(this->id())                                     // --
                            << " to 'initial' while waiting for SIPI is unsupported"    // --
                            << bsl::endl                                                // --
                            << bsl::here();                                             // --

                        return bsl::errc_failure;
                    }

                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_sipi)) {
                        bsl::error() << "setting the mp state of vs_t "              // --
                                     << bsl::hex(this->id())                         // --
                                     << " to 'initial' after SIPI is unsupported"    // --
                                     << bsl::endl                                    // --
                                     << bsl::here();                                 // --

                        return bsl::errc_failure;
                    }

                    m_mp_state = mp_state;
                    return bsl::errc_success;
                }

                case mp::mv_mp_state_t_running: {
                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_init)) {
                        bsl::error()
                            << "setting the mp state of vs_t "                          // --
                            << bsl::hex(this->id())                                     // --
                            << " to 'running' while waiting for SIPI is unsupported"    // --
                            << bsl::endl                                                // --
                            << bsl::here();                                             // --

                        return bsl::errc_failure;
                    }

                    m_mp_state = mp_state;
                    return bsl::errc_success;
                }

                case mp::mv_mp_state_t_wait: {
                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_initial)) {
                        bsl::error() << "setting the mp state of vs_t "                // --
                                     << bsl::hex(this->id())                           // --
                                     << " to 'wait' without running is unsupported"    // --
                                     << bsl::endl                                      // --
                                     << bsl::here();                                   // --

                        return bsl::errc_failure;
                    }

                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_init)) {
                        bsl::error() << "setting the mp state of vs_t "                       // --
                                     << bsl::hex(this->id())                                  // --
                                     << " to 'wait' while waiting for SIPI is unsupported"    // --
                                     << bsl::endl                                             // --
                                     << bsl::here();                                          // --

                        return bsl::errc_failure;
                    }

                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_sipi)) {
                        bsl::error() << "setting the mp state of vs_t "           // --
                                     << bsl::hex(this->id())                      // --
                                     << " to 'wait' after SIPI is unsupported"    // --
                                     << bsl::endl                                 // --
                                     << bsl::here();                              // --

                        return bsl::errc_failure;
                    }

                    m_mp_state = mp_state;
                    return bsl::errc_success;
                }

                case mp::mv_mp_state_t_init: {
                    this->init_as_16bit_guest(mut_sys);

                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_running)) {
                        bsl::error() << "setting the mp state of vs_t "              // --
                                     << bsl::hex(this->id())                         // --
                                     << " to 'init' while running is unsupported"    // --
                                     << bsl::endl                                    // --
                                     << bsl::here();                                 // --

                        return bsl::errc_failure;
                    }

                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_wait)) {
                        bsl::error() << "setting the mp state of vs_t "              // --
                                     << bsl::hex(this->id())                         // --
                                     << " to 'init' while waiting is unsupported"    // --
                                     << bsl::endl                                    // --
                                     << bsl::here();                                 // --

                        return bsl::errc_failure;
                    }

                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_sipi)) {
                        bsl::error() << "setting the mp state of vs_t "           // --
                                     << bsl::hex(this->id())                      // --
                                     << " to 'init' after SIPI is unsupported"    // --
                                     << bsl::endl                                 // --
                                     << bsl::here();                              // --

                        return bsl::errc_failure;
                    }

                    m_mp_state = mp_state;
                    return bsl::errc_success;
                }

                case mp::mv_mp_state_t_sipi: {
                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_initial)) {
                        bsl::error() << "setting the mp state of vs_t "            // --
                                     << bsl::hex(this->id())                       // --
                                     << " to 'sipi' before INIT is unsupported"    // --
                                     << bsl::endl                                  // --
                                     << bsl::here();                               // --

                        return bsl::errc_failure;
                    }

                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_running)) {
                        bsl::error() << "setting the mp state of vs_t "              // --
                                     << bsl::hex(this->id())                         // --
                                     << " to 'sipi' while running is unsupported"    // --
                                     << bsl::endl                                    // --
                                     << bsl::here();                                 // --

                        return bsl::errc_failure;
                    }

                    if (bsl::unlikely(m_mp_state == mp::mv_mp_state_t_wait)) {
                        bsl::error() << "setting the mp state of vs_t "              // --
                                     << bsl::hex(this->id())                         // --
                                     << " to 'sipi' while waiting is unsupported"    // --
                                     << bsl::endl                                    // --
                                     << bsl::here();                                 // --

                        return bsl::errc_failure;
                    }

                    m_mp_state = mp_state;
                    return bsl::errc_success;
                }

                case mp::mv_mp_state_t_invalid:
                    [[fallthrough]];
                default: {
                    break;
                }
            }

            bsl::error() << "unsupported mp state "        // --
                         << hypercall::to_i32(mp_state)    // --
                         << bsl::endl                      // --
                         << bsl::here();                   // --

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Returns the value of the requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param msr the MSR to get
        ///   @return Returns the value of the requested MSR
        ///
        [[nodiscard]] constexpr auto
        msr_get(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &msr) const noexcept
            -> bsl::safe_u64
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(sys.bf_tls_ppid() == this->assigned_pp());

            bsl::expects(msr.is_valid_and_checked());

            using mk = syscall::bf_reg_t;

            bsl::safe_u64 mut_ret{};

            switch (bsl::to_u32_unsafe(msr).get()) {
                case MSR_PAT.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_pat);
                }
                case MSR_SYSENTER_CS.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_sysenter_cs);
                }
                case MSR_SYSENTER_ESP.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_sysenter_esp);
                }
                case MSR_SYSENTER_EIP.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_sysenter_eip);
                }
                case MSR_EFER.get(): {
                    constexpr auto svme_mask{0x1000_u64};
                    mut_ret = sys.bf_vs_op_read(this->id(), mk::bf_reg_t_efer);
                    return (mut_ret & ~(svme_mask));
                }
                case MSR_STAR.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_star);
                }
                case MSR_LSTAR.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_lstar);
                }
                case MSR_CSTAR.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_cstar);
                }
                case MSR_FMASK.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_fmask);
                }
                case MSR_FS_BASE.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_fs_base);
                }
                case MSR_GS_BASE.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_gs_base);
                }
                case MSR_KERNEL_GS_BASE.get(): {
                    return sys.bf_vs_op_read(this->id(), mk::bf_reg_t_kernel_gs_base);
                }

                case MSR_APIC_BASE.get(): {
                    return m_emulated_lapic.get_apic_base();
                }

                default: {
                    break;
                }
            }

            mut_ret = m_emulated_msr.get(sys, msr);

            if (bsl::unlikely(!mut_ret.is_valid_and_checked())) {
                bsl::error() << "MSR "           // --
                             << bsl::hex(msr)    // --
                             << " is either unsupported/invalid or not yet implemented"
                             << bsl::endl       // --
                             << bsl::here();    // --
            }
            else {
                bsl::touch();
            }

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Sets the value of the requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param msr the MSR to set
        ///   @param val the value to set the MSR to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        msr_set(
            syscall::bf_syscall_t &mut_sys,
            bsl::safe_u64 const &msr,
            bsl::safe_u64 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(mut_sys.bf_tls_ppid() == this->assigned_pp());

            bsl::expects(msr.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            using mk = syscall::bf_reg_t;

            bsl::errc_type mut_ret{};

            switch (bsl::to_u32_unsafe(msr).get()) {
                case MSR_PAT.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_pat, val);
                }
                case MSR_SYSENTER_CS.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_sysenter_cs, val);
                }
                case MSR_SYSENTER_ESP.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_sysenter_esp, val);
                }
                case MSR_SYSENTER_EIP.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_sysenter_eip, val);
                }
                case MSR_EFER.get(): {
                    constexpr auto svme_mask{0x1000_u64};
                    if (bsl::unlikely((val & svme_mask).is_pos())) {
                        bsl::error() << "MSR EFER: SVME should not be set"    // --
                                     << bsl::endl                             // --
                                     << bsl::here();                          // --
                        return bsl::errc_failure;
                    }
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_efer, val | svme_mask);
                }
                case MSR_STAR.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_star, val);
                }
                case MSR_LSTAR.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_lstar, val);
                }
                case MSR_CSTAR.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_cstar, val);
                }
                case MSR_FMASK.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_fmask, val);
                }
                case MSR_FS_BASE.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_fs_base, val);
                }
                case MSR_GS_BASE.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_gs_base, val);
                }
                case MSR_KERNEL_GS_BASE.get(): {
                    return mut_sys.bf_vs_op_write(this->id(), mk::bf_reg_t_kernel_gs_base, val);
                }

                case MSR_APIC_BASE.get(): {
                    m_emulated_lapic.set_apic_base(val);
                    return bsl::errc_success;
                }

                default: {
                    break;
                }
            }

            mut_ret = m_emulated_msr.set(mut_sys, msr, val);

            if (bsl::unlikely(!mut_ret)) {
                bsl::error() << "MSR "           // --
                             << bsl::hex(msr)    // --
                             << " is either unsupported/invalid or not yet implemented"
                             << bsl::endl       // --
                             << bsl::here();    // --
            }
            else {
                bsl::touch();
            }

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Returns the value of the requested MSRs from
        ///     the provided RDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_rdl the RDL to store the requested MSR values
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        msr_get_list(syscall::bf_syscall_t const &sys, hypercall::mv_rdl_t &mut_rdl) const noexcept
            -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(sys.bf_tls_ppid() == this->assigned_pp());
            bsl::expects(mut_rdl.num_entries <= mut_rdl.entries.size());

            for (bsl::safe_idx mut_i{}; mut_i < mut_rdl.num_entries; ++mut_i) {
                auto const msr{bsl::to_u64(mut_rdl.entries.at_if(mut_i)->reg)};
                auto const val{this->msr_get(sys, msr)};
                if (bsl::unlikely(val.is_invalid())) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                mut_rdl.entries.at_if(mut_i)->val = val.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the value of the requested MSRs given
        ///     the provided RDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param rdl the RDL to get the requested MSR values from
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        msr_set_list(syscall::bf_syscall_t &mut_sys, hypercall::mv_rdl_t const &rdl) noexcept
            -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(mut_sys.bf_tls_ppid() == this->assigned_pp());
            bsl::expects(rdl.num_entries <= rdl.entries.size());

            for (bsl::safe_idx mut_i{}; mut_i < rdl.num_entries; ++mut_i) {
                auto const msr{bsl::to_u64(rdl.entries.at_if(mut_i)->reg)};
                auto const val{bsl::to_u64(rdl.entries.at_if(mut_i)->val)};

                auto const ret{this->msr_set(mut_sys, msr, val)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Injects an exception into the vs_t. Unlike interrupts,
        ///     exceptions cannot be masked, and therefore, the exception is
        ///     immediately injected.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param vector the vector to inject
        ///   @param ec the error code to inject
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        inject_exception(
            syscall::bf_syscall_t &mut_sys,
            bsl::safe_u64 const &vector,
            bsl::safe_u64 const &ec) noexcept -> bsl::errc_type
        {
            constexpr auto idx{syscall::bf_reg_t::bf_reg_t_eventinj};

            constexpr auto vector_mask{0xFF_u64};
            constexpr auto divide_by_zero_error{0x80000300_u64};
            constexpr auto debug{0x80000301_u64};
            constexpr auto nmi{0x80000202_u64};
            constexpr auto breakpoint{0x80000303_u64};
            constexpr auto overflow{0x80000304_u64};
            constexpr auto bound_range{0x80000305_u64};
            constexpr auto invalid_opcode{0x80000306_u64};
            constexpr auto device_not_available{0x80000307_u64};
            constexpr auto double_fault{0x80000B08_u64};
            constexpr auto invalid_tss{0x80000B0A_u64};
            constexpr auto segment_not_present{0x80000B0B_u64};
            constexpr auto stack{0x80000B0C_u64};
            constexpr auto general_protection{0x80000B0D_u64};
            constexpr auto page_fault{0x80000B0E_u64};
            constexpr auto floating_point{0x80000310_u64};
            constexpr auto alignment_check{0x80000B11_u64};
            constexpr auto machine_check{0x80000312_u64};
            constexpr auto simd{0x80000313_u64};

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(mut_sys.bf_tls_ppid() == this->assigned_pp());
            bsl::expects(vector.is_valid_and_checked());

            constexpr auto ec_shift{32_u64};
            auto mut_ec{ec << ec_shift};

            auto const val{mut_sys.bf_vs_op_read(this->id(), idx)};
            bsl::expects(val.is_valid_and_checked());

            if (val.is_pos()) {
                if (val == double_fault) {
                    bsl::error() << "inject_exception called with existing double fault"    // --
                                 << bsl::endl                                               // --
                                 << bsl::here();                                            // --

                    return vmexit_failure_triple_fault;
                }

                return mut_sys.bf_vs_op_write(this->id(), idx, double_fault);
            }

            switch (vector.get()) {
                case (divide_by_zero_error & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, divide_by_zero_error);
                }

                case (debug & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, debug);
                }

                case (nmi & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, nmi);
                }

                case (breakpoint & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, breakpoint);
                }

                case (overflow & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, overflow);
                }

                case (bound_range & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, bound_range);
                }

                case (invalid_opcode & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, invalid_opcode);
                }

                case (device_not_available & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, device_not_available);
                }

                case (double_fault & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, mut_ec | double_fault);
                }

                case (invalid_tss & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, mut_ec | invalid_tss);
                }

                case (segment_not_present & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, mut_ec | segment_not_present);
                }

                case (stack & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, mut_ec | stack);
                }

                case (general_protection & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, mut_ec | general_protection);
                }

                case (page_fault & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, mut_ec | page_fault);
                }

                case (floating_point & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, floating_point);
                }

                case (alignment_check & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, mut_ec | alignment_check);
                }

                case (machine_check & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, machine_check);
                }

                case (simd & vector_mask).get(): {
                    return mut_sys.bf_vs_op_write(this->id(), idx, simd);
                }

                default: {
                    break;
                }
            }

            bsl::error() << "unknown/unsupported exception vector " << vector << bsl::endl
                         << bsl::here();

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Injects an NMI into this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        inject_nmi(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
        {
            /// TODO:
            /// - AMD does not have an NMI window VMExit. What this means is
            ///   that we need to handle the case where we need to inject
            ///   an NMI into the root VM when the root VM is already handling
            ///   an NMI. To do that, you need to trap on IRET, and inject
            ///   once we see an IRET. So, the task here is simply detect if
            ///   the root VM is already handling an NMI, and then inject
            ///   the NMI after we see the next IRET. Once we do, turn IRET
            ///   trapping off and inject.
            ///
            /// - Now..., in theory this should work, but it is not really
            ///   the right thing to do. The IRET trap occurs BEFORE the IRET
            ///   completes. What this means is that RIP is just before IRET
            ///   and not after. So technically, the NMI is not open yet, and
            ///   we really should inject the NMI AFTER the IRET completes.
            ///   You could single step the IRET, but that is extremely hard
            ///   to do. Or, we inject on IRET and cross our fingers. In
            ///   theory, this should work, because we would be placing the
            ///   RIP back at the beginning of the NMI handler in the root
            ///   VM, and the NMI window remains closed. It will complete and
            ///   run IRET, but this one will not trap, and will complete,
            ///   which will open the window again. So, although this is not
            ///   what hardware does, in theory, it should work fine.
            ///
            /// - There is a not that NMIs injected do NOT block future NMIs.
            ///   This might require that we trap on NMIs in the root VM,
            ///   as well, just so that we can use the logic above to ensure
            ///   that the NMI blocking bit is preserved.
            ///

            constexpr auto nmi{2_u64};
            return this->inject_exception(mut_sys, nmi, {});
        }

        /// <!-- description -->
        ///   @brief Injects an GPF into this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        inject_gpf(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
        {
            constexpr auto gpf{13_u64};
            return this->inject_exception(mut_sys, gpf, {});
        }

        /// <!-- description -->
        ///   @brief Queues an interrupt for injection when this vs_t is
        ///     capable of injecting interrupts. If the queue is full, this
        ///     function will fail.
        ///
        /// <!-- notes -->
        ///   @note You can only queue an interrupt for a vs_t that is assigned
        ///     to the current PP. This means that one vs_t cannot queue an
        ///     interrupt for another vs_t. Instead, you need to IPI the other
        ///     PP, and queue the interrupt into the vs_t from the PP the vs_t
        ///     is assigned to. This is done to ensure that not only is there
        ///     no need for a lock on the queue, but more importantly, on Intel
        ///     you cannot actually do interrupt/exception queuing on a vs_t
        ///     on a remote PP as such an action is undefined by Intel, and
        ///     we should not be migrating a vs_t to our current PP every time
        ///     that we need to inject an interrupt.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param vector the vector to queue
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        queue_interrupt(syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &vector) noexcept
            -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(mut_sys.bf_tls_ppid() == this->assigned_pp());
            bsl::expects(vector.is_valid_and_checked());

            constexpr auto vint_a_val{0x000000FF010F0100_u64};
            constexpr auto vint_a_idx{syscall::bf_reg_t::bf_reg_t_virtual_interrupt_a};
            bsl::expects(mut_sys.bf_vs_op_write(this->id(), vint_a_idx, vint_a_val));

            return m_interrupt_queue.push(vector);
        }

        /// <!-- description -->
        ///   @brief Returns this vs_t's TSC frequency in KHz.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns this vs_t's TSC frequency in KHz.
        ///
        [[nodiscard]] constexpr auto
        tsc_khz_get() const noexcept -> bsl::safe_u64
        {
            bsl::ensures(m_tsc_khz.is_valid_and_checked());
            bsl::ensures(m_tsc_khz.is_pos());
            return m_tsc_khz;
        }
    };
}

#endif
