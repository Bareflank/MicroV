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
#include <emulated_msr_t.hpp>
#include <emulated_tlb_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_rdl_t.hpp>
#include <mv_reg_t.hpp>
#include <mv_translation_t.hpp>
#include <page_pool_t.hpp>
#include <pp_pool_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
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
        ///   @param page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            page_pool_t const &page_pool,
            intrinsic_t const &intrinsic) noexcept
        {
            this->deallocate(gs, tls, sys, page_pool, intrinsic);

            m_emulated_tlb.release(gs, tls, sys, intrinsic);
            m_emulated_msr.release(gs, tls, sys, intrinsic);
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
        ///   @param page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the vs_t to
        ///   @param vpid the ID of the VP to assign the vs_t to
        ///   @param ppid the ID of the PP to assign the vs_t to
        ///   @param slpt_spa the system physical address of the second level
        ///     page tables to use.
        ///   @return Returns ID of this vs_t
        ///
        [[maybe_unused]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            page_pool_t const &page_pool,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid,
            bsl::safe_umx const &slpt_spa) noexcept -> bsl::safe_u16
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
            bsl::discard(page_pool);
            bsl::discard(intrinsic);

            auto const vsid{this->id()};
            if (mut_sys.is_vs_a_root_vs(vsid)) {
                bsl::expects(mut_sys.bf_vs_op_init_as_root(vsid));
            }
            else {
                bsl::touch();
            }

            auto const guest_asid_val{(bsl::to_u64(vmid) + bsl::safe_u64::magic_1()).checked()};
            constexpr auto guest_asid_idx{syscall::bf_reg_t::bf_reg_t_guest_asid};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, guest_asid_idx, guest_asid_val));

            constexpr auto intercept1_val{0x00040000_u64};
            constexpr auto intercept1_idx{syscall::bf_reg_t::bf_reg_t_intercept_instruction1};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept1_idx, intercept1_val));

            constexpr auto intercept2_val{0x00000003_u64};
            constexpr auto intercept2_idx{syscall::bf_reg_t::bf_reg_t_intercept_instruction2};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, intercept2_idx, intercept2_val));

            constexpr auto ctls1_val{0x1_u64};
            constexpr auto ctls1_idx{syscall::bf_reg_t::bf_reg_t_ctls1};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, ctls1_idx, ctls1_val));

            constexpr auto n_cr3_idx{syscall::bf_reg_t::bf_reg_t_n_cr3};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, n_cr3_idx, slpt_spa));

            m_assigned_vmid = ~vmid;
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
        ///   @param page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            page_pool_t const &page_pool,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::expects(this->is_active().is_invalid());

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(page_pool);
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
        ///   @brief Returns the value of the requested register
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param reg the register to get
        ///   @return Returns the value of the requested register
        ///
        [[nodiscard]] constexpr auto
        get(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &reg) const noexcept
            -> bsl::safe_u64
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(sys.bf_tls_ppid() == this->assigned_pp());

            bsl::expects(reg.is_valid_and_checked());

            using mk = syscall::bf_reg_t;
            using mv = hypercall::mv_reg_t;

            switch (static_cast<hypercall::mv_reg_t>(reg.get())) {
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
                    break;
                }

                case mv::mv_reg_t_dr1: {
                    break;
                }

                case mv::mv_reg_t_dr2: {
                    break;
                }

                case mv::mv_reg_t_dr3: {
                    break;
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
                    break;
                }

                case mv::mv_reg_t_xcr0: {
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
        set(syscall::bf_syscall_t &mut_sys,
            bsl::safe_u64 const &reg,
            bsl::safe_u64 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(mut_sys.bf_tls_ppid() == this->assigned_pp());

            bsl::expects(reg.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            using mk = syscall::bf_reg_t;
            using mv = hypercall::mv_reg_t;

            switch (static_cast<hypercall::mv_reg_t>(reg.get())) {
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
                    break;
                }

                case mv::mv_reg_t_dr1: {
                    break;
                }

                case mv::mv_reg_t_dr2: {
                    break;
                }

                case mv::mv_reg_t_dr3: {
                    break;
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
                    break;
                }

                case mv::mv_reg_t_xcr0: {
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
        get_list(syscall::bf_syscall_t const &sys, hypercall::mv_rdl_t &mut_rdl) const noexcept
            -> bsl::errc_type
        {
            bsl::expects(mut_rdl.num_entries <= mut_rdl.entries.size());

            for (bsl::safe_idx mut_i{}; mut_i < mut_rdl.num_entries; ++mut_i) {
                auto const reg{bsl::to_u64(mut_rdl.entries.at_if(mut_i)->reg)};
                auto const val{this->get(sys, reg)};
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
        set_list(syscall::bf_syscall_t &mut_sys, hypercall::mv_rdl_t const &rdl) noexcept
            -> bsl::errc_type
        {
            bsl::expects(rdl.num_entries <= rdl.entries.size());

            for (bsl::safe_idx mut_i{}; mut_i < rdl.num_entries; ++mut_i) {
                auto const reg{bsl::to_u64(rdl.entries.at_if(mut_i)->reg)};
                auto const val{bsl::to_u64(rdl.entries.at_if(mut_i)->val)};

                auto const ret{this->set(mut_sys, reg, val)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
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

            auto const cr4{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_cr4)};
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
