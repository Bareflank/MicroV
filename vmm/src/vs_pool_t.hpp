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

#ifndef VS_POOL_T_HPP
#define VS_POOL_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <lock_guard_t.hpp>
#include <mv_exit_reason_t.hpp>
#include <mv_run_t.hpp>
#include <page_pool_t.hpp>
#include <pp_pool_t.hpp>
#include <running_status_t.hpp>
#include <spinlock_t.hpp>
#include <tls_t.hpp>
#include <vs_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::vs_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's VS pool
    ///
    class vs_pool_t final
    {
        /// @brief stores the pool of vs_t objects
        bsl::array<vs_t, HYPERVISOR_MAX_VSS.get()> m_pool{};
        /// @brief safe guards operations on the pool.
        mutable spinlock_t m_lock{};

        /// <!-- description -->
        ///   @brief Returns the vs_t associated with the provided vsid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to get
        ///   @return Returns the vs_t associated with the provided vsid.
        ///
        [[nodiscard]] constexpr auto
        get_vs(bsl::safe_u16 const &vsid) noexcept -> vs_t *
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vsid));
        }

        /// <!-- description -->
        ///   @brief Returns the vs_t associated with the provided vsid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to get
        ///   @return Returns the vs_t associated with the provided vsid.
        ///
        [[nodiscard]] constexpr auto
        get_vs(bsl::safe_u16 const &vsid) const noexcept -> vs_t const *
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vsid));
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vs_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            for (bsl::safe_idx mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                m_pool.at_if(mut_i)->initialize(gs, tls, sys, intrinsic, bsl::to_u16(mut_i));
            }
        }

        /// <!-- description -->
        ///   @brief Release the vs_pool_t.
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
            for (auto &mut_vs : m_pool) {
                mut_vs.release(gs, tls, sys, mut_page_pool, intrinsic);
            }
        }

        /// <!-- description -->
        ///   @brief Allocates a VS and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the newly created vs_t to
        ///   @param vpid the ID of the VP to assign the newly created vs_t to
        ///   @param ppid the ID of the PP to assign the newly created vs_t to
        ///   @param tsc_khz the starting TSC frequency of the newly created vs_t
        ///   @param slpt_spa the system physical address of the second level
        ///     page tables to use.
        ///   @return Returns ID of the newly allocated vs_t. Returns
        ///     bsl::safe_u16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
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
            lock_guard_t mut_lock{tls, m_lock};

            auto const vsid{mut_sys.bf_vs_op_create_vs(vpid, ppid)};
            if (bsl::unlikely(vsid.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            return this->get_vs(vsid)->allocate(
                gs, tls, mut_sys, mut_page_pool, intrinsic, vmid, vpid, ppid, tsc_khz, slpt_spa);
        }

        /// <!-- description -->
        ///   @brief Deallocates the requested vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to deallocate
        ///
        constexpr void
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            page_pool_t &mut_page_pool,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) noexcept
        {
            lock_guard_t mut_lock{tls, m_lock};

            auto *const pmut_vs{this->get_vs(vsid)};
            if (pmut_vs->is_allocated()) {
                bsl::expects(mut_sys.bf_vs_op_destroy_vs(vsid));
                pmut_vs->deallocate(gs, tls, mut_sys, mut_page_pool, intrinsic);
            }
            else {
                bsl::touch();
            }
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vs_t is allocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns true if the requested vs_t is allocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated(bsl::safe_u16 const &vsid) const noexcept -> bool
        {
            return this->get_vs(vsid)->is_allocated();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vs_t is deallocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns true if the requested vs_t is deallocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated(bsl::safe_u16 const &vsid) const noexcept -> bool
        {
            return this->get_vs(vsid)->is_deallocated();
        }

        /// <!-- description -->
        ///   @brief Sets the requested vs_t as active
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to set as active
        ///
        constexpr void
        set_active(tls_t &mut_tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vsid) noexcept
        {
            this->get_vs(vsid)->set_active(mut_tls, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Sets the requested vs_t as inactive
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to set as inactive
        ///
        constexpr void
        set_inactive(
            tls_t &mut_tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vsid) noexcept
        {
            if (bsl::unlikely(vsid == syscall::BF_INVALID_ID)) {
                return;
            }

            this->get_vs(vsid)->set_inactive(mut_tls, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP the requested vs_t is active on.
        ///     If the vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the ID of the PP the requested vs_t is active on.
        ///     If the vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        [[nodiscard]] constexpr auto
        is_active(bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u16
        {
            return this->get_vs(vsid)->is_active();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vs_t is active on the
        ///     current PP, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns true if the requested vs_t is active on the
        ///     current PP, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_this_pp(tls_t const &tls, bsl::safe_u16 const &vsid) const noexcept -> bool
        {
            return this->get_vs(vsid)->is_active_on_this_pp(tls);
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM the requested vs_t is assigned
        ///     to. If the vs_t is not assigned, syscall::BF_INVALID_ID is
        ///     returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the ID of the VM the requested vs_t is assigned
        ///     to. If the vs_t is not assigned, syscall::BF_INVALID_ID is
        ///     returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vm(bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u16
        {
            return this->get_vs(vsid)->assigned_vm();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP the requested vs_t is assigned
        ///     to. If the vs_t is not assigned, syscall::BF_INVALID_ID is
        ///     returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the ID of the VP the requested vs_t is assigned
        ///     to. If the vs_t is not assigned, syscall::BF_INVALID_ID is
        ///     returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vp(bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u16
        {
            return this->get_vs(vsid)->assigned_vp();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP the requested vs_t is assigned
        ///     to. If the vs_t is not assigned, syscall::BF_INVALID_ID is
        ///     returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the ID of the PP the requested vs_t is assigned
        ///     to. If the vs_t is not assigned, syscall::BF_INVALID_ID is
        ///     returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_pp(bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u16
        {
            return this->get_vs(vsid)->assigned_pp();
        }

        /// <!-- description -->
        ///   @brief If the requested VP is assigned to a vs_t in the pool,
        ///     the ID of the first vs_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID fo the VP to query
        ///   @return If the requested VP is assigned to a vs_t in the pool,
        ///     the ID of the first vs_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        [[nodiscard]] constexpr auto
        vs_assigned_to_vp(bsl::safe_u16 const &vpid) const noexcept -> bsl::safe_u16
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != syscall::BF_INVALID_ID);

            for (auto const &vs : m_pool) {
                if (vs.assigned_vp() == vpid) {
                    return vs.id();
                }

                bsl::touch();
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Migrates the requested vs_t to the current PP. If the
        ///     requested vs_t is already assigned to the current PP, this
        ///     function does nothing.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param vsid the ID of the vs_t to migrate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        migrate(syscall::bf_syscall_t &mut_sys, bsl::safe_u16 const &vsid) noexcept
            -> bsl::errc_type
        {
            return this->get_vs(vsid)->migrate(mut_sys);
        }

        /// <!-- description -->
        ///   @brief Translates a GLA to a GPA using the paging configuration
        ///     of the requested vs_t stored in CR0, CR3 and CR4.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_pp_pool the pp_pool_t to use
        ///   @param gla the GLA to translate to a GPA
        ///   @param vsid the ID of the vs_t to use to translate the GLA
        ///   @return Returns mv_translation_t containing the results of the
        ///     translation.
        ///
        [[nodiscard]] constexpr auto
        gla_to_gpa(
            syscall::bf_syscall_t &mut_sys,
            pp_pool_t &mut_pp_pool,
            bsl::safe_u64 const &gla,
            bsl::safe_u16 const &vsid) const noexcept -> hypercall::mv_translation_t
        {
            return this->get_vs(vsid)->gla_to_gpa(mut_sys, mut_pp_pool, gla);
        }

        /// <!-- description -->
        ///   @brief Reads CPUID for the requested vs_t and returns the results
        ///     in the appropriate bf_syscall_t TLS registers.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        cpuid_get(
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) const noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->cpuid_get(mut_sys, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Returns the value of the requested register
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param reg the register to get
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the value of the requested register
        ///
        [[nodiscard]] constexpr auto
        reg_get(
            syscall::bf_syscall_t const &sys,
            bsl::safe_u64 const &reg,
            bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u64
        {
            return this->get_vs(vsid)->reg_get(sys, reg);
        }

        /// <!-- description -->
        ///   @brief Sets the value of the requested register
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param reg the register to set
        ///   @param val the value to set the register to
        ///   @param vsid the ID of the vs_t to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        reg_set(
            syscall::bf_syscall_t &mut_sys,
            bsl::safe_u64 const &reg,
            bsl::safe_u64 const &val,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->reg_set(mut_sys, reg, val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of the requested registers from
        ///     the provided RDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_rdl the RDL to store the requested register values
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        reg_get_list(
            syscall::bf_syscall_t const &sys,
            hypercall::mv_rdl_t &mut_rdl,
            bsl::safe_u16 const &vsid) const noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->reg_get_list(sys, mut_rdl);
        }

        /// <!-- description -->
        ///   @brief Sets the value of the requested registers given
        ///     the provided RDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param rdl the RDL to get the requested register values from
        ///   @param vsid the ID of the vs_t to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        reg_set_list(
            syscall::bf_syscall_t &mut_sys,
            hypercall::mv_rdl_t const &rdl,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->reg_set_list(mut_sys, rdl);
        }

        /// <!-- description -->
        ///   @brief Returns the requested vs_t's FPU state in the provided
        ///     "page".
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_page the shared page to store the FPU state.
        ///   @param vsid the ID of the vs_t to query
        ///
        constexpr void
        fpu_get_all(
            syscall::bf_syscall_t const &sys,
            page_4k_t &mut_page,
            bsl::safe_u16 const &vsid) const noexcept
        {
            this->get_vs(vsid)->fpu_get_all(sys, mut_page);
        }

        /// <!-- description -->
        ///   @brief Sets the requested vs_t's FPU state to the provided
        ///     contents stored in "page".
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param page the shared page containing the state to set the
        ///     requested vs_t's FPU state to.
        ///   @param vsid the ID of the vs_t to set
        ///
        constexpr void
        fpu_set_all(
            syscall::bf_syscall_t const &sys,
            page_4k_t const &page,
            bsl::safe_u16 const &vsid) noexcept
        {
            this->get_vs(vsid)->fpu_set_all(sys, page);
        }

        /// <!-- description -->
        ///   @brief Returns the requested vs_t's multiprocessor state.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the requested vs_t's multiprocessor state
        ///
        [[nodiscard]] constexpr auto
        mp_state_get(bsl::safe_u16 const &vsid) const noexcept -> hypercall::mv_mp_state_t
        {
            return this->get_vs(vsid)->mp_state_get();
        }

        /// <!-- description -->
        ///   @brief Sets the requested vs_t's multiprocessor state.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mp_state the new MP state
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        mp_state_set(
            syscall::bf_syscall_t &mut_sys,
            hypercall::mv_mp_state_t const mp_state,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->mp_state_set(mut_sys, mp_state);
        }

        /// <!-- description -->
        ///   @brief Returns the value of the requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param msr the MSR to get
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the value of the requested MSR
        ///
        [[nodiscard]] constexpr auto
        msr_get(
            syscall::bf_syscall_t const &sys,
            bsl::safe_u64 const &msr,
            bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u64
        {
            return this->get_vs(vsid)->msr_get(sys, msr);
        }

        /// <!-- description -->
        ///   @brief Sets the value of the requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param msr the MSR to set
        ///   @param val the value to set the MSR to
        ///   @param vsid the ID of the vs_t to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        msr_set(
            syscall::bf_syscall_t &mut_sys,
            bsl::safe_u64 const &msr,
            bsl::safe_u64 const &val,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->msr_set(mut_sys, msr, val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of the requested MSRs from
        ///     the provided RDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_rdl the RDL to store the requested MSR values
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        msr_get_list(
            syscall::bf_syscall_t const &sys,
            hypercall::mv_rdl_t &mut_rdl,
            bsl::safe_u16 const &vsid) const noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->msr_get_list(sys, mut_rdl);
        }

        /// <!-- description -->
        ///   @brief Sets the value of the requested MSRs given
        ///     the provided RDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param rdl the RDL to get the requested MSR values from
        ///   @param vsid the ID of the vs_t to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        msr_set_list(
            syscall::bf_syscall_t &mut_sys,
            hypercall::mv_rdl_t const &rdl,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->msr_set_list(mut_sys, rdl);
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
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        inject_exception(
            syscall::bf_syscall_t &mut_sys,
            bsl::safe_u64 const &vector,
            bsl::safe_u64 const &ec,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->inject_exception(mut_sys, vector, ec);
        }

        /// <!-- description -->
        ///   @brief Injects an NMI into this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        inject_nmi(syscall::bf_syscall_t &mut_sys, bsl::safe_u16 const &vsid) noexcept
            -> bsl::errc_type
        {
            return this->get_vs(vsid)->inject_nmi(mut_sys);
        }

        /// <!-- description -->
        ///   @brief Injects an GPF into this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        inject_gpf(syscall::bf_syscall_t &mut_sys, bsl::safe_u16 const &vsid) noexcept
            -> bsl::errc_type
        {
            return this->get_vs(vsid)->inject_gpf(mut_sys);
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
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        queue_interrupt(
            syscall::bf_syscall_t &mut_sys,
            bsl::safe_u64 const &vector,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->queue_interrupt(mut_sys, vector);
        }

        /// <!-- description -->
        ///   @brief Returns the requested vs_t's TSC frequency in KHz.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the requested vs_t's TSC frequency in KHz.
        ///
        [[nodiscard]] constexpr auto
        tsc_khz_get(bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u64
        {
            return this->get_vs(vsid)->tsc_khz_get();
        }
    };
}

#endif
