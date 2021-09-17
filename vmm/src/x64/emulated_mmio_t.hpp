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

            constexpr auto max_gpa{bsl::to_umx(0x8000000000U)};
            constexpr auto gpa_inc{bsl::to_idx(PAGE_2M_T_SIZE)};

            if (mut_sys.is_vm_the_root_vm(this->assigned_vmid())) {
                for (bsl::safe_idx mut_i{}; mut_i < max_gpa; mut_i += gpa_inc) {
                    auto const spa{bsl::to_umx(mut_i)};
                    auto const gpa{bsl::to_umx(mut_i)};

                    mut_ret = m_slpt.map_page<l1e_t>(
                        tls, mut_page_pool, gpa, spa, MAP_PAGE_RWE, false, mut_sys);
                    if (bsl::unlikely(!mut_ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return mut_ret;
                    }

                    bsl::touch();
                }
            }
            else {
                bsl::touch();
            }

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
        slpt_spa() const noexcept -> bsl::safe_umx
        {
            return m_slpt.phys();
        }

        /// <!-- description -->
        ///   @brief Maps memory into the VM using instructions from the
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

                auto const gpa{bsl::to_umx(entry->dst)};
                auto const spa{this->gpa_to_spa(mut_sys, bsl::to_umx(entry->src))};

                /// TODO:
                /// - Add support for entries that have a size greater than
                ///   4k. For now we only support 4k pages.
                /// - Add support for the flags field. For now, everything
                ///   is mapped as RWE.
                ///

                auto const ret{
                    m_slpt.map_page(tls, mut_page_pool, gpa, spa, MAP_PAGE_RWE, false, mut_sys)};

                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
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
            bsl::discard(sys);

            return gpa;
        }
    };
}

#endif
