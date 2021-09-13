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

#ifndef VP_T_HPP
#define VP_T_HPP

#include <allocated_status_t.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/ensures.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>

namespace microv
{
    /// @class microv::vp_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's notion of a VP
    ///
    class vp_t final
    {
        /// @brief stores the ID associated with this vp_t
        bsl::safe_u16 m_id{};
        /// @brief stores whether or not this vp_t is allocated.
        allocated_status_t m_allocated{};
        /// @brief stores the ID of the VM this vp_t is assigned to
        bsl::safe_u16 m_assigned_vmid{};
        /// @brief stores the ID of the PP this vp_t is assigned to
        bsl::safe_u16 m_assigned_ppid{};
        /// @brief stores the ID of the PP this vp_t is active on
        bsl::safe_u16 m_active_ppid{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param i the ID for this vp_t
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

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_id = ~i;
        }

        /// <!-- description -->
        ///   @brief Release the vp_t.
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
            m_id = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vp_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_id.is_valid_and_checked());
            return ~m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates the vp_t and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the vp_t to
        ///   @param ppid the ID of the PP to assign the vp_t to
        ///   @return Returns ID of this vp_t
        ///
        [[maybe_unused]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::safe_u16
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            bsl::expects(allocated_status_t::deallocated == m_allocated);

            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != syscall::BF_INVALID_ID);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            m_assigned_vmid = ~vmid;
            m_assigned_ppid = ~ppid;
            m_allocated = allocated_status_t::allocated;

            if (!sys.is_vp_a_root_vp(this->id())) {
                bsl::debug<bsl::V>()                                   // --
                    << "vp "                                           // --
                    << bsl::grn << bsl::hex(this->id()) << bsl::rst    // --
                    << " was created"                                  // --
                    << bsl::endl;                                      // --
            }
            else {
                bsl::touch();
            }

            return this->id();
        }

        /// <!-- description -->
        ///   @brief Deallocates the vp_t
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
            m_assigned_vmid = {};
            m_allocated = allocated_status_t::deallocated;

            if (!sys.is_vp_a_root_vp(this->id())) {
                bsl::debug<bsl::V>()                                   // --
                    << "vp "                                           // --
                    << bsl::red << bsl::hex(this->id()) << bsl::rst    // --
                    << " was destroyed"                                // --
                    << bsl::endl;                                      // --
            }
            else {
                bsl::touch();
            }
        }

        /// <!-- description -->
        ///   @brief Returns true if this vp_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vp_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vp_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vp_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Sets this vp_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        set_active(tls_t &mut_tls) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vpid);

            m_active_ppid = ~bsl::to_u16(mut_tls.ppid);
            mut_tls.active_vpid = this->id().get();
        }

        /// <!-- description -->
        ///   @brief Sets this vp_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        set_inactive(tls_t &mut_tls) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(this->id() == mut_tls.active_vpid);

            m_active_ppid = {};
            mut_tls.active_vpid = syscall::BF_INVALID_ID.get();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vp_t is active on. If the
        ///     vp_t is not active, bsl::safe_u16::failure() is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vp_t is active on. If the
        ///     vp_t is not active, bsl::safe_u16::failure() is returned.
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
        ///   @brief Returns true if this vp_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vp_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_this_pp(tls_t const &tls) const noexcept -> bool
        {
            return tls.ppid == ~m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM this vp_t is assigned to. If
        ///     this vp_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VM this vp_t is assigned to. If
        ///     this vp_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vm() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vmid.is_valid_and_checked());
            return ~m_assigned_vmid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vp_t is assigned to. If
        ///     this vp_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vp_t is assigned to. If
        ///     this vp_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_pp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_ppid.is_valid_and_checked());
            return ~m_assigned_ppid;
        }
    };
}

#endif
