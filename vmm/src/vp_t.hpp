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
#include <bf_constants.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace microv
{
    /// @class microv::vp_t
    ///
    /// <!-- description -->
    ///   @brief Defines Microv's virtual processor.
    ///
    class vp_t final
    {
        /// @brief stores the ID associated with this vp_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};
        /// @brief stores whether or not this vp_t is allocated.
        allocated_status_t m_allocated{allocated_status_t::deallocated};
        /// @brief stores the ID of the VM this vp_t is assigned to
        bsl::safe_uint16 m_assigned_vmid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the PP this vp_t is assigned to
        bsl::safe_uint16 m_assigned_ppid{syscall::BF_INVALID_ID};

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
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &i) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            if (bsl::unlikely_assert(m_id)) {
                bsl::error() << "vp_t already initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!i)) {
                bsl::error() << "invalid id\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == i)) {
                bsl::error() << "id "                                                  // --
                             << bsl::hex(i)                                            // --
                             << " is invalid and cannot be used for initialization"    // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --

                return bsl::errc_invalid_argument;
            }

            m_id = i;
            return bsl::errc_success;
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
            if (this->is_allocated()) {
                auto const ret{this->deallocate(gs, tls, sys, intrinsic)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    this->zombify();
                    return;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            m_id = bsl::safe_uint16::failure();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vp_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates a vp_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the vp_t to
        ///   @param ppid the ID of the PP to assign the vp_t to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vmid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vp_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vp "                                     // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be allocated"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::allocated)) {
                bsl::error() << "vp "                                            // --
                             << bsl::hex(m_id)                                   // --
                             << " is already allocated and cannot be created"    // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!vmid)) {
                bsl::error() << "invalid vmid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == vmid)) {
                bsl::error() << "vm "                                              // --
                             << bsl::hex(vmid)                                     // --
                             << " is invalid and a vp cannot be assigned to it"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == ppid)) {
                bsl::error() << "pp "                                              // --
                             << bsl::hex(ppid)                                     // --
                             << " is invalid and a vp cannot be assigned to it"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_invalid_argument;
            }

            m_assigned_vmid = vmid;
            m_assigned_ppid = ppid;

            m_allocated = allocated_status_t::allocated;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Deallocates a vp_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vp_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vp "                                     // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be destroyed"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vp "                                                // --
                             << bsl::hex(m_id)                                       // --
                             << " is already deallocated and cannot be destroyed"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::errc_precondition;
            }

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vmid = syscall::BF_INVALID_ID;

            m_allocated = allocated_status_t::deallocated;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vp_t's status as zombified, meaning it is no
        ///     longer usable.
        ///
        constexpr void
        zombify() noexcept
        {
            if (bsl::unlikely_assert(!m_id)) {
                return;
            }

            if (allocated_status_t::zombie == m_allocated) {
                return;
            }

            bsl::alert() << "vp "                    // --
                         << bsl::hex(m_id)           // --
                         << " has been zombified"    // --
                         << bsl::endl;               // --

            m_allocated = allocated_status_t::zombie;
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
        ///   @brief Returns true if this vp_t is a zombie, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vp_t is a zombie, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_zombie() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::zombie;
        }
    };
}

#endif
