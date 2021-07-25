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

#ifndef VM_T_HPP
#define VM_T_HPP

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
    /// @class microv::vm_t
    ///
    /// <!-- description -->
    ///   @brief Defines Microv's virtual machine.
    ///
    class vm_t final
    {
        /// @brief stores the ID associated with this vm_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};
        /// @brief stores whether or not this vm_t is allocated.
        allocated_status_t m_allocated{allocated_status_t::deallocated};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param i the ID for this vm_t
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
                bsl::error() << "vm_t already initialized\n" << bsl::here();
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
        ///   @brief Release the vm_t.
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
        ///   @brief Returns the ID of this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vm_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates a vm_t.
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
        allocate(
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
                bsl::error() << "vm_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vm "                                     // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be allocated"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::allocated)) {
                bsl::error() << "vm "                                            // --
                             << bsl::hex(m_id)                                   // --
                             << " is already allocated and cannot be created"    // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return bsl::errc_precondition;
            }

            m_allocated = allocated_status_t::allocated;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Deallocates a vm_t.
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
                bsl::error() << "vm_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_id == syscall::BF_ROOT_VMID)) {
                bsl::error() << "vm "                                          // --
                             << bsl::hex(m_id)                                 // --
                             << " is the root VM which cannot be destroyed"    // --
                             << bsl::endl                                      // --
                             << bsl::here();                                   // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vm "                                     // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be destroyed"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vm "                                                // --
                             << bsl::hex(m_id)                                       // --
                             << " is already deallocated and cannot be destroyed"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::errc_precondition;
            }

            m_allocated = allocated_status_t::deallocated;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t's status as zombified, meaning it is no
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

            if (bsl::unlikely(m_id == syscall::BF_ROOT_VMID)) {
                bsl::alert() << "attempt to zombify vm "                            // --
                             << bsl::hex(m_id)                                      // --
                             << " was ignored as the root VM cannot be a zombie"    // --
                             << bsl::endl;                                          // --

                return;
            }

            bsl::alert() << "vm "                    // --
                         << bsl::hex(m_id)           // --
                         << " has been zombified"    // --
                         << bsl::endl;               // --

            m_allocated = allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is a zombie, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is a zombie, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_zombie() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::zombie;
        }
    };
}

#endif
