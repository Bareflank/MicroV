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

#ifndef VM_POOL_T_HPP
#define VM_POOL_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vm_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/finally_assert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace microv
{
    /// @class microv::vm_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines Microv's virtual machine pool.
    ///
    class vm_pool_t final
    {
        /// @brief stores the pool of VMs
        bsl::array<vm_t, HYPERVISOR_MAX_VMS.get()> m_pool{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vm_pool_t
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
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::finally_assert mut_release_on_error{
                [this, &gs, &tls, &sys, &intrinsic]() noexcept -> void {
                    this->release(gs, tls, sys, intrinsic);
                }};

            for (bsl::safe_uintmax mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                auto const ret{
                    m_pool.at_if(mut_i)->initialize(gs, tls, sys, intrinsic, bsl::to_u16(mut_i))};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            mut_release_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vm_pool_t.
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
            for (bsl::safe_uintmax mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                m_pool.at_if(mut_i)->release(gs, tls, sys, intrinsic);
            }
        }

        /// <!-- description -->
        ///   @brief Allocates a vm_t and returns it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns the ID of the newly created VM on
        ///     success, or bsl::safe_uint16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic) noexcept -> bsl::safe_uint16
        {
            auto const vmid{mut_sys.bf_vm_op_create_vm()};
            if (bsl::unlikely(!vmid)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            bsl::finally mut_destroy_vm_on_error{[&mut_sys, &vmid]() noexcept -> void {
                bsl::discard(mut_sys.bf_vm_op_destroy_vm(vmid));
            }};

            auto *const pmut_vm{m_pool.at_if(bsl::to_umax(vmid))};
            if (bsl::unlikely(nullptr == pmut_vm)) {
                bsl::error() << "vmid "                                                   // --
                             << bsl::hex(vmid)                                            // --
                             << " provided by the microkernel is invalid"                 // --
                             << " or greater than or equal to the HYPERVISOR_MAX_VMS "    // --
                             << bsl::hex(HYPERVISOR_MAX_VMS)                              // --
                             << bsl::endl                                                 // --
                             << bsl::here();                                              // --

                return bsl::safe_uint16::failure();
            }

            auto const ret{pmut_vm->allocate(gs, tls, mut_sys, intrinsic)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            mut_destroy_vm_on_error.ignore();
            return vmid;
        }

        /// <!-- description -->
        ///   @brief Deallocates a vm_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to deallocate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vmid) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            auto *const pmut_vm{m_pool.at_if(bsl::to_umax(vmid))};
            if (bsl::unlikely(nullptr == pmut_vm)) {
                bsl::error()
                    << "vmid "                                                              // --
                    << bsl::hex(vmid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VMS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VMS)                                         // --
                    << bsl::endl                                                            // --
                    << bsl::here();                                                         // --

                return bsl::errc_failure;
            }

            bsl::finally mut_zombify_vm_on_error{[&pmut_vm]() noexcept -> void {
                pmut_vm->zombify();
            }};

            mut_ret = pmut_vm->deallocate(gs, tls, mut_sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_sys.bf_vm_op_destroy_vm(vmid);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_zombify_vm_on_error.ignore();
            return bsl::errc_success;
        }
    };
}

#endif
