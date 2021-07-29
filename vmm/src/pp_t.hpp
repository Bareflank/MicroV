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

#ifndef PP_T_HPP
#define PP_T_HPP

#include <bf_constants.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <pp_cpuid_t.hpp>
#include <pp_cr_t.hpp>
#include <pp_io_t.hpp>
#include <pp_lapic_t.hpp>
#include <pp_mmio_t.hpp>
#include <pp_msr_t.hpp>
#include <pp_mtrrs_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely_assert.hpp>

namespace microv
{
    /// @class microv::pp_t
    ///
    /// <!-- description -->
    ///   @brief Defines Microv's physical processor.
    ///
    class pp_t final
    {
        /// @brief stores the ID associated with this pp_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};

        /// @brief stores this pp_t's pp_cpuid_t
        pp_cpuid_t m_pp_cpuid{};
        /// @brief stores this pp_t's pp_cr_t
        pp_cr_t m_pp_cr{};
        /// @brief stores this pp_t's pp_io_t
        pp_io_t m_pp_io{};
        /// @brief stores this pp_t's pp_lapic_t
        pp_lapic_t m_pp_lapic{};
        /// @brief stores this pp_t's pp_mmio_t
        pp_mmio_t m_pp_mmio{};
        /// @brief stores this pp_t's pp_msr_t
        pp_msr_t m_pp_msr{};
        /// @brief stores this pp_t's pp_mtrrs_t
        pp_mtrrs_t m_pp_mtrrs{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this pp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param i the ID for this pp_t
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
            bsl::errc_type mut_ret{};

            if (bsl::unlikely_assert(m_id)) {
                bsl::error() << "pp_t already initialized\n" << bsl::here();
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

            bsl::finally mut_release_vm_on_error{
                [this, &gs, &tls, &sys, &intrinsic]() noexcept -> void {
                    this->release(gs, tls, sys, intrinsic);
                }};

            mut_ret = m_pp_cpuid.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_pp_cr.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_pp_io.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_pp_lapic.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_pp_mmio.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_pp_msr.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_pp_mtrrs.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            m_id = i;

            mut_release_vm_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the pp_t.
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
            m_pp_cpuid.release(gs, tls, sys, intrinsic);
            m_pp_cr.release(gs, tls, sys, intrinsic);
            m_pp_io.release(gs, tls, sys, intrinsic);
            m_pp_lapic.release(gs, tls, sys, intrinsic);
            m_pp_mmio.release(gs, tls, sys, intrinsic);
            m_pp_msr.release(gs, tls, sys, intrinsic);
            m_pp_mtrrs.release(gs, tls, sys, intrinsic);

            m_id = bsl::safe_uint16::failure();
        }

        /// <!-- description -->
        ///   @brief Reads CPUID on the physical processor using the values
        ///     stored in the eax, ebx, ecx, and edx registers provided by the
        ///     syscall layer and stores the results in the same registers.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        cpuid_get(gs_t const &gs, syscall::bf_syscall_t &mut_sys, intrinsic_t const &intrinsic)
            const noexcept -> bsl::errc_type
        {
            return m_pp_cpuid.get(gs, mut_sys, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Please see m_pp_mmio.map() for details as there are a
        ///     lot and they are important to understand.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type to map and return
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param spa the system physical address of the T * to return.
        ///   @return Returns the resulting T * given the SPA, or a nullptr
        ///     on error.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        map(syscall::bf_syscall_t &mut_sys, bsl::safe_uintmax const &spa) noexcept
            -> pp_unique_map_t<T>
        {
            return m_pp_mmio.map<T>(mut_sys, spa);
        }
    };
}

#endif
