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

#ifndef VPS_POOL_T_HPP
#define VPS_POOL_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_constants.hpp>
#include <mv_translation_t.hpp>
#include <tls_t.hpp>
#include <vps_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/finally_assert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::vps_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines Microv's virtual processor state pool.
    ///
    class vps_pool_t final
    {
        /// @brief stores the pool of VPSs
        bsl::array<vps_t, HYPERVISOR_MAX_VPSS.get()> m_pool{};

        /// <!-- description -->
        ///   @brief Given a VPSID, returns the associated vps_t from the
        ///     pool. If the ID is invalid or out of bounds a nullptr is
        ///     returned. If the ID is MV_SELF_ID, the active vps_t is
        ///     returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param vpsid the ID of the vps_t to return
        ///   @return Given a VPSID, returns the associated vps_t from the
        ///     pool. If the ID is invalid or out of bounds a nullptr is
        ///     returned. If the ID is MV_SELF_ID, the active vps_t is
        ///     returned.
        ///
        [[nodiscard]] constexpr auto
        get_vps(syscall::bf_syscall_t const &sys, bsl::safe_uint16 const &vpsid) noexcept -> vps_t *
        {
            if (bsl::unlikely(hypercall::MV_INVALID_ID == vpsid)) {
                bsl::error() << "vpsid "                                  // --
                             << bsl::hex(vpsid)                           // --
                             << " is MV_INVALID_ID and cannot be used"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return nullptr;
            }

            if (hypercall::MV_SELF_ID == vpsid) {
                return m_pool.at_if(bsl::to_umax(sys.bf_tls_vpsid()));
            }

            auto *const mut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == mut_vps)) {
                bsl::error() << "vpsid "                                   // --
                             << bsl::hex(vpsid)                            // --
                             << " is out of bounds and cannot be used "    // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return nullptr;
            }

            return mut_vps;
        }

        /// <!-- description -->
        ///   @brief Given a VPSID, returns the associated vps_t from the
        ///     pool. If the ID is invalid or out of bounds a nullptr is
        ///     returned. If the ID is MV_SELF_ID, the active vps_t is
        ///     returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param vpsid the ID of the vps_t to return
        ///   @return Given a VPSID, returns the associated vps_t from the
        ///     pool. If the ID is invalid or out of bounds a nullptr is
        ///     returned. If the ID is MV_SELF_ID, the active vps_t is
        ///     returned.
        ///
        [[nodiscard]] constexpr auto
        get_vps(syscall::bf_syscall_t const &sys, bsl::safe_uint16 const &vpsid) const noexcept
            -> vps_t const *
        {
            if (bsl::unlikely(hypercall::MV_INVALID_ID == vpsid)) {
                bsl::error() << "vpsid "                                             // --
                             << bsl::hex(vpsid)                                      // --
                             << " is hypercall::MV_INVALID_ID and cannot be used"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return nullptr;
            }

            if (hypercall::MV_SELF_ID == vpsid) {
                return m_pool.at_if(bsl::to_umax(sys.bf_tls_vpsid()));
            }

            auto *const mut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == mut_vps)) {
                bsl::error() << "vpsid "                                   // --
                             << bsl::hex(vpsid)                            // --
                             << " is out of bounds and cannot be used "    // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return nullptr;
            }

            return mut_vps;
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vps_pool_t
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
        ///   @brief Release the vps_pool_t.
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
        ///   @brief Allocates a vps_t and returns it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the newly created VPS to
        ///   @param vpid the ID of the VP to assign the newly created VPS to
        ///   @param ppid the ID of the PP to assign the newly created VPS to
        ///   @return Returns the ID of the newly created VPS on
        ///     success, or bsl::safe_uint16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vmid,
            bsl::safe_uint16 const &vpid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::safe_uint16
        {
            auto const vpsid{mut_sys.bf_vps_op_create_vps(vpid, ppid)};
            if (bsl::unlikely(!vpsid)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            bsl::finally mut_destroy_vps_on_error{[&mut_sys, &vpsid]() noexcept -> void {
                bsl::discard(mut_sys.bf_vps_op_destroy_vps(vpsid));
            }};

            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error() << "vpsid "                                                   // --
                             << bsl::hex(vpsid)                                            // --
                             << " provided by the microkernel is invalid"                  // --
                             << " or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                             << bsl::hex(HYPERVISOR_MAX_VPSS)                              // --
                             << bsl::endl                                                  // --
                             << bsl::here();                                               // --

                return bsl::safe_uint16::failure();
            }

            auto const ret{pmut_vps->allocate(gs, tls, mut_sys, intrinsic, vmid, vpid, ppid)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            mut_destroy_vps_on_error.ignore();
            return vpsid;
        }

        /// <!-- description -->
        ///   @brief Deallocates a vps_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vpsid the ID of the VM to deallocate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vpsid) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            auto *const pmut_vps{this->get_vps(mut_sys, vpsid)};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally mut_zombify_vps_on_error{[&pmut_vps]() noexcept -> void {
                pmut_vps->zombify();
            }};

            mut_ret = pmut_vps->deallocate(gs, tls, mut_sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_sys.bf_vps_op_destroy_vps(vpsid);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_zombify_vps_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vps_t is a root VPS.
        ///     Returns false if the requested vps_t is not a root VPS or
        ///     an error occurs.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param vpsid the ID of the VPS to query
        ///   @return Returns true if the requested vps_t is a root VPS.
        ///     Returns false if the requested vps_t is not a root VPS or
        ///     an error occurs.
        ///
        [[nodiscard]] constexpr auto
        is_root_vps(syscall::bf_syscall_t const &sys, bsl::safe_uint16 const &vpsid) const noexcept
            -> bool
        {
            auto const *const vps{this->get_vps(sys, vpsid)};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::print<bsl::V>() << bsl::here();
                return false;
            }

            return vps->is_root_vps();
        }

        /// <!-- description -->
        ///   @brief RReturns true if the requested vps_t is a guest VPS.
        ///     Returns false if the requested vps_t is not a guest VPS or
        ///     an error occurs.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param vpsid the ID of the VPS to query
        ///   @return Returns true if the requested vps_t is a guest VPS.
        ///     Returns false if the requested vps_t is not a guest VPS or
        ///     an error occurs.
        ///
        [[nodiscard]] constexpr auto
        is_guest_vps(syscall::bf_syscall_t const &sys, bsl::safe_uint16 const &vpsid) const noexcept
            -> bool
        {
            auto const *const vps{this->get_vps(sys, vpsid)};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::print<bsl::V>() << bsl::here();
                return false;
            }

            return vps->is_guest_vps();
        }

        /// <!-- description -->
        ///   @brief Translates a guest GLA to a guest GPA using the paging
        ///     configuration of the guest stored in CR0, CR3 and CR4.
        ///
        /// <!-- notes -->
        ///   @note This function is slow. It has to map in guest page tables
        ///     so that it can walk these tables and perform the translation.
        ///     Once the translation is done, these translations are unmapped.
        ///     If we didn't do this, the direct map would become polluted with
        ///     maps that are no longer needed, and these maps may eventually
        ///     point to memory used by the guest to store a secret.
        ///
        ///   @note IMPORTANT: One way to improve performance of code that
        ///     uses this function is to cache these translations. This would
        ///     implement a virtual TLB. You might not call it that, but that
        ///     is what it is. If we store ANY translations, we must clear
        ///     them when the guest attempts to perform any TLB invalidations,
        ///     as the translation might not be valid any more. This is made
        ///     even worse with remote TLB invalidations that the guest
        ///     performs because the hypervisor has to mimic the same behaviour
        ///     that any race conditions introduce. For example, if we are in
        ///     the middle of emulating an instruction on one CPU, and another
        ///     performs an invalidation, emulation needs to complete before
        ///     the invalidation takes place. Otherwise, a use-after-free
        ///     bug could occur. This only applies to the decoding portion of
        ///     emulation as the CPU is pipelined. Reads/writes to memory
        ///     during the rest of emulation may still read garbage, and that
        ///     is what the CPU would do. To simplify this, all translations
        ///     should ALWAYS come from this function. Meaning, if a translation
        ///     must be stored, it should be stored here in a virtual TLB. This
        ///     way, any invalidations to a VPS can be flushed in the VPS. If
        ///     all functions always have to call this function, it will simply
        ///     return a cached translation. If the cache is flushed because
        ///     the guest performed a flush, the required TLB update will
        ///     automatically happen. This way, software always does the GLA
        ///     to GPA conversion when it is needed, and only when it is needed
        ///     the same way the hardware would. DO NOT CACHE THE RESULTS OF
        ///     THIS FUNCTION. YOU MUST ALWAYS CALL THIS FUNCTION EVERYTIME
        ///     A TRANSLATION IS NEEDED.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_pp_pool the pp_pool_t to use
        ///   @param gla the GLA to translate to a GPA
        ///   @param vpsid the ID of the VPS to perform the translation for
        ///   @return Returns mv_translation_t containing the results of the
        ///     translation.
        ///
        [[nodiscard]] constexpr auto
        gla_to_gpa(
            syscall::bf_syscall_t &mut_sys,
            pp_pool_t &mut_pp_pool,
            bsl::safe_uint64 const &gla,
            bsl::safe_uint16 const &vpsid) const noexcept -> hypercall::mv_translation_t
        {
            auto const *const vps{this->get_vps(mut_sys, vpsid)};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::print<bsl::V>() << bsl::here();
                return {{}, {}, {}, {}, false};
            }

            return vps->gla_to_gpa(mut_sys, mut_pp_pool, gla);
        }
    };
}

#endif
