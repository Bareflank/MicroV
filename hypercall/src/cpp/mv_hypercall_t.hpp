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

#ifndef MV_HYPERCALL_T_HPP
#define MV_HYPERCALL_T_HPP

#include <mv_constants.hpp>
#include <mv_hypercall_impl.hpp>
#include <mv_reg_t.hpp>
#include <mv_translation_t.hpp>
#include <mv_types.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace hypercall
{
    /// @class hypercall::mv_hypercall_t
    ///
    /// <!-- description -->
    ///   @brief Provides an API wrapper around all of MicroV's ABIs.
    ///     For more information about these APIs, please see MicroV's
    ///     Hypercall Specification.
    ///
    ///
    class mv_hypercall_t final
    {
        /// @brief stores the handle used for making hypercalls.
        bsl::safe_uint64 m_hndl{};

    public:
        /// <!-- description -->
        ///   @brief Initializes the mv_hypercall_t by verifying version
        ///     compatibility and then opening a handle.
        ///
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize() noexcept -> bsl::errc_type
        {
            mv_status_t mut_ret{};
            bsl::safe_uint32 mut_version{};

            mut_ret = mv_id_op_version_impl(mut_version.data());
            if (bsl::unlikely_assert(mut_ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_id_op_version_impl failed with status "    // --
                             << bsl::hex(mut_ret)                              // --
                             << bsl::endl                                      // --
                             << bsl::here();                                   // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!mv_is_spec1_supported(mut_version))) {
                bsl::error() << "unsupported version of MicroV "    // --
                             << bsl::hex(mut_version)               // --
                             << bsl::endl                           // --
                             << bsl::here();                        // --

                return bsl::errc_unsupported;
            }

            mut_ret = mv_handle_op_open_handle_impl(MV_SPEC_ID1_VAL.get(), m_hndl.data());
            if (bsl::unlikely_assert(mut_ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_handle_op_open_handle_impl failed with status "    // --
                             << bsl::hex(mut_ret)                                      // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Releases the mv_hypercall_t by closing the handle.
        ///
        constexpr void
        release() noexcept
        {
            bsl::discard(mv_handle_op_close_handle_impl(m_hndl.get()));
            m_hndl = {};
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to translate the provided
        ///     guest virtual address (GVA) to a guest linear address (GLA).
        ///     To perform this translation, MicroV will use the current state
        ///     of CR0, CR4, EFER, the GDT and the segment registers. To
        ///     perform this translation, software must provide the ID of the
        ///     VPS whose state will be used during translation, the segment
        ///     register to use, and the the GVA to translate. How the
        ///     translation occurs depends on whether or not the VPS is in
        ///     16bit real mode, 32bit protected mode, or 64bit long mode. In
        ///     16bit real mode, the segment registers are used for the
        ///     translation. In 32bit protected mode, the segment registers and
        ///     the GDT are used for the translation. 64bit long mode is the
        ///     same as 32bit protected mode with the difference being that
        ///     certain segments will return an error as they are not supported
        ///     (e.g., ES and DS). If the translation fails for any reason, the
        ///     resulting GLA is undefined.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to use for the translation
        ///   @param ssid The SSID of the segment to use for the translation
        ///   @param gva The GVA to translate
        ///   @return Returns an mv_translation_t containing the results of
        ///     the translation.
        ///
        [[nodiscard]] constexpr auto
        mv_vps_op_gva_to_gla(
            bsl::safe_uint16 const &vpsid,
            bsl::safe_uint16 const &ssid,
            bsl::safe_uint64 const &gva) const noexcept -> mv_translation_t
        {
            bsl::safe_uint64 gla{};
            constexpr auto ssid_shift{16_u16};

            mv_status_t const ret{mv_vps_op_gva_to_gla_impl(
                m_hndl.get(), (vpsid | (ssid << ssid_shift)).get(), gva.get(), gla.data())};

            if (bsl::unlikely_assert(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vps_op_gva_to_gla_impl failed with status "    // --
                             << bsl::hex(ret)                                      // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return {{}, {}, {}, {}, false};
            }

            return {gva, gla, {}, {}, true};
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to translate the provided
        ///     guest linear address (GLA) to a guest physical address (GPA).
        ///     To perform this translation, MicroV will perform a linear to
        ///     physical address conversion using the current state of CR0,
        ///     CR3, and CR4. To perform this translation, software must
        ///     provide the ID of the VPS whose state will be used during
        ///     translation and the the GLA to translate. How the translation
        ///     occurs depends on whether or not the VPS is in 16bit real mode,
        ///     32bit protected mode, 32bit protected mode with paging enabled,
        ///     or 64bit long mode. If the VPS is in 16bit real mode or 32bit
        ///     protected mode with paging disabled, no translation is
        ///     performed and the provided GLA is returned as the GPA. If the
        ///     VPS is in 32bit protected mode with paging enabled or 64bit
        ///     long mode, MicroV will walk the guest page tables pointed to by
        ///     CR3 in the VPS and return the resulting GPA and GPA flags used
        ///     to map the GLA to the GPA (caching flags are not included). If
        ///     the translation fails for any reason, the resulting GPA is
        ///     undefined.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to use for the translation
        ///   @param gla The GLA to translate
        ///   @return Returns an mv_translation_t containing the results of
        ///     the translation.
        ///
        [[nodiscard]] constexpr auto
        mv_vps_op_gla_to_gpa(bsl::safe_uint16 const &vpsid, bsl::safe_uint64 const &gla)
            const noexcept -> mv_translation_t
        {
            bsl::safe_uint64 gpa_and_flags{};
            constexpr auto gpa_mask{0xFFFFFFFFFFFFF000_u64};
            constexpr auto fgs_mask{0x0000000000000FFF_u64};

            mv_status_t const ret{mv_vps_op_gla_to_gpa_impl(
                m_hndl.get(), vpsid.get(), gla.get(), gpa_and_flags.data())};

            if (bsl::unlikely_assert(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vps_op_gla_to_gpa_impl failed with status "    // --
                             << bsl::hex(ret)                                      // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return {{}, {}, {}, {}, false};
            }

            return {{}, gla, (gpa_and_flags & gpa_mask), (gpa_and_flags & fgs_mask), true};
        }
    };
}

#endif
