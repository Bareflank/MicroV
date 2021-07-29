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

#ifndef PP_MMIO_T_HPP
#define PP_MMIO_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <pp_unique_map_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely_assert.hpp>

namespace microv
{
    /// @class microv::pp_mmio_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's physical processor MMIO handler. Physical
    ///     processor resources are owned by the physical processors and
    ///     are used by the VM, VP and VPSs to directly access the hardware
    ///     and provide emulated responses to VMExits from the root VM.
    ///
    class pp_mmio_t final
    {
        /// @brief stores the initialization state of pp_mmio_t.
        bool m_initialized{};
        /// @brief stores the SPAs that have yet to be unmapped.
        bsl::array<bsl::safe_uint64, MICROV_MAX_PP_MAPS.get()> m_mapped_spas{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this pp_mmio_t.
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
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            if (bsl::unlikely_assert(m_initialized)) {
                bsl::error() << "pp_mmio_t already initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            m_initialized = true;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the pp_mmio_t.
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

            m_initialized = false;
        }

        /// <!-- description -->
        ///   @brief Given an SPA, maps the SPA to a T *. T must be a pod type.
        ///     Actually, T could be a trivially copyable type for this map to
        ///     work without invoking UB at runtime, but we only use POD types
        ///     anyways, which adds an additional layer of sanity. T must also
        ///     be a page in size or less, otherwise the SPA would have to be
        ///     physically contiguous, which would be a dangerous assumption.
        ///     If an error occurs, this function will return a nullptr.
        ///
        /// <!-- notes -->
        ///   @note All this function does is return a T * using a reinterpret
        ///     cast. This is because the "first use" of the T * will actually
        ///     perform the map since the microkernel uses on-demand paging.
        ///
        ///   @note This function is clearly not constexpr friendly. This is
        ///     one of the few examples of where we cannot test using a
        ///     constexpr. Specifically, any virt to phys or phys to virt
        ///     translations have this issue. This function however does not
        ///     perform anything other than a reinterpret cast. So, the only
        ///     thing we have to do is ensure that UB is not invoked. We can
        ///     safely take any memory and map it to a POD type (really just a
        ///     trivially copyable type). Furthermore, we are mapping an SPA,
        ///     so the only other forms of UB that could occur would be a page
        ///     fault if the SPA is invalid. Anything that uses this code will
        ///     use a mocked version of it that actually performs an allocation
        ///     when the memory is mapped, and then a deallocation when the
        ///     memory is unmapped, so any code that uses this can still be
        ///     tested using a constexpr.
        ///
        ///   @note The reason that we keep a list of all of the SPAs that
        ///     have been mapped is you cannot map the same SPA twice. If you
        ///     do, you would be violating the strict aliasing rules. We also
        ///     don't want to allow millions of maps as that would pollute
        ///     the extensions direct map. So, we keep track of our maps so
        ///     that we can protect the direct map and prevent UB. If you need
        ///     a lot of maps all at the same time, you probably need to
        ///     rethink what you are doing.
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
            if (bsl::unlikely_assert(!spa)) {
                bsl::error() << "invalid spa\n" << bsl::here();
                return pp_unique_map_t<T>{};
            }

            if (bsl::unlikely_assert(spa.is_zero())) {
                bsl::error() << "invalid spa\n" << bsl::here();
                return pp_unique_map_t<T>{};
            }

            auto mut_i{MICROV_MAX_PP_MAPS};
            for (auto const elem : m_mapped_spas) {
                if (*elem.data == spa) {
                    bsl::error() << "spa " << bsl::hex(spa) << " already mapped" << bsl::endl
                                 << bsl::here();

                    return pp_unique_map_t<T>{};
                }

                if (elem.data->is_zero()) {
                    mut_i = elem.index;
                }
                else {
                    bsl::touch();
                }
            }

            auto *const pmut_spa{m_mapped_spas.at_if(mut_i)};
            if (bsl::unlikely(nullptr == pmut_spa)) {
                bsl::error() << "pp_mmio_t is out of available maps\n" << bsl::here();
                return pp_unique_map_t<T>{};
            }

            auto const hva{spa + HYPERVISOR_EXT_DIRECT_MAP_ADDR};
            if (bsl::unlikely_assert(!hva)) {
                bsl::error() << "map failed due to invalid spa "    // --
                             << bsl::hex(spa)                       // --
                             << bsl::endl                           // --
                             << bsl::here();

                return pp_unique_map_t<T>{};
            }

            *pmut_spa = spa;
            return pp_unique_map_t<T>{reinterpret_cast<T *>(hva.get()), &mut_sys, pmut_spa};
        }
    };
}

#endif
