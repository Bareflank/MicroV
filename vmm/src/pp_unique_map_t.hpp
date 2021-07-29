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

#ifndef PP_UNIQUE_MAP_T_HPP
#define PP_UNIQUE_MAP_T_HPP

#include <bf_syscall_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::pp_unique_map_t
    ///
    /// <!-- description -->
    ///   @brief Similar to a std::unique_ptr, stores a pointer to memory.
    ///     This memory is released when it loses scope. The pp_unique_map_t
    ///     specifically uses mapped memory from a pp_t, and uses the syscall
    ///     interface to unmap the memory using the microkernel when complete.
    ///     A pp_unique_map_t does not support copies, meaning this is a
    ///     move-only class. The pp_unique_map_t can only be used on the PP
    ///     that it was created on. The TLS block that is required for all
    ///     functions is used to ensure the PP is correct and that no mistakes
    ///     are made. This is because the pp_unique_map_t will unmap the
    ///     address using a local unmap (meaning no remote TLB flush is
    ///     required).
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of pointer the pp_unique_map_t stores.
    ///
    template<typename T>
    class pp_unique_map_t final
    {
        static_assert(bsl::is_pod<T>::value);
        static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

        /// @brief stores the pointer that is held by pp_unique_map_t.
        T *m_ptr;
        /// @brief stores the bf_syscall_t used to unmap the pointer.
        syscall::bf_syscall_t *m_sys;
        /// @brief stores the spa associated with this map.
        bsl::safe_uint64 *m_spa;
        /// @brief stores the ppid associated with this map.
        bsl::safe_uint16 m_ppid;

    public:
        /// <!-- description -->
        ///   @brief Creates a default constructed invalid pp_unique_map_t
        ///
        constexpr pp_unique_map_t() noexcept
            : m_ptr{}, m_sys{}, m_spa{}, m_ppid{syscall::BF_INVALID_ID}
        {}

        /// <!-- description -->
        ///   @brief Creates a pp_unique_map_t given a pointer to hold, a
        ///     reference to the a bf_syscall_t which will be used to unmap
        ///     the pointer when the pp_unique_map_t loses scope, and a
        ///     reference to the spa that is associated with this map. When
        ///     the pp_unique_map_t is unmapped, this spa will be set to zero
        ///     indicated that the spa has been unmapped.
        ///
        /// <!-- inputs/outputs -->
        ///   @param umut_ptr the pointer to hold
        ///   @param pmut_sys the bf_syscall_t to use
        ///   @param pmut_spa the SPA associated with this map
        ///
        constexpr pp_unique_map_t(
            T *const umut_ptr,
            syscall::bf_syscall_t *const pmut_sys,
            bsl::safe_uint64 *const pmut_spa) noexcept
            : m_ptr{umut_ptr}, m_sys{pmut_sys}, m_spa{pmut_spa}, m_ppid{syscall::BF_INVALID_ID}
        {
            if (bsl::unlikely_assert(nullptr == umut_ptr)) {
                bsl::error() << "invalid umut_ptr\n" << bsl::here();
                *this = pp_unique_map_t<T>{};
                return;
            }

            if (bsl::unlikely_assert(nullptr == pmut_sys)) {
                bsl::error() << "invalid pmut_sys\n" << bsl::here();
                *this = pp_unique_map_t<T>{};
                return;
            }

            if (bsl::unlikely_assert(nullptr == pmut_spa)) {
                bsl::error() << "invalid pmut_spa\n" << bsl::here();
                *this = pp_unique_map_t<T>{};
                return;
            }

            m_ppid = pmut_sys->bf_tls_ppid();
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::pp_unique_map_t.
        ///     If the pointer being held is not a nullptr, and the PP this
        ///     is being executed on is the same as the PP the pp_unique_map_t
        ///     was created on, the pointer is unmapped and the SPA associated
        ///     with this map is released.
        ///
        constexpr ~pp_unique_map_t() noexcept
        {
            if (bsl::unlikely(nullptr == m_ptr)) {
                return;
            }

            if (m_ppid != m_sys->bf_tls_ppid()) {
                bsl::error() << "pp_unique_map_t was created on " << bsl::hex(m_ppid)
                             << " but it's destructor was run on pp "
                             << bsl::hex(m_sys->bf_tls_ppid()) << " which is not allowed"
                             << bsl::endl
                             << bsl::here();

                /// NOTE:
                /// - If this happens, the map will be leaked.
                ///

                return;
            }

            /// TODO:
            /// - We need to actually unmap memory using a microkernel ABI.
            ///

            bsl::alert() << "~pp_unique_map_t no implemented\n";
            *m_spa = {};
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr pp_unique_map_t(pp_unique_map_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr pp_unique_map_t(pp_unique_map_t &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(pp_unique_map_t const &o) &noexcept
            -> pp_unique_map_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(pp_unique_map_t &&mut_o) &noexcept
            -> pp_unique_map_t & = default;

        /// <!-- description -->
        ///   @brief Returns the pointer being held by the pp_unique_map_t.
        ///     If the PP is not the same PP the pp_unique_map_t was created
        ///     on, a nullptr is returned. If the pp_unique_map_t was created
        ///     with a nullptr, a nullptr is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @return Returns the pointer being held by the pp_unique_map_t.
        ///     If the PP is not the same PP the pp_unique_map_t was created
        ///     on, a nullptr is returned. If the pp_unique_map_t was created
        ///     with a nullptr, a nullptr is returned.
        ///
        [[nodiscard]] constexpr auto
        get(syscall::bf_syscall_t const &sys) const noexcept -> T *
        {
            if (m_ppid != sys.bf_tls_ppid()) {
                bsl::error() << "pp_unique_map_t was created on " << bsl::hex(m_ppid)
                             << " but get was run on pp " << bsl::hex(sys.bf_tls_ppid())
                             << " which is not allowed" << bsl::endl
                             << bsl::here();

                return nullptr;
            }

            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns nullptr != this->get().
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns nullptr != this->get().
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return nullptr != m_ptr;
        }
    };
}

#endif
