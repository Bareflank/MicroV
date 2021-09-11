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

#include <bsl/add_lvalue_reference.hpp>
#include <bsl/debug.hpp>
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
    ///     This memory is released when it loses scope. Unlike the
    ///     std::unique_ptr, the pp_unique_map_t can only be used on a specifc
    ///     PP, and can only hold a POD type.
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
        /// @brief stores the bf_syscall_t to use.
        syscall::bf_syscall_t *m_sys;
        /// @brief stores the spa associated with this map.
        bsl::safe_u64 *m_spa;
        /// @brief stores the ppid associated with this map.
        bsl::safe_u16 m_assigned_ppid;
        /// @brief stores the vmid associated with this map.
        bsl::safe_u16 m_assigned_vmid;

    public:
        /// <!-- description -->
        ///   @brief Creates a default constructed invalid pp_unique_map_t
        ///
        constexpr pp_unique_map_t() noexcept    // --
            : m_ptr{}, m_sys{}, m_spa{}, m_assigned_ppid{}, m_assigned_vmid{}
        {}

        /// <!-- description -->
        ///   @brief Creates a valid pp_unique_map_t. When the pp_unique_map_t
        ///     loses scope, it will unmap the provided pointer and set the
        ///     spa associated with the pointer to 0, telling the MMIO handler
        ///     that the spa is no longer in use.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pudm_ptr the pointer to hold
        ///   @param pmut_sys the bf_syscall_t to use
        ///   @param pmut_spa the SPA associated with this map
        ///
        constexpr pp_unique_map_t(
            T *const pudm_ptr,
            syscall::bf_syscall_t *const pmut_sys,
            bsl::safe_u64 *const pmut_spa) noexcept
            : m_ptr{pudm_ptr}
            , m_sys{pmut_sys}
            , m_spa{pmut_spa}
            , m_assigned_ppid{}
            , m_assigned_vmid{}
        {
            bsl::expects(nullptr != pudm_ptr);
            bsl::expects(nullptr != pmut_sys);
            bsl::expects(nullptr != pmut_spa);

            m_assigned_ppid = ~pmut_sys->bf_tls_ppid();
            m_assigned_vmid = ~pmut_sys->bf_tls_vmid();
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
            bsl::expects(this->assigned_ppid() == m_sys->bf_tls_ppid());
            bsl::expects(this->assigned_vmid() == m_sys->bf_tls_vmid());

            if (nullptr != m_ptr) {
                bsl::expects(m_sys->bf_vm_op_unmap_direct(m_sys->bf_tls_vmid(), m_ptr));
                *m_spa = {};
            }
            else {
                bsl::touch();
            }
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
        ///   @brief Returns the ID of the PP associated with this
        ///     pp_unique_map_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     pp_unique_map_t
        ///
        [[nodiscard]] constexpr auto
        assigned_ppid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_ppid.is_valid_and_checked());
            return ~m_assigned_ppid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM associated with this
        ///     pp_unique_map_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VM associated with this
        ///     pp_unique_map_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vmid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vmid.is_valid_and_checked());
            return ~m_assigned_vmid;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the data being mapped by the
        ///     pp_unique_map_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the data being mapped by the
        ///     pp_unique_map_t.
        ///
        [[nodiscard]] constexpr auto
        get() const noexcept -> T *
        {
            bsl::expects(this->assigned_ppid() == m_sys->bf_tls_ppid());
            bsl::expects(this->assigned_vmid() == m_sys->bf_tls_vmid());
            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the data being mapped by the
        ///     pp_unique_map_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the data being mapped by the
        ///     pp_unique_map_t.
        ///
        [[nodiscard]] constexpr auto
        operator*() const noexcept -> bsl::add_lvalue_reference_t<T>
        {
            bsl::expects(this->assigned_ppid() == m_sys->bf_tls_ppid());
            bsl::expects(this->assigned_vmid() == m_sys->bf_tls_vmid());
            return *m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the data being mapped by the
        ///     pp_unique_map_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the data being mapped by the
        ///     pp_unique_map_t.
        ///
        [[nodiscard]] constexpr auto
        operator->() const noexcept -> T *
        {
            bsl::expects(this->assigned_ppid() == m_sys->bf_tls_ppid());
            bsl::expects(this->assigned_vmid() == m_sys->bf_tls_vmid());
            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns nullptr == this->get().
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns nullptr == this->get().
        ///
        [[nodiscard]] constexpr auto
        is_invalid() const noexcept -> bool
        {
            bsl::expects(this->assigned_ppid() == m_sys->bf_tls_ppid());
            bsl::expects(this->assigned_vmid() == m_sys->bf_tls_vmid());
            return nullptr == m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns nullptr != this->get().
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns nullptr != this->get().
        ///
        [[nodiscard]] constexpr auto
        is_valid() const noexcept -> bool
        {
            bsl::expects(this->assigned_ppid() == m_sys->bf_tls_ppid());
            bsl::expects(this->assigned_vmid() == m_sys->bf_tls_vmid());
            return nullptr != m_ptr;
        }
    };
}

#endif
