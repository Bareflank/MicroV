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

#ifndef PP_UNIQUE_SHARED_PAGE_T_HPP
#define PP_UNIQUE_SHARED_PAGE_T_HPP

#include <bf_syscall_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::pp_unique_shared_page_t
    ///
    /// <!-- description -->
    ///   @brief Similar to a std::unique_ptr, stores a pointer to memory.
    ///     This memory is released when it loses scope. Unlike the
    ///     std::unique_ptr, the pp_unique_shared_page_t can only be used on a specifc
    ///     PP, and can only hold a POD type.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of pointer the pp_unique_shared_page_t stores.
    ///
    template<typename T>
    class pp_unique_shared_page_t final
    {
        static_assert(bsl::is_pod<T>::value);
        static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

        /// @brief stores the pointer that is held by pp_unique_shared_page_t.
        T *m_ptr;
        /// @brief stores the bf_syscall_t to use.
        syscall::bf_syscall_t *m_sys;
        /// @brief stores whether or not the shared page is in use.
        bool *m_use;
        /// @brief stores the vmid associated with this map.
        bsl::safe_u16 m_vmid;
        /// @brief stores the ppid associated with this map.
        bsl::safe_u16 m_ppid;

    public:
        /// <!-- description -->
        ///   @brief Creates a default constructed invalid pp_unique_shared_page_t
        ///
        constexpr pp_unique_shared_page_t() noexcept    // --
            : m_ptr{}, m_sys{}, m_use{}, m_ppid{}
        {}

        /// <!-- description -->
        ///   @brief Creates a valid pp_unique_shared_page_t. When the pp_unique_shared_page_t
        ///     loses scope, it will unmap the provided pointer and set the
        ///     spa associated with the pointer to 0, telling the MMIO handler
        ///     that the spa is no longer in use.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pudm_ptr the pointer to hold
        ///   @param pmut_sys the bf_syscall_t to use
        ///   @param pmut_use the SPA associated with this map
        ///
        constexpr pp_unique_shared_page_t(
            T *const pudm_ptr, syscall::bf_syscall_t *const pmut_sys, bool *const pmut_use) noexcept
            : m_ptr{pudm_ptr}, m_sys{pmut_sys}, m_use{pmut_use}, m_ppid{}
        {
            bsl::expects(nullptr != pmut_sys);
            bsl::expects(nullptr != pmut_use);

            if (nullptr == pudm_ptr) {
                bsl::error() << "shared page for pp "                // --
                             << bsl::hex(pmut_sys->bf_tls_ppid())    // --
                             << " is NULL"                           // --
                             << bsl::endl;                           // --

                *this = pp_unique_shared_page_t{};
                return;
            }

            /// NOTE:
            /// - If you see the following narrow contract fail, it means
            ///   that you are using the shared page twice without releasing
            ///   the first one.
            ///
            /// - Specifically, if you grab the shared page, you have to
            ///   release it before using it again. Otherwise, you would
            ///   end up with the same pointer, pointing two two different
            ///   objects (and possibly of different types) which breaks
            ///   strict aliasing rules. You can only have a pointer to one
            ///   object at a time, and this specific checks enforces that.
            ///
            /// - Also, this needs to be the root VM for now. If it is not,
            ///   you will end up having to map the shared page into the
            ///   memory space of the extension for each guest VM and not
            ///   just the root VM. This means there would be a memory map
            ///   in MicroV that is shared between all of the VMs. From a
            ///   security point of view, this is not really a problem. But
            ///   from a TLB point of view, chaning the shared page would
            ///   almost certainly cause issues. To fix this, the shared
            ///   page will need a per-VM set of shared pages, and should
            ///   only actually be needed if device domains require it.
            ///   But careful attention to the TLB will have to be taken to
            ///   ensure that if you change the shared page, something
            ///   horrible happens.
            ///
            /// - TL;DR Either fix the bug, or rethink your design!!!
            ///

            bsl::expects(!*pmut_use);
            bsl::expects(pmut_sys->is_the_active_vm_the_root_vm());

            *pmut_use = true;

            m_vmid = ~pmut_sys->bf_tls_vmid();
            m_ppid = ~pmut_sys->bf_tls_ppid();
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::pp_unique_shared_page_t.
        ///     If the pointer being held is not a nullptr, and the PP this
        ///     is being executed on is the same as the PP the pp_unique_shared_page_t
        ///     was created on, the pointer is unmapped and the SPA associated
        ///     with this map is released.
        ///
        constexpr ~pp_unique_shared_page_t() noexcept
        {
            if (nullptr != m_use) {
                bsl::expects(this->assigned_ppid() == m_sys->bf_tls_ppid());
                bsl::expects(this->assigned_vmid() == m_sys->bf_tls_vmid());

                *m_use = {};
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
        constexpr pp_unique_shared_page_t(pp_unique_shared_page_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr pp_unique_shared_page_t(pp_unique_shared_page_t &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(pp_unique_shared_page_t const &o) &noexcept
            -> pp_unique_shared_page_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(pp_unique_shared_page_t &&mut_o) &noexcept
            -> pp_unique_shared_page_t & = default;

        /// <!-- description -->
        ///   @brief Returns the ID of the PP associated with this
        ///     pp_unique_shared_page_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     pp_unique_shared_page_t
        ///
        [[nodiscard]] constexpr auto
        assigned_ppid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_ppid.is_valid_and_checked());
            return ~m_ppid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM associated with this
        ///     pp_unique_shared_page_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VM associated with this
        ///     pp_unique_shared_page_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vmid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_vmid.is_valid_and_checked());
            return ~m_vmid;
        }

        /// <!-- description -->
        ///   @brief Returns the pointer being held by the
        ///     pp_unique_shared_page_t. If the pp_unique_shared_page_t is
        ///     invalid, a nullptr is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the pointer being held by the
        ///     pp_unique_shared_page_t. If the pp_unique_shared_page_t is
        ///     invalid, a nullptr is returned.
        ///
        [[nodiscard]] constexpr auto
        get() const noexcept -> T *
        {
            bsl::expects(this->assigned_ppid() == m_sys->bf_tls_ppid());
            bsl::expects(this->assigned_vmid() == m_sys->bf_tls_vmid());

            if (this->is_invalid()) {
                return nullptr;
            }

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
        ///   @brief Returns true if the shared page is invalid. This
        ///     could be a default pp_unique_shared_page_t was created, or
        ///     it could be because MicroV asked for a pp_unique_shared_page_t
        ///     when the SPA of the shared page was never set. It is also
        ///     possible that the shared page is invalid because the SPA of
        ///     the shared page was cleared after it was created. This is
        ///     why this API only provided get() and not */-> You must always
        ///     check to make sure the shared page is valid before using it.
        ///     When a hypercall is made that would use the shared page, it
        ///     would be impossible for guest software to clear the SPA for
        ///     the PP that the hypercall is on, because the hypercall is
        ///     in the process of being executed, so the PP is busy.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the shared page is invalid.
        ///
        [[nodiscard]] constexpr auto
        is_invalid() const noexcept -> bool
        {
            if (nullptr == m_use) {
                return true;
            }

            return !*m_use;
        }

        /// <!-- description -->
        ///   @brief Returns !this->is_invalid().
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !this->is_invalid()
        ///
        [[nodiscard]] constexpr auto
        is_valid() const noexcept -> bool
        {
            return !this->is_invalid();
        }
    };
}

#endif
