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
#include <mv_constants.hpp>
#include <page_4k_t.hpp>
#include <pp_unique_map_t.hpp>
#include <pp_unique_shared_page_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @brief defines the list of possible maps for this PP/VM combo
    using pp_map_list_t = bsl::array<bsl::safe_u64, MICROV_MAX_PP_MAPS.get()>;
    /// @brief defines the list of possible maps for all VMs
    using vm_map_list_t = bsl::array<pp_map_list_t, HYPERVISOR_MAX_VMS.get()>;

    /// @class microv::pp_mmio_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's physical processor MMIO handler. Physical
    ///     processor resources are owned by the physical processors and
    ///     are used by the VM, VP and VSs to directly access the hardware
    ///     and provide emulated responses to VMExits from the root VM.
    ///
    /// <!-- notes -->
    ///   @note IMPORTANT: The most important aspect of this class is it
    ///     gives out T*s (both from the map() and shared_page() functions).
    ///     Each map has to have a unique SPA which is why we have a max number
    ///     of maps and track these maps using the SPA that is provided. This
    ///     is because YOU CANNOT HAVE MORE THAN ONE T* FOR THE SAME ADDRESS.
    ///     If you do, you will violate strict aliasing rules. That's why you
    ///     have to checkout the shared page and then return it. It is also
    ///     why you can only have one map for each SPA. Any code that is
    ///     added to this has to enforce the same rules. Any T* that is given
    ///     needs to be unique. If you need to change T, that is fine, so
    ///     long as T is a POD type, but whoever is using T* for the old T has
    ///     to stop using it (meaning it needs to be released) so that a new
    ///     T* can be created for that same address. Again, if this is not done
    ///     right, strict aliasing rules will be violated. It will also prevent
    ///     constexpr from working as you cannot have the same address point
    ///     to two different types in a constexpr, for the same reasons.
    ///
    ///   @note IMPORTANT: The PP can only handle SPAs. It makes no sense for
    ///     a PP to store or handle a GPA because it has no guest VM to work
    ///     with.
    ///
    ///   @note IMPORTANT: You might be asking, why do we have a unique map
    ///     and a unique shared page. Why not just make them the same thing.
    ///     This is because maps will be created and released, and when they
    ///     are released, the memory is no longer needed. The shared page
    ///     however will be created, and then remapped to different T *s
    ///     all the time, but the memory itself is not actually released until
    ///     clr_shared_page_spa is called. So the unique map frees the
    ///     memory and then tells the m_maps that the SPA it owned is now
    ///     free. The unique shared page simply flips m_shared_page_in_use
    ///     and the memory stays mapped until clr_shared_page_spa is called.
    ///
    ///   @note IMPORTANT: You might also be asking, why not just make all
    ///     maps global? Why do we have a per-VM, per-PP map. The reason each
    ///     map is per-VM, is because the extension (in this case MicroV)
    ///     has a different direct map per VM. This is to deal with
    ///     speculative execution attacks, and ensures that the direct map
    ///     for MicroV is isolated between VMs. The reason maps are also
    ///     on a per-PP is actually for two different reasons. Each PP is
    ///     symmetric, which means that they can execute at the same time,
    ///     with independence. Using a global map would require locks to
    ///     handle this safely. Global maps would also require that when the
    ///     unmap occurres, all PPs are flushed, which would be slow not
    ///     just from the locks that would be required, but the IPIs that
    ///     would also be required to flush all PPs. Per-PP maps means that
    ///     they can map whatever memory they need without an issue, and
    ///     they don't need to notify other PPs when an unmap occurs.
    ///
    ///   @note IMPORTANT: The map function should not be used to map the
    ///     shared page (use set_shared_page_spa for that), or the LAPIC.
    ///     This is because the shared page and LAPIC have different map
    ///     functions. The shared page needs to be handled differently (see
    ///     above for more details), and the LAPIC needs to actually have
    ///     the same address, so this is a global map (that is never unmapped
    ///     so there is no issue here with IPIs), and that is because the
    ///     LAPIC is mapped to the same virtual address on all PPs, even
    ///     though that virtual address talks to the LAPIC associated with
    ///     the PP making the calls. Any attempt to use map() for these
    ///     will result in UB. You have been warned.
    ///
    class pp_mmio_t final
    {
        /// @brief stores the ID of the PP associated with this pp_mmio_t
        bsl::safe_u16 m_assigned_ppid{};
        /// @brief stores the shared page associated with this pp_mmio_t
        page_4k_t *m_shared_page{};
        /// @brief stores whether or not the shared page is in use.
        bool m_shared_page_in_use{};
        /// @brief stores the SPAs that have been mapped.
        vm_map_list_t m_maps{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this pp_mmio_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param ppid the ID of the PP this pp_mmio_t is assigned to
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &ppid) noexcept
        {
            bsl::expects(this->assigned_ppid() == syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_ppid = ~ppid;
        }

        /// <!-- description -->
        ///   @brief Release the pp_mmio_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            this->clr_shared_page_spa(mut_sys);
            m_assigned_ppid = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP associated with this
        ///     pp_mmio_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     pp_mmio_t
        ///
        [[nodiscard]] constexpr auto
        assigned_ppid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_ppid.is_valid_and_checked());
            return ~m_assigned_ppid;
        }

        /// <!-- description -->
        ///   @brief Returns a pp_unique_map_t<T> given an SPA to map. If an
        ///     error occurs, an invalid pp_unique_map_t<T> is returned.
        ///
        /// <!-- notes -->
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
        ///   @tparam T the type of map to return
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param spa the system physical address of the pp_unique_map_t<T>
        ///     to return.
        ///   @return Returns a pp_unique_map_t<T> given an SPA to map. If an
        ///     error occurs, an invalid pp_unique_map_t<T> is returned.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        map(syscall::bf_syscall_t &mut_sys, bsl::safe_umx const &spa) noexcept -> pp_unique_map_t<T>
        {
            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

            bsl::expects(this->assigned_ppid() == mut_sys.bf_tls_ppid());

            bsl::expects(spa.is_valid_and_checked());
            bsl::expects(spa.is_pos());

            /// TODO:
            /// - In the future, we should change this to a linked list to
            ///   make maps faster. The challenge will be in debug mode,
            ///   and ensuring that we are not mapping the same SPA more
            ///   than once, which the list approach does well, and is
            ///   optimized out in release mode.
            ///

            auto *const pmut_maps_for_current_vm{m_maps.at_if(bsl::to_idx(mut_sys.bf_tls_vmid()))};
            bsl::expects(nullptr != pmut_maps_for_current_vm);

            for (bsl::safe_idx mut_i{}; mut_i < pmut_maps_for_current_vm->size(); ++mut_i) {
                bsl::expects(spa != *pmut_maps_for_current_vm->at_if(mut_i));
            }

            bsl::safe_u64 *pmut_mut_spa{};
            for (bsl::safe_idx mut_i{}; mut_i < pmut_maps_for_current_vm->size(); ++mut_i) {
                pmut_mut_spa = pmut_maps_for_current_vm->at_if(mut_i);
                if (pmut_mut_spa->is_zero()) {
                    break;
                }

                bsl::touch();
            }

            bsl::expects(nullptr != pmut_mut_spa);
            *pmut_mut_spa = spa;

            auto *const hva{mut_sys.bf_vm_op_map_direct<T>(mut_sys.bf_tls_vmid(), spa)};
            if (bsl::unlikely(nullptr == hva)) {
                bsl::print<bsl::V>() << bsl::here();
                return pp_unique_map_t<T>{};
            }

            return pp_unique_map_t<T>{hva, &mut_sys, pmut_mut_spa};
        }

        /// <!-- description -->
        ///   @brief Clears the SPA of the shared page.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///
        constexpr void
        clr_shared_page_spa(syscall::bf_syscall_t &mut_sys) noexcept
        {
            constexpr auto vmid{hypercall::MV_ROOT_VMID};

            bsl::expects(this->assigned_ppid() == mut_sys.bf_tls_ppid());
            bsl::expects(mut_sys.is_the_active_vm_the_root_vm());

            if (nullptr != m_shared_page) {
                bsl::expects(mut_sys.bf_vm_op_unmap_direct(vmid, m_shared_page));
                m_shared_page = {};
                m_shared_page_in_use = {};
            }
            else {
                bsl::touch();
            }
        }

        /// <!-- description -->
        ///   @brief Sets the SPA of the shared page.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param spa the system physical address of the shared page
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_shared_page_spa(syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &spa) noexcept
            -> bsl::errc_type
        {
            constexpr auto vmid{hypercall::MV_ROOT_VMID};

            bsl::expects(this->assigned_ppid() == mut_sys.bf_tls_ppid());
            bsl::expects(mut_sys.is_the_active_vm_the_root_vm());

            bsl::expects(spa.is_valid_and_checked());
            bsl::expects(spa.is_pos());

            bsl::expects(nullptr == m_shared_page);
            bsl::expects(!m_shared_page_in_use);

            m_shared_page = mut_sys.bf_vm_op_map_direct<page_4k_t>(vmid, spa);
            if (bsl::unlikely(nullptr == m_shared_page)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns a pp_unique_shared_page_t<T> if the shared page
        ///     is not currently in use. If an error occurs, returns an invalid
        ///     pp_unique_shared_page_t<T>.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of shared page to return
        ///   @param sys the bf_syscall_t to use
        ///   @return Returns a pp_unique_shared_page_t<T> if the shared page
        ///     is not currently in use. If an error occurs, returns an invalid
        ///     pp_unique_shared_page_t<T>.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        shared_page(syscall::bf_syscall_t const &sys) noexcept -> pp_unique_shared_page_t<T>
        {
            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

            bsl::expects(this->assigned_ppid() == sys.bf_tls_ppid());
            bsl::expects(sys.is_the_active_vm_the_root_vm());

            bsl::expects(!m_shared_page_in_use);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            return {reinterpret_cast<T *>(m_shared_page), sys, &m_shared_page_in_use};
        }
    };
}

#endif
