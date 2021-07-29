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

#ifndef VPS_T_HPP
#define VPS_T_HPP

#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <bf_syscall_t.hpp>
#include <emulated_cpuid_t.hpp>
#include <emulated_cr_t.hpp>
#include <emulated_decoder_t.hpp>
#include <emulated_io_t.hpp>
#include <emulated_ioapic_t.hpp>
#include <emulated_lapic_t.hpp>
#include <emulated_mmio_t.hpp>
#include <emulated_msr_t.hpp>
#include <emulated_pic_t.hpp>
#include <emulated_pit_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <pdpt_t.hpp>
#include <pdpte_t.hpp>
#include <pdt_t.hpp>
#include <pdte_t.hpp>
#include <pml4t_t.hpp>
#include <pml4te_t.hpp>
#include <pp_pool_t.hpp>
#include <pt_t.hpp>
#include <pte_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace microv
{
    /// @class microv::vps_t
    ///
    /// <!-- description -->
    ///   @brief Defines Microv's virtual processor state.
    ///
    class vps_t final
    {
        /// @brief stores the ID associated with this vps_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};
        /// @brief stores whether or not this vm_t is allocated.
        allocated_status_t m_allocated{allocated_status_t::deallocated};
        /// @brief stores the ID of the VM this vps_t is assigned to
        bsl::safe_uint16 m_assigned_vmid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the VP this vps_t is assigned to
        bsl::safe_uint16 m_assigned_vpid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the PP this vps_t is assigned to
        bsl::safe_uint16 m_assigned_ppid{syscall::BF_INVALID_ID};

        /// @brief stores this vps_t's emulated_cpuid_t
        emulated_cpuid_t m_emulated_cpuid{};
        /// @brief stores this vps_t's emulated_cr_t
        emulated_cr_t m_emulated_cr{};
        /// @brief stores this vps_t's emulated_decoder_t
        emulated_decoder_t m_emulated_decoder{};
        /// @brief stores this vps_t's emulated_io_t
        emulated_io_t m_emulated_io{};
        /// @brief stores this vps_t's emulated_ioapic_t
        emulated_ioapic_t m_emulated_ioapic{};
        /// @brief stores this vps_t's emulated_lapic_t
        emulated_lapic_t m_emulated_lapic{};
        /// @brief stores this vps_t's emulated_mmio_t
        emulated_mmio_t m_emulated_mmio{};
        /// @brief stores this vps_t's emulated_msr_t
        emulated_msr_t m_emulated_msr{};
        /// @brief stores this vps_t's emulated_pic_t
        emulated_pic_t m_emulated_pic{};
        /// @brief stores this vps_t's emulated_pit_t
        emulated_pit_t m_emulated_pit{};

        /// <!-- description -->
        ///   @brief Returns the masked version of the VMCS control fields
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value of the control fields read from the MSRs
        ///   @return The masked version of the control fields.
        ///
        [[nodiscard]] constexpr auto
        ctls_mask(bsl::safe_uint64 const &val) noexcept -> bsl::safe_uint64
        {
            constexpr auto mask{0x00000000FFFFFFFF_u64};
            constexpr auto shift{32_u64};
            return (val & mask) & (val >> shift);
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param i the ID for this vps_t
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
                bsl::error() << "vps_t already initialized\n" << bsl::here();
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

            mut_ret = m_emulated_cpuid.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_emulated_cr.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_emulated_decoder.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_emulated_io.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_emulated_ioapic.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_emulated_lapic.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_emulated_mmio.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_emulated_msr.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_emulated_pic.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = m_emulated_pit.initialize(gs, tls, sys, intrinsic);
            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            m_id = i;

            mut_release_vm_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vps_t.
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

            m_emulated_cpuid.release(gs, tls, sys, intrinsic);
            m_emulated_cr.release(gs, tls, sys, intrinsic);
            m_emulated_decoder.release(gs, tls, sys, intrinsic);
            m_emulated_io.release(gs, tls, sys, intrinsic);
            m_emulated_ioapic.release(gs, tls, sys, intrinsic);
            m_emulated_lapic.release(gs, tls, sys, intrinsic);
            m_emulated_mmio.release(gs, tls, sys, intrinsic);
            m_emulated_msr.release(gs, tls, sys, intrinsic);
            m_emulated_pic.release(gs, tls, sys, intrinsic);
            m_emulated_pit.release(gs, tls, sys, intrinsic);

            m_id = bsl::safe_uint16::failure();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vp_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates a vps_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the vps_t to
        ///   @param vpid the ID of the VP to assign the vps_t to
        ///   @param ppid the ID of the PP to assign the vps_t to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vmid,
            bsl::safe_uint16 const &vpid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            bsl::errc_type mut_ret{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vps "                                    // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be allocated"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::allocated)) {
                bsl::error() << "vps "                                           // --
                             << bsl::hex(m_id)                                   // --
                             << " is already allocated and cannot be created"    // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!vmid)) {
                bsl::error() << "invalid vmid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == vmid)) {
                bsl::error() << "vm "                                               // --
                             << bsl::hex(vmid)                                      // --
                             << " is invalid and a vps cannot be assigned to it"    // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == vpid)) {
                bsl::error() << "vp "                                               // --
                             << bsl::hex(vpid)                                      // --
                             << " is invalid and a vps cannot be assigned to it"    // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == ppid)) {
                bsl::error() << "pp "                                              // --
                             << bsl::hex(ppid)                                     // --
                             << " is invalid and a vp cannot be assigned to it"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_invalid_argument;
            }

            if (ppid == m_id) {
                mut_ret = mut_sys.bf_vps_op_init_as_root(m_id);
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            constexpr auto vmcs_vpid_val{0x1_u64};
            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier, vmcs_vpid_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            constexpr auto vmcs_link_ptr_val{0xFFFFFFFFFFFFFFFF_u64};
            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer, vmcs_link_ptr_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            constexpr auto ia32_vmx_true_pinbased_ctls{0x48D_u32};
            constexpr auto ia32_vmx_true_procbased_ctls{0x48E_u32};
            constexpr auto ia32_vmx_true_exit_ctls{0x48F_u32};
            constexpr auto ia32_vmx_true_entry_ctls{0x490_u32};
            constexpr auto ia32_vmx_true_procbased_ctls2{0x48B_u32};

            bsl::safe_uintmax mut_ctls{};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_pinbased_ctls);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls, ctls_mask(mut_ctls));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            constexpr auto enable_msr_bitmaps{0x10000000_u64};
            constexpr auto enable_procbased_ctls2{0x80000000_u64};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_procbased_ctls);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ctls |= enable_msr_bitmaps;
            mut_ctls |= enable_procbased_ctls2;

            mut_ret = mut_sys.bf_vps_op_write(
                m_id,
                syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls,
                ctls_mask(mut_ctls));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_exit_ctls);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_vmexit_ctls, ctls_mask(mut_ctls));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_entry_ctls);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_vmentry_ctls, ctls_mask(mut_ctls));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            constexpr auto enable_vpid{0x00000020_u64};
            constexpr auto enable_rdtscp{0x00000008_u64};
            constexpr auto enable_invpcid{0x00001000_u64};
            constexpr auto enable_xsave{0x00100000_u64};
            constexpr auto enable_uwait{0x04000000_u64};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_procbased_ctls2);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ctls |= enable_vpid;
            mut_ctls |= enable_rdtscp;
            mut_ctls |= enable_invpcid;
            mut_ctls |= enable_xsave;
            mut_ctls |= enable_uwait;

            mut_ret = mut_sys.bf_vps_op_write(
                m_id,
                syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls,
                ctls_mask(mut_ctls));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps, gs.msr_bitmap_phys);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            m_assigned_vmid = vmid;
            m_assigned_vpid = vpid;
            m_assigned_ppid = ppid;

            m_allocated = allocated_status_t::allocated;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Deallocates a vps_t.
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
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vps "                                    // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be destroyed"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                               // --
                             << bsl::hex(m_id)                                       // --
                             << " is already deallocated and cannot be destroyed"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::errc_precondition;
            }

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_assigned_vmid = syscall::BF_INVALID_ID;

            m_allocated = allocated_status_t::deallocated;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vps_t's status as zombified, meaning it is no
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

            bsl::alert() << "vps "                   // --
                         << bsl::hex(m_id)           // --
                         << " has been zombified"    // --
                         << bsl::endl;               // --

            m_allocated = allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is a zombie, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is a zombie, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_zombie() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is a root VPS. Returns false if
        ///     this vps_t is not a root VPS or an error occurs.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is a root VPS. Returns false if
        ///     this vps_t is not a root VPS or an error occurs.
        ///
        [[nodiscard]] constexpr auto
        is_root_vps() const noexcept -> bool
        {
            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == m_assigned_vmid)) {
                bsl::error() << "vps_t not allocated\n" << bsl::here();
                return false;
            }

            return syscall::BF_ROOT_VMID == m_assigned_vmid;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is a guest VPS. Returns false if
        ///     this vps_t is not a guest VPS or an error occurs.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is a guest VPS. Returns false if
        ///     this vps_t is not a guest VPS or an error occurs.
        ///
        [[nodiscard]] constexpr auto
        is_guest_vps() const noexcept -> bool
        {
            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == m_assigned_vmid)) {
                bsl::error() << "vps_t not allocated\n" << bsl::here();
                return false;
            }

            return syscall::BF_ROOT_VMID != m_assigned_vmid;
        }

        /// <!-- description -->
        ///   @brief Translates a guest GVA to a guest GPA using the paging
        ///     configuration of the guest stored in CR0 and CR4. Translation
        ///     occurs using whatever CR3 the VPS has as the root page table
        ///     to parse, and the pp_pool it uses to map in guest page tables
        ///     during translation.
        ///
        /// <!-- notes -->
        ///   @note This function is slow. It has to map in guest page tables
        ///     so that it can walk these tables and perform the translation.
        ///     Once the translation is done, these translations are unmapped.
        ///     If we didn't do this, the direct map would become polluted with
        ///     maps that are no longer needed.
        ///
        ///   @note IMPORTANT: One way to improve performance of code that
        ///     uses this function is to cache these translations. This would
        ///     implement a virtual TLB. You might not call it that, but that
        ///     is what it is. If you store ANY translations, you must clear
        ///     them when the guest attempts to perform any TLB invalidations,
        ///     as the translation might not be valid any more. This is made
        ///     even worse with remote TLB invalidations that the guest
        ///     performs because the hypervisor has to mimic the same behaviour
        ///     that any race conditions introduce. For example, if you are in
        ///     the middle of emulating an instruction on one CPU, and another
        ///     performs a race condition, emulation needs to complete before
        ///     the invalidation takes place. Otherwise, a use-after-free
        ///     bug could occur. This only applies to the decoding portion of
        ///     emulation as the CPU is pipelined. Reads/writes to memory
        ///     during the rest of emulation may still read garbage, and that
        ///     is what the CPU would do. To simplify this, all translations
        ///     should ALWAYS come from this function. Meaning, if a translation
        ///     must be stored, it should be stored here in a virtual TLB. This
        ///     way, any invalidations to a VP can be flushed in the VPS. If
        ///     all functions always have to call this function, it will simply
        ///     return a cached translation. If the cache is flushed because
        ///     the guest performed a flush, the translation process will
        ///     automatically happen. This way, software always does the GVA
        ///     to GPA conversion when it is needed, and only when it is needed
        ///     the same way the hardware would, and then uses this GPA to
        ///     determine what the SPA is. If the SPA is the same, it can use a
        ///     cached map that it already has. If not, it must release the
        ///     previous map and ask the PP for a new one with the new SPA.
        ///     This will ensure there are no issues with TLB flushing and
        ///     caching, and still be performant. For now, we don't use a cache.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_pp_pool the pp_pool_t to use
        ///   @param gva the GVA to translate to a GPA
        ///   @return Returns the GPA associated with the provided GVA on
        ///     success, or bsl::safe_uint64::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        gva_to_gpa(
            syscall::bf_syscall_t &mut_sys,
            pp_pool_t &mut_pp_pool,
            bsl::safe_uint64 const &gva) noexcept -> bsl::safe_uint64
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::safe_uint64::failure();
            }

            if (bsl::unlikely_assert(!gva)) {
                bsl::error() << "invalid gva\n" << bsl::here();
                return bsl::safe_uint64::failure();
            }

            auto const cr0{mut_sys.bf_vps_op_read(m_id, syscall::bf_reg_t::bf_reg_t_guest_cr0)};
            if (bsl::unlikely_assert(!cr0)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint64::failure();
            }

            auto const cr3{mut_sys.bf_vps_op_read(m_id, syscall::bf_reg_t::bf_reg_t_guest_cr3)};
            if (bsl::unlikely_assert(!cr0)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint64::failure();
            }

            auto const cr4{mut_sys.bf_vps_op_read(m_id, syscall::bf_reg_t::bf_reg_t_guest_cr4)};
            if (bsl::unlikely_assert(!cr0)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint64::failure();
            }

            auto const pml4t{mut_pp_pool.map<pml4t_t const *>(mut_sys, cr3)};
            if (bsl::unlikely_assert(!pml4t)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint64::failure();
            }

            return bsl::safe_uint64::failure();
        }
    };
}

#endif
