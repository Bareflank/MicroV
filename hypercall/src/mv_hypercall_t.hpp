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
#include <mv_exit_reason_t.hpp>
#include <mv_hypercall_impl.hpp>
#include <mv_reg_t.hpp>
#include <mv_translation_t.hpp>
#include <mv_types.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

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
        bsl::safe_u64 m_hndl{};

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
            bsl::safe_u32 mut_version{};

            mut_ret = mv_id_op_version_impl(mut_version.data());
            if (bsl::unlikely(mut_ret != MV_STATUS_SUCCESS)) {
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
            if (bsl::unlikely(mut_ret != MV_STATUS_SUCCESS)) {
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
        ///   @brief Returns the handle that is used for hypercalls. If this
        ///     class has not been initialized, a default (likely 0) handle
        ///     is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the handle that is used for hypercalls. If this
        ///     class has not been initialized, a default (likely 0) handle
        ///     is returned.
        ///
        [[nodiscard]] constexpr auto
        handle() noexcept -> bsl::safe_u64
        {
            return m_hndl;
        }

        // ---------------------------------------------------------------------
        // mv_pp_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This hypercall returns the ID of the PP that executed this
        ///     hypercall.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP that executed this hypercall.
        ///
        [[nodiscard]] constexpr auto
        mv_pp_op_ppid() noexcept -> bsl::safe_u16
        {
            bsl::safe_u16 mut_ppid;

            mv_status_t const ret{mv_pp_op_ppid_impl(m_hndl.get(), mut_ppid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_pp_op_ppid failed with status "    // --
                             << bsl::hex(ret)                          // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_ppid == MV_INVALID_ID)) {
                bsl::error() << "the PPID "                                // --
                             << bsl::hex(mut_ppid)                         // --
                             << " returned by mv_pp_op_ppid is invalid"    // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_ppid) >= HYPERVISOR_MAX_PPS)) {
                bsl::error() << "the PPID "                                     // --
                             << bsl::hex(mut_ppid)                              // --
                             << " returned by mv_pp_op_ppid is out of range"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            return mut_ppid;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to clear the GPA of the
        ///     current PP's shared page.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_pp_op_clr_shared_page_gpa() noexcept -> bsl::errc_type
        {
            mv_status_t const ret{mv_pp_op_clr_shared_page_gpa_impl(m_hndl.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_pp_op_clr_shared_page_gpa failed with status "    // --
                             << bsl::hex(ret)                                         // --
                             << bsl::endl                                             // --
                             << bsl::here();                                          // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to set the GPA of the current PP's
        ///     shared page.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gpa The GPA to set the requested PP's shared page to
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_pp_op_set_shared_page_gpa(bsl::safe_u64 const &gpa) noexcept -> bsl::errc_type
        {
            bsl::expects(gpa.is_valid_and_checked());
            bsl::expects(gpa.is_pos());
            bsl::expects(mv_is_page_aligned(gpa));

            mv_status_t const ret{mv_pp_op_set_shared_page_gpa_impl(m_hndl.get(), gpa.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_pp_op_set_shared_page_gpa failed with status "    // --
                             << bsl::hex(ret)                                         // --
                             << bsl::endl                                             // --
                             << bsl::here();                                          // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        // ---------------------------------------------------------------------
        // mv_vm_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to create a VM and return its ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the resulting ID, or bsl::safe_u16::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_vm_op_create_vm() noexcept -> bsl::safe_u16
        {
            bsl::safe_u16 mut_vmid{};

            mv_status_t const ret{mv_vm_op_create_vm_impl(m_hndl.get(), mut_vmid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vm_op_create_vm failed with status "    // --
                             << bsl::hex(ret)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_vmid == MV_INVALID_ID)) {
                bsl::error() << "the VMID "                                     // --
                             << bsl::hex(mut_vmid)                              // --
                             << " returned by mv_vm_op_create_vm is invalid"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_vmid) >= HYPERVISOR_MAX_VMS)) {
                bsl::error() << "the VMID "                                          // --
                             << bsl::hex(mut_vmid)                                   // --
                             << " returned by mv_vm_op_create_vm is out of range"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::safe_u16::failure();
            }

            return mut_vmid;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to destroy a VM given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        mv_vm_op_destroy_vm(bsl::safe_u16 const &vmid) noexcept -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != MV_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);

            mv_status_t const ret{mv_vm_op_destroy_vm_impl(m_hndl.get(), vmid.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vm_op_destroy_vm failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();                                 // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall returns the ID of the VM that executed this
        ///     hypercall.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VM that executed this hypercall.
        ///
        [[nodiscard]] constexpr auto
        mv_vm_op_vmid() noexcept -> bsl::safe_u16
        {
            bsl::safe_u16 mut_vmid;

            mv_status_t const ret{mv_vm_op_vmid_impl(m_hndl.get(), mut_vmid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vm_op_vmid failed with status "    // --
                             << bsl::hex(ret)                          // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_vmid == MV_INVALID_ID)) {
                bsl::error() << "the VMID "                                // --
                             << bsl::hex(mut_vmid)                         // --
                             << " returned by mv_vm_op_vmid is invalid"    // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_vmid) >= HYPERVISOR_MAX_VMS)) {
                bsl::error() << "the VMID "                                     // --
                             << bsl::hex(mut_vmid)                              // --
                             << " returned by mv_vm_op_vmid is out of range"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            return mut_vmid;
        }

        /// <!-- description -->
        ///   @brief This hypercall is used to map a range of physically
        ///     discontiguous guest memory from one VM to another using a Memory
        ///     Descriptor List (MDL) in the shared page. For this ABI, the dst
        ///     field in the mv_mdl_entry_t refers to the GPA to map the contiguous
        ///     memory region described by the entry to. The src field in the
        ///     mv_mdl_entry_t refers to the GPA to map the contiguous memory region
        ///     from. The dst and src VMIDs must be different. If the src VMID is
        ///     not MV_ROOT_VMID, the map is considered a foreign map and is
        ///     currently not supported (although will be in the future to support
        ///     device domains). The bytes field in the mv_mdl_entry_t must be page
        ///     aligned and cannot be 0. The flags field in the mv_mdl_entry_t
        ///     refers to Map Flags and only apply to the destination (meaning
        ///     source mappings are not affected by this hypercall). The only flags
        ///     that are supported by this hypercall are the access/permission flags
        ///     and the capability flags. Of these flags, MicroV may reject the use
        ///     of certain flags based on MicroV's configuration and which CPU
        ///     architecture is in use. mv_id_op_get_capability can be used to
        ///     determine which specific flags are supported by MicroV. Care should
        ///     be taken to ensure that both the dst and src memory is mapped with
        ///     the same cacheability. In general, the safest option is to map
        ///     MV_MAP_FLAG_WRITE_BACK from the src to MV_MAP_FLAG_WRITE_BACK in
        ///     the dst. This ABI does not use any of the reg 0-7 fields in the
        ///     mv_mdl_t. Double maps (i.e., mapping memory that is already mapped)
        ///     is undefined and may result in MicroV returning an error.
        ///
        /// <!-- inputs/outputs -->
        ///   @param dst_vmid The ID of the dst VM to map memory to
        ///   @param src_vmid The ID of the src VM to map memory from
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_vm_op_mmio_map(bsl::safe_u16 const &dst_vmid, bsl::safe_u16 const &src_vmid) noexcept
            -> bsl::errc_type
        {
            bsl::expects(dst_vmid.is_valid_and_checked());
            bsl::expects(dst_vmid != MV_INVALID_ID);
            bsl::expects(src_vmid.is_valid_and_checked());
            bsl::expects(src_vmid != MV_INVALID_ID);

            mv_status_t const ret{
                mv_vm_op_mmio_map_impl(m_hndl.get(), dst_vmid.get(), src_vmid.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vm_op_mmio_map failed with status "    // --
                             << bsl::hex(ret)                              // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall is used to unmap a range of physically
        ///     discontiguous guest memory from a VM. For this ABI, the dst field
        ///     in the mv_mdl_entry_t refers to the GPA of the contiguous memory
        ///     region to unmap. The src field is ignored. The bytes field in the
        ///     mv_mdl_entry_t must be page aligned and cannot be 0. The flags
        ///     field is ignored. This ABI does not use any of the reg 0-7 fields
        ///     in the mv_mdl_t. Double unmaps (i.e., unmapping memory that is
        ///     already unmapped) is undefined and may result in MicroV returning
        ///     an error. To ensure the unmap is seen by the processor, this
        ///     hypercall performs a TLB invalidation of all of the memory
        ///     described in the MDL. MicroV reserves the right to invalidate the
        ///     entire TLB and cache if needed. If a VM has more than one VP, this
        ///     hypercall may perform a remote TLB invalidation. How remote TLB
        ///     invalidations are performed by MicroV is undefined and left to
        ///     MicroV to determine.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to unmap memory from
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_vm_op_mmio_unmap(bsl::safe_u16 const &vmid) noexcept -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != MV_INVALID_ID);

            mv_status_t const ret{mv_vm_op_mmio_unmap_impl(m_hndl.get(), vmid.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vm_op_mmio_unmap failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();                                 // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        // ---------------------------------------------------------------------
        // mv_vp_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to create a VP given the
        ///     IDs of the VM and PP the VP will be assigned to. Upon success,
        ///     this syscall returns the ID of the newly created VP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to assign the newly created VP to
        ///   @return Returns the resulting ID, or bsl::safe_u16::failure()
        ///     on failure.
        ///
        ///
        [[nodiscard]] constexpr auto
        mv_vp_op_create_vp(bsl::safe_u16 const &vmid) noexcept -> bsl::safe_u16
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != MV_INVALID_ID);

            bsl::safe_u16 mut_vpid{};

            mv_status_t const ret{
                mv_vp_op_create_vp_impl(m_hndl.get(), vmid.get(), mut_vpid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vp_op_create_vp failed with status "    // --
                             << bsl::hex(ret)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_vpid == MV_INVALID_ID)) {
                bsl::error() << "the VPID "                                     // --
                             << bsl::hex(mut_vpid)                              // --
                             << " returned by mv_vm_op_create_vm is invalid"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_vpid) >= HYPERVISOR_MAX_VPS)) {
                bsl::error() << "the VPID "                                          // --
                             << bsl::hex(mut_vpid)                                   // --
                             << " returned by mv_vm_op_create_vm is out of range"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::safe_u16::failure();
            }

            return mut_vpid;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VP
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        mv_vp_op_destroy_vp(bsl::safe_u16 const &vpid) noexcept -> bsl::errc_type
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != MV_INVALID_ID);
            bsl::expects(bsl::to_umx(vpid) < HYPERVISOR_MAX_VPS);

            mv_status_t const ret{mv_vp_op_destroy_vp_impl(m_hndl.get(), vpid.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vp_op_destroy_vp failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();                                 // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall returns the ID of the VM the requested VP is
        ///     assigned to.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to query
        ///   @return Returns the ID of the VP the requested VP is assigned to.
        ///
        [[nodiscard]] constexpr auto
        mv_vp_op_vmid(bsl::safe_u16 const &vpid) noexcept -> bsl::safe_u16
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != MV_INVALID_ID);

            bsl::safe_u16 mut_vmid;

            mv_status_t const ret{mv_vp_op_vmid_impl(m_hndl.get(), vpid.get(), mut_vmid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vp_op_vmid failed with status "    // --
                             << bsl::hex(ret)                          // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_vmid == MV_INVALID_ID)) {
                bsl::error() << "the VMID "                                // --
                             << bsl::hex(mut_vmid)                         // --
                             << " returned by mv_vp_op_vmid is invalid"    // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_vmid) >= HYPERVISOR_MAX_VMS)) {
                bsl::error() << "the VMID "                                     // --
                             << bsl::hex(mut_vmid)                              // --
                             << " returned by mv_vp_op_vmid is out of range"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            return mut_vmid;
        }

        /// <!-- description -->
        ///   @brief This hypercall returns the ID of the VP that executed this
        ///     hypercall.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VP that executed this hypercall.
        ///
        [[nodiscard]] constexpr auto
        mv_vp_op_vpid() noexcept -> bsl::safe_u16
        {
            bsl::safe_u16 mut_vpid;

            mv_status_t const ret{mv_vp_op_vpid_impl(m_hndl.get(), mut_vpid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vp_op_vpid failed with status "    // --
                             << bsl::hex(ret)                          // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_vpid == MV_INVALID_ID)) {
                bsl::error() << "the VPID "                                // --
                             << bsl::hex(mut_vpid)                         // --
                             << " returned by mv_vp_op_vpid is invalid"    // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_vpid) >= HYPERVISOR_MAX_VPS)) {
                bsl::error() << "the VPID "                                     // --
                             << bsl::hex(mut_vpid)                              // --
                             << " returned by mv_vp_op_vpid is out of range"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            return mut_vpid;
        }

        // ---------------------------------------------------------------------
        // mv_vm_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to create a VS
        ///     and return it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to assign the newly created VS to
        ///   @return Returns the resulting ID, or bsl::safe_u16::failure()
        ///     on failure.
        ///
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_create_vs(bsl::safe_u16 const &vpid) noexcept -> bsl::safe_u16
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != MV_INVALID_ID);

            bsl::safe_u16 mut_vsid{};

            mv_status_t const ret{
                mv_vs_op_create_vs_impl(m_hndl.get(), vpid.get(), mut_vsid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_create_vs failed with status "    // --
                             << bsl::hex(ret)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();                                // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_vsid == MV_INVALID_ID)) {
                bsl::error() << "the VSID "                                     // --
                             << bsl::hex(mut_vsid)                              // --
                             << " returned by mv_vm_op_create_vm is invalid"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_vsid) >= HYPERVISOR_MAX_VSS)) {
                bsl::error() << "the VSID "                                          // --
                             << bsl::hex(mut_vsid)                                   // --
                             << " returned by mv_vm_op_create_vm is out of range"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::safe_u16::failure();
            }

            return mut_vsid;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VS
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_destroy_vs(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            mv_status_t const ret{mv_vs_op_destroy_vs_impl(m_hndl.get(), vsid.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_destroy_vs failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();                                 // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall returns the ID of the VM the requested VS is
        ///     assigned to.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to query
        ///   @return Returns the ID of the VM the requested VS is assigned to.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_vmid(bsl::safe_u16 const &vsid) noexcept -> bsl::safe_u16
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);

            bsl::safe_u16 mut_vmid;

            mv_status_t const ret{mv_vs_op_vmid_impl(m_hndl.get(), vsid.get(), mut_vmid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_vmid failed with status "    // --
                             << bsl::hex(ret)                          // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_vmid == MV_INVALID_ID)) {
                bsl::error() << "the VMID "                                // --
                             << bsl::hex(mut_vmid)                         // --
                             << " returned by mv_vs_op_vmid is invalid"    // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_vmid) >= HYPERVISOR_MAX_VMS)) {
                bsl::error() << "the VMID "                                     // --
                             << bsl::hex(mut_vmid)                              // --
                             << " returned by mv_vs_op_vmid is out of range"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            return mut_vmid;
        }

        /// <!-- description -->
        ///   @brief This hypercall returns the ID of the VP the requested VS is
        ///     assigned to.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to query
        ///   @return Returns the ID of the VP the requested VS is assigned to.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_vpid(bsl::safe_u16 const &vsid) noexcept -> bsl::safe_u16
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);

            bsl::safe_u16 mut_vpid;

            mv_status_t const ret{mv_vs_op_vpid_impl(m_hndl.get(), vsid.get(), mut_vpid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_vpid failed with status "    // --
                             << bsl::hex(ret)                          // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_vpid == MV_INVALID_ID)) {
                bsl::error() << "the VPID "                                // --
                             << bsl::hex(mut_vpid)                         // --
                             << " returned by mv_vs_op_vpid is invalid"    // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_vpid) >= HYPERVISOR_MAX_VPS)) {
                bsl::error() << "the VPID "                                     // --
                             << bsl::hex(mut_vpid)                              // --
                             << " returned by mv_vs_op_vpid is out of range"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            return mut_vpid;
        }

        /// <!-- description -->
        ///   @brief This hypercall returns the ID of the VS that executed this
        ///     hypercall.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VS that executed this hypercall.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_vsid() noexcept -> bsl::safe_u16
        {
            bsl::safe_u16 mut_vsid;

            mv_status_t const ret{mv_vs_op_vsid_impl(m_hndl.get(), mut_vsid.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_vsid failed with status "    // --
                             << bsl::hex(ret)                          // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(mut_vsid == MV_INVALID_ID)) {
                bsl::error() << "the VSID "                                // --
                             << bsl::hex(mut_vsid)                         // --
                             << " returned by mv_vs_op_vsid is invalid"    // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::safe_u16::failure();
            }

            if (bsl::unlikely(bsl::to_umx(mut_vsid) >= HYPERVISOR_MAX_VSS)) {
                bsl::error() << "the VSID "                                     // --
                             << bsl::hex(mut_vsid)                              // --
                             << " returned by mv_vs_op_vsid is out of range"    // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return bsl::safe_u16::failure();
            }

            return mut_vsid;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to translate the provided
        ///     guest linear address (GLA) to a guest physical address (GPA).
        ///     To perform this translation, MicroV will perform a linear to
        ///     physical address conversion using the current state of CR0,
        ///     CR3, and CR4. To perform this translation, software must
        ///     provide the ID of the VS whose state will be used during
        ///     translation and the the GLA to translate. How the translation
        ///     occurs depends on whether or not the VS is in 16bit real mode,
        ///     32bit protected mode, 32bit protected mode with paging enabled,
        ///     or 64bit long mode. If the VS is in 16bit real mode or 32bit
        ///     protected mode with paging disabled, no translation is
        ///     performed and the provided GLA is returned as the GPA. If the
        ///     VS is in 32bit protected mode with paging enabled or 64bit
        ///     long mode, MicroV will walk the guest page tables pointed to by
        ///     CR3 in the VS and return the resulting GPA and GPA flags used
        ///     to map the GLA to the GPA (caching flags are not included). If
        ///     the translation fails for any reason, the resulting GPA is
        ///     undefined.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to use for the translation
        ///   @param gla The GLA to translate
        ///   @return Returns an mv_translation_t containing the results of
        ///     the translation.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_gla_to_gpa(bsl::safe_u16 const &vsid, bsl::safe_u64 const &gla) const noexcept
            -> mv_translation_t
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);
            bsl::expects(gla.is_valid_and_checked());
            bsl::expects(gla.is_pos());
            bsl::expects(mv_is_page_aligned(gla));

            bsl::safe_u64 mut_gpa_and_flags{};
            constexpr auto gpa_mask{0xFFFFFFFFFFFFF000_u64};
            constexpr auto fgs_mask{0x0000000000000FFF_u64};

            mv_status_t const ret{mv_vs_op_gla_to_gpa_impl(
                m_hndl.get(), vsid.get(), gla.get(), mut_gpa_and_flags.data())};

            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_gla_to_gpa_impl failed with status "    // --
                             << bsl::hex(ret)                                     // --
                             << bsl::endl                                         // --
                             << bsl::here();                                      // --

                return {{}, {}, {}, {}, false};
            }

            return {{}, gla, (mut_gpa_and_flags & gpa_mask), (mut_gpa_and_flags & fgs_mask), true};
        }

        /// <!-- description -->
        ///   @brief This hypercall executes a VM's VP using the requested VS.
        ///     The VM and VP that are executed is determined by which VM and VP
        ///     were assigned during the creation of the VP and VS. This hypercall
        ///     does not return until an exit condition occurs, or an error is
        ///     encountered. The exit condition can be identified using the output
        ///     REG0 which defines the "exit reason". Whenever mv_vs_op_run is
        ///     executed, MicroV reads the shared page using a mv_run_t as input.
        ///     When mv_vs_op_run returns, and no error has occurred, the shared
        ///     page's contents depends on the exit condition. For some exit
        ///     conditions, the shared page is ignored. In other cases, a structure
        ///     specific to the exit condition is returned providing software with
        ///     the information that it needs to handle the exit.
        ///
        /// <!-- inputs/outputs -->s
        ///   @param vsid The ID of the VS to run
        ///   @return Returns A mv_exit_reason_t describing the reason for the exit
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_run(bsl::safe_u16 const &vsid) noexcept -> mv_exit_reason_t
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            mv_exit_reason_t mut_exit_reason{};

            mv_status_t const ret{mv_vs_op_run_impl(m_hndl.get(), vsid.get(), &mut_exit_reason)};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_run failed with status "    // --
                             << bsl::hex(ret)                         // --
                             << bsl::endl                             // --
                             << bsl::here();                          // --

                return mut_exit_reason;
            }

            return mut_exit_reason;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to return the value of a requested
        ///     register. Not all registers values require 64 bits. Any unused bits
        ///     are REVI.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to query
        ///   @param reg The register to get
        ///   @return Returns the value read from the requested register
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_reg_get(bsl::safe_u16 const &vsid, mv_reg_t const reg) noexcept -> bsl::safe_u64
        {
            bsl::safe_u64 mut_val{};

            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);
            bsl::expects(reg < mv_reg_t::mv_reg_t_invalid);

            mv_status_t const ret{
                mv_vs_op_reg_get_impl(m_hndl.get(), vsid.get(), reg, mut_val.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_reg_get failed with status "    // --
                             << bsl::hex(ret)                             // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::safe_u64::failure();
            }

            return mut_val;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to set the value of a requested
        ///     register. Not all registers values require 64 bits. Any unused bits
        ///     are REVI.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to set
        ///   @param reg The register to set
        ///   @param val The value to write to the requested register
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_reg_set(
            bsl::safe_u16 const &vsid, mv_reg_t const reg, bsl::safe_u64 const &val) noexcept
            -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);
            bsl::expects(reg < mv_reg_t::mv_reg_t_invalid);
            bsl::expects(val.is_valid_and_checked());

            mv_status_t const ret{mv_vs_op_reg_set_impl(m_hndl.get(), vsid.get(), reg, val.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_reg_set failed with status "    // --
                             << bsl::hex(ret)                             // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to return the values of multiple
        ///     requested registers using a Register Descriptor List (RDL) in the
        ///     shared page. For this ABI, the reg field of each mv_rdl_entry_t
        ///     refers to an mv_reg_t. The val field refers to the returned value
        ///     of the requested register in that entry. Not all registers values
        ///     require 64 bits. Any unused bits are REVI. This ABI does not use
        ///     any of the reg 0-7 fields in the mv_rdl_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to query
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_reg_get_list(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);

            mv_status_t const ret{mv_vs_op_reg_get_list_impl(m_hndl.get(), vsid.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_reg_get_list failed with status "    // --
                             << bsl::hex(ret)                                  // --
                             << bsl::endl                                      // --
                             << bsl::here();                                   // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to set the values of multiple
        ///     requested registers using a Register Descriptor List (RDL) in the
        ///     shared page. For this ABI, the reg field of each mv_rdl_entry_t
        ///     refers to an mv_reg_t. The val field refers to the value to set the
        ///     requested register in that entry to. Not all registers values
        ///     require 64 bits. Any unused bits are REVI. This ABI does not use any
        ///     of the reg 0-7 fields in the mv_rdl_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to set
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_reg_set_list(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);

            mv_status_t const ret{mv_vs_op_reg_set_list_impl(m_hndl.get(), vsid.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_reg_set_list failed with status "    // --
                             << bsl::hex(ret)                                  // --
                             << bsl::endl                                      // --
                             << bsl::here();                                   // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to return the value of a
        ///     requested MSR.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to query
        ///   @param msr The index of the MSR to get
        ///   @return Returns the value read from the MSR
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_msr_get(bsl::safe_u16 const &vsid, bsl::safe_u32 const &msr) noexcept
            -> bsl::safe_u64
        {
            bsl::safe_u64 mut_val{};

            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);
            bsl::expects(msr.is_valid_and_checked());

            mv_status_t const ret{
                mv_vs_op_msr_get_impl(m_hndl.get(), vsid.get(), msr.get(), mut_val.data())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_msr_get failed with status "    // --
                             << bsl::hex(ret)                             // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::safe_u64::failure();
            }

            return mut_val;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to set the value of a
        ///     requested MSR.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to set
        ///   @param msr The index of the MSR to set
        ///   @param val The value to write to the requested MSR
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_msr_set(
            bsl::safe_u16 const &vsid, bsl::safe_u32 const &msr, bsl::safe_u64 const &val) noexcept
            -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);
            bsl::expects(msr.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            mv_status_t const ret{
                mv_vs_op_msr_set_impl(m_hndl.get(), vsid.get(), msr.get(), val.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_msr_set failed with status "    // --
                             << bsl::hex(ret)                             // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to return the values of multiple
        ///     requested MSRs using a Register Descriptor List (RDL) in the shared
        ///     page. For this ABI, the reg field of each mv_rdl_entry_t refers to
        ///     the index of the MSR. The val field refers to the returned value of
        ///     the requested MSR in that entry. This ABI does not use any of the
        ///     reg 0-7 fields in the mv_rdl_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to query
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_msr_get_list(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);

            mv_status_t const ret{mv_vs_op_msr_get_list_impl(m_hndl.get(), vsid.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_msr_get_list failed with status "    // --
                             << bsl::hex(ret)                                  // --
                             << bsl::endl                                      // --
                             << bsl::here();                                   // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This hypercall tells MicroV to set the values of multiple
        ///     requested MSRs using a Register Descriptor List (RDL) in the shared
        ///     page. For this ABI, the reg field of each mv_rdl_entry_t refers to
        ///     the index of the MSR. The val field refers to the value to set the
        ///     requested MSR in that entry to. This ABI does not use any of the
        ///     reg 0-7 fields in the mv_rdl_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to set
        ///   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
        ///     and friends on failure.
        ///
        [[nodiscard]] constexpr auto
        mv_vs_op_msr_set_list(bsl::safe_u16 const vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != MV_INVALID_ID);

            mv_status_t const ret{mv_vs_op_msr_set_list_impl(m_hndl.get(), vsid.get())};
            if (bsl::unlikely(ret != MV_STATUS_SUCCESS)) {
                bsl::error() << "mv_vs_op_msr_set_list failed with status "    // --
                             << bsl::hex(ret)                                  // --
                             << bsl::endl                                      // --
                             << bsl::here();                                   // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }
    };
}

#endif
