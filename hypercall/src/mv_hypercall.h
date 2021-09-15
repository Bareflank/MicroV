/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MV_HYPERCALL_H
#define MV_HYPERCALL_H

#include <debug.h>
#include <mv_constants.h>
#include <mv_exit_reason_t.h>
#include <mv_hypercall_impl.h>
#include <mv_reg_t.h>
#include <mv_translation_t.h>
#include <mv_types.h>
#include <platform.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ---------------------------------------------------------------------- */
    /* mv_id_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to return the version of the spec
     *     that it supports.
     *
     * <!-- inputs/outputs -->
     *   @return Returns which versions of the spec MicroV supports
     */
    NODISCARD static inline uint32_t
    mv_id_op_version(void) NOEXCEPT
    {
        uint32_t version = ((uint32_t)0);
        if (mv_id_op_version_impl(&version) != MV_STATUS_SUCCESS) {
            return MV_INVALID_VERSION;
        }

        return version;
    }

    /* ---------------------------------------------------------------------- */
    /* mv_handle_ops                                                          */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief This hypercall returns the handle that is required to execute the
     *     remaining hypercalls.
     *
     * <!-- inputs/outputs -->
     *   @param version The version of this spec that software supports
     *   @return Returns the resulting handle which is the value to set REG0 to for
     *     most other hypercalls
     */
    NODISCARD static inline uint64_t
    mv_handle_op_open_handle(uint32_t const version) NOEXCEPT
    {
        uint64_t hndl = ((uint64_t)0);
        if (mv_handle_op_open_handle_impl(version, &hndl) != MV_STATUS_SUCCESS) {
            return MV_INVALID_HANDLE;
        }

        return hndl;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall closes a previously opened handle.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_handle_op_close_handle(uint64_t const hndl) NOEXCEPT
    {
        return mv_handle_op_close_handle_impl(hndl);
    }

    /* ---------------------------------------------------------------------- */
    /* mv_pp_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief This hypercall returns the ID of the PP that executed this
     *     hypercall.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns the ID of the PP that executed this hypercall.
     */
    NODISCARD static inline uint16_t
    mv_pp_op_ppid(uint64_t const hndl) NOEXCEPT
    {
        uint16_t mut_ppid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));

        if (mv_pp_op_ppid_impl(hndl, &mut_ppid)) {
            bferror("mv_pp_op_ppid failed");
            return MV_INVALID_ID;
        }

        if (mut_ppid == MV_INVALID_ID) {
            bferror("the PPID returned by mv_pp_op_ppid is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_ppid >= HYPERVISOR_MAX_PPS) {
            bferror("the PPID returned by mv_pp_op_ppid is out of range");
            return MV_INVALID_ID;
        }

        return mut_ppid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to clear the GPA of the
     *     current PP's shared page.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_pp_op_clr_shared_page_gpa(uint64_t const hndl) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));

        mut_ret = mv_pp_op_clr_shared_page_gpa_impl(hndl);
        if (mut_ret) {
            bferror("mv_pp_op_clr_shared_page_gpa failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to set the GPA of the current PP's
     *     shared page.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param gpa The GPA to set the requested PP's shared page to
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_pp_op_set_shared_page_gpa(uint64_t const hndl, uint64_t const gpa) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(gpa > ((uint64_t)0));
        platform_expects(mv_is_page_aligned(gpa));

        mut_ret = mv_pp_op_set_shared_page_gpa_impl(hndl, gpa);
        if (mut_ret) {
            bferror("mv_pp_op_set_shared_page_gpa failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /* ---------------------------------------------------------------------- */
    /* mv_vm_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to create a VM and return its ID.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns the resulting ID of the newly created VM
     */
    NODISCARD static inline uint16_t
    mv_vm_op_create_vm(uint64_t const hndl) NOEXCEPT
    {
        uint16_t mut_vmid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));

        if (mv_vm_op_create_vm_impl(hndl, &mut_vmid)) {
            bferror("mv_vm_op_create_vm failed");
            return MV_INVALID_ID;
        }

        if (mut_vmid == MV_INVALID_ID) {
            bferror("the VMID returned by mv_vm_op_create_vm is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_vmid >= HYPERVISOR_MAX_VMS) {
            bferror("the VMID returned by mv_vm_op_create_vm is out of range");
            return MV_INVALID_ID;
        }

        return mut_vmid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to destroy a VM given an ID.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vmid The ID of the VM to destroy
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_destroy_vm(uint64_t const hndl, uint16_t const vmid) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vmid != MV_INVALID_ID);
        platform_expects(((uint64_t)vmid) < HYPERVISOR_MAX_VMS);

        mut_ret = mv_vm_op_destroy_vm_impl(hndl, vmid);
        if (mut_ret) {
            bferror("mv_vm_op_destroy_vm failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall returns the ID of the VM that executed this
     *     hypercall.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns the ID of the VM that executed this hypercall.
     */
    NODISCARD static inline uint16_t
    mv_vm_op_vmid(uint64_t const hndl) NOEXCEPT
    {
        uint16_t mut_vmid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));

        if (mv_vm_op_vmid_impl(hndl, &mut_vmid)) {
            bferror("mv_vm_op_vmid failed");
            return MV_INVALID_ID;
        }

        if (mut_vmid == MV_INVALID_ID) {
            bferror("the VMID returned by mv_vm_op_vmid is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_vmid >= HYPERVISOR_MAX_VMS) {
            bferror("the VMID returned by mv_vm_op_vmid is out of range");
            return MV_INVALID_ID;
        }

        return mut_vmid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall is used to map a range of physically
     *     discontiguous guest memory from one VM to another using a Memory
     *     Descriptor List (MDL) in the shared page. For this ABI, the dst
     *     field in the mv_mdl_entry_t refers to the GPA to map the contiguous
     *     memory region described by the entry to. The src field in the
     *     mv_mdl_entry_t refers to the GPA to map the contiguous memory region
     *     from. The dst and src VMIDs must be different. If the src VMID is
     *     not MV_ROOT_VMID, the map is considered a foreign map and is
     *     currently not supported (although will be in the future to support
     *     device domains). The bytes field in the mv_mdl_entry_t must be page
     *     aligned and cannot be 0. The flags field in the mv_mdl_entry_t
     *     refers to Map Flags and only apply to the destination (meaning
     *     source mappings are not affected by this hypercall). The only flags
     *     that are supported by this hypercall are the access/permission flags
     *     and the capability flags. Of these flags, MicroV may reject the use
     *     of certain flags based on MicroV's configuration and which CPU
     *     architecture is in use. mv_id_op_get_capability can be used to
     *     determine which specific flags are supported by MicroV. Care should
     *     be taken to ensure that both the dst and src memory is mapped with
     *     the same cacheability. In general, the safest option is to map
     *     MV_MAP_FLAG_WRITE_BACK from the src to MV_MAP_FLAG_WRITE_BACK in
     *     the dst. This ABI does not use any of the reg 0-7 fields in the
     *     mv_mdl_t. Double maps (i.e., mapping memory that is already mapped)
     *     is undefined and may result in MicroV returning an error.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param dst_vmid The ID of the dst VM to map memory to
     *   @param src_vmid The ID of the src VM to map memory from
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_mmio_map(
        uint64_t const hndl, uint16_t const dst_vmid, uint16_t const src_vmid) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(dst_vmid != MV_INVALID_ID);
        platform_expects(src_vmid != MV_INVALID_ID);

        mut_ret = mv_vm_op_mmio_map_impl(hndl, dst_vmid, src_vmid);
        if (mut_ret) {
            bferror("mv_vm_op_mmio_map failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall is used to unmap a range of physically
     *     discontiguous guest memory from a VM. For this ABI, the dst field
     *     in the mv_mdl_entry_t refers to the GPA of the contiguous memory
     *     region to unmap. The src field is ignored. The bytes field in the
     *     mv_mdl_entry_t must be page aligned and cannot be 0. The flags
     *     field is ignored. This ABI does not use any of the reg 0-7 fields
     *     in the mv_mdl_t. Double unmaps (i.e., unmapping memory that is
     *     already unmapped) is undefined and may result in MicroV returning
     *     an error. To ensure the unmap is seen by the processor, this
     *     hypercall performs a TLB invalidation of all of the memory
     *     described in the MDL. MicroV reserves the right to invalidate the
     *     entire TLB and cache if needed. If a VM has more than one VP, this
     *     hypercall may perform a remote TLB invalidation. How remote TLB
     *     invalidations are performed by MicroV is undefined and left to
     *     MicroV to determine.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vmid The ID of the VM to unmap memory from
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_mmio_unmap(uint64_t const hndl, uint16_t const vmid) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vmid != MV_INVALID_ID);

        mut_ret = mv_vm_op_mmio_unmap_impl(hndl, vmid);
        if (mut_ret) {
            bferror("mv_vm_op_mmio_unmap failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /* ---------------------------------------------------------------------- */
    /* mv_vp_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to create a VP given the ID of
     *     the VM the VP will be assigned to. Upon success, this hypercall
     *     returns the ID of the newly created VP.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vmid The ID of the VM to assign the newly created VP to
     *   @return Returns the resulting ID of the newly created VP
     */
    NODISCARD static inline uint16_t
    mv_vp_op_create_vp(uint64_t const hndl, uint16_t const vmid) NOEXCEPT
    {
        uint16_t mut_vpid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vmid != MV_INVALID_ID);

        if (mv_vp_op_create_vp_impl(hndl, vmid, &mut_vpid)) {
            bferror("mv_vp_op_create_vp failed");
            return MV_INVALID_ID;
        }

        if (mut_vpid == MV_INVALID_ID) {
            bferror("the VPID returned by mv_vp_op_create_vp is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_vpid >= HYPERVISOR_MAX_VPS) {
            bferror("the VPID returned by mv_vp_op_create_vp is out of range");
            return MV_INVALID_ID;
        }

        return mut_vpid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to destroy a VP given an ID.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vpid The ID of the VP to destroy
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vp_op_destroy_vp(uint64_t const hndl, uint16_t const vpid) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vpid != MV_INVALID_ID);
        platform_expects(((uint64_t)vpid) < HYPERVISOR_MAX_VPS);

        mut_ret = mv_vp_op_destroy_vp_impl(hndl, vpid);
        if (mut_ret) {
            bferror("mv_vp_op_destroy_vp failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall returns the ID of the VM the requested VP is
     *     assigned to.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vpid The ID of the VP to query
     *   @return Returns the ID of the VP the requested VP is assigned to.
     */
    NODISCARD static inline uint16_t
    mv_vp_op_vmid(uint64_t const hndl, uint16_t const vpid) NOEXCEPT
    {
        uint16_t mut_vmid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vpid != MV_INVALID_ID);

        if (mv_vp_op_vmid_impl(hndl, vpid, &mut_vmid)) {
            bferror("mv_vp_op_vmid failed");
            return MV_INVALID_ID;
        }

        if (mut_vmid == MV_INVALID_ID) {
            bferror("the VMID returned by mv_vp_op_vmid is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_vmid >= HYPERVISOR_MAX_VMS) {
            bferror("the VMID returned by mv_vp_op_vmid is out of range");
            return MV_INVALID_ID;
        }

        return mut_vmid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall returns the ID of the VP that executed this
     *     hypercall.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns the ID of the VP that executed this hypercall.
     */
    NODISCARD static inline uint16_t
    mv_vp_op_vpid(uint64_t const hndl) NOEXCEPT
    {
        uint16_t mut_vpid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));

        if (mv_vp_op_vpid_impl(hndl, &mut_vpid)) {
            bferror("mv_vp_op_vpid failed");
            return MV_INVALID_ID;
        }

        if (mut_vpid == MV_INVALID_ID) {
            bferror("the VPID returned by mv_vp_op_vpid is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_vpid >= HYPERVISOR_MAX_VPS) {
            bferror("the VPID returned by mv_vp_op_vpid is out of range");
            return MV_INVALID_ID;
        }

        return mut_vpid;
    }

    /* ---------------------------------------------------------------------- */
    /* mv_vs_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to create a VS given the ID of
     *     the VP the VS will be assigned to. Upon success, this hypercall
     *     returns the ID of the newly created VS.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vpid The ID of the VP to assign the newly created VS to
     *   @return Returns the resulting ID of the newly created VS
     */
    NODISCARD static inline uint16_t
    mv_vs_op_create_vs(uint64_t const hndl, uint16_t const vpid) NOEXCEPT
    {
        uint16_t mut_vsid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vpid != MV_INVALID_ID);

        if (mv_vs_op_create_vs_impl(hndl, vpid, &mut_vsid)) {
            bferror("mv_vs_op_create_vs failed");
            return MV_INVALID_ID;
        }

        if (mut_vsid == MV_INVALID_ID) {
            bferror("the VSID returned by mv_vs_op_create_vs is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_vsid >= HYPERVISOR_MAX_VSS) {
            bferror("the VSID returned by mv_vs_op_create_vs is out of range");
            return MV_INVALID_ID;
        }

        return mut_vsid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to destroy a VS given an ID.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to destroy
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_destroy_vs(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);
        platform_expects(((uint64_t)vsid) < HYPERVISOR_MAX_VPS);

        mut_ret = mv_vs_op_destroy_vs_impl(hndl, vsid);
        if (mut_ret) {
            bferror("mv_vs_op_destroy_vs failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall returns the ID of the VM the requested VS is
     *     assigned to.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to query
     *   @return Returns the ID of the VM the requested VS is assigned to.
     */
    NODISCARD static inline uint16_t
    mv_vs_op_vmid(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        uint16_t mut_vmid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);

        if (mv_vs_op_vmid_impl(hndl, vsid, &mut_vmid)) {
            bferror("mv_vs_op_vmid failed");
            return MV_INVALID_ID;
        }

        if (mut_vmid == MV_INVALID_ID) {
            bferror("the VMID returned by mv_vs_op_vmid is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_vmid >= HYPERVISOR_MAX_VMS) {
            bferror("the VMID returned by mv_vs_op_vmid is out of range");
            return MV_INVALID_ID;
        }

        return mut_vmid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall returns the ID of the VP the requested VS is
     *     assigned to.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to query
     *   @return Returns the ID of the VP the requested VS is assigned to.
     */
    NODISCARD static inline uint16_t
    mv_vs_op_vpid(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        uint16_t mut_vpid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);

        if (mv_vs_op_vpid_impl(hndl, vsid, &mut_vpid)) {
            bferror("mv_vs_op_vpid failed");
            return MV_INVALID_ID;
        }

        if (mut_vpid == MV_INVALID_ID) {
            bferror("the VPID returned by mv_vs_op_vpid is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_vpid >= HYPERVISOR_MAX_VPS) {
            bferror("the VPID returned by mv_vs_op_vpid is out of range");
            return MV_INVALID_ID;
        }

        return mut_vpid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall returns the ID of the VS that executed this
     *     hypercall.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns the ID of the VS that executed this hypercall.
     */
    NODISCARD static inline uint16_t
    mv_vs_op_vsid(uint64_t const hndl) NOEXCEPT
    {
        uint16_t mut_vsid;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));

        if (mv_vs_op_vsid_impl(hndl, &mut_vsid)) {
            bferror("mv_vs_op_vsid failed");
            return MV_INVALID_ID;
        }

        if (mut_vsid == MV_INVALID_ID) {
            bferror("the VSID returned by mv_vs_op_vsid is invalid");
            return MV_INVALID_ID;
        }

        if ((uint64_t)mut_vsid >= HYPERVISOR_MAX_VSS) {
            bferror("the VSID returned by mv_vs_op_vsid is out of range");
            return MV_INVALID_ID;
        }

        return mut_vsid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to translate the provided
     *     guest linear address (GLA) to a guest physical address (GPA).
     *     To perform this translation, MicroV will perform a linear to
     *     physical address conversion using the current state of CR0,
     *     CR3, and CR4. To perform this translation, software must
     *     provide the ID of the VS whose state will be used during
     *     translation and the the GLA to translate. How the translation
     *     occurs depends on whether or not the VS is in 16bit real mode,
     *     32bit protected mode, 32bit protected mode with paging enabled,
     *     or 64bit long mode. If the VS is in 16bit real mode or 32bit
     *     protected mode with paging disabled, no translation is
     *     performed and the provided GLA is returned as the GPA. If the
     *     VS is in 32bit protected mode with paging enabled or 64bit
     *     long mode, MicroV will walk the guest page tables pointed to by
     *     CR3 in the VS and return the resulting GPA and GPA flags used
     *     to map the GLA to the GPA (caching flags are not included). If
     *     the translation fails for any reason, the resulting GPA is
     *     undefined.
     *
     * <!-- inputs/outputs -->
     *   @param vsid The ID of the VS to use for the translation
     *   @param gla The GLA to translate
     *   @return Returns an mv_translation_t containing the results of
     *     the translation.
     */
    NODISCARD static inline struct mv_translation_t
    mv_vs_op_gla_to_gpa(uint64_t const hndl, uint16_t const vsid, uint64_t const gla) NOEXCEPT
    {
        uint64_t gpa_and_flags;
        uint64_t const gpa_mask = ((uint64_t)0xFFFFFFFFFFFFF000U);
        uint64_t const fgs_mask = ((uint64_t)0x0000000000000FFFU);
        struct mv_translation_t ret = {0};

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);
        platform_expects(gla > ((uint64_t)0));
        platform_expects(mv_is_page_aligned(gla));

        if (mv_vs_op_gla_to_gpa_impl(hndl, vsid, gla, &gpa_and_flags)) {
            bferror("mv_vs_op_destroy_vs failed");
            ret.is_valid = MV_TRANSLATION_T_IS_INVALID;
            return ret;
        }

        ret.laddr = gla;
        ret.paddr = (gpa_and_flags & gpa_mask);
        ret.flags = (gpa_and_flags & fgs_mask);
        ret.is_valid = MV_TRANSLATION_T_IS_VALID;
        return ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall executes a VM's VP using the requested VS.
     *     The VM and VP that are executed is determined by which VM and VP
     *     were assigned during the creation of the VP and VS. This hypercall
     *     does not return until an exit condition occurs, or an error is
     *     encountered. The exit condition can be identified using the output
     *     REG0 which defines the "exit reason". Whenever mv_vs_op_run is
     *     executed, MicroV reads the shared page using a mv_run_t as input.
     *     When mv_vs_op_run returns, and no error has occurred, the shared
     *     page's contents depends on the exit condition. For some exit
     *     conditions, the shared page is ignored. In other cases, a structure
     *     specific to the exit condition is returned providing software with
     *     the information that it needs to handle the exit.
     *
     * <!-- inputs/outputs -->s
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to run
     *   @return Returns a mv_exit_reason_t describing the reason for the exit
     */
    NODISCARD static inline enum mv_exit_reason_t
    mv_vs_op_run(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        enum mv_exit_reason_t mut_exit_reason;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);
        platform_expects(((uint64_t)vsid) < HYPERVISOR_MAX_VPS);

        if (mv_vs_op_run_impl(hndl, vsid, &mut_exit_reason)) {
            bferror("mv_vs_op_run failed");
            return mut_exit_reason;
        }

        return mut_exit_reason;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to return the value of a requested
     *     register. Not all registers values require 64 bits. Any unused bits
     *     are REVI.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to query
     *   @param reg The register to get
     *   @param pmut_val The value read from the requested register
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_get(
        uint64_t const hndl,
        uint16_t const vsid,
        enum mv_reg_t const reg,
        uint64_t *const pmut_val) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);
        platform_expects(reg < mv_reg_t_invalid);

        mut_ret = mv_vs_op_reg_get_impl(hndl, vsid, reg, pmut_val);
        if (mut_ret) {
            bferror("mv_vs_op_reg_get failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to set the value of a requested
     *     register. Not all registers values require 64 bits. Any unused bits
     *     are REVI.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to set
     *   @param reg The register to set
     *   @param val The value to write to the requested register
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_set(
        uint64_t const hndl,
        uint16_t const vsid,
        enum mv_reg_t const reg,
        uint64_t const val) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);
        platform_expects(reg < mv_reg_t_invalid);

        mut_ret = mv_vs_op_reg_set_impl(hndl, vsid, reg, val);
        if (mut_ret) {
            bferror("mv_vs_op_reg_set failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to return the values of multiple
     *     requested registers using a Register Descriptor List (RDL) in the
     *     shared page. For this ABI, the reg field of each mv_rdl_entry_t
     *     refers to an mv_reg_t. The val field refers to the returned value
     *     of the requested register in that entry. Not all registers values
     *     require 64 bits. Any unused bits are REVI. This ABI does not use
     *     any of the reg 0-7 fields in the mv_rdl_t.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to query
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_get_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);

        mut_ret = mv_vs_op_reg_get_list_impl(hndl, vsid);
        if (mut_ret) {
            bferror("mv_vs_op_reg_get_list failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to set the values of multiple
     *     requested registers using a Register Descriptor List (RDL) in the
     *     shared page. For this ABI, the reg field of each mv_rdl_entry_t
     *     refers to an mv_reg_t. The val field refers to the value to set the
     *     requested register in that entry to. Not all registers values
     *     require 64 bits. Any unused bits are REVI. This ABI does not use any
     *     of the reg 0-7 fields in the mv_rdl_t.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to set
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_set_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);

        mut_ret = mv_vs_op_reg_set_list_impl(hndl, vsid);
        if (mut_ret) {
            bferror("mv_vs_op_reg_set_list failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to return the value of a
     *     requested MSR.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to query
     *   @param msr The index of the MSR to get
     *   @param pmut_val The value read from the MSR
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_msr_get(
        uint64_t const hndl,
        uint16_t const vsid,
        uint32_t const msr,
        uint64_t *const pmut_val) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);

        mut_ret = mv_vs_op_msr_get_impl(hndl, vsid, msr, pmut_val);
        if (mut_ret) {
            bferror("mv_vs_op_msr_get failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to set the value of a
     *     requested MSR.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to set
     *   @param msr The index of the MSR to set
     *   @param val The value to write to the requested MSR
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_msr_set(
        uint64_t const hndl, uint16_t const vsid, uint32_t const msr, uint64_t const val) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);

        mut_ret = mv_vs_op_msr_set_impl(hndl, vsid, msr, val);
        if (mut_ret) {
            bferror("mv_vs_op_msr_set failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to return the values of multiple
     *     requested MSRs using a Register Descriptor List (RDL) in the shared
     *     page. For this ABI, the reg field of each mv_rdl_entry_t refers to
     *     the index of the MSR. The val field refers to the returned value of
     *     the requested MSR in that entry. This ABI does not use any of the
     *     reg 0-7 fields in the mv_rdl_t.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to query
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_msr_get_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);

        mut_ret = mv_vs_op_msr_get_list_impl(hndl, vsid);
        if (mut_ret) {
            bferror("mv_vs_op_msr_get_list failed");
            return mut_ret;
        }

        return mut_ret;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to set the values of multiple
     *     requested MSRs using a Register Descriptor List (RDL) in the shared
     *     page. For this ABI, the reg field of each mv_rdl_entry_t refers to
     *     the index of the MSR. The val field refers to the value to set the
     *     requested MSR in that entry to. This ABI does not use any of the
     *     reg 0-7 fields in the mv_rdl_t.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to set
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_msr_set_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        mv_status_t mut_ret;

        platform_expects(hndl != MV_INVALID_HANDLE);
        platform_expects(hndl > ((uint64_t)0));
        platform_expects(vsid != MV_INVALID_ID);

        mut_ret = mv_vs_op_msr_set_list_impl(hndl, vsid);
        if (mut_ret) {
            bferror("mv_vs_op_msr_set_list failed");
            return mut_ret;
        }

        return mut_ret;
    }

#ifdef __cplusplus
}
#endif

#endif
