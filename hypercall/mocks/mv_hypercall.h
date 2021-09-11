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

#ifndef MOCKS_MV_HYPERCALL_H
#define MOCKS_MV_HYPERCALL_H

#include <g_mut_shared_pages.h>
#include <mv_constants.h>
#include <mv_mdl_t.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <mv_translation_t.h>
#include <mv_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /** @brief used to set the value of mv_rdl_entry_t.val */
    extern uint64_t g_mut_rdl_entry_val;

    /* ---------------------------------------------------------------------- */
    /* mv_id_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /** @brief stores the return value for mv_id_op_version */
    extern uint32_t g_mut_mv_id_op_version;

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
        return g_mut_mv_id_op_version;
    }

    /* ---------------------------------------------------------------------- */
    /* mv_handle_ops                                                          */
    /* ---------------------------------------------------------------------- */

    /** @brief stores the return value for mv_handle_op_open_handle */
    extern uint64_t g_mut_mv_handle_op_open_handle;
    /** @brief stores the return value for mv_handle_op_close_handle */
    extern mv_status_t g_mut_mv_handle_op_close_handle;

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
        (void)version;
        return g_mut_mv_handle_op_open_handle;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall closes a previously opened handle.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns MV_STATUS_SUCCESS on success, otherwise returns a
     *     failure code on failure.
     */
    NODISCARD static inline mv_status_t
    mv_handle_op_close_handle(uint64_t const hndl) NOEXCEPT
    {
        (void)hndl;
        return g_mut_mv_handle_op_close_handle;
    }

    /* -------------------------------------------------------------------------- */
    /* mv_vm_ops                                                                  */
    /* -------------------------------------------------------------------------- */

    /** @brief stores the return value for mv_vm_op_create_vm */
    extern uint16_t g_mut_mv_vm_op_create_vm;
    /** @brief stores the return value for mv_vm_op_destroy_vm */
    extern mv_status_t g_mut_mv_vm_op_destroy_vm;
    /** @brief stores the return value for mv_vm_op_mmio_map */
    extern mv_status_t g_mut_mv_vm_op_mmio_map;
    /** @brief stores the return value for mv_vm_op_mmio_unmap */
    extern mv_status_t g_mut_mv_vm_op_mmio_unmap;

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to create a VM and return its ID.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns the resulting VMID of the newly created VM
     */
    NODISCARD static inline uint16_t
    mv_vm_op_create_vm(uint64_t const hndl) NOEXCEPT
    {
        (void)hndl;
        return g_mut_mv_vm_op_create_vm;
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
        (void)hndl;
        (void)vmid;

        return g_mut_mv_vm_op_destroy_vm;
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
     *     mv_rdl_t. Double maps (i.e., mapping memory that is already mapped)
     *     is undefined and may result in MicroV returning an error.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param dst_vmid The VMID of the dst VM to map memory to
     *   @param src_vmid The VMID of the src VM to map memory from
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_mmio_map(
        uint64_t const hndl, uint16_t const dst_vmid, uint16_t const src_vmid) NOEXCEPT
    {
        (void)hndl;
        (void)dst_vmid;
        (void)src_vmid;

        return g_mut_mv_vm_op_mmio_map;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall is used to unmap a range of physically
     *     discontiguous guest memory from a VM. For this ABI, the dst field
     *     in the mv_mdl_entry_t refers to the GPA of the contiguous memory
     *     region to unmap. The src field is ignored. The bytes field in the
     *     mv_mdl_entry_t must be page aligned and cannot be 0. The flags
     *     field is ignored. This ABI does not use any of the reg 0-7 fields
     *     in the mv_rdl_t. Double unmaps (i.e., unmapping memory that is
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
     *   @param vmid The VMID of the VM to unmap memory from
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_mmio_unmap(uint64_t const hndl, uint16_t const vmid) NOEXCEPT
    {
        (void)hndl;
        (void)vmid;

        return g_mut_mv_vm_op_mmio_unmap;
    }

    /* -------------------------------------------------------------------------- */
    /* mv_vp_ops                                                                  */
    /* -------------------------------------------------------------------------- */

    /** @brief stores the return value for mv_vp_op_create_vp */
    extern uint16_t g_mut_mv_vp_op_create_vp;
    /** @brief stores the return value for mv_vp_op_destroy_vp */
    extern mv_status_t g_mut_mv_vp_op_destroy_vp;

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to create a VP given the ID of
     *     the VM the VP will be assigned to. Upon success, this hypercall
     *     returns the ID of the newly created VP.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vmid The ID of the VM to assign the newly created VP to
     *   @return Returns the resulting VPID of the newly created VP
     */
    NODISCARD static inline uint16_t
    mv_vp_op_create_vp(uint64_t const hndl, uint16_t const vmid) NOEXCEPT
    {
        (void)hndl;
        (void)vmid;

        return g_mut_mv_vp_op_create_vp;
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
        (void)hndl;
        (void)vpid;

        return g_mut_mv_vp_op_destroy_vp;
    }

    /* -------------------------------------------------------------------------- */
    /* mv_vs_ops                                                                  */
    /* -------------------------------------------------------------------------- */

    /** @brief stores the return value for mv_vs_op_create_vs */
    extern uint16_t g_mut_mv_vs_op_create_vs;
    /** @brief stores the return value for mv_vs_op_destroy_vs */
    extern mv_status_t g_mut_mv_vs_op_destroy_vs;
    /** @brief stores the return value for mv_vs_op_reg_get_list */
    extern mv_status_t g_mut_mv_vs_op_reg_get_list;
    /** @brief stores the return value for mv_vs_op_reg_set_list */
    extern mv_status_t g_mut_mv_vs_op_reg_set_list;

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to create a VS given the ID of
     *     the VP the VS will be assigned to. Upon success, this hypercall
     *     returns the ID of the newly created VS.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vpid The ID of the VP to assign the newly created VS to
     *   @return Returns the resulting VSID of the newly created VS
     */
    NODISCARD static inline uint16_t
    mv_vs_op_create_vs(uint64_t const hndl, uint16_t const vpid) NOEXCEPT
    {
        (void)hndl;
        (void)vpid;

        return g_mut_mv_vs_op_create_vs;
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
        (void)hndl;
        (void)vsid;

        return g_mut_mv_vs_op_destroy_vs;
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
     *   @param vsid The VSID of the VS to query
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_get_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        uint64_t mut_i;

        (void)hndl;
        (void)vsid;

        struct mv_rdl_t *const pmut_mdl = (struct mv_rdl_t *)g_mut_shared_pages[0];
        for (mut_i = ((uint64_t)0); mut_i < pmut_mdl->num_entries; ++mut_i) {
            pmut_mdl->entries[mut_i].val = g_mut_rdl_entry_val;
        }

        return g_mut_mv_vs_op_reg_get_list;
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
     *   @param vsid The VSID of the VS to set
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_set_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        (void)hndl;
        (void)vsid;

        return g_mut_mv_vs_op_reg_set_list;
    }

#ifdef __cplusplus
}
#endif

#endif
