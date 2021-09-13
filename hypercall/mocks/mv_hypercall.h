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
#include <mv_exit_reason_t.h>
#include <mv_mdl_t.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <mv_translation_t.h>
#include <mv_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /** @brief stores a value that can be returned by certain hypercalls */
    extern uint64_t g_mut_val;

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

    /* ---------------------------------------------------------------------- */
    /* mv_pp_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /** @brief stores the return value for mv_pp_op_ppid */
    extern uint16_t g_mut_mv_pp_op_ppid;
    /** @brief stores the return value for mv_pp_op_clr_shared_page_gpa */
    extern mv_status_t g_mut_mv_pp_op_clr_shared_page_gpa;
    /** @brief stores the return value for mv_pp_op_set_shared_page_gpa */
    extern mv_status_t g_mut_mv_pp_op_set_shared_page_gpa;

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
        (void)hndl;
        return g_mut_mv_pp_op_ppid;
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
        (void)hndl;
        return g_mut_mv_pp_op_clr_shared_page_gpa;
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
        (void)hndl;
        (void)gpa;

        return g_mut_mv_pp_op_set_shared_page_gpa;
    }

    /* -------------------------------------------------------------------------- */
    /* mv_vm_ops                                                                  */
    /* -------------------------------------------------------------------------- */

    /** @brief stores the return value for mv_vm_op_create_vm */
    extern uint16_t g_mut_mv_vm_op_create_vm;
    /** @brief stores the return value for mv_vm_op_destroy_vm */
    extern mv_status_t g_mut_mv_vm_op_destroy_vm;
    /** @brief stores the return value for mv_vm_op_vmid */
    extern uint16_t g_mut_mv_vm_op_vmid;
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
        (void)hndl;
        return g_mut_mv_vm_op_vmid;
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
    /** @brief stores the return value for mv_vp_op_vmid */
    extern uint16_t g_mut_mv_vp_op_vmid;
    /** @brief stores the return value for mv_vp_op_vpid */
    extern uint16_t g_mut_mv_vp_op_vpid;

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
        (void)hndl;
        (void)vpid;

        return g_mut_mv_vp_op_vmid;
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
        (void)hndl;
        return g_mut_mv_vp_op_vpid;
    }

    /* -------------------------------------------------------------------------- */
    /* mv_vs_ops                                                                  */
    /* -------------------------------------------------------------------------- */

    /** @brief stores the return value for mv_vs_op_create_vs */
    extern uint16_t g_mut_mv_vs_op_create_vs;
    /** @brief stores the return value for mv_vs_op_destroy_vs */
    extern mv_status_t g_mut_mv_vs_op_destroy_vs;
    /** @brief stores the return value for mv_vs_op_vmid */
    extern uint16_t g_mut_mv_vs_op_vmid;
    /** @brief stores the return value for mv_vs_op_vpid */
    extern uint16_t g_mut_mv_vs_op_vpid;
    /** @brief stores the return value for mv_vs_op_vsid */
    extern uint16_t g_mut_mv_vs_op_vsid;
    /** @brief stores the return value for mv_vs_op_gla_to_gpa */
    extern struct mv_translation_t g_mut_mv_vs_op_gla_to_gpa;
    /** @brief stores the return value for mv_vs_op_run */
    extern enum mv_exit_reason_t g_mut_mv_vs_op_run;
    /** @brief stores the return value for mv_vs_op_reg_get */
    extern mv_status_t g_mut_mv_vs_op_reg_get;
    /** @brief stores the return value for mv_vs_op_reg_set */
    extern mv_status_t g_mut_mv_vs_op_reg_set;
    /** @brief stores the return value for mv_vs_op_reg_get_list */
    extern mv_status_t g_mut_mv_vs_op_reg_get_list;
    /** @brief stores the return value for mv_vs_op_reg_set_list */
    extern mv_status_t g_mut_mv_vs_op_reg_set_list;
    /** @brief stores the return value for mv_vs_op_msr_get */
    extern mv_status_t g_mut_mv_vs_op_msr_get;
    /** @brief stores the return value for mv_vs_op_msr_set */
    extern mv_status_t g_mut_mv_vs_op_msr_set;
    /** @brief stores the return value for mv_vs_op_msr_get_list */
    extern mv_status_t g_mut_mv_vs_op_msr_get_list;
    /** @brief stores the return value for mv_vs_op_msr_set_list */
    extern mv_status_t g_mut_mv_vs_op_msr_set_list;

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
        (void)hndl;
        (void)vsid;

        return g_mut_mv_vs_op_vmid;
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
        (void)hndl;
        (void)vsid;

        return g_mut_mv_vs_op_vpid;
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
        (void)hndl;
        return g_mut_mv_vs_op_vsid;
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
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to use for the translation
     *   @param gla The GLA to translate
     *   @return Returns an mv_translation_t containing the results of
     *     the translation.
     */
    NODISCARD static inline struct mv_translation_t
    mv_vs_op_gla_to_gpa(uint64_t const hndl, uint16_t const vsid, uint64_t const gla) NOEXCEPT
    {
        (void)hndl;
        (void)vsid;
        (void)gla;

        return g_mut_mv_vs_op_gla_to_gpa;
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
        (void)hndl;
        (void)vsid;

        return g_mut_mv_vs_op_run;
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
        (void)hndl;
        (void)vsid;
        (void)reg;

        *pmut_val = g_mut_val;
        return g_mut_mv_vs_op_reg_get;
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
        (void)hndl;
        (void)vsid;
        (void)reg;
        (void)val;

        return g_mut_mv_vs_op_reg_set;
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
        uint64_t mut_i;

        (void)hndl;
        (void)vsid;

        struct mv_rdl_t *const pmut_mdl = (struct mv_rdl_t *)g_mut_shared_pages[0];
        for (mut_i = ((uint64_t)0); mut_i < pmut_mdl->num_entries; ++mut_i) {
            pmut_mdl->entries[mut_i].val = g_mut_val;
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
     *   @param vsid The ID of the VS to set
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
        (void)hndl;
        (void)vsid;
        (void)msr;

        *pmut_val = g_mut_val;
        return g_mut_mv_vs_op_msr_get;
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
        (void)hndl;
        (void)vsid;
        (void)msr;
        (void)val;

        return g_mut_mv_vs_op_msr_set;
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
        uint64_t mut_i;

        (void)hndl;
        (void)vsid;

        struct mv_rdl_t *const pmut_mdl = (struct mv_rdl_t *)g_mut_shared_pages[0];
        for (mut_i = ((uint64_t)0); mut_i < pmut_mdl->num_entries; ++mut_i) {
            pmut_mdl->entries[mut_i].val = g_mut_val;
        }

        return g_mut_mv_vs_op_msr_get_list;
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
        (void)hndl;
        (void)vsid;

        return g_mut_mv_vs_op_msr_set_list;
    }

#ifdef __cplusplus
}
#endif

#endif
