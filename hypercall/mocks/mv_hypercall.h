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

#include <mv_constants.h>
#include <mv_exit_io_t.h>
#include <mv_exit_reason_t.h>
#include <mv_mp_state_t.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <mv_translation_t.h>
#include <mv_types.h>

#ifdef __cplusplus
#include <bsl/expects.hpp>
#else
#include <platform.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef G_MUT_SHARED_PAGES_H
    /** @brief stores the shared pages used by some hypercalls */
    extern void *g_mut_shared_pages[HYPERVISOR_MAX_PPS];
#endif

#define GARBAGE ((uint64_t)0xFFFFFFFFFFFFFFFFU)

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
#endif

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
    /** @brief stores the return value for mv_pp_op_cpuid_get_supported_list */
    extern mv_status_t g_mut_mv_pp_op_cpuid_get_supported_list;
    /** @brief stores the return value for mv_pp_op_msr_get_supported_list */
    extern mv_status_t g_mut_mv_pp_op_msr_get_supported_list;
    /** @brief stores the return value for mv_pp_op_tsc_get_khz */
    extern mv_status_t g_mut_mv_pp_op_tsc_get_khz;
    /** @brief stores the return value for mv_pp_op_tsc_get_khz */
    extern mv_status_t g_mut_mv_pp_op_tsc_set_khz;

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
#endif

        return g_mut_mv_pp_op_ppid;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to clear the GPA of the
     *     current PP's shared page.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_pp_op_clr_shared_page_gpa(uint64_t const hndl) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
#endif

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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_pp_op_set_shared_page_gpa(uint64_t const hndl, uint64_t const gpa) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects(gpa > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects(gpa > ((uint64_t)0));
#endif

        return g_mut_mv_pp_op_set_shared_page_gpa;
    }

    /**
     * <!-- description -->
     *   @brief Given the shared page cast as a mv_cdl_t, with each entry's
     *     mv_cdl_entry_t.fun and mv_cdl_entry_t.idx set to the requested CPUID
     *     leaf, the same entries are returned in the shared page with each
     *     entry's mv_cdl_entry_t.eax, mv_cdl_entry_t.ebx, mv_cdl_entry_t.ecx
     *     and mv_cdl_entry_t.edx set with all supported CPU features set to 1.
     *     Any non-feature fields returned by CPUID are returned as 0.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_pp_op_cpuid_get_supported_list(uint64_t const hndl) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
#endif

        return g_mut_mv_pp_op_cpuid_get_supported_list;
    }

    /**
     * <!-- description -->
     *   @brief Given the shared page cast as a mv_rdl_t, with each entry's
     *     mv_rdl_entry_t.reg set to the requested MSR, the same entries are
     *     returned in the shared page with each entry's mv_rdl_entry_t.val set
     *     to 1 if the MSR is supported, and 0 if the MSR is not supported.
     *
     *     This hypercall supports flag modifiers in mv_rdl_t.reg0. When
     *     MV_RDL_FLAG_ALL is enabled, the entire list of supported MSRs will be
     *     returned via the shared page and no entries must be given as input.
     *     If the entire list doesn't fit in the shared page, this hypercall
     *     will output in mv_rdl_t.reg1 the number of entries that are left
     *     allowing to make subsequent continuation calls by providing the
     *     current index of entries to resume from in mv_rdl_t.reg1 as input,
     *     i.e. mv_rdl_t.reg1 should be incremented by MV_RDL_MAX_ENTRIES.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_pp_op_msr_get_supported_list(uint64_t const hndl) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
#endif

        return g_mut_mv_pp_op_msr_get_supported_list;
    }

    /**
     * <!-- description -->
     *   @brief Returns the frequency of the PP. If the frequency has not
     *     been set, returns 0.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param pmut_freq Where to return the frequency in KHz
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_pp_op_tsc_get_khz(uint64_t const hndl, uint64_t *const pmut_freq) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects(NULLPTR != pmut_freq);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects(NULLPTR != pmut_freq);
#endif

        *pmut_freq = g_mut_val;
        return g_mut_mv_pp_op_tsc_get_khz;
    }

    /**
     * <!-- description -->
     *   @brief Sets the frequency of the PP. This hypercall must be called
     *     before any VS can be created.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param freq The frequency in KHz
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_pp_op_tsc_set_khz(uint64_t const hndl, uint64_t const freq) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects(freq > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects(freq > ((uint64_t)0));
#endif

        return g_mut_mv_pp_op_tsc_set_khz;
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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
#endif

        return g_mut_mv_vm_op_create_vm;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to destroy a VM given an ID.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vmid The ID of the VM to destroy
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_destroy_vm(uint64_t const hndl, uint16_t const vmid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vmid);
        bsl::expects(((uint64_t)vmid) < HYPERVISOR_MAX_VMS);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vmid);
    platform_expects(((uint64_t)vmid) < HYPERVISOR_MAX_VMS);
#endif

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
#endif

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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_mmio_map(
        uint64_t const hndl, uint16_t const dst_vmid, uint16_t const src_vmid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)dst_vmid);
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)src_vmid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)dst_vmid);
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)src_vmid);
#endif

        if (g_mut_mv_vm_op_mmio_map > ((uint64_t)0)) {
            --g_mut_mv_vm_op_mmio_map;
            if (((uint64_t)0) == g_mut_mv_vm_op_mmio_map) {
                return MV_STATUS_FAILURE_UNKNOWN;
            }

            return MV_STATUS_SUCCESS;
        }

        return MV_STATUS_SUCCESS;
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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_mmio_unmap(uint64_t const hndl, uint16_t const vmid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vmid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vmid);
#endif

        if (g_mut_mv_vm_op_mmio_unmap > ((uint64_t)0)) {
            --g_mut_mv_vm_op_mmio_unmap;
            if (((uint64_t)0) == g_mut_mv_vm_op_mmio_unmap) {
                return MV_STATUS_FAILURE_UNKNOWN;
            }

            return MV_STATUS_SUCCESS;
        }

        return MV_STATUS_SUCCESS;
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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vmid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vmid);
#endif

        return g_mut_mv_vp_op_create_vp;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to destroy a VP given an ID.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vpid The ID of the VP to destroy
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vp_op_destroy_vp(uint64_t const hndl, uint16_t const vpid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vpid);
        bsl::expects(((uint64_t)vpid) < HYPERVISOR_MAX_VPS);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vpid);
    platform_expects(((uint64_t)vpid) < HYPERVISOR_MAX_VPS);
#endif

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vpid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vpid);
#endif

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
#endif

        return g_mut_mv_vp_op_vpid;
    }

/* -------------------------------------------------------------------------- */
/* mv_vs_ops                                                                  */
/* -------------------------------------------------------------------------- */

/** tells the list APIs to add an unknown entry */
#define MV_STATUS_FAILURE_INC_NUM_ENTRIES ((mv_status_t)0x1234567800000001U)
/** tells the list APIs to add an unknown entry */
#define MV_STATUS_FAILURE_ADD_UNKNOWN ((mv_status_t)0x1234567800000002U)
/** tells the list APIs to corrupt the number of entries */
#define MV_STATUS_FAILURE_CORRUPT_NUM_ENTRIES ((mv_status_t)0x1234567800000003U)

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
    /** @brief stores the return value for mv_vs_op_run */
    extern struct mv_exit_io_t g_mut_mv_vs_op_run_io;
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
    /** @brief stores the return value for mv_vs_op_fpu_get_all */
    extern mv_status_t g_mut_mv_vs_op_fpu_get_all;
    /** @brief stores the return value for mv_vs_op_fpu_set_all */
    extern mv_status_t g_mut_mv_vs_op_fpu_set_all;
    /** @brief stores the return value for mv_vs_op_mp_state_get */
    extern mv_status_t g_mut_mv_vs_op_mp_state_get;
    /** @brief stores the return value for mv_vs_op_mp_state_set */
    extern mv_status_t g_mut_mv_vs_op_mp_state_set;
    /** @brief stores the return value for mv_vs_op_tsc_get_khz */
    extern mv_status_t g_mut_mv_vs_op_tsc_get_khz;

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vpid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vpid);
#endif

        return g_mut_mv_vs_op_create_vs;
    }

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to destroy a VS given an ID.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to destroy
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_destroy_vs(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
        bsl::expects(((uint64_t)vsid) < HYPERVISOR_MAX_VPS);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
    platform_expects(((uint64_t)vsid) < HYPERVISOR_MAX_VPS);
#endif

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#endif

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#endif

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
#endif

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
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
        bsl::expects(gla > ((uint64_t)0));
        bsl::expects(mv_is_page_aligned(gla));
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
    platform_expects(gla > ((uint64_t)0));
    platform_expects(mv_is_page_aligned(gla));
#endif

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
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to run
     *   @return Returns a mv_exit_reason_t describing the reason for the exit
     */
    NODISCARD static inline enum mv_exit_reason_t
    mv_vs_op_run(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
        bsl::expects(((uint64_t)vsid) < HYPERVISOR_MAX_VPS);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
    platform_expects(((uint64_t)vsid) < HYPERVISOR_MAX_VPS);
#endif

        switch ((int32_t)g_mut_mv_vs_op_run) {
            case mv_exit_reason_t_io: {
                struct mv_exit_io_t *const pmut_out = (struct mv_exit_io_t *)g_mut_shared_pages[0];
                *pmut_out = g_mut_mv_vs_op_run_io;
                break;
            }

            case mv_exit_reason_t_interrupt: {
                g_mut_mv_vs_op_run = (enum mv_exit_reason_t)mv_exit_reason_t_failure;
                return (enum mv_exit_reason_t)mv_exit_reason_t_interrupt;
            }

            case mv_exit_reason_t_nmi: {
                g_mut_mv_vs_op_run = (enum mv_exit_reason_t)mv_exit_reason_t_failure;
                return (enum mv_exit_reason_t)mv_exit_reason_t_nmi;
            }

            default: {
                break;
            }
        }

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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_get(
        uint64_t const hndl,
        uint16_t const vsid,
        enum mv_reg_t const reg,
        uint64_t *const pmut_val) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
        bsl::expects((int32_t)reg < (int32_t)mv_reg_t_invalid);
        bsl::expects(NULLPTR != pmut_val);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
    platform_expects((int32_t)reg < (int32_t)mv_reg_t_invalid);
    platform_expects(NULLPTR != pmut_val);
#endif

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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_set(
        uint64_t const hndl,
        uint16_t const vsid,
        enum mv_reg_t const reg,
        uint64_t const val) NOEXCEPT
    {
        (void)val;

#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
        bsl::expects((int32_t)reg < (int32_t)mv_reg_t_invalid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
    platform_expects((int32_t)reg < (int32_t)mv_reg_t_invalid);
#endif

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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_get_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        uint64_t mut_i;

#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#endif

        struct mv_rdl_t *const pmut_rdl = (struct mv_rdl_t *)g_mut_shared_pages[0];

#ifdef __cplusplus
        bsl::expects(nullptr != pmut_rdl);
        bsl::expects(pmut_rdl->num_entries < MV_RDL_MAX_ENTRIES);
#else
    platform_expects(NULL != pmut_rdl);
    platform_expects(pmut_rdl->num_entries < MV_RDL_MAX_ENTRIES);
#endif
        for (mut_i = ((uint64_t)0); mut_i < pmut_rdl->num_entries; ++mut_i) {
            pmut_rdl->entries[mut_i].val = g_mut_val;
        }

        if (MV_STATUS_FAILURE_INC_NUM_ENTRIES == g_mut_mv_vs_op_reg_get_list) {
            pmut_rdl->entries[pmut_rdl->num_entries].reg = ((uint64_t)0);
            ++pmut_rdl->num_entries;
            return MV_STATUS_SUCCESS;
        }

        if (MV_STATUS_FAILURE_ADD_UNKNOWN == g_mut_mv_vs_op_reg_get_list) {
            pmut_rdl->entries[pmut_rdl->num_entries].reg = GARBAGE;
            ++pmut_rdl->num_entries;
            return MV_STATUS_SUCCESS;
        }

        if (MV_STATUS_FAILURE_CORRUPT_NUM_ENTRIES == g_mut_mv_vs_op_reg_get_list) {
            pmut_rdl->num_entries = GARBAGE;
            return MV_STATUS_SUCCESS;
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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_reg_set_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#endif

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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_msr_get(
        uint64_t const hndl,
        uint16_t const vsid,
        uint32_t const msr,
        uint64_t *const pmut_val) NOEXCEPT
    {
        (void)msr;

#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
        bsl::expects(NULLPTR != pmut_val);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
    platform_expects(NULLPTR != pmut_val);
#endif

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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_msr_set(
        uint64_t const hndl, uint16_t const vsid, uint32_t const msr, uint64_t const val) NOEXCEPT
    {
        (void)msr;
        (void)val;

#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#endif

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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_msr_get_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
        uint64_t mut_i;

#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#endif

        struct mv_rdl_t *const pmut_rdl = (struct mv_rdl_t *)g_mut_shared_pages[0];

#ifdef __cplusplus
        bsl::expects(nullptr != pmut_rdl);
        bsl::expects(pmut_rdl->num_entries < MV_RDL_MAX_ENTRIES);
#else
    platform_expects(NULL != pmut_rdl);
    platform_expects(pmut_rdl->num_entries < MV_RDL_MAX_ENTRIES);
#endif
        for (mut_i = ((uint64_t)0); mut_i < pmut_rdl->num_entries; ++mut_i) {
            pmut_rdl->entries[mut_i].val = g_mut_val;
        }

        if (MV_STATUS_FAILURE_INC_NUM_ENTRIES == g_mut_mv_vs_op_msr_get_list) {
            pmut_rdl->entries[pmut_rdl->num_entries].reg = ((uint64_t)0);
            ++pmut_rdl->num_entries;
            return MV_STATUS_SUCCESS;
        }

        if (MV_STATUS_FAILURE_ADD_UNKNOWN == g_mut_mv_vs_op_msr_get_list) {
            pmut_rdl->entries[pmut_rdl->num_entries].reg = GARBAGE;
            ++pmut_rdl->num_entries;
            return MV_STATUS_SUCCESS;
        }

        if (MV_STATUS_FAILURE_CORRUPT_NUM_ENTRIES == g_mut_mv_vs_op_msr_get_list) {
            pmut_rdl->num_entries = GARBAGE;
            return MV_STATUS_SUCCESS;
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
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_msr_set_list(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#endif

        return g_mut_mv_vs_op_msr_set_list;
    }

    /**
     * <!-- description -->
     *   @brief Returns FPU state as seen by the VS in the shared page.
     *     The format of the FPU state depends on which mode the VS is
     *     currently in.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to query
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_fpu_get_all(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#endif

        return g_mut_mv_vs_op_fpu_get_all;
    }

    /**
     * <!-- description -->
     *   @brief Sets the FPU state as seen by the VS in the shared page.
     *     The format of the FPU state depends on which mode the VS is
     *     currently in.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to set
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_fpu_set_all(uint64_t const hndl, uint16_t const vsid) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
#endif

        return g_mut_mv_vs_op_fpu_set_all;
    }

    /**
     * <!-- description -->
     *   @brief Returns the mv_mp_state_t of the VS.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to set
     *   @param pmut_state Where to store the new MP state
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_mp_state_get(
        uint64_t const hndl, uint16_t const vsid, enum mv_mp_state_t *const pmut_state) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
        bsl::expects(NULLPTR != pmut_state);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
    platform_expects(NULLPTR != pmut_state);
#endif

        *pmut_state = (enum mv_mp_state_t)g_mut_val;
        return g_mut_mv_vs_op_mp_state_get;
    }

    /**
     * <!-- description -->
     *   @brief Sets the mv_mp_state_t of the VS.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid the ID of the VS to set
     *   @param state The new MP state
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_mp_state_set(
        uint64_t const hndl, uint16_t const vsid, enum mv_mp_state_t const state) NOEXCEPT
    {
        (void)state;

#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
        bsl::expects((int32_t)state < (int32_t)mv_mp_state_t_invalid);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
    platform_expects((int32_t)state < (int32_t)mv_mp_state_t_invalid);
#endif

        return g_mut_mv_vs_op_mp_state_set;
    }

    /**
     * <!-- description -->
     *   @brief Returns the frequency of the VS.
     *
     * <!-- inputs/outputs -->
     *   @param hndl Set to the result of mv_handle_op_open_handle
     *   @param vsid The ID of the VS to get
     *   @param pmut_freq Where to return the frequency in KHz
     *   @return Returns MV_STATUS_SUCCESS on success, MV_STATUS_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vs_op_tsc_get_khz(
        uint64_t const hndl, uint16_t const vsid, uint64_t *const pmut_freq) NOEXCEPT
    {
#ifdef __cplusplus
        bsl::expects(MV_INVALID_HANDLE != hndl);
        bsl::expects(hndl > ((uint64_t)0));
        bsl::expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
        bsl::expects(NULLPTR != pmut_freq);
#else
    platform_expects(MV_INVALID_HANDLE != hndl);
    platform_expects(hndl > ((uint64_t)0));
    platform_expects((int32_t)MV_INVALID_ID != (int32_t)vsid);
    platform_expects(NULLPTR != pmut_freq);
#endif

        *pmut_freq = g_mut_val;
        return g_mut_mv_vs_op_tsc_get_khz;
    }

#ifdef __cplusplus
}
#endif

#endif
