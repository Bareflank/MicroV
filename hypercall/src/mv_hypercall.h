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

#include <mv_constants.h>
#include <mv_hypercall_impl.h>
#include <mv_reg_t.h>
#include <mv_translation_t.h>
#include <mv_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* -------------------------------------------------------------------------- */
    /* mv_id_ops                                                                  */
    /* -------------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to return the version of the spec
     *     that it supports.
     *
     * <!-- inputs/outputs -->
     *   @return Returns which versions of the spec MicroV supports
     */
    static inline uint32_t
    mv_id_op_version(void)
    {
        uint32_t version = ((uint32_t)0);
        if (mv_id_op_version_impl(&version) != MV_STATUS_SUCCESS) {
            return MV_INVALID_VERSION;
        }

        return version;
    }

    /* -------------------------------------------------------------------------- */
    /* mv_handle_ops                                                              */
    /* -------------------------------------------------------------------------- */

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
    static inline uint64_t
    mv_handle_op_open_handle(uint32_t const version)
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
     *   @return Returns MV_STATUS_SUCCESS on success, otherwise returns a
     *     failure code on failure.
     */
    static inline mv_status_t
    mv_handle_op_close_handle(uint64_t const hndl)
    {
        return mv_handle_op_close_handle_impl(hndl);
    }

    /* -------------------------------------------------------------------------- */
    /* mv_debug_ops                                                               */
    /* -------------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief This hypercall tells MicroV to output reg0 and reg1 to the console
     *     device MicroV is currently using for debugging. The purpose of this
     *     hypercall is to provide a simple means for debugging issues with the
     *     guest and can be used by a VM from both userspace and the kernel, even
     *     when the operating system is not fully bootstrapped or is in a failure
     *     state.
     *
     * <!-- inputs/outputs -->
     *   @param reg0 The first value to output to MicroV's console
     *   @param reg1 The second value to output to MicroV's console
     */
    static inline void
    mv_debug_op_out(uint64_t const reg0, uint64_t const reg1)
    {
        mv_debug_op_out_impl(reg0, reg1);
    }

    /* -------------------------------------------------------------------------- */
    /* mv_vm_ops                                                                  */
    /* -------------------------------------------------------------------------- */

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
        uint16_t mut_vmid;
        if (mv_vm_op_create_vm_impl(hndl, &mut_vmid)) {
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
        return mv_vm_op_destroy_vm_impl(hndl, vmid);
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
     *   @param dst_vmid The VMID of the dst VM to map memory to
     *   @param src_vmid The VMID of the src VM to map memory from
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_mmio_map(
        uint64_t const hndl, uint16_t const dst_vmid, uint16_t const src_vmid) NOEXCEPT
    {
        return mv_vm_op_mmio_map_impl(hndl, dst_vmid, src_vmid);
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
     *   @param vmid The VMID of the VM to unmap memory from
     *   @return Returns MV_STATUS_SUCCESS on success, MV_FAILURE_UNKNOWN
     *     and friends on failure.
     */
    NODISCARD static inline mv_status_t
    mv_vm_op_mmio_unmap(uint64_t const hndl, uint16_t const vmid) NOEXCEPT
    {
        return mv_vm_op_mmio_unmap_impl(hndl, vmid);
    }

    /* -------------------------------------------------------------------------- */
    /* mv_vp_ops                                                                  */
    /* -------------------------------------------------------------------------- */

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
        uint16_t mut_vpid;
        if (mv_vp_op_create_vp_impl(hndl, vmid, &mut_vpid)) {
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
        return mv_vp_op_destroy_vp_impl(hndl, vpid);
    }

    /* -------------------------------------------------------------------------- */
    /* mv_vs_ops                                                                  */
    /* -------------------------------------------------------------------------- */

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
        uint16_t mut_vsid;
        if (mv_vs_op_create_vs_impl(hndl, vpid, &mut_vsid)) {
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
        return mv_vs_op_destroy_vs_impl(hndl, vsid);
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
        return mv_vs_op_reg_get_list_impl(hndl, vsid);
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
        return mv_vs_op_reg_set_list_impl(hndl, vsid);
    }

    // /**
    //  * <!-- description -->
    //  *   @brief This hypercall tells MicroV to translate the provided
    //  *     guest virtual address (GVA) to a guest linear address (GLA).
    //  *     To perform this translation, MicroV will use the current state
    //  *     of CR0, CR4, EFER, the GDT and the segment registers. To
    //  *     perform this translation, software must provide the ID of the
    //  *     VS whose state will be used during translation, the segment
    //  *     register to use, and the the GVA to translate. How the
    //  *     translation occurs depends on whether or not the VS is in
    //  *     16bit real mode, 32bit protected mode, or 64bit long mode. In
    //  *     16bit real mode, the segment registers are used for the
    //  *     translation. In 32bit protected mode, the segment registers and
    //  *     the GDT are used for the translation. 64bit long mode is the
    //  *     same as 32bit protected mode with the difference being that
    //  *     certain segments will return an error as they are not supported
    //  *     (e.g., ES and DS). If the translation fails for any reason, the
    //  *     resulting GLA is undefined.
    //  *
    //  * <!-- inputs/outputs -->
    //  *   @param vsid The VSID of the VS to use for the translation
    //  *   @param ssid The SSID of the segment to use for the translation
    //  *   @param gva The GVA to translate
    //  *   @return Returns an mv_translation_t containing the results of
    //  *     the translation.
    //  */
    // static inline struct mv_translation_t
    // mv_vs_op_gva_to_gla(
    //     uint64_t const hndl, uint16_t const vsid, uint16_t const ssid, uint64_t const gva)
    // {
    //     uint64_t gla;
    //     uint16_t const ssid_shift = ((uint16_t)16);
    //     struct mv_translation_t ret = {0};

    //     if (mv_vs_op_gva_to_gla_impl(hndl, (vsid | (ssid << ssid_shift)), gva, &gla)) {
    //         ret.is_valid = MV_TRANSLATION_T_IS_INVALID;
    //         return ret;
    //     }

    //     ret.vaddr = gva;
    //     ret.laddr = gla;
    //     ret.is_valid = MV_TRANSLATION_T_IS_VALID;
    //     return ret;
    // }

    // /**
    //  * <!-- description -->
    //  *   @brief This hypercall tells MicroV to translate the provided
    //  *     guest linear address (GLA) to a guest physical address (GPA).
    //  *     To perform this translation, MicroV will perform a linear to
    //  *     physical address conversion using the current state of CR0,
    //  *     CR3, and CR4. To perform this translation, software must
    //  *     provide the ID of the VS whose state will be used during
    //  *     translation and the the GLA to translate. How the translation
    //  *     occurs depends on whether or not the VS is in 16bit real mode,
    //  *     32bit protected mode, 32bit protected mode with paging enabled,
    //  *     or 64bit long mode. If the VS is in 16bit real mode or 32bit
    //  *     protected mode with paging disabled, no translation is
    //  *     performed and the provided GLA is returned as the GPA. If the
    //  *     VS is in 32bit protected mode with paging enabled or 64bit
    //  *     long mode, MicroV will walk the guest page tables pointed to by
    //  *     CR3 in the VS and return the resulting GPA and GPA flags used
    //  *     to map the GLA to the GPA (caching flags are not included). If
    //  *     the translation fails for any reason, the resulting GPA is
    //  *     undefined.
    //  *
    //  * <!-- inputs/outputs -->
    //  *   @param vsid The VSID of the VS to use for the translation
    //  *   @param gla The GLA to translate
    //  *   @return Returns an mv_translation_t containing the results of
    //  *     the translation.
    //  */
    // static inline struct mv_translation_t
    // mv_vs_op_gla_to_gpa(uint64_t const hndl, uint16_t const vsid, uint64_t const gla)
    // {
    //     uint64_t gpa_and_flags;
    //     uint64_t const gpa_mask = ((uint64_t)0xFFFFFFFFFFFFF000U);
    //     uint64_t const fgs_mask = ((uint64_t)0x0000000000000FFFU);
    //     struct mv_translation_t ret = {0};

    //     if (mv_vs_op_gla_to_gpa_impl(hndl, vsid, gla, &gpa_and_flags)) {
    //         ret.is_valid = MV_TRANSLATION_T_IS_INVALID;
    //         return ret;
    //     }

    //     ret.laddr = gla;
    //     ret.paddr = (gpa_and_flags & gpa_mask);
    //     ret.flags = (gpa_and_flags & fgs_mask);
    //     ret.is_valid = MV_TRANSLATION_T_IS_VALID;
    //     return ret;
    // }

#ifdef __cplusplus
}
#endif

#endif
