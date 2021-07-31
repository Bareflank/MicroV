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
#include <mv_reg_t.h>
#include <mv_translation_t.h>
#include <mv_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

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
    extern uint64_t g_mut_mv_handle_op_close_handle;

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

    /* -------------------------------------------------------------------------- */
    /* mv_vp_ops                                                                  */
    /* -------------------------------------------------------------------------- */

    /** @brief stores the return value for mv_vp_op_create_vp */
    extern uint16_t g_mut_mv_vp_op_create_vp;

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

    /* -------------------------------------------------------------------------- */
    /* mv_vs_ops                                                                  */
    /* -------------------------------------------------------------------------- */

    /** @brief stores the return value for mv_vs_op_create_vs */
    extern uint16_t g_mut_mv_vs_op_create_vs;

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

#ifdef __cplusplus
}
#endif

#endif
