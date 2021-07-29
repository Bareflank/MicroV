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
/* mv_vps_ops                                                               */
/* -------------------------------------------------------------------------- */

/// <!-- description -->
///   @brief This hypercall tells MicroV to translate the provided
///     guest virtual address (GVA) to a guest linear address (GLA).
///     To perform this translation, MicroV will use the current state
///     of CR0, CR4, EFER, the GDT and the segment registers. To
///     perform this translation, software must provide the ID of the
///     VPS whose state will be used during translation, the segment
///     register to use, and the the GVA to translate. How the
///     translation occurs depends on whether or not the VPS is in
///     16bit real mode, 32bit protected mode, or 64bit long mode. In
///     16bit real mode, the segment registers are used for the
///     translation. In 32bit protected mode, the segment registers and
///     the GDT are used for the translation. 64bit long mode is the
///     same as 32bit protected mode with the difference being that
///     certain segments will return an error as they are not supported
///     (e.g., ES and DS). If the translation fails for any reason, the
///     resulting GLA is undefined.
///
/// <!-- inputs/outputs -->
///   @param vpsid The VPSID of the VPS to use for the translation
///   @param ssid The SSID of the segment to use for the translation
///   @param gva The GVA to translate
///   @return Returns an mv_translation_t containing the results of
///     the translation.
///
static inline struct mv_translation_t
mv_vps_op_gva_to_gla(
    uint64_t const hndl, uint16_t const vpsid, uint16_t const ssid, uint64_t const gva)
{
    uint64_t gla;
    uint16_t const ssid_shift = ((uint16_t)16);
    struct mv_translation_t ret = {0};

    if (mv_vps_op_gva_to_gla_impl(hndl, (vpsid | (ssid << ssid_shift)), gva, &gla)) {
        ret.is_valid = MV_TRANSLATION_T_IS_INVALID;
        return ret;
    }

    ret.vaddr = gva;
    ret.laddr = gla;
    ret.is_valid = MV_TRANSLATION_T_IS_VALID;
    return ret;
}

/// <!-- description -->
///   @brief This hypercall tells MicroV to translate the provided
///     guest linear address (GLA) to a guest physical address (GPA).
///     To perform this translation, MicroV will perform a linear to
///     physical address conversion using the current state of CR0,
///     CR3, and CR4. To perform this translation, software must
///     provide the ID of the VPS whose state will be used during
///     translation and the the GLA to translate. How the translation
///     occurs depends on whether or not the VPS is in 16bit real mode,
///     32bit protected mode, 32bit protected mode with paging enabled,
///     or 64bit long mode. If the VPS is in 16bit real mode or 32bit
///     protected mode with paging disabled, no translation is
///     performed and the provided GLA is returned as the GPA. If the
///     VPS is in 32bit protected mode with paging enabled or 64bit
///     long mode, MicroV will walk the guest page tables pointed to by
///     CR3 in the VPS and return the resulting GPA and GPA flags used
///     to map the GLA to the GPA (caching flags are not included). If
///     the translation fails for any reason, the resulting GPA is
///     undefined.
///
/// <!-- inputs/outputs -->
///   @param vpsid The VPSID of the VPS to use for the translation
///   @param gla The GLA to translate
///   @return Returns an mv_translation_t containing the results of
///     the translation.
///
static inline struct mv_translation_t
mv_vps_op_gla_to_gpa(uint64_t const hndl, uint16_t const vpsid, uint64_t const gla)
{
    uint64_t gpa_and_flags;
    uint64_t const gpa_mask = ((uint64_t)0xFFFFFFFFFFFFF000U);
    uint64_t const fgs_mask = ((uint64_t)0x0000000000000FFFU);
    struct mv_translation_t ret = {0};

    if (mv_vps_op_gla_to_gpa_impl(hndl, vpsid, gla, &gpa_and_flags)) {
        ret.is_valid = MV_TRANSLATION_T_IS_INVALID;
        return ret;
    }

    ret.laddr = gla;
    ret.paddr = (gpa_and_flags & gpa_mask);
    ret.flags = (gpa_and_flags & fgs_mask);
    ret.is_valid = MV_TRANSLATION_T_IS_VALID;
    return ret;
}

#endif
