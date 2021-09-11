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

#include <constants.h>
#include <debug.h>
#include <g_mut_hndl.h>
#include <g_mut_shared_pages.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <platform.h>
#include <touch.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is common between
 *     all archiectures and all platforms that is needed for initializing
 *     the shim. This function will call platform and architecture specific
 *     functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
shim_init(void) NOEXCEPT
{
    uint64_t mut_i;
    uint32_t mut_version;
    uint64_t mut_num_pps;

    mut_num_pps = (uint64_t)platform_num_online_cpus();
    if (mut_num_pps > HYPERVISOR_MAX_PPS) {
        bferror_d64("unsupported number of CPUs", mut_num_pps);
        return SHIM_FAILURE;
    }

    mut_version = mv_id_op_version();
    if (mv_is_spec1_supported(mut_version)) {
        bferror_x32("unsupported version of MicroV. Is MicroV running?", mut_version);
        return SHIM_FAILURE;
    }

    g_mut_hndl = mv_handle_op_open_handle(MV_SPEC_ID1_VAL);
    if (MV_INVALID_HANDLE == g_mut_hndl) {
        bferror("mv_handle_op_open_handle failed");
        return SHIM_FAILURE;
    }

    for (mut_i = ((uint64_t)0); mut_i < mut_num_pps; ++mut_i) {
        g_mut_shared_pages[mut_i] = (void *)platform_alloc(HYPERVISOR_PAGE_SIZE);
        if (((void *)0) == g_mut_shared_pages[mut_i]) {
            bferror("platform_alloc failed");
            goto platform_alloc_failed;
        }

        touch();
    }

    return SHIM_SUCCESS;

platform_alloc_failed:

    for (mut_i = ((uint64_t)0); mut_i < mut_num_pps; ++mut_i) {
        platform_free(g_mut_shared_pages[mut_i], HYPERVISOR_PAGE_SIZE);
    }

    return SHIM_FAILURE;
}
