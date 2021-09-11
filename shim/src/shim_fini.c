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
 *     all archiectures and all platforms that is needed for finalizing
 *     the shim. This function will call platform and architecture specific
 *     functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
shim_fini(void) NOEXCEPT
{
    uint64_t mut_i;

    for (mut_i = ((uint64_t)0); mut_i < (uint64_t)platform_num_online_cpus(); ++mut_i) {
        platform_free(g_mut_shared_pages[mut_i], HYPERVISOR_PAGE_SIZE);
    }

    if (MV_INVALID_HANDLE != g_mut_hndl) {
        if (mv_handle_op_close_handle(g_mut_hndl)) {
            bferror("mv_handle_op_close_handle failed");
            return SHIM_FAILURE;
        }

        touch();
    }
    else {
        touch();
    }

    return SHIM_SUCCESS;
}
