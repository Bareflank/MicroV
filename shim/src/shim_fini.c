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

#include <detect_hypervisor.h>
#include <g_mut_hndl.h>
#include <g_mut_shared_pages.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_types.h>
#include <platform.h>

/**
 * <!-- description -->
 *   @brief Initializes the shim on the requested cpu (i.e. PP). This is
 *     needed because to tell MicroV what the GPA of the shared page is
 *     on a PP, we need to execute mv_pp_op_set_shared_page_gpa from the
 *     PP the shared page will be used on (which MicroV requires so that
 *     it doesn't have to perform IPIs when setting or clearing the shared
 *     page from it's own page tables).
 *
 * <!-- inputs/outputs -->
 *   @param cpu the cpu (i.e. PP) we are executing on
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
shim_fini_on_cpu(uint32_t const cpu) NOEXCEPT
{
    if (detect_hypervisor()) {
        (void)platform_free(g_mut_shared_pages[cpu], HYPERVISOR_PAGE_SIZE);
        return SHIM_SUCCESS;
    }

    (void)mv_pp_op_clr_shared_page_gpa(g_mut_hndl);
    (void)platform_free(g_mut_shared_pages[cpu], HYPERVISOR_PAGE_SIZE);

    return SHIM_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is common between
 *     all archiectures and all platforms that is needed for finalizing
 *     the shim. This function will call platform and architecture specific
 *     functions as needed.
 */
void
shim_fini(void) NOEXCEPT
{
    if (MV_INVALID_HANDLE == g_mut_hndl) {
        return;
    }

    (void)platform_on_each_cpu(shim_fini_on_cpu, PLATFORM_REVERSE);
    (void)mv_handle_op_close_handle(g_mut_hndl);

    g_mut_hndl = MV_INVALID_HANDLE;
}
