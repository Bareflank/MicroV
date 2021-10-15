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

#include <debug.h>
#include <detect_hypervisor.h>
#include <g_mut_hndl.h>
#include <g_mut_shared_pages.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_types.h>
#include <platform.h>
#include <shim_fini.h>

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
shim_init_on_cpu(uint32_t const cpu) NOEXCEPT
{
    uint64_t mut_gpa;

    g_mut_shared_pages[cpu] = (void *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == g_mut_shared_pages[cpu]) {
        bferror("platform_alloc failed");
        return SHIM_FAILURE;
    }

    mut_gpa = platform_virt_to_phys(g_mut_shared_pages[cpu]);

    (void)mv_pp_op_clr_shared_page_gpa(g_mut_hndl);
    if (mv_pp_op_set_shared_page_gpa(g_mut_hndl, mut_gpa)) {
        bferror("mv_pp_op_set_shared_page_gpa failed");
        return SHIM_FAILURE;
    }

    if (mv_pp_op_tsc_set_khz(g_mut_hndl, platform_tsc_khz())) {
        bferror("mv_pp_op_tsc_set_khz failed");
        return SHIM_FAILURE;
    }

    return SHIM_SUCCESS;
}

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
    uint32_t mut_version;
    uint64_t mut_num_pps;

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Is MicroV running?");
        return SHIM_FAILURE;
    }

    mut_version = mv_id_op_version();
    if (mv_is_spec1_supported(mut_version)) {
        bferror_x32("Unsupported version of MicroV. Is MicroV running?", mut_version);
        return SHIM_FAILURE;
    }

    mut_num_pps = (uint64_t)platform_num_online_cpus();
    if (mut_num_pps > HYPERVISOR_MAX_PPS) {
        bferror_d64("Unsupported number of CPUs", mut_num_pps);
        return SHIM_FAILURE;
    }

    g_mut_hndl = mv_handle_op_open_handle(MV_SPEC_ID1_VAL);
    if (MV_INVALID_HANDLE == g_mut_hndl) {
        bferror("mv_handle_op_open_handle failed");
        return SHIM_FAILURE;
    }

    if (platform_on_each_cpu(shim_init_on_cpu, PLATFORM_FORWARD)) {
        bferror("shim_init_on_cpu failed");
        goto shim_init_on_cpu_failed;
    }

    return SHIM_SUCCESS;

shim_init_on_cpu_failed:
    shim_fini();

    return SHIM_FAILURE;
}
