/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <common.h>
#include <xue.h>

#include <bftypes.h>
#include <bfdebug.h>
#include <bfmemory.h>
#include <bfplatform.h>
#include <bfconstants.h>
#include <bfthreadcontext.h>
#include <bfdriverinterface.h>
#include <bfxsave.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

int g_uefi_boot = 0;

struct xue g_xue;
struct xue_ops g_xue_ops;

int64_t g_num_modules = 0;
struct bfelf_binary_t g_modules[MAX_NUM_MODULES];

_start_t _start_func = 0;
struct crt_info_t g_info;
struct bfelf_loader_t g_loader;

uint64_t g_num_cpus = 0;
int64_t g_num_cpus_started = 0;
int64_t g_vmm_status = VMM_UNLOADED;

void *g_tls = 0;
void *g_stack = 0;

uint64_t g_tls_size = 0;
uint64_t g_stack_size = 0;
uint64_t g_stack_top = 0;

void *g_rsdp = 0;

struct xsave_info *g_xsi = 0;
uint64_t g_xsi_size = 0;
uint64_t g_xcr0_supported = 0;

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

static int valid_xsave_area(uint8_t *area, int size)
{
    if (!area) {
        return 0;
    }

    if ((uint64_t)area & 0x3FU) {
        BFERROR("Invalid XSAVE area alignment: %llx", (uint64_t)area);
        platform_free_rw(area, size);
        return 0;
    }

    if (((uint64_t)area >> 12) != ((uint64_t)area + size - 1) >> 12) {
        BFERROR("Invalid XSAVE area must be on one 4K page: %llx", (uint64_t)area);
        platform_free_rw(area, size);
        return 0;
    }

    return 1;
}

/*
 * Note that the xsave size is likely less than 4K, but we add
 * the mdl to the vmm as 4K below
 */
static int64_t private_setup_xsave(void)
{
    uint64_t i;

    uint32_t eax = 1;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    platform_cpuid(&eax, &ebx, &ecx, &edx);
    if ((ecx & (1UL << 26)) == 0) {
        return BF_ERROR_NO_XSAVE;
    }

    eax = 0xD;
    ecx = 0x0;
    platform_cpuid(&eax, &ebx, &ecx, &edx);

    /* Allocate an xsave_info for each cpu */
    g_num_cpus = (int)platform_num_cpus();
    g_xsi_size = g_num_cpus * sizeof(*g_xsi);
    g_xsi = (struct xsave_info *)platform_alloc_rw(g_xsi_size);
    if (!g_xsi) {
        return BF_ERROR_OUT_OF_MEMORY;
    }

    platform_memset(g_xsi, 0, g_xsi_size);

    for (i = 0; i < g_num_cpus; i++) {
        struct xsave_info *info = &g_xsi[i];
        info->host_area = platform_alloc_rw(ecx);
        platform_memset(info->host_area, 0, ecx);
        if (!valid_xsave_area(info->host_area, ecx)) {
            return BF_ERROR_XSAVE_AREA;
        }

        info->guest_area = platform_alloc_rw(ecx);
        platform_memset(info->guest_area, 0, ecx);
        if (!valid_xsave_area(info->guest_area, ecx)) {
            return BF_ERROR_XSAVE_AREA;
        }

        info->pcpuid = i;
        info->vcpuid = i;
        info->host_size = ecx;
        info->host_xcr0 = XSAVE_BUILD_XCR0;
        info->guest_size = ecx;
        info->cpuid_xcr0 = ((uint64_t)edx << 32) | eax;
    }

    return BF_SUCCESS;
}

int64_t
private_setup_stack(void)
{
    g_stack_size = STACK_SIZE * 2;

    g_stack = platform_alloc_rw(g_stack_size);
    if (g_stack == 0) {
        return BF_ERROR_OUT_OF_MEMORY;
    }

    g_stack_top = (uint64_t)g_stack + g_stack_size;
    g_stack_top = (g_stack_top & ~(STACK_SIZE - 1)) - 1;

    platform_memset(g_stack, 0, g_stack_size);
    return BF_SUCCESS;
}

int64_t
private_setup_tls(void)
{
    g_tls_size = THREAD_LOCAL_STORAGE_SIZE * (uint64_t)platform_num_cpus();

    g_tls = platform_alloc_rw(g_tls_size);
    if (g_tls == 0) {
        return BF_ERROR_OUT_OF_MEMORY;
    }

    platform_memset(g_tls, 0, g_tls_size);
    return BF_SUCCESS;
}

int64_t
private_setup_rsdp(void)
{
    g_rsdp = platform_get_rsdp();
    return BF_SUCCESS;
}

int64_t
private_add_raw_md_to_memory_manager(uint64_t virt, uint64_t type)
{
    int64_t ret = 0;
    struct memory_descriptor md = {0, 0, 0};

    md.virt = virt;
    md.phys = (uint64_t)platform_virt_to_phys((void *)md.virt);
    md.type = type;

    ret = platform_call_vmm_on_core(
        0, BF_REQUEST_ADD_MDL, (uintptr_t)&md, 0);

    if (ret != MEMORY_MANAGER_SUCCESS) {
        return ret;
    }

    return BF_SUCCESS;
}

int64_t
private_add_md_to_memory_manager(struct bfelf_binary_t *module)
{
    bfelf64_word s = 0;

    for (s = 0; s < bfelf_file_get_num_load_instrs(&module->ef); s++) {

        int64_t ret = 0;

        uint64_t exec_s = 0;
        uint64_t exec_e = 0;
        const struct bfelf_load_instr *instr = 0;

        ret = bfelf_file_get_load_instr(&module->ef, s, &instr);
        bfignored(ret);

        exec_s = (uint64_t)module->exec + instr->mem_offset;
        exec_e = (uint64_t)module->exec + instr->mem_offset + instr->memsz;
        exec_s &= ~(BAREFLANK_PAGE_SIZE - 1);
        exec_e &= ~(BAREFLANK_PAGE_SIZE - 1);

        for (; exec_s <= exec_e; exec_s += BAREFLANK_PAGE_SIZE) {
            if ((instr->perm & bfpf_x) != 0) {
                ret = private_add_raw_md_to_memory_manager(
                          exec_s, MEMORY_TYPE_R | MEMORY_TYPE_E);
            }
            else {
                ret = private_add_raw_md_to_memory_manager(
                          exec_s, MEMORY_TYPE_R | MEMORY_TYPE_W);
            }

            if (ret != MEMORY_MANAGER_SUCCESS) {
                return ret;
            }
        }
    }

    return BF_SUCCESS;
}

static int64_t private_add_xsave_mdl(void)
{
    uint64_t i;
    int64_t ret;
    const uint64_t type = MEMORY_TYPE_R | MEMORY_TYPE_W;

    for (i = 0; i < g_xsi_size; i += BAREFLANK_PAGE_SIZE) {
        ret = private_add_raw_md_to_memory_manager((uint64_t)g_xsi + i, type);
        if (ret != BF_SUCCESS) {
            return ret;
        }
    }

    for (i = 0; i < g_num_cpus; i++) {
        struct xsave_info *info = &g_xsi[i];
        uint64_t size = info->host_size;
        uint64_t j = 0;

        for (; j < size; j += BAREFLANK_PAGE_SIZE) {
            uint64_t virt = (uint64_t)info->host_area + j;
            ret = private_add_raw_md_to_memory_manager(virt, type);
            if (ret != BF_SUCCESS) {
                return ret;
            }
        }

        size = info->guest_size;
        for (j = 0; j < size; j += BAREFLANK_PAGE_SIZE) {
            uint64_t virt = (uint64_t)info->guest_area + j;
            ret = private_add_raw_md_to_memory_manager(virt, type);
            if (ret != BF_SUCCESS) {
                return ret;
            }
        }
    }

    return BF_SUCCESS;
}

int64_t
private_add_tls_mdl(void)
{
    uint64_t i = 0;

    for (i = 0; i < g_tls_size; i += BAREFLANK_PAGE_SIZE) {

        int64_t ret = private_add_raw_md_to_memory_manager(
                  (uint64_t)g_tls + i, MEMORY_TYPE_R | MEMORY_TYPE_W);

        if (ret != BF_SUCCESS) {
            return ret;
        }
    }

    return BF_SUCCESS;
}

int64_t
private_add_modules_mdl(void)
{
    int64_t i = 0;

    for (i = 0; i < g_num_modules; i++) {
        int64_t ret = private_add_md_to_memory_manager(&g_modules[i]);
        if (ret != BF_SUCCESS) {
            return ret;
        }
    }

    return BF_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

int64_t
common_vmm_status(void)
{ return g_vmm_status; }

void
common_reset(void)
{
    int64_t i;

    if (g_xsi != 0) {
        for (i = 0; i < (int64_t)g_num_cpus; i++) {
            struct xsave_info *info = &g_xsi[i];
            if (info->host_area) {
                platform_free_rw(info->host_area, info->host_size);
            }
            if (info->guest_area) {
                platform_free_rw(info->guest_area, info->guest_size);
            }
        }
        platform_free_rw(g_xsi, g_xsi_size);
        g_xsi = 0;
        g_xsi_size = 0;
        g_num_cpus = 0;
    }

    for (i = 0; i < g_num_modules; i++) {
        if (g_modules[i].exec != 0) {
            platform_free_rwe(g_modules[i].exec, g_modules[i].exec_size);
        }
    }

    platform_memset(&g_modules, 0, sizeof(g_modules));
    platform_memset(&g_loader, 0, sizeof(struct bfelf_loader_t));
    platform_memset(&g_info, 0, sizeof(struct crt_info_t));
    platform_memset(&g_loader, 0, sizeof(struct bfelf_loader_t));

    _start_func = 0;

    g_num_modules = 0;
    g_num_cpus_started = 0;
    g_vmm_status = VMM_UNLOADED;

    if (g_tls != 0) {
        platform_free_rw(g_tls, g_tls_size);
    }

    if (g_stack != 0) {
        platform_free_rw(g_stack, g_stack_size);
    }


    g_tls = 0;
    g_stack = 0;
    g_stack_top = 0;
    g_uefi_boot = 0;
    g_rsdp = 0;
}

int64_t
common_init(void)
{
    int64_t ret = platform_init();
    if (ret != BF_SUCCESS) {
        return ret;
    }

    common_reset();

    return BF_SUCCESS;
}

int64_t
common_fini(void)
{
    if (common_vmm_status() == VMM_RUNNING) {
        if (common_stop_vmm() != BF_SUCCESS) {
            BFALERT("common_fini: failed to stop vmm\n");
        }
    }

    if (common_vmm_status() == VMM_LOADED) {
        if (common_unload_vmm() != BF_SUCCESS) {
            BFALERT("common_fini: failed to unload vmm\n");
        }
    }

    if (common_vmm_status() == VMM_CORRUPT) {
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (g_num_modules > 0) {
        common_reset();
    }

    return BF_SUCCESS;
}

int64_t
common_add_module(const char *file, uint64_t fsize)
{
    if (file == 0 || fsize == 0) {
        return BF_ERROR_INVALID_ARG;
    }

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            return BF_ERROR_VMM_CORRUPTED;
        case VMM_LOADED:
            return BF_ERROR_VMM_INVALID_STATE;
        case VMM_RUNNING:
            return BF_ERROR_VMM_INVALID_STATE;
        default:
            break;
    }

    if (g_num_modules >= MAX_NUM_MODULES) {
        return BF_ERROR_MAX_MODULES_REACHED;
    }

    g_modules[g_num_modules].file = file;
    g_modules[g_num_modules].file_size = fsize;

    g_num_modules++;
    return BF_SUCCESS;
}

int64_t
common_load_vmm(void)
{
    int64_t ret = 0;
    int64_t ignore_ret = 0;

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            return BF_ERROR_VMM_CORRUPTED;
        case VMM_LOADED:
            return BF_SUCCESS;
        case VMM_RUNNING:
            return BF_ERROR_VMM_INVALID_STATE;
        default:
            break;
    }

    if (g_num_modules == 0) {
        return BF_ERROR_NO_MODULES_ADDED;
    }

    ret = private_setup_stack();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = private_setup_xsave();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = private_setup_tls();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = private_setup_rsdp();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = bfelf_load(g_modules, (uint64_t)g_num_modules,(void **)&_start_func, &g_info, &g_loader);
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = platform_call_vmm_on_core(0, BF_REQUEST_INIT, 0, 0);
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = platform_call_vmm_on_core(0, BF_REQUEST_SET_RSDP,  (uint64_t)g_rsdp, 0);
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = platform_call_vmm_on_core(0, BF_REQUEST_UEFI_BOOT,  (uint64_t)g_uefi_boot, 0);
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = private_add_modules_mdl();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = private_add_tls_mdl();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = private_add_xsave_mdl();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    g_xue.sysid = XUE_SYSID;

    if (g_xue.sysid != xue_sysid_linux) {
        platform_memset(&g_xue, 0, sizeof(g_xue));
        platform_memset(&g_xue_ops, 0, sizeof(g_xue_ops));
        g_xue.sysid = XUE_SYSID;
        if (g_xue.sysid != xue_sysid_windows) {
            xue_open(&g_xue, &g_xue_ops, NULL);
        }
    } else {
        xue_start(&g_xue);
    }

    ret = platform_call_vmm_on_core(0, BF_REQUEST_INIT_XUE,  (uint64_t)&g_xue, 0);
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    g_vmm_status = VMM_LOADED;
    return BF_SUCCESS;

failure:

    ignore_ret = common_unload_vmm();
    bfignored(ignore_ret);

    return ret;
}

int64_t
common_unload_vmm(void)
{
    int64_t ret = 0;

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            return BF_ERROR_VMM_CORRUPTED;
        case VMM_RUNNING:
            return BF_ERROR_VMM_INVALID_STATE;
        case VMM_UNLOADED:
            goto unloaded;
        default:
            break;
    }

    if (g_xue.sysid != xue_sysid_windows) {
        xue_close(&g_xue);
    }

    ret = platform_call_vmm_on_core(0, BF_REQUEST_FINI, 0, 0);
    if (ret != BF_SUCCESS) {
        goto corrupted;
    }

unloaded:

    common_reset();

    g_vmm_status = VMM_UNLOADED;
    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return ret;
}

int64_t
common_start_vmm(void)
{
    int64_t ret = 0;
    int64_t cpuid = 0;
    int64_t ignore_ret = 0;

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            return BF_ERROR_VMM_CORRUPTED;
        case VMM_RUNNING:
            return BF_SUCCESS;
        case VMM_UNLOADED:
            return BF_ERROR_VMM_INVALID_STATE;
        default:
            break;
    }

    for (cpuid = 0, g_num_cpus_started = 0; cpuid < platform_num_cpus(); cpuid++) {
        ret = platform_call_vmm_on_core(
                  (uint64_t)cpuid, BF_REQUEST_VMM_INIT, (uint64_t)cpuid, 0);

        if (ret != BF_SUCCESS) {
            goto failure;
        }

        g_num_cpus_started++;
    }

    g_vmm_status = VMM_RUNNING;
    return BF_SUCCESS;

failure:

    ignore_ret = common_stop_vmm();
    bfignored(ignore_ret);

    return ret;
}

int64_t
common_stop_vmm(void)
{
    int64_t ret = 0;
    int64_t cpuid = 0;

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            return BF_ERROR_VMM_CORRUPTED;
        case VMM_UNLOADED:
            return BF_ERROR_VMM_INVALID_STATE;
        default:
            break;
    }

    for (cpuid = g_num_cpus_started - 1; cpuid >= 0 ; cpuid--) {
        ret = platform_call_vmm_on_core(
            (uint64_t)cpuid, BF_REQUEST_VMM_FINI, (uint64_t)cpuid, 0);

        if (ret != BFELF_SUCCESS) {
            goto corrupted;
        }

        g_num_cpus_started--;
    }

    g_vmm_status = VMM_LOADED;
    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return ret;
}

int64_t
common_dump_vmm(struct debug_ring_resources_t **drr, uint64_t vcpuid)
{
    int64_t ret = 0;

    if (drr == 0) {
        return BF_ERROR_INVALID_ARG;
    }

    if (common_vmm_status() == VMM_UNLOADED) {
        return BF_ERROR_VMM_INVALID_STATE;
    }

    ret = platform_call_vmm_on_core(
        0, BF_REQUEST_GET_DRR, (uint64_t)vcpuid, (uint64_t)drr);

    if (ret != BFELF_SUCCESS) {
        return ret;
    }

    return BF_SUCCESS;
}

typedef struct thread_context_t tc_t;

int64_t
common_call_vmm(
    uint64_t cpuid, uint64_t request, uintptr_t arg1, uintptr_t arg2)
{
    int64_t ignored_ret = 0;
    tc_t *tc = (tc_t *)(g_stack_top - sizeof(tc_t));

    ignored_ret = bfelf_set_integer_args(&g_info, request, arg1, arg2, 0);
    bfignored(ignored_ret);

    tc->cpuid = cpuid;
    tc->tlsptr = (uint64_t *)((uint64_t)g_tls + (THREAD_LOCAL_STORAGE_SIZE * (uint64_t)cpuid));
    tc->xsave_info = &g_xsi[cpuid];

    return _start_func((void *)(g_stack_top - sizeof(tc_t) - 1), &g_info);
}
