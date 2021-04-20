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

#ifdef USE_XUE
#include <xue.h>
#endif

#include <bftypes.h>
#include <bfdebug.h>
#include <bfmemory.h>
#include <bfplatform.h>
#include <bfconstants.h>
#include <bfthreadcontext.h>
#include <bfdriverinterface.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

int g_uefi_boot = 0;
int g_enable_winpv = 0;
int g_disable_xen_pfd = 0;
int g_enable_xue = 0;

#define PCI_PT_CLASS_LIST_SIZE 14
uint64_t pci_pt_class_list[PCI_PT_CLASS_LIST_SIZE];
uint64_t pci_pt_class_count = 0;

#define NO_PCI_PT_LIST_SIZE 256
uint64_t no_pci_pt_list[NO_PCI_PT_LIST_SIZE];
uint64_t no_pci_pt_count = 0;

#ifdef USE_XUE
struct xue g_xue;
struct xue_ops g_xue_ops;
#endif

int64_t g_num_modules = 0;
struct bfelf_binary_t g_modules[MAX_NUM_MODULES];

_start_t _start_func = 0;
struct crt_info_t g_info;
struct bfelf_loader_t g_loader;

int64_t g_num_cpus_started = 0;
int64_t g_vmm_status = VMM_UNLOADED;

void *g_tls = 0;
void *g_stack = 0;

uint64_t g_tls_size = 0;
uint64_t g_stack_size = 0;
uint64_t g_stack_top = 0;

void *g_rsdp = 0;

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

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

int64_t
private_add_tss_mdl(void)
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

#ifdef USE_XUE

static int64_t add_xue_dma_to_mm(uint64_t virt, uint64_t order)
{
    int64_t ret = 0;
    struct memory_descriptor md = {0, 0, 0};
    uint64_t pages = 1UL << order;
    uint64_t i = 0;
    uint64_t first_phys = g_xue.ops->virt_to_dma(g_xue.sys, (const void *)virt);
    uint64_t phys = first_phys;
    uint64_t dma_contiguous = 1;

    for (i = 0; i < pages; i++) {
        md.virt = virt;
        md.phys = phys;
        md.type = MEMORY_TYPE_R | MEMORY_TYPE_W | MEMORY_TYPE_SHARED;

        if (!md.phys) {
            BFALERT("%s: NULL DMA translation for virt 0x%llx\n",
                    __func__,
                    md.virt);
            return FAILURE;
        }

        ret = platform_call_vmm_on_core(0, BF_REQUEST_ADD_MDL, (uintptr_t)&md, 0);
        if (ret != MEMORY_MANAGER_SUCCESS) {
            return ret;
        }

        if (i + 1 == pages) {
            break;
        }

        virt += XUE_PAGE_SIZE;
        phys = g_xue.ops->virt_to_dma(g_xue.sys, (const void *)virt);

        if (md.phys + XUE_PAGE_SIZE != phys) {
            BFALERT("xue dma is not contiguous\n");
            dma_contiguous = 0U;
        }
    }

    if (dma_contiguous) {
        BFDEBUG("add md: 0x%llx-0x%llx (xue-dma)\n",
                first_phys,
                first_phys + (pages * XUE_PAGE_SIZE) - 1);
    }

    return BF_SUCCESS;
}

static int64_t add_xue_mmio_to_mm(struct xue *xue)
{
    int64_t ret = 0;
    struct memory_descriptor md = {0, 0, 0};
    uint64_t pages = xue->xhc_mmio_size / XUE_PAGE_SIZE;
    uint64_t i = 0;

    if (xue->xhc_mmio_size & (XUE_PAGE_SIZE - 1)) {
        pages++;
    }

    for (; i < pages; i++) {
        md.virt = (uint64_t)(xue->xhc_mmio) + (i * XUE_PAGE_SIZE);
        md.phys = xue->xhc_mmio_phys + (i * XUE_PAGE_SIZE);

        md.type = MEMORY_TYPE_R | MEMORY_TYPE_W | MEMORY_TYPE_UC |
                  MEMORY_TYPE_SHARED;

        ret = platform_call_vmm_on_core(0, BF_REQUEST_ADD_MDL, (uintptr_t)&md, 0);
        if (ret != MEMORY_MANAGER_SUCCESS) {
            return ret;
        }
    }

    BFDEBUG("add md: 0x%llx-0x%llx (xue-mmio)\n",
            xue->xhc_mmio_phys,
            xue->xhc_mmio_phys + (pages * XUE_PAGE_SIZE) - 1);

    return BF_SUCCESS;
}

static void add_xue_mdl(void)
{
    int64_t ret = 0;

    if (!g_xue.open) {
        return;
    }

    ret = add_xue_mmio_to_mm(&g_xue);
    if (ret != BF_SUCCESS) {
        BFALERT("%s: failed to add mmio\n", __func__);
        return;
    }

    ret = add_xue_dma_to_mm((uint64_t)g_xue.dbc_ctx, 0);
    if (ret != BF_SUCCESS) {
        BFALERT("%s: failed to add dbc_ctx\n", __func__);
        return;
    }

    ret = add_xue_dma_to_mm((uint64_t)g_xue.dbc_erst, 0);
    if (ret != BF_SUCCESS) {
        BFALERT("%s: failed to add dbc_erst\n", __func__);
        return;
    }

    ret = add_xue_dma_to_mm((uint64_t)g_xue.dbc_ering.trb, XUE_TRB_RING_ORDER);
    if (ret != BF_SUCCESS) {
        BFALERT("%s: failed to add dbc_ering.trb\n", __func__);
        return;
    }

    ret = add_xue_dma_to_mm((uint64_t)g_xue.dbc_oring.trb, XUE_TRB_RING_ORDER);
    if (ret != BF_SUCCESS) {
        BFALERT("%s: failed to add dbc_oring.trb\n", __func__);
        return;
    }

    ret = add_xue_dma_to_mm((uint64_t)g_xue.dbc_iring.trb, XUE_TRB_RING_ORDER);
    if (ret != BF_SUCCESS) {
        BFALERT("%s: failed to add dbc_iring.trb\n", __func__);
        return;
    }

    ret = add_xue_dma_to_mm((uint64_t)g_xue.dbc_owork.buf, XUE_WORK_RING_ORDER);
    if (ret != BF_SUCCESS) {
        BFALERT("%s: failed to add dbc_owork.buf\n", __func__);
        return;
    }

    ret = add_xue_dma_to_mm((uint64_t)g_xue.dbc_str, 0);
    if (ret != BF_SUCCESS) {
        BFALERT("%s: failed to add dbc_str\n", __func__);
        return;
    }
}

#endif

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
    uint64_t i;

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

    ret = platform_call_vmm_on_core(0,
                                    BF_REQUEST_WINPV,
                                    (uint64_t)g_enable_winpv,
                                    (uint64_t)g_disable_xen_pfd);
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    for (i = 0; i < pci_pt_class_count; i++) {
        ret = platform_call_vmm_on_core(0,
                                        BF_REQUEST_PCI_PT_CLASS,
                                        pci_pt_class_list[i],
                                        0);
        if (ret != BF_SUCCESS) {
            goto failure;
        }
    }

    for (i = 0; i < no_pci_pt_count; i++) {
        ret = platform_call_vmm_on_core(0,
                                        BF_REQUEST_NO_PCI_PT,
                                        no_pci_pt_list[i],
                                        0);
        if (ret != BF_SUCCESS) {
            goto failure;
        }
    }

    ret = private_add_modules_mdl();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = private_add_tss_mdl();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

#ifdef USE_XUE
    if (g_enable_xue) {
        if (!g_xue.open) {
            platform_memset(&g_xue, 0, sizeof(g_xue));
            platform_memset(&g_xue_ops, 0, sizeof(g_xue_ops));
            g_xue.sysid = XUE_SYSID;

            if (g_xue.sysid != xue_sysid_windows) {
                xue_open(&g_xue, &g_xue_ops, NULL);
            }
        }

        if (g_xue.open) {
            add_xue_mdl();
        }

        ret = platform_call_vmm_on_core(0, BF_REQUEST_INIT_XUE,  (uint64_t)&g_xue, 0);
        if (ret != BF_SUCCESS) {
            goto failure;
        }
    }
#endif

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

#ifdef USE_XUE
    if (g_enable_xue) {
        if (g_xue.sysid != xue_sysid_windows) {
            xue_close(&g_xue);
        }
    }
#endif

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

    return _start_func((void *)(g_stack_top - sizeof(tc_t) - 1), &g_info);
}
