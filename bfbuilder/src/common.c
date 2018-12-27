/*
 * Copyright (C) 2018 Assured Information Security, Inc.
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
#include <bootparam.h>

#include <bfdebug.h>
#include <bfplatform.h>
#include <bfconstants.h>
#include <bfgpalayout.h>
#include <bfhypercall.h>

#define bfalloc_page(a) \
    (a *)platform_memset(platform_alloc_rwe(BAREFLANK_PAGE_SIZE), 0, BAREFLANK_PAGE_SIZE);
#define bfalloc_buffer(a,b) \
    (a *)platform_memset(platform_alloc_rwe(b), 0, b);

/* -------------------------------------------------------------------------- */
/* VM Object                                                                  */
/* -------------------------------------------------------------------------- */

#define MAX_VMS 0x1000

struct vm_t {
    uint64_t domainid;

    void *bios_ram;
    void *zero_page;

    struct boot_params *params;
    char *cmdline;

    uint64_t *gdt;
    uint64_t *idt;
    uint64_t *tss;

    char *addr;
    uint64_t size;

    int used;
};

static struct vm_t g_vms[MAX_VMS] = {0};

static struct vm_t *
acquire_vm(void)
{
    int64_t i;
    struct vm_t *vm = 0;

    platform_acquire_mutex();

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used == 0) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. Could not acquire VM\n");
        goto done;
    }

    vm->used = 1;

done:

    platform_release_mutex();
    return vm;
}

static void
release_vm(struct vm_t *vm)
{
    platform_acquire_mutex();
    platform_memset(vm, 0, sizeof(struct vm_t));
    platform_release_mutex();
}

static struct vm_t *
get_vm(domainid_t domainid)
{
    int64_t i;
    struct vm_t *vm = 0;

    platform_acquire_mutex();

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used != 0 && vm->domainid == domainid) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. Could not locate VM\n");
        goto done;
    }

done:

    platform_release_mutex();
    return vm;
}

/* -------------------------------------------------------------------------- */
/* E820 Functions                                                             */
/* -------------------------------------------------------------------------- */

int64_t
add_e820_entry(void *vm, uint64_t saddr, uint64_t eaddr, uint32_t type)
{
    status_t ret = 0;
    // struct vm_t *_vm = (struct vm_t *)vm;

    // ret = __domain_op__add_e820_entry(_vm->domainid, saddr, eaddr - saddr, type);
    // if (ret != SUCCESS) {
    //     BFDEBUG("__domain_op__add_e820_entry: failed\n");
    // }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* Donate Functions                                                           */
/* -------------------------------------------------------------------------- */

static status_t
donate_page(
    struct vm_t *vm, void *gva, uint64_t domain_gpa, uint64_t type)
{
    status_t ret;
    uint64_t gpa = (uint64_t)platform_virt_to_phys(gva);

    ret = __domain_op__share_page(vm->domainid, gpa, domain_gpa, type);
    if (ret != SUCCESS) {
        BFDEBUG("donate_page: __domain_op__donate_gpa failed\n");
    }

    return ret;
}

static status_t
donate_buffer(
    struct vm_t *vm, void *gva, uint64_t domain_gpa, uint64_t size, uint64_t type)
{
    uint64_t i;
    status_t ret = SUCCESS;

    for (i = 0; i < size; i += BAREFLANK_PAGE_SIZE) {
        ret = donate_page(vm, (char *)gva + i, domain_gpa + i, type);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return ret;
}

static status_t
donate_page_to_page_range(
    struct vm_t *vm, void *gva, uint64_t domain_gpa, uint64_t size, uint64_t type)
{
    uint64_t i;
    status_t ret = SUCCESS;

    for (i = 0; i < size; i += BAREFLANK_PAGE_SIZE) {
        ret = donate_page(vm, gva, domain_gpa + i, type);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* UART                                                                       */
/* -------------------------------------------------------------------------- */

static status_t
setup_uart(
    struct vm_t *vm, uint64_t uart)
{
    status_t ret = SUCCESS;

    if (uart != 0) {
        ret = __domain_op__set_uart(vm->domainid, uart);
        if (ret != SUCCESS) {
            BFDEBUG("donate_page: __domain_op__set_uart failed\n");
        }
    }

    return ret;
}

static status_t
setup_pt_uart(
    struct vm_t *vm, uint64_t uart)
{
    status_t ret = SUCCESS;

    if (uart != 0) {
        ret = __domain_op__set_pt_uart(vm->domainid, uart);
        if (ret != SUCCESS) {
            BFDEBUG("donate_page: __domain_op__set_pt_uart failed\n");
        }
    }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* GPA Functions                                                              */
/* -------------------------------------------------------------------------- */

static status_t
setup_boot_params(struct vm_t *vm)
{
    status_t ret;

    vm->params = bfalloc_page(struct boot_params);
    if (vm->params == 0) {
        BFDEBUG("setup_boot_params: failed to alloc start into page\n");
        return FAILURE;
    }

    // vm->xen_start_info->magic = XEN_HVM_START_MAGIC_VALUE;
    // vm->xen_start_info->version = 0;
    // vm->xen_start_info->cmdline_paddr = XEN_COMMAND_LINE_PAGE_GPA;
    // vm->xen_start_info->rsdp_paddr = ACPI_RSDP_GPA;

    ret = donate_page(vm, vm->params, BOOT_PARAMS_PAGE_GPA, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_boot_params: donate failed\n");
        return ret;
    }

    return ret;
}

static status_t
setup_kernel(struct vm_t *vm, struct create_from_elf_args *args)
{
    // Notes:
    //
    // The instructions for how to a 64bit kernel can be found here:
    // https://www.kernel.org/doc/Documentation/x86/boot.txt
    //
    // Some important notes include:
    // - A bzImage has a setup_header struct located at 0x1f1 from the start
    //   of the file. The actual beginning of the image appears to be a piece
    //   of code that tells the user to use a boot-loader and then reboots.
    // - The setup_header that is inside the bzImage needs to be copied to
    //   our own boot_params structure, and it already has a bunch of the
    //   values filled in for us based on how the kernel was compiled. For
    //   example, this header contains (as the first value) the number of
    //   512 blocks to the start of the actual kernel in a field called
    //   setup_sects. To calculate the start of the kernel, you use the
    //   following:
    //
    //   start = (file[0x1f1] + 1) * 512
    //
    //   Once you have the start of the kernel, you need to load the kernel
    //   at the address in code32_start which must be 0x100000 as that is
    //   what is stated by the "LOADING THE REST OF THE KERNEL" section in
    //   boot.txt
    //

// alloc, zero bp;
// copy 0x1f1 to end of setup in kernel to bp. end == 202 + value at 202
// kernel starts at sects + 1 * 512. Copy to GPA == code_32 (which should be 0x100000)
// entry is the 0x100000 + 0x200

    status_t ret = 0;
    const struct setup_header *header = (struct setup_header *)(args->file + 0x1f1);
BFDEBUG("line: %d\n", __LINE__);

    if (args->file == 0) {
        BFDEBUG("setup_kernel: bzImage is null\n");
        return FAILURE;
    }
BFDEBUG("line: %d\n", __LINE__);

    if (args->size == 0) {
        BFDEBUG("setup_kernel: bzImage has 0 size\n");
        return FAILURE;
    }
BFDEBUG("line: %d\n", __LINE__);

    if (args->file_size > args->size) {
        BFDEBUG("setup_kernel: requested RAM is smaller than bzImage\n");
        return FAILURE;
    }
BFDEBUG("line: %d\n", __LINE__);

    if (header->header != 0x53726448) {
        BFDEBUG("setup_kernel: bzImage does not contain magic number\n");
        return FAILURE;
    }

BFDEBUG("line: %d\n", __LINE__);
    if (header->version != 0x020d) {
        BFDEBUG("setup_kernel: unsupported bzImage protocol\n");
        return FAILURE;
    }

BFDEBUG("line: %d\n", __LINE__);
    if (header->code32_start != 0x100000) {
        BFDEBUG("setup_kernel: unsupported bzImage start location\n");
        return FAILURE;
    }
BFDEBUG("line: %d\n", __LINE__);

    vm->size = args->size;
    vm->addr = bfalloc_buffer(char, vm->size);

    if (vm->addr == 0) {
        BFDEBUG("setup_kernel: failed to alloc ram\n");
        return FAILURE;
    }

BFDEBUG("line: %d\n", __LINE__);
    // platform_memcpy(vm->addr, args->file, args->file_size);

    // 0x000100000

    // ret = donate_buffer(
    //     vm, vm->addr, START_ADDR, vm->size, MAP_RWE);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    // ret = setup_e820_map(vm, vm->size);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    return ret;
}



// static status_t
// setup_xen_cmdline(struct vm_t *vm, struct create_from_elf_args *args)
// {
//     status_t ret;

//     if (args->cmdl_size >= BAREFLANK_PAGE_SIZE) {
//         BFDEBUG("setup_xen_cmdline: cmdl must be smaller than a page\n");
//         return FAILURE;
//     }

//     vm->xen_cmdl = bfalloc_page(char);
//     if (vm->xen_cmdl == 0) {
//         BFDEBUG("setup_xen_cmdline: failed to alloc cmdl page\n");
//         return FAILURE;
//     }

//     platform_memcpy(vm->xen_cmdl, args->cmdl, args->cmdl_size);

//     ret = donate_page(vm, vm->xen_cmdl, XEN_COMMAND_LINE_PAGE_GPA, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFDEBUG("setup_xen_cmdline: donate failed\n");
//         return ret;
//     }

//     return SUCCESS;
// }

// static status_t
// setup_xen_console(struct vm_t *vm)
// {
//     status_t ret;

//     vm->xen_console = bfalloc_page(void);
//     if (vm->xen_console == 0) {
//         BFDEBUG("setup_xen_console: failed to alloc console page\n");
//         return FAILURE;
//     }

//     ret = donate_page(vm, vm->xen_console, XEN_CONSOLE_PAGE_GPA, MAP_RW);
//     if (ret != BF_SUCCESS) {
//         BFDEBUG("setup_xen_console: donate failed\n");
//         return ret;
//     }

//     return ret;
// }

static status_t
setup_bios_ram(struct vm_t *vm)
{
    status_t ret;

    vm->bios_ram = bfalloc_buffer(void, BIOS_RAM_SIZE);
    if (vm->bios_ram == 0) {
        BFDEBUG("setup_bios_ram: failed to alloc bios ram\n");
        return FAILURE;
    }

    ret = donate_buffer(vm, vm->bios_ram, BIOS_RAM_ADDR, BIOS_RAM_SIZE, MAP_RWE);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_bios_ram: donate failed\n");
        return ret;
    }

    return ret;
}

static status_t
setup_reserved_free(struct vm_t *vm)
{
    status_t ret;

    vm->zero_page = bfalloc_page(void);
    if (vm->zero_page == 0) {
        BFDEBUG("setup_reserved_free: failed to alloc zero page\n");
        return FAILURE;
    }

    ret = donate_page_to_page_range(
        vm, vm->zero_page, RESERVED1_ADRR, RESERVED1_SIZE, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_reserved_free: donate failed\n");
        return ret;
    }

    ret = donate_page_to_page_range(
        vm, vm->zero_page, RESERVED2_ADRR, RESERVED2_ADRR, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_reserved_free: donate failed\n");
        return ret;
    }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* Initial Register State                                                     */
/* -------------------------------------------------------------------------- */

// static status_t
// setup_entry(struct vm_t *vm)
// {
//     status_t ret;

//     ret = __domain_op__set_entry(vm->domainid, vm->entry);
//     if (ret != SUCCESS) {
//         BFDEBUG("setup_entry: __domain_op__set_entry failed\n");
//     }

//     return ret;
// }

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

int64_t
common_create_from_elf(
    struct create_from_elf_args *args)
{
    status_t ret;
    struct vm_t *vm = acquire_vm();

    args->domainid = INVALID_DOMAINID;

BFDEBUG("line: %d\n", __LINE__);
    if (_cpuid_eax(0xBF00) != 0xBF01) {
        return COMMON_NO_HYPERVISOR;
    }

BFDEBUG("line: %d\n", __LINE__);

    vm->domainid = __domain_op__create_domain();
    if (vm->domainid == INVALID_DOMAINID) {
        BFDEBUG("__domain_op__create_domain failed\n");
        return COMMON_CREATE_FROM_ELF_FAILED;
    }

BFDEBUG("line: %d\n", __LINE__);
    ret = setup_kernel(vm, args);
    if (ret != SUCCESS) {
        return ret;
    }

    // ret = setup_boot_params(vm);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    // ret = setup_xen_cmdline(vm, args);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    // ret = setup_xen_console(vm);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    // ret = setup_bios_ram(vm);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    // ret = setup_reserved_free(vm);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    // ret = setup_entry(vm);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    // ret = setup_uart(vm, args->uart);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    // ret = setup_pt_uart(vm, args->pt_uart);
    // if (ret != SUCCESS) {
    //     return ret;
    // }

    args->domainid = vm->domainid;
    return BF_SUCCESS;
}

int64_t
common_destroy(uint64_t domainid)
{
    status_t ret;
    struct vm_t *vm = get_vm(domainid);

    if (_cpuid_eax(0xBF00) != 0xBF01) {
        return COMMON_NO_HYPERVISOR;
    }

    ret = __domain_op__destroy_domain(vm->domainid);
    if (ret != SUCCESS) {
        BFDEBUG("__domain_op__destroy_domain failed\n");
        return ret;
    }

    platform_free_rw(vm->bios_ram, 0xE8000);
    platform_free_rw(vm->zero_page, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->params, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->cmdline, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->gdt, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->idt, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->tss, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->addr, vm->size);

    release_vm(vm);
    return BF_SUCCESS;
}
