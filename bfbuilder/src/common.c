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

#include <bootparams.h>

#include <acpi.h>
#include <common.h>

#include <bfack.h>
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

    char *addr;
    uint64_t size;

    struct rsdp_t *rsdp;
    struct xsdt_t *xsdt;
    struct madt_t *madt;
    struct fadt_t *fadt;
    struct dsdt_t *dsdt;

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
    struct vm_t *_vm = (struct vm_t *)vm;

    if (_vm->params->e820_entries >= E820_MAX_ENTRIES_ZEROPAGE) {
        BFDEBUG("add_e820_entry: E820_MAX_ENTRIES_ZEROPAGE reached\n");
        return FAILURE;
    }

    _vm->params->e820_table[_vm->params->e820_entries].addr = saddr;
    _vm->params->e820_table[_vm->params->e820_entries].size = eaddr - saddr;
    _vm->params->e820_table[_vm->params->e820_entries].type = type;
    _vm->params->e820_entries++;

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Donate Functions                                                           */
/* -------------------------------------------------------------------------- */

static status_t
donate_page_r(
    struct vm_t *vm, void *gva, uint64_t domain_gpa)
{
    status_t ret = SUCCESS;
    uint64_t gpa = (uint64_t)platform_virt_to_phys(gva);

    ret = __domain_op__donate_page_r(vm->domainid, gpa, domain_gpa);
    if (ret != SUCCESS) {
        BFDEBUG("donate_page: __domain_op__donate_page_r failed\n");
        return ret;
    }

    return SUCCESS;
}

static status_t
donate_page_rw(
    struct vm_t *vm, void *gva, uint64_t domain_gpa)
{
    status_t ret = SUCCESS;
    uint64_t gpa = (uint64_t)platform_virt_to_phys(gva);

    ret = __domain_op__donate_page_rw(vm->domainid, gpa, domain_gpa);
    if (ret != SUCCESS) {
        BFDEBUG("donate_page: __domain_op__donate_page_rw failed\n");
        return ret;
    }

    return SUCCESS;
}

static status_t
donate_page_rwe(
    struct vm_t *vm, void *gva, uint64_t domain_gpa)
{
    status_t ret = SUCCESS;
    uint64_t gpa = (uint64_t)platform_virt_to_phys(gva);

    ret = __domain_op__donate_page_rwe(vm->domainid, gpa, domain_gpa);
    if (ret != SUCCESS) {
        BFDEBUG("donate_page: __domain_op__donate_page_rwe failed\n");
        return ret;
    }

    return SUCCESS;
}

static status_t
donate_buffer(
    struct vm_t *vm, void *gva, uint64_t domain_gpa, uint64_t size)
{
    uint64_t i;
    status_t ret = SUCCESS;

    for (i = 0; i < size; i += BAREFLANK_PAGE_SIZE) {
        ret = donate_page_rwe(vm, (char *)gva + i, domain_gpa + i);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
}

static status_t
donate_page_to_page_range(
    struct vm_t *vm, void *gva, uint64_t domain_gpa, uint64_t size)
{
    uint64_t i;
    status_t ret = SUCCESS;

    for (i = 0; i < size; i += BAREFLANK_PAGE_SIZE) {
        ret = donate_page_r(vm, gva, domain_gpa + i);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return SUCCESS;
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
            return ret;
        }
    }

    return SUCCESS;
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
            return ret;
        }
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* GPA Functions                                                              */
/* -------------------------------------------------------------------------- */

#define HDR_SIZE sizeof(struct setup_header)

static status_t
setup_cmdline(struct vm_t *vm, struct create_vm_from_bzimage_args *args)
{
    status_t ret = SUCCESS;

    vm->cmdline = bfalloc_page(char);
    if (vm->cmdline == 0) {
        BFDEBUG("setup_cmdline: failed to alloc cmdline page\n");
        return FAILURE;
    }

    ret = platform_memcpy(
        vm->cmdline, BAREFLANK_PAGE_SIZE, args->cmdl, args->cmdl_size, args->cmdl_size);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = donate_page_r(vm, vm->cmdline, COMMAND_LINE_PAGE_GPA);
    if (ret != SUCCESS) {
        return ret;
    }

    vm->params->hdr.cmd_line_ptr = COMMAND_LINE_PAGE_GPA;
    return SUCCESS;
}

static status_t
setup_acpi(struct vm_t *vm)
{
    status_t ret = SUCCESS;

    vm->rsdp = bfalloc_page(struct rsdp_t);
    if (vm->rsdp == 0) {
        BFDEBUG("setup_acpi: failed to alloc rsdp page\n");
        return FAILURE;
    }

    vm->xsdt = bfalloc_page(struct xsdt_t);
    if (vm->xsdt == 0) {
        BFDEBUG("setup_acpi: failed to alloc xsdt page\n");
        return FAILURE;
    }

    vm->madt = bfalloc_page(struct madt_t);
    if (vm->madt == 0) {
        BFDEBUG("setup_acpi: failed to alloc madt page\n");
        return FAILURE;
    }

    vm->fadt = bfalloc_page(struct fadt_t);
    if (vm->fadt == 0) {
        BFDEBUG("setup_acpi: failed to alloc fadt page\n");
        return FAILURE;
    }

    vm->dsdt = bfalloc_page(struct dsdt_t);
    if (vm->dsdt == 0) {
        BFDEBUG("setup_acpi: failed to alloc dsdt page\n");
        return FAILURE;
    }

    ret = donate_page_r(vm, vm->rsdp, ACPI_RSDP_GPA);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = donate_page_r(vm, vm->xsdt, ACPI_XSDT_GPA);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = donate_page_r(vm, vm->madt, ACPI_MADT_GPA);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = donate_page_r(vm, vm->fadt, ACPI_FADT_GPA);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = donate_page_r(vm, vm->dsdt, ACPI_DSDT_GPA);
    if (ret != SUCCESS) {
        return ret;
    }

    setup_rsdp(vm->rsdp);
    setup_xsdt(vm->xsdt);
    setup_madt(vm->madt);
    setup_fadt(vm->fadt);
    setup_dsdt(vm->dsdt);

    return SUCCESS;
}

static status_t
setup_boot_params(
    struct vm_t *vm, struct create_vm_from_bzimage_args *args, const struct setup_header *hdr)
{
    status_t ret = SUCCESS;

    vm->params = bfalloc_page(struct boot_params);
    if (vm->params == 0) {
        BFDEBUG("setup_boot_params: failed to alloc start into page\n");
        return FAILURE;
    }

    ret = platform_memcpy(&vm->params->hdr, HDR_SIZE, hdr, HDR_SIZE, HDR_SIZE);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = donate_page_rw(vm, vm->params, BOOT_PARAMS_PAGE_GPA);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_cmdline(vm, args);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_acpi(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_e820_map(vm, args->size);
    if (ret != SUCCESS) {
        return ret;
    }

    vm->params->hdr.type_of_loader = 0xFF;
    return SUCCESS;
}

static status_t
setup_kernel(struct vm_t *vm, struct create_vm_from_bzimage_args *args)
{
    /**
     * Notes:
     *
     * The instructions for how to load a 32bit kernel can be found here:
     * https://www.kernel.org/doc/Documentation/x86/boot.txt
     *
     * Some important notes include:
     * - A bzImage has a setup_header struct located at 0x1f1 from the start
     *   of the file. The actual beginning of the image appears to be a piece
     *   of code that tells the user to use a boot-loader and then reboots.
     * - The setup_header that is inside the bzImage needs to be copied to
     *   our own boot_params structure which has the same header in it. The
     *   header in the bzImage already has a bunch of the read-only
     *   values filled in for us based on how the kernel was compiled. For
     *   example, this header contains (as the first value) the number of
     *   512 blocks to the start of the actual kernel in a field called
     *   setup_sects.
     * -
     * - To calculate the start of the kernel that we need to load, you use the
     *   following:
     *
     *   start = (file[0x1f1] + 1) * 512
     *
     *   Once you have the start of the kernel, you need to load the kernel
     *   at the address in code32_start which must be 0x100000 as that is
     *   what is stated by the "LOADING THE REST OF THE KERNEL" section in
     *   boot.txt
     * - After the kernel is loaded to 0x100000, you need to jump to this same
     *   address which is the start of the 32bit section in the kernel which
     *   can be found here (yes, the 32bit code is in the 64bit file):
     *   https://github.com/torvalds/linux/blob/master/arch/x86/boot/compressed/head_64.S
     *
     *   This code will unpack the kernel and put it into the proper place in
     *   memory. From there, it will boot the kernel.
     */

    status_t ret = SUCCESS;
    const struct setup_header *hdr = (struct setup_header *)(args->bzimage + 0x1f1);

    const void *kernel = 0;
    uint64_t kernel_size = 0;
    uint64_t kernel_offset = 0;

    if (args->bzimage == 0) {
        BFDEBUG("setup_kernel: bzImage is null\n");
        return FAILURE;
    }

    if (args->size == 0) {
        BFDEBUG("setup_kernel: bzImage has 0 size\n");
        return FAILURE;
    }

    if (args->bzimage_size + args->initrd_size > args->size) {
        BFDEBUG("setup_kernel: requested RAM is too small\n");
        return FAILURE;
    }

    if (hdr->header != 0x53726448) {
        BFDEBUG("setup_kernel: bzImage does not contain magic number\n");
        return FAILURE;
    }

    if (hdr->version < 0x020d) {
        BFDEBUG("setup_kernel: unsupported bzImage protocol\n");
        return FAILURE;
    }

    if (hdr->code32_start != 0x100000) {
        BFDEBUG("setup_kernel: unsupported bzImage start location\n");
        return FAILURE;
    }

    vm->size = args->size;
    vm->addr = bfalloc_buffer(char, vm->size);

    if (vm->addr == 0) {
        BFDEBUG("setup_kernel: failed to alloc ram\n");
        return FAILURE;
    }

    kernel_offset = ((hdr->setup_sects + 1) * 512);

    if (kernel_offset > args->bzimage_size) {
        BFDEBUG("setup_kernel: corrupt setup_sects\n");
        return FAILURE;
    }

    // TODO
    //
    // We need to clean up this implementation with a lot more checks
    // to ensure that no overflows or underflows are possible
    //

    kernel = args->bzimage + kernel_offset;
    kernel_size = args->bzimage_size - kernel_offset;

    ret = platform_memcpy(
        vm->addr, vm->size, kernel, kernel_size, kernel_size);
    if (ret != SUCCESS) {
        return ret;
    }

    if ((kernel_size & 0xFFF) != 0) {
        kernel_size += 0x1000;
        kernel_size &= ~(0xFFF);
    }

    ret = platform_memcpy(
        vm->addr + kernel_size, vm->size - kernel_size, args->initrd, args->initrd_size, args->initrd_size);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = donate_buffer(vm, vm->addr, 0x100000, vm->size);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_boot_params(vm, args, hdr);
    if (ret != SUCCESS) {
        return ret;
    }

    // TODO
    //
    // Check initrd size and location to ensure they are in the 32bit
    // boundary
    //

    vm->params->hdr.ramdisk_image = (uint32_t)(0x100000 + kernel_size);
    vm->params->hdr.ramdisk_size = (uint32_t)(args->initrd_size);

    return SUCCESS;
}

static status_t
setup_bios_ram(struct vm_t *vm)
{
    status_t ret;

    vm->bios_ram = bfalloc_buffer(void, BIOS_RAM_SIZE);
    if (vm->bios_ram == 0) {
        BFDEBUG("setup_bios_ram: failed to alloc bios ram\n");
        return FAILURE;
    }

    ret = donate_buffer(vm, vm->bios_ram, BIOS_RAM_ADDR, BIOS_RAM_SIZE);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static status_t
setup_reserved_free(struct vm_t *vm)
{
    status_t ret = SUCCESS;

    /**
     * We are not required to map in reserved ranges, only RAM ranges. The
     * problem is the Linux kernel will attempt to scan these ranges for
     * BIOS specific data structures like the MP tables, ACPI, etc... For this
     * reason we map in all of the reserved ranges in the first 1mb of
     * memory
     */

    vm->zero_page = bfalloc_page(void);
    if (vm->zero_page == 0) {
        BFDEBUG("setup_reserved_free: failed to alloc zero page\n");
        return FAILURE;
    }

    ret = donate_page_to_page_range(
        vm, vm->zero_page, RESERVED1_ADRR, RESERVED1_SIZE);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = donate_page_to_page_range(
        vm, vm->zero_page, RESERVED2_ADRR, RESERVED2_SIZE);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Initial Register State                                                     */
/* -------------------------------------------------------------------------- */

static void
set_gdt_entry(
    uint64_t *descriptor, uint32_t base, uint32_t limit, uint16_t flag)
{
    *descriptor = limit & 0x000F0000;
    *descriptor |= (flag <<  8) & 0x00F0FF00;
    *descriptor |= (base >> 16) & 0x000000FF;
    *descriptor |= base & 0xFF000000;

    *descriptor <<= 32;
    *descriptor |= base << 16;
    *descriptor |= limit & 0x0000FFFF;
}

static status_t
setup_32bit_gdt(struct vm_t *vm)
{
    status_t ret = SUCCESS;

    vm->gdt = bfalloc_page(void);
    if (vm->gdt == 0) {
        BFDEBUG("setup_32bit_gdt: failed to alloc gdt\n");
        return FAILURE;
    }

    set_gdt_entry(&vm->gdt[0], 0, 0, 0);
    set_gdt_entry(&vm->gdt[1], 0, 0, 0);
    set_gdt_entry(&vm->gdt[2], 0, 0xFFFFFFFF, 0xc09b);
    set_gdt_entry(&vm->gdt[3], 0, 0xFFFFFFFF, 0xc093);

    ret = donate_page_r(vm, vm->gdt, INITIAL_GDT_GPA);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

static status_t
setup_32bit_register_state(struct vm_t *vm)
{
    /**
     * Notes:
     *
     * The instructions for the initial register state for a 32bit Linux
     * kernel can be found here
     * https://www.kernel.org/doc/Documentation/x86/boot.txt
     */

    status_t ret = SUCCESS;

    ret |= __domain_op__set_rip(vm->domainid, 0x100000);
    ret |= __domain_op__set_rsi(vm->domainid, BOOT_PARAMS_PAGE_GPA);

    ret |= __domain_op__set_gdt_base(vm->domainid, INITIAL_GDT_GPA);
    ret |= __domain_op__set_gdt_limit(vm->domainid, 32);

    ret |= __domain_op__set_cr0(vm->domainid, 0x10037);
    ret |= __domain_op__set_cr3(vm->domainid, 0x0);
    ret |= __domain_op__set_cr4(vm->domainid, 0x02000);

    ret |= __domain_op__set_es_selector(vm->domainid, 0x18);
    ret |= __domain_op__set_es_base(vm->domainid, 0x0);
    ret |= __domain_op__set_es_limit(vm->domainid, 0xFFFFFFFF);
    ret |= __domain_op__set_es_access_rights(vm->domainid, 0xc093);

    ret |= __domain_op__set_cs_selector(vm->domainid, 0x10);
    ret |= __domain_op__set_cs_base(vm->domainid, 0x0);
    ret |= __domain_op__set_cs_limit(vm->domainid, 0xFFFFFFFF);
    ret |= __domain_op__set_cs_access_rights(vm->domainid, 0xc09b);

    ret |= __domain_op__set_ss_selector(vm->domainid, 0x18);
    ret |= __domain_op__set_ss_base(vm->domainid, 0x0);
    ret |= __domain_op__set_ss_limit(vm->domainid, 0xFFFFFFFF);
    ret |= __domain_op__set_ss_access_rights(vm->domainid, 0xc093);

    ret |= __domain_op__set_ds_selector(vm->domainid, 0x18);
    ret |= __domain_op__set_ds_base(vm->domainid, 0x0);
    ret |= __domain_op__set_ds_limit(vm->domainid, 0xFFFFFFFF);
    ret |= __domain_op__set_ds_access_rights(vm->domainid, 0xc093);

    ret |= __domain_op__set_fs_selector(vm->domainid, 0x0);
    ret |= __domain_op__set_fs_base(vm->domainid, 0x0);
    ret |= __domain_op__set_fs_limit(vm->domainid, 0x0);
    ret |= __domain_op__set_fs_access_rights(vm->domainid, 0x10000);

    ret |= __domain_op__set_gs_selector(vm->domainid, 0x0);
    ret |= __domain_op__set_gs_base(vm->domainid, 0x0);
    ret |= __domain_op__set_gs_limit(vm->domainid, 0x0);
    ret |= __domain_op__set_gs_access_rights(vm->domainid, 0x10000);

    ret |= __domain_op__set_tr_selector(vm->domainid, 0x0);
    ret |= __domain_op__set_tr_base(vm->domainid, 0x0);
    ret |= __domain_op__set_tr_limit(vm->domainid, 0x0);
    ret |= __domain_op__set_tr_access_rights(vm->domainid, 0x008b);

    ret |= __domain_op__set_ldtr_selector(vm->domainid, 0x0);
    ret |= __domain_op__set_ldtr_base(vm->domainid, 0x0);
    ret |= __domain_op__set_ldtr_limit(vm->domainid, 0x0);
    ret |= __domain_op__set_ldtr_access_rights(vm->domainid, 0x10000);

    if (ret != SUCCESS) {
        BFDEBUG("setup_entry: setup_32bit_register_state failed\n");
        return FAILURE;
    }

    ret = setup_32bit_gdt(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

int64_t
common_create_vm_from_bzimage(
    struct create_vm_from_bzimage_args *args)
{
    status_t ret;
    struct vm_t *vm = acquire_vm();

    args->domainid = INVALID_DOMAINID;

    if (bfack() == 0) {
        return COMMON_NO_HYPERVISOR;
    }

    vm->domainid = __domain_op__create_domain();
    if (vm->domainid == INVALID_DOMAINID) {
        BFDEBUG("__domain_op__create_domain failed\n");
        return COMMON_CREATE_VM_FROM_BZIMAGE_FAILED;
    }

    ret = setup_kernel(vm, args);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_bios_ram(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_reserved_free(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_32bit_register_state(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_uart(vm, args->uart);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_pt_uart(vm, args->pt_uart);
    if (ret != SUCCESS) {
        return ret;
    }

    args->domainid = vm->domainid;
    return SUCCESS;
}

int64_t
common_destroy(uint64_t domainid)
{
    status_t ret;
    struct vm_t *vm = get_vm(domainid);

    if (bfack() == 0) {
        return COMMON_NO_HYPERVISOR;
    }

    ret = __domain_op__destroy_domain(vm->domainid);
    if (ret != SUCCESS) {
        BFDEBUG("__domain_op__destroy_domain failed\n");
        return ret;
    }

    platform_free_rw(vm->bios_ram, BIOS_RAM_SIZE);
    platform_free_rw(vm->zero_page, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->params, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->cmdline, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->gdt, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->rsdp, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->xsdt, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->madt, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->fadt, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->dsdt, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->addr, vm->size);

    release_vm(vm);
    return SUCCESS;
}
