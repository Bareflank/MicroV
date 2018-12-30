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
    //   our own boot_params structure which has the same header in it. The
    //   header in the bzImage already has a bunch of the read-only
    //   values filled in for us based on how the kernel was compiled. For
    //   example, this header contains (as the first value) the number of
    //   512 blocks to the start of the actual kernel in a field called
    //   setup_sects.
    // -
    // - To calculate the start of the kernel that we need to load, you use the
    //   following:
    //
    //   start = (file[0x1f1] + 1) * 512
    //
    //   Once you have the start of the kernel, you need to load the kernel
    //   at the address in code32_start which must be 0x100000 as that is
    //   what is stated by the "LOADING THE REST OF THE KERNEL" section in
    //   boot.txt
    // - After the kernel is loaded to 0x100000, you need to jump to this same
    //   address + 0x200 which is the start of the 64bit section in the kernel.
    //   This code will unpack the kernel and put it into the proper place in
    //   memory.
    //

    status_t ret = 0;
    const struct setup_header *header = (struct setup_header *)(args->file + 0x1f1);

    const void *kernel = 0;
    uint64_t kernel_size = 0;

    if (args->file == 0) {
        BFDEBUG("setup_kernel: bzImage is null\n");
        return FAILURE;
    }

    if (args->size == 0) {
        BFDEBUG("setup_kernel: bzImage has 0 size\n");
        return FAILURE;
    }

    if (args->file_size > args->size) {
        BFDEBUG("setup_kernel: requested RAM is smaller than bzImage\n");
        return FAILURE;
    }

    if (header->header != 0x53726448) {
        BFDEBUG("setup_kernel: bzImage does not contain magic number\n");
        return FAILURE;
    }

    if (header->version < 0x020d) {
        BFDEBUG("setup_kernel: unsupported bzImage protocol\n");
        return FAILURE;
    }

    if (header->code32_start != 0x100000) {
        BFDEBUG("setup_kernel: unsupported bzImage start location\n");
        return FAILURE;
    }

    vm->size = args->size;
    vm->addr = bfalloc_buffer(char, vm->size);

    if (vm->addr == 0) {
        BFDEBUG("setup_kernel: failed to alloc ram\n");
        return FAILURE;
    }

    kernel = args->file + ((header->setup_sects + 1) * 512);
    kernel_size = args->file_size - ((header->setup_sects + 1) * 512);

    platform_memcpy(vm->addr, vm->size, kernel, kernel_size, kernel_size);

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

    // using namespace ::intel_x64;
    // using namespace ::intel_x64::vmcs;
    // using namespace ::intel_x64::cpuid;

    // using namespace ::x64::access_rights;
    // using namespace ::x64::segment_register;

    // uint64_t cr0 = guest_cr0::get();
    // cr0 |= cr0::protection_enable::mask;
    // cr0 |= cr0::monitor_coprocessor::mask;
    // cr0 |= cr0::extension_type::mask;
    // cr0 |= cr0::numeric_error::mask;
    // cr0 |= cr0::write_protect::mask;

    // uint64_t cr4 = guest_cr4::get();
    // cr4 |= cr4::vmx_enable_bit::mask;

    // guest_cr0::set(cr0);
    // guest_cr4::set(cr4);

    // vm_entry_controls::ia_32e_mode_guest::disable();

    // unsigned es_index = 3;
    // unsigned cs_index = 2;
    // unsigned ss_index = 3;
    // unsigned ds_index = 3;
    // unsigned fs_index = 3;
    // unsigned gs_index = 3;
    // unsigned tr_index = 4;

    // guest_es_selector::set(es_index << 3);
    // guest_cs_selector::set(cs_index << 3);
    // guest_ss_selector::set(ss_index << 3);
    // guest_ds_selector::set(ds_index << 3);
    // guest_fs_selector::set(fs_index << 3);
    // guest_gs_selector::set(gs_index << 3);
    // guest_tr_selector::set(tr_index << 3);

    // guest_es_limit::set(domain->gdt()->limit(es_index));
    // guest_cs_limit::set(domain->gdt()->limit(cs_index));
    // guest_ss_limit::set(domain->gdt()->limit(ss_index));
    // guest_ds_limit::set(domain->gdt()->limit(ds_index));
    // guest_fs_limit::set(domain->gdt()->limit(fs_index));
    // guest_gs_limit::set(domain->gdt()->limit(gs_index));
    // guest_tr_limit::set(domain->gdt()->limit(tr_index));

    // guest_es_access_rights::set(domain->gdt()->access_rights(es_index));
    // guest_cs_access_rights::set(domain->gdt()->access_rights(cs_index));
    // guest_ss_access_rights::set(domain->gdt()->access_rights(ss_index));
    // guest_ds_access_rights::set(domain->gdt()->access_rights(ds_index));
    // guest_fs_access_rights::set(domain->gdt()->access_rights(fs_index));
    // guest_gs_access_rights::set(domain->gdt()->access_rights(gs_index));
    // guest_tr_access_rights::set(domain->gdt()->access_rights(tr_index));

    // guest_ldtr_access_rights::set(guest_ldtr_access_rights::unusable::mask);

    // guest_es_base::set(domain->gdt()->base(es_index));
    // guest_cs_base::set(domain->gdt()->base(cs_index));
    // guest_ss_base::set(domain->gdt()->base(ss_index));
    // guest_ds_base::set(domain->gdt()->base(ds_index));
    // guest_fs_base::set(domain->gdt()->base(fs_index));
    // guest_gs_base::set(domain->gdt()->base(gs_index));
    // guest_tr_base::set(domain->gdt()->base(tr_index));

    // guest_rflags::set(2);
    // vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFF);

    // // m_lapic.init();
    // // m_ioapic.init();

    // using namespace primary_processor_based_vm_execution_controls;
    // hlt_exiting::enable();
    // rdpmc_exiting::enable();

    // using namespace secondary_processor_based_vm_execution_controls;
    // enable_invpcid::disable();
    // enable_xsaves_xrstors::disable();

    // this->set_rip(domain->entry());
    // this->set_rbx(XEN_START_INFO_PAGE_GPA);

    // this->add_default_cpuid_handler(
    //     ::handler_delegate_t::create<cpuid_handler>()
    // );

    // this->add_default_wrmsr_handler(
    //     ::handler_delegate_t::create<wrmsr_handler>()
    // );

    // this->add_default_rdmsr_handler(
    //     ::handler_delegate_t::create<rdmsr_handler>()
    // );

    // this->add_default_io_instruction_handler(
    //     ::handler_delegate_t::create<io_instruction_handler>()
    // );

    // this->add_default_ept_read_violation_handler(
    //     ::handler_delegate_t::create<ept_violation_handler>()
    // );

    // this->add_default_ept_write_violation_handler(
    //     ::handler_delegate_t::create<ept_violation_handler>()
    // );

    // this->add_default_ept_execute_violation_handler(
    //     ::handler_delegate_t::create<ept_violation_handler>()
    // );

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
