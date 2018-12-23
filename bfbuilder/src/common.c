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

#include <bfdebug.h>
#include <bfconstants.h>
#include <bfgpalayout.h>
#include <bfhypercall.h>

#define bfalloc_page(a) \
    (a *)platform_memset(platform_alloc_rwe(BAREFLANK_PAGE_SIZE), 0, BAREFLANK_PAGE_SIZE);
#define bfalloc_buffer(a,b) \
    (a *)platform_memset(platform_alloc_rwe(b), 0, b);













    // std::strncpy(m_rsdp->signature, "RSD PTR ", sizeof(m_rsdp->signature));
    // m_rsdp->checksum = 0;
    // std::strncpy(m_rsdp->oemid, "AIS", sizeof(m_rsdp->oemid));
    // m_rsdp->revision = 2;
    // m_rsdp->rsdtphysicaladdress = 0;
    // m_rsdp->length = sizeof(rsdp_t);
    // m_rsdp->xsdtphysicaladdress = ACPI_XSDT_GPA;
    // m_rsdp->extendedchecksum = 0;
    // std::memset(m_rsdp->reserved, 0, sizeof(m_rsdp->reserved));
    // m_rsdp->checksum = acpi_checksum(m_rsdp.get(), 20);
    // m_rsdp->extendedchecksum = acpi_checksum(m_rsdp.get(), m_rsdp->length);

    // std::strncpy(m_xsdt->header.signature, "XSDT", sizeof(m_xsdt->header.signature));
    // m_xsdt->header.length = sizeof(xsdt_t);
    // m_xsdt->header.revision = 1;
    // m_xsdt->header.checksum = 0;
    // std::strncpy(m_xsdt->header.oemid, OEMID, sizeof(m_xsdt->header.oemid));
    // std::strncpy(m_xsdt->header.oemtableid, OEMTABLEID, sizeof(m_xsdt->header.oemtableid));
    // m_xsdt->header.oemrevision = OEMREVISION;
    // std::strncpy(m_xsdt->header.aslcompilerid, ASLCOMPILERID, sizeof(m_xsdt->header.aslcompilerid));
    // m_xsdt->header.aslcompilerrevision = ASLCOMPILERREVISION;
    // m_xsdt->entries[0] = ACPI_MADT_GPA;
    // m_xsdt->entries[1] = ACPI_FADT_GPA;
    // m_xsdt->header.checksum = acpi_checksum(m_xsdt.get(), m_xsdt->header.length);

    // std::strncpy(m_madt->header.signature, "APIC", sizeof(m_madt->header.signature));
    // m_madt->header.length = sizeof(madt_t);
    // m_madt->header.revision = 4;
    // m_madt->header.checksum = 0;
    // std::strncpy(m_madt->header.oemid, OEMID, sizeof(m_madt->header.oemid));
    // std::strncpy(m_madt->header.oemtableid, OEMTABLEID, sizeof(m_madt->header.oemtableid));
    // m_madt->header.oemrevision = OEMREVISION;
    // std::strncpy(m_madt->header.aslcompilerid, ASLCOMPILERID, sizeof(m_madt->header.aslcompilerid));
    // m_madt->header.aslcompilerrevision = ASLCOMPILERREVISION;
    // m_madt->address = LAPIC_GPA;
    // m_madt->flags = 0;

    // m_madt->lapic.header.type = ICS_TYPE_LOCAL_APIC;
    // m_madt->lapic.header.length = 8;
    // m_madt->lapic.processorid = 0;      // TODO: This should be generated from the vCPUs
    // m_madt->lapic.id = 0;               // TODO: This should be generated from the vCPUs
    // m_madt->lapic.flags = 1;

    // m_madt->ioapic.header.type = ICS_TYPE_IO_APIC;
    // m_madt->ioapic.header.length = sizeof(ics_ioapic_t);
    // m_madt->ioapic.id = 0;
    // m_madt->ioapic.reserved = 0;
    // m_madt->ioapic.address = IOAPIC_GPA;
    // m_madt->ioapic.gsi_base = 0;

    // m_madt->header.checksum = acpi_checksum(m_madt.get(), m_madt->header.length);

    // std::strncpy(m_fadt->header.signature, "FACP", sizeof(m_fadt->header.signature));
    // m_fadt->header.length = sizeof(fadt_t);
    // m_fadt->header.revision = 6;
    // m_fadt->header.checksum = 0;
    // std::strncpy(m_fadt->header.oemid, OEMID, sizeof(m_fadt->header.oemid));
    // std::strncpy(m_fadt->header.oemtableid, OEMTABLEID, sizeof(m_fadt->header.oemtableid));
    // m_fadt->header.oemrevision = OEMREVISION;
    // std::strncpy(m_fadt->header.aslcompilerid, ASLCOMPILERID, sizeof(m_fadt->header.aslcompilerid));
    // m_fadt->header.aslcompilerrevision = ASLCOMPILERREVISION;
    // m_fadt->dsdt = 0;
    // m_fadt->flags = 0x101873U;
    // m_fadt->minorrevision = 1;
    // m_fadt->xdsdt = ACPI_DSDT_GPA;
    // m_fadt->hypervisorid = 0xBFU;
    // m_fadt->header.checksum = acpi_checksum(m_fadt.get(), m_fadt->header.length);

    // std::strncpy(m_dsdt->header.signature, "DSDT", sizeof(m_dsdt->header.signature));
    // m_dsdt->header.length = sizeof(dsdt_t);
    // m_dsdt->header.revision = 6;
    // m_dsdt->header.checksum = 0;
    // std::strncpy(m_dsdt->header.oemid, OEMID, sizeof(m_dsdt->header.oemid));
    // std::strncpy(m_dsdt->header.oemtableid, OEMTABLEID, sizeof(m_dsdt->header.oemtableid));
    // m_dsdt->header.oemrevision = OEMREVISION;
    // std::strncpy(m_dsdt->header.aslcompilerid, ASLCOMPILERID, sizeof(m_dsdt->header.aslcompilerid));
    // m_dsdt->header.aslcompilerrevision = ASLCOMPILERREVISION;
    // m_dsdt->header.checksum = acpi_checksum(m_dsdt.get(), m_dsdt->header.length);

    // auto rsdp_hpa = g_mm->virtptr_to_physint(m_rsdp.get());
    // auto xsdt_hpa = g_mm->virtptr_to_physint(m_xsdt.get());
    // auto madt_hpa = g_mm->virtptr_to_physint(m_madt.get());
    // auto fadt_hpa = g_mm->virtptr_to_physint(m_fadt.get());
    // auto dsdt_hpa = g_mm->virtptr_to_physint(m_dsdt.get());

    // m_ept_map.map_4k(ACPI_RSDP_GPA, rsdp_hpa, ept::mmap::attr_type::read_only);
    // m_ept_map.map_4k(ACPI_XSDT_GPA, xsdt_hpa, ept::mmap::attr_type::read_only);
    // m_ept_map.map_4k(ACPI_MADT_GPA, madt_hpa, ept::mmap::attr_type::read_only);
    // m_ept_map.map_4k(ACPI_FADT_GPA, fadt_hpa, ept::mmap::attr_type::read_only);
    // m_ept_map.map_4k(ACPI_DSDT_GPA, dsdt_hpa, ept::mmap::attr_type::read_only);


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

// static status_t
// setup_xen_start_info(struct vm_t *vm)
// {
//     status_t ret;

//     vm->xen_start_info = bfalloc_page(struct hvm_start_info);
//     if (vm->xen_start_info == 0) {
//         BFDEBUG("setup_xen_start_info: failed to alloc start into page\n");
//         return FAILURE;
//     }

//     vm->xen_start_info->magic = XEN_HVM_START_MAGIC_VALUE;
//     vm->xen_start_info->version = 0;
//     vm->xen_start_info->cmdline_paddr = XEN_COMMAND_LINE_PAGE_GPA;
//     vm->xen_start_info->rsdp_paddr = ACPI_RSDP_GPA;

//     ret = donate_page(vm, vm->xen_start_info, XEN_START_INFO_PAGE_GPA, MAP_RO);
//     if (ret != BF_SUCCESS) {
//         BFDEBUG("setup_xen_start_info: donate failed\n");
//         return ret;
//     }

//     return ret;
// }

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

static status_t
setup_kernel(struct vm_t *vm, struct create_from_elf_args *args)
{
    status_t ret;

    vm->bfelf_binary.file = args->file;
    vm->bfelf_binary.file_size = args->file_size;
    vm->bfelf_binary.exec = 0;
    vm->bfelf_binary.exec_size = args->size;
    vm->bfelf_binary.start_addr = (void *)START_ADDR;

    ret = bfelf_load(&vm->bfelf_binary, 1, 0, 0, &vm->bfelf_loader);
    if (ret != BF_SUCCESS) {
        return ret;
    }

    ret = donate_buffer(
        vm, vm->bfelf_binary.exec, START_ADDR, args->size, MAP_RWE);
    if (ret != SUCCESS) {
        return ret;
    }

    return ret;
}

// TODO:
//
// We need to move the ACPI and Initial GDT/IDT/TSS to this driver and
// out of the hypervisor as these should be resources managed by the
// builder, not the hypervisor.
//

/* -------------------------------------------------------------------------- */
/* Initial Register State                                                     */
/* -------------------------------------------------------------------------- */

static status_t
setup_entry(struct vm_t *vm)
{
    status_t ret;

    // ret = get_phys32_entry(vm, &vm->entry);
    // if (ret != SUCCESS) {
    //     BFDEBUG("setup_entry: failed to locate pvh_start_xen\n");
    //     return ret;
    // }

    ret = __domain_op__set_entry(vm->domainid, vm->entry);
    if (ret != SUCCESS) {
        BFDEBUG("setup_entry: __domain_op__set_entry failed\n");
    }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

int64_t
common_create_from_elf(
    struct vm_t *vm, struct create_from_elf_args *args)
{
    status_t ret;

    if (_cpuid_eax(0xBF00) != 0xBF01) {
        return HYPERVISOR_NOT_LOADED;
    }

    vm->domainid = __domain_op__create_domain();
    if (vm->domainid == INVALID_DOMAINID) {
        BFDEBUG("__domain_op__create_domain failed\n");
        return CREATE_FROM_ELF_FAILED;
    }

    ret = setup_e820_map(vm, args->size);
    if (ret != SUCCESS) {
        return ret;
    }

    // ret = setup_xen_start_info(vm);
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

    ret = setup_bios_ram(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_reserved_free(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_kernel(vm, args);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_entry(vm);
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
    return BF_SUCCESS;
}

int64_t
common_destroy(struct vm_t *vm)
{
    status_t ret;

    if (_cpuid_eax(0xBF00) != 0xBF01) {
        return HYPERVISOR_NOT_LOADED;
    }

    ret = __domain_op__destroy_domain(vm->domainid);
    if (ret != SUCCESS) {
        BFDEBUG("__domain_op__destroy_domain failed\n");
        return FAILURE;
    }

    platform_free_rw(vm->bfelf_binary.exec, vm->bfelf_binary.exec_size);
    platform_free_rw(vm->xen_start_info, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->xen_cmdl, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->xen_console, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->bios_ram, 0xE8000);
    platform_free_rw(vm->zero_page, BAREFLANK_PAGE_SIZE);

    platform_memset(vm, 0, sizeof(struct vm_t));
    return BF_SUCCESS;
}
