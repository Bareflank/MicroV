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

#ifndef ACPI_INTEL_X64_HYPERKERNEL_H
#define ACPI_INTEL_X64_HYPERKERNEL_H

#include <cstdint>
#include <bfgsl.h>

#pragma pack(push, 1)

#define OEMID                   "AIS"
#define OEMTABLEID              "none"
#define OEMREVISION             1
#define ASLCOMPILERID           "none"
#define ASLCOMPILERREVISION     1

// -----------------------------------------------------------------------------
// ACPI Header
// -----------------------------------------------------------------------------

typedef struct {
    char                    signature[4];               ///< ASCII table signature
    uint32_t                length;                     ///< Length of table in bytes, including this header
    uint8_t                 revision;                   ///< ACPI Specification minor version number
    uint8_t                 checksum;                   ///< To make sum of entire table == 0
    char                    oemid[6];                   ///< ASCII OEM identification
    char                    oemtableid[8];              ///< ASCII OEM table identification
    uint32_t                oemrevision;                ///< OEM revision number
    char                    aslcompilerid[4];           ///< ASCII ASL compiler vendor ID
    uint32_t                aslcompilerrevision;        ///< ASL compiler version
} __attribute__((packed)) acpi_header_t;

// -----------------------------------------------------------------------------
// ACPI Subtable Header
// -----------------------------------------------------------------------------

typedef struct {
    uint8_t                 type;                       ///< Table type
    uint8_t                 length;                     ///< Length of table in bytes, including this header
} __attribute__((packed)) acpi_subtable_header_t;

// -----------------------------------------------------------------------------
// GAS - Generic Address Structure v2
// -----------------------------------------------------------------------------

typedef struct {
    uint8_t                 SpaceId;                    ///< Address space where struct or register exists
    uint8_t                 BitWidth;                   ///< Size in bits of given register
    uint8_t                 BitOffset;                  ///< Bit offset within the register
    uint8_t                 AccessWidth;                ///< Minimum Access size (ACPI 3.0)
    uint64_t                Address;                    ///< 64-bit address of struct or register
} __attribute__((packed)) acpi_generic_address_t;

// -----------------------------------------------------------------------------
// RSDP - Root System Description Pointer v2
// -----------------------------------------------------------------------------

typedef struct {
    char                    signature[8];               ///< ACPI signature, contains "RSD PTR "
    uint8_t                 checksum;                   ///< ACPI 1.0 checksum
    char                    oemid[6];                   ///< OEM identification
    uint8_t                 revision;                   ///< Must be (0) for ACPI 1.0 or (2) for ACPI 2.0+
    uint32_t                rsdtphysicaladdress;        ///< 32-bit physical address of the RSDT
    uint32_t                length;                     ///< Table length in bytes, including header (ACPI 2.0+)
    uint64_t                xsdtphysicaladdress;        ///< 64-bit physical address of the XSDT (ACPI 2.0+)
    uint8_t                 extendedchecksum;           ///< Checksum of entire table (ACPI 2.0+)
    uint8_t                 reserved[3];                ///< Reserved, must be zero
} __attribute__((packed)) rsdp_t;

// -----------------------------------------------------------------------------
// XSDT - Extended Root System Description Tables v1
// -----------------------------------------------------------------------------

typedef struct {
    acpi_header_t           header;                     ///< Common ACPI table header
    uint64_t                entries[2];                 ///< Array of pointers to ACPI tables
} __attribute__((packed)) xsdt_t;

// -----------------------------------------------------------------------------
// MADT - Multiple APIC Description Table v3
// -----------------------------------------------------------------------------

enum ics_type_t {
    ICS_TYPE_LOCAL_APIC               = 0,
    ICS_TYPE_IO_APIC                  = 1,
    ICS_TYPE_INTERRUPT_OVERRIDE       = 2,
    ICS_TYPE_NMI_SOURCE               = 3,
    ICS_TYPE_LOCAL_APIC_NMI           = 4,
    ICS_TYPE_LOCAL_APIC_OVERRIDE      = 5,
    ICS_TYPE_IO_SAPIC                 = 6,
    ICS_TYPE_LOCAL_SAPIC              = 7,
    ICS_TYPE_INTERRUPT_SOURCE         = 8,
    ICS_TYPE_LOCAL_X2APIC             = 9,
    ICS_TYPE_LOCAL_X2APIC_NMI         = 10,
    ICS_TYPE_GENERIC_INTERRUPT        = 11,
    ICS_TYPE_GENERIC_DISTRIBUTOR      = 12,
    ICS_TYPE_GENERIC_MSI_FRAME        = 13,
    ICS_TYPE_GENERIC_REDISTRIBUTOR    = 14,
    ICS_TYPE_GENERIC_TRANSLATOR       = 15,
    ICS_TYPE_RESERVED                 = 16
};

typedef struct {
    acpi_subtable_header_t  header;
    uint8_t                 processorid;
    uint8_t                 id;
    uint32_t                flags;
} __attribute__((packed)) ics_lapic_t;

typedef struct {
    acpi_subtable_header_t  header;
    uint8_t                 id;
    uint8_t                 reserved;
    uint32_t                address;
    uint32_t                gsi_base;
} __attribute__((packed)) ics_ioapic_t;

typedef struct {
    acpi_header_t           header;                 ///< Common ACPI table header
    uint32_t                address;                ///< Physical address of local APIC
    uint32_t                flags;                  ///< MADT flags (0 == No PIC)
    ics_lapic_t             lapic;                  ///< Local APIC ICS
    ics_ioapic_t            ioapic;                 ///< IOAPIC ICS
} __attribute__((packed)) madt_t;

// -----------------------------------------------------------------------------
// FADT
// -----------------------------------------------------------------------------

typedef struct {
    acpi_header_t           header;                 ///< Common ACPI table header
    uint32_t                facs;                   ///< 32-bit physical address of FACS
    uint32_t                dsdt;                   ///< 32-bit physical address of DSDT
    uint8_t                 model;                  ///< System Interrupt Model (ACPI 1.0) - not used in ACPI 2.0+
    uint8_t                 preferredprofile;       ///< Conveys preferred power management profile to OSPM.
    uint16_t                sciinterrupt;           ///< System vector of SCI interrupt
    uint32_t                smicommand;             ///< 32-bit Port address of SMI command port
    uint8_t                 acpienable;             ///< Value to write to SMI_CMD to enable ACPI
    uint8_t                 acpidisable;            ///< Value to write to SMI_CMD to disable ACPI
    uint8_t                 s4biosrequest;          ///< Value to write to SMI_CMD to enter S4BIOS state
    uint8_t                 pstatecontrol;          ///< Processor performance state control*/
    uint32_t                pm1aeventblock;         ///< 32-bit port address of Power Mgt 1a Event Reg Blk
    uint32_t                pm1beventblock;         ///< 32-bit port address of Power Mgt 1b Event Reg Blk
    uint32_t                pm1acontrolblock;       ///< 32-bit port address of Power Mgt 1a Control Reg Blk
    uint32_t                pm1bcontrolblock;       ///< 32-bit port address of Power Mgt 1b Control Reg Blk
    uint32_t                pm2controlblock;        ///< 32-bit port address of Power Mgt 2 Control Reg Blk
    uint32_t                pmtimerblock;           ///< 32-bit port address of Power Mgt Timer Ctrl Reg Blk
    uint32_t                gpe0block;              ///< 32-bit port address of General Purpose Event 0 Reg Blk
    uint32_t                gpe1block;              ///< 32-bit port address of General Purpose Event 1 Reg Blk
    uint8_t                 pm1eventlength;         ///< Byte Length of ports at Pm1xEventBlock
    uint8_t                 pm1controllength;       ///< Byte Length of ports at Pm1xControlBlock
    uint8_t                 pm2controllength;       ///< Byte Length of ports at Pm2ControlBlock
    uint8_t                 pmtimerlength;          ///< Byte Length of ports at PmTimerBlock
    uint8_t                 gpe0blocklength;        ///< Byte Length of ports at Gpe0Block
    uint8_t                 gpe1blocklength;        ///< Byte Length of ports at Gpe1Block
    uint8_t                 gpe1base;               ///< Offset in GPE number space where GPE1 events start
    uint8_t                 cstcontrol;             ///< Support for the _CST object and C-States change notification
    uint16_t                c2latency;              ///< Worst case HW latency to enter/exit C2 state
    uint16_t                c3latency;              ///< Worst case HW latency to enter/exit C3 state
    uint16_t                flushsize;              ///< Processor memory cache line width, in bytes
    uint16_t                flushstride;            ///< Number of flush strides that need to be read
    uint8_t                 dutyoffset;             ///< Processor duty cycle index in processor P_CNT reg
    uint8_t                 dutywidth;              ///< Processor duty cycle value bit width in P_CNT register
    uint8_t                 dayalarm;               ///< Index to day-of-month alarm in RTC CMOS RAM
    uint8_t                 monthalarm;             ///< Index to month-of-year alarm in RTC CMOS RAM
    uint8_t                 century;                ///< Index to century in RTC CMOS RAM
    uint16_t                bootflags;              ///< IA-PC Boot Architecture Flags (see below for individual flags)
    uint8_t                 reserved;               ///< Reserved, must be zero
    uint32_t                flags;                  ///< Miscellaneous flag bits (see below for individual flags)
    acpi_generic_address_t  resetregister;          ///< 64-bit address of the Reset register
    uint8_t                 resetvalue;             ///< Value to write to the ResetRegister port to reset the system
    uint16_t                armbootflags;           ///< ARM-Specific Boot Flags (see below for individual flags) (ACPI 5.1)
    uint8_t                 minorrevision;          ///< FADT Minor Revision (ACPI 5.1)
    uint64_t                xfacs;                  ///< 64-bit physical address of FACS
    uint64_t                xdsdt;                  ///< 64-bit physical address of DSDT
    acpi_generic_address_t  xpm1aeventblock;        ///< 64-bit Extended Power Mgt 1a Event Reg Blk address
    acpi_generic_address_t  xpm1beventblock;        ///< 64-bit Extended Power Mgt 1b Event Reg Blk address
    acpi_generic_address_t  xpm1acontrolblock;      ///< 64-bit Extended Power Mgt 1a Control Reg Blk address
    acpi_generic_address_t  xpm1bcontrolblock;      ///< 64-bit Extended Power Mgt 1b Control Reg Blk address
    acpi_generic_address_t  xpm2controlblock;       ///< 64-bit Extended Power Mgt 2 Control Reg Blk address
    acpi_generic_address_t  xpmtimerblock;          ///< 64-bit Extended Power Mgt Timer Ctrl Reg Blk address
    acpi_generic_address_t  xgpe0block;             ///< 64-bit Extended General Purpose Event 0 Reg Blk address
    acpi_generic_address_t  xgpe1block;             ///< 64-bit Extended General Purpose Event 1 Reg Blk address
    acpi_generic_address_t  sleepcontrol;           ///< 64-bit Sleep Control register (ACPI 5.0)
    acpi_generic_address_t  sleepstatus;            ///< 64-bit Sleep Status register (ACPI 5.0)
    uint64_t                hypervisorid;           ///< Hypervisor Vendor ID (ACPI 6.0)
} __attribute__((packed)) fadt_t;

typedef struct {
    acpi_header_t header;
} __attribute__((packed)) dsdt_t;

// -----------------------------------------------------------------------------
// ACPI Checksum
// -----------------------------------------------------------------------------

inline uint8_t
acpi_checksum(void *table, uint32_t len)
{
    uint8_t sum = 0;
    auto view = gsl::span(static_cast<uint8_t *>(table), len);

    for (const auto &byte : view) {
        sum += byte;
    }

    return 0x100U - sum;
}


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

#pragma pack(pop)

#endif
