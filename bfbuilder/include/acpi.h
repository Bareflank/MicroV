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

#ifndef ACPI_INTEL_X64_BOXY_H
#define ACPI_INTEL_X64_BOXY_H

#include <bftypes.h>
#include <bfgpalayout.h>

#pragma pack(push, 1)

#define OEMID                   "AIS"
#define OEMTABLEID              "none"
#define OEMREVISION             1
#define ASLCOMPILERID           "none"
#define ASLCOMPILERREVISION     1

// -----------------------------------------------------------------------------
// ACPI Header
// -----------------------------------------------------------------------------

struct acpi_header_t {
    char                    signature[4];               ///< ASCII table signature
    uint32_t                length;                     ///< Length of table in bytes, including this header
    uint8_t                 revision;                   ///< ACPI Specification minor version number
    uint8_t                 checksum;                   ///< To make sum of entire table == 0
    char                    oemid[6];                   ///< ASCII OEM identification
    char                    oemtableid[8];              ///< ASCII OEM table identification
    uint32_t                oemrevision;                ///< OEM revision number
    char                    aslcompilerid[4];           ///< ASCII ASL compiler vendor ID
    uint32_t                aslcompilerrevision;        ///< ASL compiler version
};

// -----------------------------------------------------------------------------
// ACPI Subtable Header
// -----------------------------------------------------------------------------

struct acpi_subtable_header_t {
    uint8_t                 type;                       ///< Table type
    uint8_t                 length;                     ///< Length of table in bytes, including this header
};

// -----------------------------------------------------------------------------
// GAS - Generic Address Structure
// -----------------------------------------------------------------------------

struct acpi_generic_address_t {
    uint8_t                 SpaceId;                    ///< Address space where struct or register exists
    uint8_t                 BitWidth;                   ///< Size in bits of given register
    uint8_t                 BitOffset;                  ///< Bit offset within the register
    uint8_t                 AccessWidth;                ///< Minimum Access size (ACPI 3.0)
    uint64_t                Address;                    ///< 64-bit address of struct or register
};

// -----------------------------------------------------------------------------
// RSDP - Root System Description Pointer
// -----------------------------------------------------------------------------

struct rsdp_t {
    char                    signature[8];               ///< ACPI signature, contains "RSD PTR "
    uint8_t                 checksum;                   ///< ACPI 1.0 checksum
    char                    oemid[6];                   ///< OEM identification
    uint8_t                 revision;                   ///< Must be (0) for ACPI 1.0 or (2) for ACPI 2.0+
    uint32_t                rsdtphysicaladdress;        ///< 32-bit physical address of the RSDT
    uint32_t                length;                     ///< Table length in bytes, including header (ACPI 2.0+)
    uint64_t                xsdtphysicaladdress;        ///< 64-bit physical address of the XSDT (ACPI 2.0+)
    uint8_t                 extendedchecksum;           ///< Checksum of entire table (ACPI 2.0+)
    uint8_t                 reserved[3];                ///< Reserved, must be zero
};

// -----------------------------------------------------------------------------
// XSDT - Extended Root System Description Tables
// -----------------------------------------------------------------------------

struct xsdt_t {
    struct acpi_header_t    header;                     ///< Common ACPI table header
    uint64_t                entries[2];                 ///< Array of pointers to ACPI tables
};

// -----------------------------------------------------------------------------
// MADT - Multiple APIC Description Table
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

struct ics_lapic_t {
    struct acpi_subtable_header_t   header;
    uint8_t                         processorid;
    uint8_t                         id;
    uint32_t                        flags;
};

struct madt_t {
    struct acpi_header_t            header;                 ///< Common ACPI table header
    uint32_t                        address;                ///< Physical address of local APIC
    uint32_t                        flags;                  ///< MADT flags (0 == No PIC)
    struct ics_lapic_t              lapic;                  ///< Local APIC ICS
};

// -----------------------------------------------------------------------------
// FADT - Fixed ACPI Description Table
// -----------------------------------------------------------------------------

struct fadt_t {
    struct acpi_header_t            header;                 ///< Common ACPI table header
    uint32_t                        facs;                   ///< 32-bit physical address of FACS
    uint32_t                        dsdt;                   ///< 32-bit physical address of DSDT
    uint8_t                         model;                  ///< System Interrupt Model (ACPI 1.0) - not used in ACPI 2.0+
    uint8_t                         preferredprofile;       ///< Conveys preferred power management profile to OSPM.
    uint16_t                        sciinterrupt;           ///< System vector of SCI interrupt
    uint32_t                        smicommand;             ///< 32-bit Port address of SMI command port
    uint8_t                         acpienable;             ///< Value to write to SMI_CMD to enable ACPI
    uint8_t                         acpidisable;            ///< Value to write to SMI_CMD to disable ACPI
    uint8_t                         s4biosrequest;          ///< Value to write to SMI_CMD to enter S4BIOS state
    uint8_t                         pstatecontrol;          ///< Processor performance state control*/
    uint32_t                        pm1aeventblock;         ///< 32-bit port address of Power Mgt 1a Event Reg Blk
    uint32_t                        pm1beventblock;         ///< 32-bit port address of Power Mgt 1b Event Reg Blk
    uint32_t                        pm1acontrolblock;       ///< 32-bit port address of Power Mgt 1a Control Reg Blk
    uint32_t                        pm1bcontrolblock;       ///< 32-bit port address of Power Mgt 1b Control Reg Blk
    uint32_t                        pm2controlblock;        ///< 32-bit port address of Power Mgt 2 Control Reg Blk
    uint32_t                        pmtimerblock;           ///< 32-bit port address of Power Mgt Timer Ctrl Reg Blk
    uint32_t                        gpe0block;              ///< 32-bit port address of General Purpose Event 0 Reg Blk
    uint32_t                        gpe1block;              ///< 32-bit port address of General Purpose Event 1 Reg Blk
    uint8_t                         pm1eventlength;         ///< Byte Length of ports at Pm1xEventBlock
    uint8_t                         pm1controllength;       ///< Byte Length of ports at Pm1xControlBlock
    uint8_t                         pm2controllength;       ///< Byte Length of ports at Pm2ControlBlock
    uint8_t                         pmtimerlength;          ///< Byte Length of ports at PmTimerBlock
    uint8_t                         gpe0blocklength;        ///< Byte Length of ports at Gpe0Block
    uint8_t                         gpe1blocklength;        ///< Byte Length of ports at Gpe1Block
    uint8_t                         gpe1base;               ///< Offset in GPE number space where GPE1 events start
    uint8_t                         cstcontrol;             ///< Support for the _CST object and C-States change notification
    uint16_t                        c2latency;              ///< Worst case HW latency to enter/exit C2 state
    uint16_t                        c3latency;              ///< Worst case HW latency to enter/exit C3 state
    uint16_t                        flushsize;              ///< Processor memory cache line width, in bytes
    uint16_t                        flushstride;            ///< Number of flush strides that need to be read
    uint8_t                         dutyoffset;             ///< Processor duty cycle index in processor P_CNT reg
    uint8_t                         dutywidth;              ///< Processor duty cycle value bit width in P_CNT register
    uint8_t                         dayalarm;               ///< Index to day-of-month alarm in RTC CMOS RAM
    uint8_t                         monthalarm;             ///< Index to month-of-year alarm in RTC CMOS RAM
    uint8_t                         century;                ///< Index to century in RTC CMOS RAM
    uint16_t                        bootflags;              ///< IA-PC Boot Architecture Flags (see below for individual flags)
    uint8_t                         reserved;               ///< Reserved, must be zero
    uint32_t                        flags;                  ///< Miscellaneous flag bits (see below for individual flags)
    struct acpi_generic_address_t   resetregister;          ///< 64-bit address of the Reset register
    uint8_t                         resetvalue;             ///< Value to write to the ResetRegister port to reset the system
    uint16_t                        armbootflags;           ///< ARM-Specific Boot Flags (see below for individual flags) (ACPI 5.1)
    uint8_t                         minorrevision;          ///< FADT Minor Revision (ACPI 5.1)
    uint64_t                        xfacs;                  ///< 64-bit physical address of FACS
    uint64_t                        xdsdt;                  ///< 64-bit physical address of DSDT
    struct acpi_generic_address_t   xpm1aeventblock;        ///< 64-bit Extended Power Mgt 1a Event Reg Blk address
    struct acpi_generic_address_t   xpm1beventblock;        ///< 64-bit Extended Power Mgt 1b Event Reg Blk address
    struct acpi_generic_address_t   xpm1acontrolblock;      ///< 64-bit Extended Power Mgt 1a Control Reg Blk address
    struct acpi_generic_address_t   xpm1bcontrolblock;      ///< 64-bit Extended Power Mgt 1b Control Reg Blk address
    struct acpi_generic_address_t   xpm2controlblock;       ///< 64-bit Extended Power Mgt 2 Control Reg Blk address
    struct acpi_generic_address_t   xpmtimerblock;          ///< 64-bit Extended Power Mgt Timer Ctrl Reg Blk address
    struct acpi_generic_address_t   xgpe0block;             ///< 64-bit Extended General Purpose Event 0 Reg Blk address
    struct acpi_generic_address_t   xgpe1block;             ///< 64-bit Extended General Purpose Event 1 Reg Blk address
    struct acpi_generic_address_t   sleepcontrol;           ///< 64-bit Sleep Control register (ACPI 5.0)
    struct acpi_generic_address_t   sleepstatus;            ///< 64-bit Sleep Status register (ACPI 5.0)
    uint64_t                        hypervisorid;           ///< Hypervisor Vendor ID (ACPI 6.0)
};

// -----------------------------------------------------------------------------
// DSDT - Differentiated System Description Table
// -----------------------------------------------------------------------------

struct dsdt_t {
    struct acpi_header_t    header;                         ///< Common ACPI table header
};

// -----------------------------------------------------------------------------
// ACPI Checksum
// -----------------------------------------------------------------------------

static inline uint8_t
acpi_checksum(void *table, int len)
{
    int i;
    uint8_t sum = 0;

    for (i = 0; i < len; i++) {
        sum += ((uint8_t *)table)[i];
    }

    return (uint8_t)(0x100U - sum);
}

// -----------------------------------------------------------------------------
// Setup Functions
// -----------------------------------------------------------------------------

static inline void
setup_rsdp(struct rsdp_t *rsdp)
{
    static struct rsdp_t s_rsdp = {
        .signature = {'R', 'S', 'D', ' ', 'P', 'T', 'R', ' '},
        .checksum = 0,
        .oemid = {'A', 'I', 'S', ' ', ' ', ' '},
        .revision = 2,
        .rsdtphysicaladdress = 0,
        .length = sizeof(struct rsdp_t),
        .xsdtphysicaladdress = ACPI_XSDT_GPA,
        .extendedchecksum = 0,
        .reserved = {0, 0, 0}
    };

    *rsdp = s_rsdp;

    rsdp->checksum = acpi_checksum(rsdp, 20);
    rsdp->extendedchecksum = acpi_checksum(rsdp, rsdp->length);
}

static inline void
setup_xsdt(struct xsdt_t *xsdt)
{
    static struct xsdt_t s_xsdt = {
        .header = {
            .signature = {'X', 'S', 'D', 'T'},
            .length = sizeof(struct xsdt_t),
            .revision = 1,
            .checksum = 0,
            .oemid = {'A', 'I', 'S', ' ', ' ', ' '},
            .oemtableid = {'n', 'o', 'n', 'e', ' ', ' ', ' ', ' '},
            .oemrevision = 1,
            .aslcompilerid = {'n', 'o', 'n', 'e'},
            .aslcompilerrevision = 1
        },
        .entries = {ACPI_MADT_GPA, ACPI_FADT_GPA}
    };

    *xsdt = s_xsdt;
    xsdt->header.checksum = acpi_checksum(xsdt, xsdt->header.length);
}

static inline void
setup_madt(struct madt_t *madt)
{
    static struct madt_t s_madt = {
        .header = {
            .signature = {'A', 'P', 'I', 'C'},
            .length = sizeof(struct madt_t),
            .revision = 4,
            .checksum = 0,
            .oemid = {'A', 'I', 'S', ' ', ' ', ' '},
            .oemtableid = {'n', 'o', 'n', 'e', ' ', ' ', ' ', ' '},
            .oemrevision = 1,
            .aslcompilerid = {'n', 'o', 'n', 'e'},
            .aslcompilerrevision = 1
        },
        .address = XAPIC_GPA,
        .flags = 0,
        .lapic = {
            .header = {
                .type = ICS_TYPE_LOCAL_APIC,
                .length = 8
            },
            .processorid = 0,
            .id = 0,
            .flags = 1
        }
    };

    *madt = s_madt;
    madt->header.checksum = acpi_checksum(madt, madt->header.length);
}

static inline void
setup_fadt(struct fadt_t *fadt)
{
    static struct fadt_t s_fadt = {
        .header = {
            .signature = {'F', 'A', 'C', 'P'},
            .length = sizeof(struct fadt_t),
            .revision = 6,
            .checksum = 0,
            .oemid = {'A', 'I', 'S', ' ', ' ', ' '},
            .oemtableid = {'n', 'o', 'n', 'e', ' ', ' ', ' ', ' '},
            .oemrevision = 1,
            .aslcompilerid = {'n', 'o', 'n', 'e'},
            .aslcompilerrevision = 1
        },
        .facs = 0,
        .dsdt = ACPI_DSDT_GPA,
        .model = 0,
        .preferredprofile = 0,
        .sciinterrupt = 0,
        .smicommand = 0,
        .acpienable = 0,
        .acpidisable = 0,
        .s4biosrequest = 0,
        .pstatecontrol = 0,
        .pm1aeventblock = 0,
        .pm1beventblock = 0,
        .pm1acontrolblock = 0,
        .pm1bcontrolblock = 0,
        .pm2controlblock = 0,
        .pmtimerblock = 0,
        .gpe0block = 0,
        .gpe1block = 0,
        .pm1eventlength = 0,
        .pm1controllength = 0,
        .pm2controllength = 0,
        .pmtimerlength = 0,
        .gpe0blocklength = 0,
        .gpe1blocklength = 0,
        .gpe1base = 0,
        .cstcontrol = 0,
        .c2latency = 0,
        .c3latency = 0,
        .flushsize = 0,
        .flushstride = 0,
        .dutyoffset = 0,
        .dutywidth = 0,
        .dayalarm = 0,
        .monthalarm = 0,
        .century = 0,
        .bootflags = 0,
        .reserved = 0,
        .flags = 0x101873U,
        .resetregister = {0, 0, 0, 0, 0},
        .resetvalue = 0,
        .armbootflags = 0,
        .minorrevision = 1,
        .xfacs = 0,
        .xdsdt = 0,
        .xpm1aeventblock = {0, 0, 0, 0, 0},
        .xpm1beventblock = {0, 0, 0, 0, 0},
        .xpm1acontrolblock = {0, 0, 0, 0, 0},
        .xpm1bcontrolblock = {0, 0, 0, 0, 0},
        .xpm2controlblock = {0, 0, 0, 0, 0},
        .xpmtimerblock = {0, 0, 0, 0, 0},
        .xgpe0block = {0, 0, 0, 0, 0},
        .xgpe1block = {0, 0, 0, 0, 0},
        .sleepcontrol = {0, 0, 0, 0, 0},
        .sleepstatus = {0, 0, 0, 0, 0},
        .hypervisorid = 0xBF
    };

    *fadt = s_fadt;
    fadt->header.checksum = acpi_checksum(fadt, fadt->header.length);
}

static inline void
setup_dsdt(struct dsdt_t *dsdt)
{
    static struct dsdt_t s_dsdt = {
        .header = {
            .signature = {'D', 'S', 'D', 'T'},
            .length = sizeof(struct dsdt_t),
            .revision = 2,
            .checksum = 0,
            .oemid = {'A', 'I', 'S', ' ', ' ', ' '},
            .oemtableid = {'n', 'o', 'n', 'e', ' ', ' ', ' ', ' '},
            .oemrevision = 1,
            .aslcompilerid = {'n', 'o', 'n', 'e'},
            .aslcompilerrevision = 1
        }
    };

    *dsdt = s_dsdt;
    dsdt->header.checksum = acpi_checksum(dsdt, dsdt->header.length);
}

#pragma pack(pop)

#endif
