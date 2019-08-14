//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef MICROV_DMAR_H
#define MICROV_DMAR_H

#include <bfacpi.h>

namespace microv {

#pragma pack(push, 1)

/*
 * The following definitions are derived from chapter 8 of the VT-d spec.
 *
 * The DMAR is an ACPI table that contains a list of remapping structures.
 * Each structure contains a header with the type and length of the structure,
 * followed by type-specific data.
 *
 * Firmware that complies with the VT-d specification will order the list
 * of remapping structures by type, starting with dmar_drhd and ending with
 * dmar_andd as defined below.
 */

/*
 * Byte offset of the DMA remapping structure (drs) list
 * from the base of the DMAR
 */
constexpr auto drs_offset = 48;

/* Remapping structure types */
enum drs_type {
    drs_drhd,
    drs_rmrr,
    drs_atsr,
    drs_rhsa,
    drs_andd
};

/* Common remapping structure header */
struct drs_hdr {
    uint16_t type;
    uint16_t length;
};

/*
 * Each DRHD structure defines one hardware remapping unit (IOMMU).
 * There must be at least one per PCI segment on the platform.
 */
struct drhd {
    struct drs_hdr hdr;
    uint8_t flags;
    uint8_t rsvd;
    uint16_t seg_nr;
    uint64_t base_gpa;
};

#define DRHD_FLAG_PCI_ALL (1U << 0)

enum drhd_devscope_type {
    drhd_pci_device = 1,
    drhd_pci_subhierarchy = 2,
    drhd_ioapic = 3,
    drhd_msi_hpet = 4,
    drhd_acpi_dev = 5
};

struct drhd_devscope {
    uint8_t type;
    uint8_t length;
    uint16_t rsvd;
    uint8_t enum_id;
    uint8_t start_bus;
};

struct devscope_path {
    uint8_t dev;
    uint8_t fun;
};

#pragma pack(pop)

}
#endif
