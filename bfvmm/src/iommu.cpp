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

#include <list>
#include <memory>
#include <errno.h>

#include <acpi.h>
#include <iommu/dmar.h>
#include <iommu/iommu.h>

#include <hve/arch/intel_x64/vcpu.h>

extern microv::intel_x64::vcpu *vcpu0;
using namespace bfvmm::x64;

namespace microv {

static std::list<std::unique_ptr<class iommu>> iommu_list;
static bfvmm::x64::unique_map<rsdp_t> rsdp_map;
static bfvmm::x64::unique_map<char> dmar_map;
static size_t dmar_len;

static char *find_dmar()
{
    constexpr auto HDR_SIZE = sizeof(acpi_header_t);
    constexpr auto XSDT_ENTRY_SIZE = 8;
    constexpr auto XSDT_ENTRY_FROM = 3;

    if (!vcpu0 || !g_rsdp) {
        return NULL;
    }

    rsdp_map = vcpu0->map_gpa_4k<rsdp_t>(g_rsdp, 1);
    expects(rsdp_map->revision == 2);

    auto xsdt_gpa = rsdp_map->xsdtphysicaladdress;
    auto xsdt_len = 0U;
    auto xsdt_entry_len = 0U;

    {
        auto hdr = vcpu0->map_gpa_4k<acpi_header_t>(xsdt_gpa, 1);
        xsdt_len = hdr->length;
        xsdt_entry_len = (xsdt_len - HDR_SIZE);
        expects((xsdt_entry_len & (XSDT_ENTRY_SIZE - 1)) == 0);
    }

    auto xsdt = vcpu0->map_gpa_4k<char>(xsdt_gpa, xsdt_len);
    auto xsdt_entries = xsdt_entry_len >> XSDT_ENTRY_FROM;
    auto entry = reinterpret_cast<acpi_header_t **>(xsdt.get() + HDR_SIZE);

    for (auto i = 0; i < xsdt_entries; i++) {
        auto hdr = vcpu0->map_gpa_4k<acpi_header_t>(entry[i], 1);
        if (!strncmp(dmar_sig, hdr->signature, 4)) {
            {
                auto dmar_hdr = std::move(hdr);
                dmar_len = dmar_hdr->length;
            }
            dmar_map = vcpu0->map_gpa_4k<char>(entry[i], dmar_len);
            return dmar_map.get();
        }
    }

    return nullptr;
}

int probe_iommu()
{
    auto dmar = find_dmar();
    if (!dmar) {
        bferror_info(0, "DMAR not found");
        return -ENODEV;
    }

    auto drs = dmar + drs_offset;
    auto end = dmar + dmar_len;

    while (drs < end) {
        /* Read the type and size of the DMAR remapping structure */
        auto drs_hdr = reinterpret_cast<struct drs_hdr *>(drs);

        /* Compliant firmware enumerates DRHDs before anything else */
        expects(drs_hdr->type == drs_drhd);

        auto drhd = reinterpret_cast<struct drhd *>(drs);
        iommu_list.push_front(std::make_unique<class iommu>(drhd));

        if (drhd->flags & DRHD_FLAG_PCI_ALL) {
            return 0;
        }

        drs += drs_hdr->length;
    }

    return 0;
}

iommu::iommu(struct drhd *drhd)
{
    this->drhd = drhd;

    auto base_hpa = vcpu0->gpa_to_hpa(drhd->base_gpa).first;
    auto base_hva = g_mm->alloc_map(page_size);

    g_cr3->map_4k(base_hva,
                  base_hpa,
                  cr3::mmap::attr_type::read_write,
                  cr3::mmap::memory_type::uncacheable);

    reg_base = reinterpret_cast<uintptr_t>(base_hva);

    ver = this->read32(ver_offset);
    cap = this->read64(cap_offset);
    ecap = this->read64(ecap_offset);

    frcd_reg_off = ((cap & cap_fro_mask) >> cap_fro_from) << 4;
    frcd_reg_num = ((cap & cap_nfr_mask) >> cap_nfr_from) + 1;
    frcd_reg_bytes = frcd_reg_num * frcd_reg_len;

    iotlb_reg_off = ((ecap & ecap_iro_mask) >> ecap_iro_from) << 4;

    auto ioreg_end = reg_base + iotlb_reg_off + iotlb_reg_bytes - 1;
    auto frreg_end = reg_base + frcd_reg_off + frcd_reg_bytes - 1;

    auto ioreg_end_4k = ioreg_end & ~(page_size - 1);
    auto frreg_end_4k = frreg_end & ~(page_size - 1);

    expects(reg_base == ioreg_end_4k);
    expects(reg_base == frreg_end_4k);
}

}
