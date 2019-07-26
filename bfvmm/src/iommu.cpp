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
#include <bfacpi.h>
#include <iommu/dmar.h>
#include <iommu/iommu.h>
#include <hve/arch/intel_x64/vcpu.h>

constexpr auto PAGE_SIZE_4K = (1UL << 12);
constexpr auto PAGE_SIZE_2M = (1UL << 21);

extern microv::intel_x64::vcpu *vcpu0;
using namespace bfvmm::x64;

namespace microv {

static std::list<std::unique_ptr<class iommu>> iommu_list;
static struct acpi_table *dmar{};

static void hide_dmar(struct acpi_table *dmar)
{
    using namespace bfvmm::intel_x64;

    auto gpa_4k = bfn::upper(dmar->gpa, 12);
    auto hva_4k = reinterpret_cast<const char *>(bfn::upper(dmar->hva, 12));
    auto offset = reinterpret_cast<uintptr_t>(dmar->gpa - gpa_4k);

    static auto copy = make_page<char>();
    memcpy(copy.get(), hva_4k, PAGE_SIZE_4K);

    ensures(!memcmp(copy.get() + offset, "DMAR", 4));
    memset(copy.get() + offset, 0, ACPI_SIG_SIZE);

    auto dom = vcpu0->dom();
    dom->unmap(gpa_4k);
    dom->map_4k_rw(gpa_4k, g_mm->virtptr_to_physint(copy.get()));

    ::intel_x64::vmx::invept_global();
}

int probe_iommu()
{
    dmar = find_acpi_table("DMAR");
    if (!dmar) {
        bferror_info(0, "probe_iommu: DMAR not found");
        return -EINVAL;
    }

    if (memcmp(dmar->hva, "DMAR", 4)) {
        bferror_info(0, "probe_iommu: Invalid DMAR signature");
    }

    hide_dmar(dmar);

    auto drs = dmar->hva + drs_offset;
    auto end = dmar->hva + dmar->len;

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
