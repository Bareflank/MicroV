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

#include <errno.h>
#include <list>
#include <memory>

#include <acpi.h>
#include <bfacpi.h>
#include <hve/arch/intel_x64/vcpu.h>

#define XSDT_ENTRY_SIZE 8
#define HDR_SIZE sizeof(acpi_header_t)

extern ::microv::intel_x64::vcpu *vcpu0;

namespace microv {

using namespace bfvmm::x64;

static std::vector<struct acpi_table> table_list;
static bfvmm::x64::unique_map<char> table_region_map;
static uintptr_t table_region_gpa;
static size_t table_region_len;

static uintptr_t parse_rsdp()
{
    auto rsdp = vcpu0->map_gpa_4k<rsdp_t>(g_rsdp, 1);
    expects(rsdp->revision == 2);

    return rsdp->xsdtphysicaladdress;
}

static void parse_xsdt(uintptr_t gpa, size_t len)
{
    expects(((len - HDR_SIZE) & (XSDT_ENTRY_SIZE - 1)) == 0);

    auto xsdt = vcpu0->map_gpa_4k<char>(gpa, len);
    auto nr_entries = (len - HDR_SIZE) / XSDT_ENTRY_SIZE;
    auto entry = reinterpret_cast<uintptr_t *>(xsdt.get() + HDR_SIZE);

    struct acpi_table tab{};

    memcpy(tab.sig.data(), "XSDT", tab.sig.size());
    tab.gpa = gpa;
    tab.len = len;
    tab.hva = 0;
    table_list.push_back(tab);

    for (auto i = 0; i < nr_entries; i++) {
        memset(&tab, 0, sizeof(tab));
        tab.gpa = entry[i];
        table_list.push_back(tab);
    }
}

struct acpi_table *find_acpi_table(const acpi_sig_t &sig)
{
    expects(table_region_map);

    for (auto i = 0; i < table_list.size(); i++) {
        auto tab = &table_list[i];
        if (!memcmp(tab->sig.data(), sig.data(), sig.size())) {
            tab->hva = table_region_map.get() + (tab->gpa - table_region_gpa);
            return tab;
        }
    }

    return nullptr;
}

struct acpi_table *find_acpi_table(const char sig[4])
{
    acpi_sig_t array;
    memcpy(array.data(), sig, array.size());
    return find_acpi_table(array);
}

int init_acpi()
{
    uintptr_t xsdt_gpa;
    size_t xsdt_len;

    if (!vcpu0 || !g_rsdp) {
        return -EINVAL;
    }

    xsdt_gpa = parse_rsdp();
    {
        auto hdr = vcpu0->map_gpa_4k<acpi_header_t>(xsdt_gpa, 1);
        xsdt_len = hdr->length;
    }
    parse_xsdt(xsdt_gpa, xsdt_len);

    /* Store the length of each table */
    for (auto i = 2; i < table_list.size(); i++) {
        auto tab = &table_list[i];
        auto hdr = vcpu0->map_gpa_4k<acpi_header_t>(tab->gpa, 1);
        memcpy(tab->sig.data(), &hdr->signature[0], tab->sig.size());
        tab->len = hdr->length;
    }

    /* Sort tables by address */
    std::sort(
        table_list.begin(),
        table_list.end(),
        [] (struct acpi_table l, struct acpi_table r) { return l.gpa < r.gpa; }
    );

    auto last = &table_list[table_list.size() - 1];
    auto base = bfn::upper(table_list[0].gpa, 21);
    auto npgs = bfn::upper(last->gpa + last->len - 1, 21) - base + 1;

    /*
     * Reduce EPT granularity of the ACPI table region to 4K. This is to
     * facilitate later remapping of individual tables like the DMAR
     */
    for (auto i = 0; i < npgs; i++) {
        using namespace bfvmm::intel_x64::ept;

        auto dom0 = vcpu0->dom();
        auto addr = base + (i * ::x64::pd::page_size);

        if (dom0->ept().from(addr) == ::x64::pd::from) {
            identity_map_convert_2m_to_4k(dom0->ept(), addr);
        }
    }

    ::intel_x64::vmx::invept_global();

    /*
     * Map the table region into the VMM. Note this maps in every table that is
     * directly referenced by the XSDT. Other tables that are indirectly
     * referenced, like the FACS, may not mapped be in at this point
     */
    table_region_gpa = table_list[0].gpa;
    table_region_len = (last->gpa + last->len) - table_region_gpa;
    table_region_map = vcpu0->map_gpa_4k<char>(table_region_gpa,
                                               table_region_len);
    return 0;
}

}
