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
#include <microv/acpi.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <printv.h>

#define PAGE_SIZE_4K 0x1000UL
#define XSDT_ENTRY_SIZE 8
#define HDR_SIZE sizeof(acpi_header_t)

extern ::microv::intel_x64::vcpu *vcpu0;

namespace microv {

using namespace bfvmm::x64;

static std::vector<struct acpi_table> table_list;
static std::unordered_set<uintptr_t> tables_2m_gpas;
static std::unordered_map<uintptr_t, page_ptr<char>> tables_spoof;

static void acpi_table_add(uintptr_t gpa)
{
    auto hdr = vcpu0->map_gpa_4k<acpi_header_t>(gpa, 1);
    struct acpi_table tab{};

    memcpy(tab.sig.data(), hdr->signature, sizeof(hdr->signature));
    tab.gpa = gpa;
    tab.len = hdr->length;
    tab.hidden = false;
    table_list.push_back(tab);

    auto gpa_base = bfn::upper(gpa, 21);
    auto gpa_end = bfn::upper(gpa + hdr->length + (1 << 21) - 1, 21);
    for (auto a = gpa_base; a < gpa_end; a += (1 << 21)) {
        tables_2m_gpas.insert(a);
    }
}

static void parse_rsdp()
{
    auto rsdp = vcpu0->map_gpa_4k<rsdp_t>(g_rsdp, 1);
    auto sig_len = sizeof("RSD PTR ") - 1;

    expects(!memcmp(rsdp->signature, "RSD PTR ", sig_len));
    expects(rsdp->revision == 2);

    /*
     * Consider the RSDP as part of the ACPI mapped range, it may already be by
     * being in a 4k-range already used for another ACPI table.
     */
    tables_2m_gpas.insert(bfn::upper(g_rsdp, 21));

    printv("acpi: RSDP: %#lx-%#lx (%uB).\n",
        g_rsdp, g_rsdp + rsdp->length - 1, rsdp->length);
}

static void parse_xsdt()
{
    auto rsdp = vcpu0->map_gpa_4k<rsdp_t>(g_rsdp, 1);
    auto xsdt_gpa = rsdp->xsdtphysicaladdress;
    auto xsdt_hdr = vcpu0->map_gpa_4k<acpi_header_t>(xsdt_gpa, 1);

    expects(!memcmp(xsdt_hdr->signature, "XSDT", sizeof(xsdt_hdr->signature)));

    acpi_table_add(xsdt_gpa);

    auto entries_gpa = xsdt_gpa + HDR_SIZE;
    auto entries_size = xsdt_hdr->length - HDR_SIZE;
    auto entries_map = vcpu0->map_gpa_4k<uintptr_t>(entries_gpa, entries_size);
    auto entries = reinterpret_cast<uintptr_t*>(entries_map.get());
    auto n = entries_size / XSDT_ENTRY_SIZE;

    for (auto i = 0; i < n; ++i) {
        acpi_table_add(entries[i]);
    }
}

struct acpi_table *find_acpi_table(const acpi_sig_t &sig)
{
    for (auto i = 0; i < table_list.size(); i++) {
        auto tab = &table_list[i];
        auto gpa_base = bfn::upper(tab->gpa);
        auto gpa_offset = bfn::lower(tab->gpa);

        if (!memcmp(tab->sig.data(), sig.data(), sig.size())) {
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
    if (!vcpu0 || !g_rsdp) {
        return -EINVAL;
    }

    parse_rsdp();
    parse_xsdt();

    for (auto const& tab : table_list) {
        printv("acpi: %c%c%c%c: %#lx-%#lx (%luB).\n",
            tab.sig[0], tab.sig[1], tab.sig[2], tab.sig[3],
            tab.gpa, tab.gpa + tab.len - 1, tab.len);
    }

    /*
     * Reduce EPT granularity of the ACPI table region to 4K. This is to
     * facilitate later remapping of individual tables like the DMAR
     */
    printv("acpi: reducing granularity of %luMB table region to 4KB\n",
        tables_2m_gpas.size() * 2);
    for (auto const& gpa : tables_2m_gpas) {
        using namespace bfvmm::intel_x64::ept;

        auto dom0 = vcpu0->dom();
        auto from = dom0->ept().from(gpa);

        if (from == ::x64::pd::from) {
            identity_map_convert_2m_to_4k(dom0->ept(), gpa);
        } else {
            expects(from == ::x64::pt::from);
        }
    }

    ::intel_x64::vmx::invept_global();

    return 0;
}

void hide_acpi_table(struct acpi_table *tab)
{
    expects(tab);

    if (tab->hidden) {
        return;
    }

    auto gpa = bfn::upper(tab->gpa);
    auto offset = bfn::lower(tab->gpa);

    expects(gpa);

    if (tables_spoof.count(gpa)) {
        auto iter = tables_spoof.find(gpa);
        char *spoof = iter->second.get();
        char *sig = spoof + offset;

        memset(sig, 0, ACPI_SIG_SIZE);
    } else {
        auto orig = vcpu0->map_gpa_4k<char>(gpa, PAGE_SIZE_4K);
        auto iter = tables_spoof.try_emplace(gpa, make_page<char>()).first;
        char *spoof = iter->second.get();
        char *sig = spoof + offset;

        memcpy(spoof, orig.get(), PAGE_SIZE_4K);
        expects(!memcmp(sig, tab->sig.data(), ACPI_SIG_SIZE));
        memset(sig, 0, ACPI_SIG_SIZE);

        auto dom0 = vcpu0->dom();

        /* Replacing the signature only requires the first page, but we could
         * wipe the table. */
        dom0->unmap(gpa);
        dom0->map_4k_rw(gpa, g_mm->virtptr_to_physint(spoof));
        ::intel_x64::vmx::invept_global();
    }

    tab->hidden = true;

    printv("acpi: hiding table %c%c%c%c %#lx-%#lx (%luB).\n",
            tab->sig[0], tab->sig[1], tab->sig[2], tab->sig[3],
            tab->gpa, tab->gpa + tab->len - 1,
            tab->len);
}

}
