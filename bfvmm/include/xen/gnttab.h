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

#ifndef MICROV_XEN_GNTTAB_H
#define MICROV_XEN_GNTTAB_H

#include "types.h"
#include "../page.h"
#include <public/grant_table.h>
#include <public/memory.h>

namespace microv {

bool xen_gnttab_query_size(xen_vcpu *vcpu);
bool xen_gnttab_set_version(xen_vcpu *vcpu);

class xen_gnttab {
//    using shared_entry_t = grant_entry_v2_t;
//    static_assert(is_power_of_2(sizeof(shared_entry_t)));

    using tabid_t = enum { tabid_shared, tabid_status };
    using raw_tab_t = std::vector<page_ptr<uint8_t>>;
    using page_tab_t = std::vector<class page *>;

    uint32_t version{};
    xen_domain *xen_dom{};
    xen_memory *xen_mem{};

    raw_tab_t shrtab_raw;
    raw_tab_t ststab_raw;

    page_tab_t shrtab_pages;
    page_tab_t ststab_pages;

public:
    static constexpr auto max_nr_frames = 64;

    int get_page(int tabid, size_t idx, class page **page);
    int get_pages(int tabid, size_t base, size_t count,
                  gsl::span<class page *> pages);

    int get_shared_page(size_t idx, class page **page)
    {
        return get_page(tabid_shared, idx, page);
    }

    int get_status_page(size_t idx, class page **page)
    {
        return get_page(tabid_status, idx, page);
    }

    int get_shared_pages(size_t base,
                         size_t count,
                         gsl::span<class page *> pages)
    {
        return get_pages(tabid_shared, base, count, pages);
    }

    int get_status_pages(size_t base,
                         size_t count,
                         gsl::span<class page *> pages)
    {
        return get_pages(tabid_status, base, count, pages);
    }

    bool query_size(xen_vcpu *vcpu, gnttab_query_size_t *gqs);
    bool set_version(xen_vcpu *vcpu, gnttab_set_version_t *gsv);
    bool mapspace_grant_table(xen_vcpu *vcpu, xen_add_to_physmap_t *atp);

    xen_gnttab(xen_domain *dom, xen_memory *mem);
    ~xen_gnttab() = default;

    xen_gnttab(xen_gnttab &&) = default;
    xen_gnttab(const xen_gnttab &) = delete;
    xen_gnttab &operator=(xen_gnttab &&) = default;
    xen_gnttab &operator=(const xen_gnttab &) = delete;
};

}
#endif
