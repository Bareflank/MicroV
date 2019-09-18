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
#include <public/grant_table.h>
#include <public/memory.h>

namespace microv {

bool xen_gnttab_query_size(xen_vcpu *vcpu);
bool xen_gnttab_set_version(xen_vcpu *vcpu);

class xen_gnttab {
    using shared_entry_t = grant_entry_v2_t;
    static_assert(is_power_of_2(sizeof(shared_entry_t)));

    uint32_t version{};
    xen_domain *dom{};
    std::vector<page_ptr<shared_entry_t>> shared_gnttab;

public:
    static constexpr auto max_nr_frames = 64;

    bool query_size(xen_vcpu *vcpu, gnttab_query_size_t *gqs);
    bool set_version(xen_vcpu *vcpu, gnttab_set_version_t *gsv);
    bool mapspace_grant_table(xen_vcpu *vcpu, xen_add_to_physmap_t *atp);

    xen_gnttab(xen_domain *dom);
    ~xen_gnttab() = default;

    xen_gnttab(xen_gnttab &&) = default;
    xen_gnttab(const xen_gnttab &) = delete;
    xen_gnttab &operator=(xen_gnttab &&) = default;
    xen_gnttab &operator=(const xen_gnttab &) = delete;
};

}
#endif
