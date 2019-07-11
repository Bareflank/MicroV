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

class gnttab {
    using shared_entry_t = grant_entry_v2_t;
    static_assert(is_power_of_2(sizeof(shared_entry_t)));

    static constexpr auto max_nr_frames = 64;

    uint32_t m_version{};
    xen *m_xen{};
    xen_vcpu *m_vcpu{};
    std::vector<page_ptr<shared_entry_t>> m_shared_gnttab;

public:
    void query_size(gnttab_query_size_t *arg);
    void set_version(gnttab_set_version_t *arg);
    void mapspace_grant_table(xen_add_to_physmap_t *arg);

    gnttab(xen *xen);
    ~gnttab() = default;

    gnttab(gnttab &&) = default;
    gnttab &operator=(gnttab &&) = default;

    gnttab(const gnttab &) = delete;
    gnttab &operator=(const gnttab &) = delete;
};

}
#endif
