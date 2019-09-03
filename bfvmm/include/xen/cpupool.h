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

#ifndef MICROV_XEN_CPUPOOL_H
#define MICROV_XEN_CPUPOOL_H

#include <unordered_set>
#include <public/sysctl.h>
#include "types.h"

namespace microv {

void xen_cpupool_add_domain(xen_cpupoolid_t poolid, xen_domid_t domid);
void xen_cpupool_rm_domain(xen_cpupoolid_t poolid, xen_domid_t domid);
int xen_cpupool_mv_domain(xen_cpupoolid_t old_pool,
                          xen_cpupoolid_t new_pool,
                          xen_domid_t domid);
bool xen_cpupool_op(xen_vcpu *vcpu, struct xen_sysctl *ctl);

class xen_cpupool {
public:
    static constexpr xen_cpupoolid_t id_none = -1;

    xen_cpupool(xen_cpupoolid_t poolid);
    uint32_t nr_domains() const;
    void add_domain(xen_domid_t domid);
    void rm_domain(xen_domid_t domid);

    xen_cpupoolid_t m_id{id_none};
    uint32_t m_sched_id{};
    std::unordered_set<xen_domid_t> m_domid_set{};

public:
    ~xen_cpupool() = default;
    xen_cpupool(xen_cpupool &&) = delete;
    xen_cpupool(const xen_cpupool &) = delete;
    xen_cpupool &operator=(xen_cpupool &&) = delete;
    xen_cpupool &operator=(const xen_cpupool &) = delete;
};

}

#endif
