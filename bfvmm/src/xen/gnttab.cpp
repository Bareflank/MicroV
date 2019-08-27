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

#include <hve/arch/intel_x64/vcpu.h>
#include <xen/gnttab.h>
#include <xen/vcpu.h>

namespace microv {

gnttab::gnttab(xen_vcpu *xen) :
    m_xen{xen},
    m_vcpu{xen->m_vcpu},
    m_version{2}
{
    m_shared_gnttab.reserve(max_nr_frames);
    m_shared_gnttab.push_back(make_page<shared_entry_t>());
}

bool gnttab::query_size()
{
    auto gqs = m_vcpu->map_arg<gnttab_query_size_t>(m_vcpu->rsi());

    gqs->nr_frames = gsl::narrow_cast<uint32_t>(m_shared_gnttab.size());
    gqs->max_nr_frames = max_nr_frames;
    gqs->status = GNTST_okay;

    m_vcpu->set_rax(0);
    return true;
}

bool gnttab::set_version()
{
    auto gsv = m_vcpu->map_arg<gnttab_set_version_t>(m_vcpu->rsi());
    gsv->version = m_version;

    m_vcpu->set_rax(0);
    return true;
}

bool gnttab::mapspace_grant_table(xen_add_to_physmap_t *atp)
{
    expects((atp->idx & XENMAPIDX_grant_table_status) == 0);

    auto hpa = 0ULL;
    auto idx = atp->idx;
    auto size = m_shared_gnttab.size();

    if (idx < size) {
        auto hva = m_shared_gnttab[idx].get();
        hpa = g_mm->virtptr_to_physint(hva);
    } else {
        expects(size < m_shared_gnttab.capacity());
        auto map = make_page<shared_entry_t>();
        hpa = g_mm->virtptr_to_physint(map.get());
        m_shared_gnttab.push_back(std::move(map));
    }

    m_vcpu->map_4k_rw(atp->gpfn << x64::pt::page_shift, hpa);
    m_vcpu->set_rax(0);
    return true;
}
}
