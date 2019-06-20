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
#include <xen/arch/intel_x64/gnttab_op.h>
#include <public/memory.h>

namespace microv::xen::intel_x64
{

gnttab_op::gnttab_op(microv::intel_x64::vcpu *vcpu) :
    m_vcpu{vcpu},
    m_version{2}
{
    m_shared_gnttab.reserve(max_nr_frames);
    m_shared_gnttab.push_back(make_page<shared_entry_t>());
}

void
gnttab_op::query_size(gsl::not_null<gnttab_query_size_t *> arg)
{
    arg->nr_frames = gsl::narrow_cast<uint32_t>(m_shared_gnttab.size());
    arg->max_nr_frames = max_nr_frames;
    arg->status = GNTST_okay;
}

void
gnttab_op::set_version(gsl::not_null<gnttab_set_version_t *> arg)
{
    arg->version = m_version;
}

void
gnttab_op::mapspace_grant_table(gsl::not_null<xen_add_to_physmap_t *> arg)
{
    expects((arg->idx & XENMAPIDX_grant_table_status) == 0);

    auto hpa = 0ULL;
    auto idx = arg->idx;
    auto size = m_shared_gnttab.size();

    // Get the mfn
    //
    if (idx < size) {
        auto hva = m_shared_gnttab[idx].get();
        hpa = g_mm->virtptr_to_physint(hva);
    } else {
        expects(size < m_shared_gnttab.capacity());
        auto map = make_page<shared_entry_t>();
        hpa = g_mm->virtptr_to_physint(map.get());
        m_shared_gnttab.push_back(std::move(map));
    }

    m_vcpu->map_4k_rw(arg->gpfn << x64::pt::page_shift, hpa);
}

}
