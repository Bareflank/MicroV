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

#include <printv.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <xen/gnttab.h>
#include <xen/domain.h>
#include <xen/vcpu.h>

namespace microv {

bool xen_gnttab_query_size(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto gqs = uvv->map_arg<gnttab_query_size_t>(uvv->rsi());
    auto domid = gqs->dom;

    if (domid == DOMID_SELF) {
        domid = vcpu->m_xen_dom->m_id;
    }

    auto dom = get_xen_domain(domid);
    if (!dom) {
        bfalert_nhex(0, "xen_domain not found:", domid);
        gqs->status = GNTST_bad_domain;
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_gnttab->query_size(vcpu, gqs.get());
    put_xen_domain(domid);

    return ret;
}

bool xen_gnttab_set_version(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto gsv = uvv->map_arg<gnttab_set_version_t>(uvv->rsi());

    return vcpu->m_xen_dom->m_gnttab->set_version(vcpu, gsv.get());
}

xen_gnttab::xen_gnttab(xen_domain *dom)
{
    this->version = 2;
    this->dom = dom;

    this->shared_gnttab.reserve(max_nr_frames);
    this->shared_gnttab.push_back(make_page<shared_entry_t>());
}

bool xen_gnttab::query_size(xen_vcpu *vcpu, gnttab_query_size_t *gqs)
{
    gqs->nr_frames = gsl::narrow_cast<uint32_t>(shared_gnttab.size());
    gqs->max_nr_frames = max_nr_frames;
    gqs->status = GNTST_okay;

    vcpu->m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_gnttab::set_version(xen_vcpu *vcpu, gnttab_set_version_t *gsv)
{
    bfdebug_ndec(0, "gnttab: set version to", gsv->version);

    this->version = gsv->version;
    vcpu->m_uv_vcpu->set_rax(0);

    return true;
}

bool xen_gnttab::mapspace_grant_table(xen_vcpu *vcpu, xen_add_to_physmap_t *atp)
{
    expects((atp->idx & XENMAPIDX_grant_table_status) == 0);

    auto hpa = 0ULL;
    auto idx = atp->idx;
    auto size = shared_gnttab.size();

    printv("gnttab: mapspace idx:%lx nr_pages:%u\n", idx, atp->size);

    if (idx < size) {
        auto hva = shared_gnttab[idx].get();
        hpa = g_mm->virtptr_to_physint(hva);
    } else {
        expects(size < shared_gnttab.capacity());
        auto map = make_page<shared_entry_t>();
        hpa = g_mm->virtptr_to_physint(map.get());
        shared_gnttab.push_back(std::move(map));
    }

    vcpu->m_uv_vcpu->map_4k_rw(atp->gpfn << x64::pt::page_shift, hpa);
    vcpu->m_uv_vcpu->set_rax(0);

    return true;
}
}
