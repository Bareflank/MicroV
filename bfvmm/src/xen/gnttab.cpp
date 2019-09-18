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

xen_gnttab::xen_gnttab(xen_domain *dom, xen_memory *mem)
{
    version = 1;
    xen_dom = dom;
    xen_mem = mem;

    shrtab_raw.reserve(max_nr_frames);
    ststab_raw.reserve(max_nr_frames);

    shrtab_pages.reserve(max_nr_frames);
    ststab_pages.reserve(max_nr_frames);
}

int xen_gnttab::get_pages(int tabid, size_t base, size_t count,
                          gsl::span<class page *> pages)
{
    expects(base < max_nr_frames);
    expects(count <= pages.size());

    raw_tab_t *raw_tab{};
    page_tab_t *pg_tab{};

    switch (tabid) {
    case tabid_shared:
        raw_tab = &shrtab_raw;
        pg_tab = &shrtab_pages;
        break;
    case tabid_status:
        raw_tab = &ststab_raw;
        pg_tab = &ststab_pages;
        break;
    default:
        bferror_nhex(0, "xen_gnttab::get_pages: unknown tabid:", tabid);
        return -EINVAL;
    }

    const auto last = base + count - 1;
    const auto size = raw_tab->size();
    const auto cpty = raw_tab->capacity();

    /*
     * If the last requested index is greater than the
     * last possible index, return error
     */
    if (last >= cpty) {
        return -EINVAL;
    }

    /* Grow if we need to */
    if (last >= size) {
        size_t new_pages = last + 1 - size;

        while (new_pages-- > 0) {
            auto raw_page = make_page<uint8_t>();
            auto dom_page = alloc_vmm_backed_page(raw_page.get());

            raw_tab->emplace_back(std::move(raw_page));
            pg_tab->emplace_back(dom_page);
        }
    }

    /* Populate the page list */
    for (auto i = 0; i < count; i++) {
        pages[i] = (*pg_tab)[base + i];
    }

    return 0;
}

int xen_gnttab::get_page(int tabid, size_t idx, class page **pg)
{
    class page *list[1]{};

    auto rc = this->get_pages(tabid, idx, 1, list);
    if (rc) {
        return rc;
    }

    *pg = list[0];
    return 0;
}

/*
 * The guest calls query_size to determine the number of shared
 * frames it has with the VMM
 */
bool xen_gnttab::query_size(xen_vcpu *vcpu, gnttab_query_size_t *gqs)
{
    gqs->nr_frames = gsl::narrow_cast<uint32_t>(shrtab_raw.size());
    gqs->max_nr_frames = max_nr_frames;
    gqs->status = GNTST_okay;

    vcpu->m_uv_vcpu->set_rax(0);
    return true;
}

/* TODO: complete me, setup reserved entries etc. */
bool xen_gnttab::set_version(xen_vcpu *vcpu, gnttab_set_version_t *gsv)
{
    auto uvv = vcpu->m_uv_vcpu;

    if (gsv->version != 1 && gsv->version != 2) {
        uvv->set_rax(-EINVAL);
        return true;
    }

    if (gsv->version == 2) {
        bferror_info(0, "gnttab::set_version to 2 unimplemented");
        return false;
    }

    uvv->set_rax(0);
    return true;
}

bool xen_gnttab::mapspace_grant_table(xen_vcpu *vcpu, xen_add_to_physmap_t *atp)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto idx = atp->idx;
    class page *page{};

    if (idx & XENMAPIDX_grant_table_status) {
        if (version != 2) {
            bferror_ndec(0, "mapspace gnttab status but version is", version);
            uvv->set_rax(-EINVAL);
            return true;
        }

        idx &= ~XENMAPIDX_grant_table_status;
        auto rc = this->get_status_page(idx, &page);
        if (rc) {
            bferror_nhex(0, "get_status_page failed, idx=", idx);
            return rc;
        }
    } else {
        expects(version != 0);
        auto rc = this->get_shared_page(idx, &page);
        if (rc) {
            bferror_nhex(0, "get_shared_page failed, idx=", idx);
            return rc;
        }
    }

    xen_mem->add_local_page(atp->gpfn, pg_perm_rw, pg_mtype_wb, page);
    uvv->set_rax(0);

    return true;
}
}
