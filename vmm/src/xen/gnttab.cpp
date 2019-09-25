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

constexpr grant_handle_t invalid_mgl_node = ~0;

/*
 * mappable_gtf
 *
 * Check if the given GTF value indicates a mappable grant entry
 * The GTF value is from the shared entry in the granter's table.
 *
 * @param gtf the flags to test
 * @return true iff the gtf represents a mappable entry
 */
static inline bool mappable_gtf(const uint16_t gtf)
{
    /* Only allow GTF_permit_access type */
    if ((gtf & GTF_type_mask) != GTF_permit_access) {
        return false;
    }

    return (gtf & (GTF_PWT|GTF_PCD|GTF_PAT|GTF_sub_page)) == 0;
}

/*
 * supported_map_flags
 *
 * Check the given GNTMAP_* flags are supported by the current implementation
 *
 * @param gntmap the flags to test
 * @return true iff the value is supported
 */
static inline bool supported_map_flags(const uint32_t gntmap)
{
    constexpr auto host_rw = GNTMAP_host_map;
    constexpr auto host_ro = GNTMAP_host_map | GNTMAP_readonly;

    return gntmap == host_rw || gntmap == host_ro;
}

/*
 * already_mapped
 *
 * Check if the given value indicates an entry that has already been mapped
 * The GTF value is from the shared entry in the granter's table.
 *
 * @param gtf the flags to test
 * @return true iff the gtf is already mapped
 */
static inline bool already_mapped(const uint16_t gtf)
{
    return (gtf & (GTF_reading | GTF_writing)) != 0;
}

bool xen_gnttab_map_grant_ref(xen_vcpu *vcpu)
{
    grant_entry_header_t *fhdr;
    xen_domid_t ldomid;
    uint16_t new_flags;
    xen_pfn_t fgfn, lgfn;
    class xen_memory *fmem, *lmem;
    class xen_page *fpg;
    uint32_t perm;

    int rc = GNTST_okay;
    auto uvv = vcpu->m_uv_vcpu;
    auto map = uvv->map_arg<gnttab_map_grant_ref_t>(uvv->rsi());

    printv("%s: domid:%x flags:%x ref:%x gpa:%lx\n",
           __func__, map->dom, map->flags, map->ref, map->host_addr);

    if (!supported_map_flags(map->flags)) {
        printv("%s: unsupported GNTMAP flags:0x%x\n", __func__, map->flags);
        return false;
    }

    const auto map_ro = (map->flags & GNTMAP_readonly) != 0;
    const auto fdomid = map->dom;

    auto fdom = get_xen_domain(fdomid);
    if (!fdom) {
        printv("%s: bad dom:0x%x\n", __func__, fdomid);
        map->status = GNTST_bad_domain;
        return true;
    }

    auto fgnt = fdom->m_gnttab.get();
    auto fref = map->ref;
    if (fgnt->invalid_ref(fref)) {
        printv("%s: OOB ref:0x%x for dom:0x%x\n", __func__, fref, fdomid);
        rc = GNTST_bad_gntref;
        goto put_domain;
    }

    fhdr = fgnt->shared_header(fref);
    if (!mappable_gtf(fhdr->flags)) {
        printv("%s: invalid flags: gtf:0x%x ref:0x%x dom:0x%x\n",
               __func__, fhdr->flags, fref, fdomid);
        rc = GNTST_general_error;
        goto put_domain;
    }

    ldomid = vcpu->m_xen_dom->m_id;
    if (fhdr->domid != ldomid) {
        printv("%s: invalid dom: fdom:0x%x ldom:0x%x\n",
               __func__, fhdr->domid, ldomid);
        rc = GNTST_bad_domain;
        goto put_domain;
    }

    if (already_mapped(fhdr->flags)) {
        printv("%s: remapping entry: ref:0x%x dom:0x%x\n",
               __func__, fref, fdomid);
        put_xen_domain(fdomid);
        return false;
    }

    new_flags = fhdr->flags | GTF_reading | (map_ro ? 0 : GTF_writing);
    fhdr->flags = new_flags;

    fgfn = fgnt->shared_gfn(fref);
    fmem = fdom->m_memory.get();
    fpg = fmem->find_page(fgfn);

    if (!fpg) {
        printv("%s: gfn 0x%lx not mapped in dom 0x%x\n",
               __func__, fgfn, fdomid);
        rc = GNTST_general_error;
        goto put_domain;
    }

    perm = (map_ro) ? pg_perm_r : pg_perm_rw;
    lmem = vcpu->m_xen_dom->m_memory.get();
    lgfn = xen_frame(map->host_addr);
    lmem->add_foreign_page(lgfn, perm, pg_mtype_wb, fpg->page);

    map->handle = ((uint32_t)fdomid << 16) | fref;
    map->dev_bus_addr = 0;
    rc = GNTST_okay;

put_domain:
    put_xen_domain(fdomid);

    map->status = rc;
    uvv->set_rax(rc);
    return true;
}

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

    shared_rsrc_pages.reserve(max_shared_gte_pages());
    shared_tab.reserve(max_shared_gte_pages());

    this->grow(1);
}

grant_entry_header_t *xen_gnttab::shared_header(grant_ref_t ref)
{
    if (version == 1) {
        auto ent = this->shr_v1_entry(ref);
        return reinterpret_cast<grant_entry_header_t *>(ent);
    } else {
        auto ent = this->shr_v2_entry(ref);
        return reinterpret_cast<grant_entry_header_t *>(ent);
    }
}

uintptr_t xen_gnttab::shared_gfn(grant_ref_t ref)
{
    if (version == 1) {
        auto ent = this->shr_v1_entry(ref);
        return ent->frame;
    } else {
        auto ent = this->shr_v2_entry(ref);
        return ent->full_page.frame;
    }
}

bool xen_gnttab::invalid_ref(grant_ref_t ref) const noexcept
{
    if (version == 1) {
        return ref >= (shared_tab.size() * shr_v1_gte_per_page);
    } else {
        return ref >= (shared_tab.size() * shr_v2_gte_per_page);
    }
}

constexpr uint32_t xen_gnttab::max_status_gte_pages()
{
    /*
     * Since status pages are only used when v2 is used, the max v2
     * shared entries determine the max status pages
     */
    constexpr auto max_sts = max_shared_gte_pages() * shr_v2_gte_per_page;
    if constexpr (max_sts <= status_gte_per_page) {
        return 1;
    }

    return max_sts / status_gte_per_page;
}

inline uint32_t
xen_gnttab::shared_to_status_pages(uint32_t shr_pages) const noexcept
{
    const auto ent_per_page = (version == 1) ? shr_v1_gte_per_page :
                                               shr_v2_gte_per_page;
    const auto ent = shr_pages * ent_per_page;
    const auto rem = ent & (status_gte_per_page - 1);

    return (ent >> status_gte_page_shift) + (rem) ? 1 : 0;
}

inline uint32_t
xen_gnttab::status_to_shared_pages(uint32_t sts_pages) const noexcept
{
    const auto ent = sts_pages * status_gte_per_page;
    const auto rem = ent & (shr_v2_gte_per_page - 1);

    return (ent >> shr_v2_gte_page_shift) + (rem) ? 1 : 0;
}

inline xen_gnttab::shr_v1_gte_t *xen_gnttab::shr_v1_entry(grant_ref_t ref)
{
    const auto pg_idx = ref >> shr_v1_gte_page_shift;
    const auto pg_off = ref & (shr_v1_gte_per_page - 1);

    expects(pg_idx < shared_tab.size());

    auto gte = reinterpret_cast<shr_v1_gte_t *>(shared_tab[pg_idx].get());
    return &gte[pg_off];
}

inline xen_gnttab::shr_v2_gte_t *xen_gnttab::shr_v2_entry(grant_ref_t ref)
{
    const auto pg_idx = ref >> shr_v2_gte_page_shift;
    const auto pg_off = ref & (shr_v2_gte_per_page - 1);

    expects(pg_idx < shared_tab.size());

    auto gte = reinterpret_cast<shr_v2_gte_t *>(shared_tab[pg_idx].get());
    return &gte[pg_off];
}

inline xen_gnttab::status_gte_t *xen_gnttab::status_entry(grant_ref_t ref)
{
    const auto pg_idx = ref >> status_gte_page_shift;
    const auto pg_off = ref & (status_gte_per_page - 1);

    expects(pg_idx < status_tab.size());

    auto gte = reinterpret_cast<status_gte_t *>(status_tab[pg_idx].get());
    return &gte[pg_off];
}

void xen_gnttab::dump_shared_entry(grant_ref_t ref)
{
    if (invalid_ref(ref)) {
        printv("%s: OOB ref:0x%x\n", __func__, ref);
        return;
    }

    if (version == 1) {
        auto ent = shr_v1_entry(ref);
        printv("%s: v1: ref:0x%x flags:0x%x domid:0x%x frame:0x%x\n",
                __func__, ref, ent->flags, ent->domid, ent->frame);
    } else {
        auto ent = shr_v2_entry(ref);
        printv("%s: v2: ref:0x%x flags:0x%x domid:0x%x\n",
                __func__, ref, ent->hdr.flags, ent->hdr.domid);
    }
}

int xen_gnttab::get_shared_page(size_t idx, class page **page)
{
    return get_page(XENMEM_resource_grant_table_id_shared, idx, page);
}

int xen_gnttab::get_status_page(size_t idx, class page **page)
{
    return get_page(XENMEM_resource_grant_table_id_status, idx, page);
}

int xen_gnttab::get_shared_pages(size_t idx, size_t count,
                                 gsl::span<class page *> pages)
{
    return get_pages(XENMEM_resource_grant_table_id_shared, idx, count, pages);
}

int xen_gnttab::get_status_pages(size_t idx, size_t count,
                                 gsl::span<class page *> pages)
{
    return get_pages(XENMEM_resource_grant_table_id_status, idx, count, pages);
}

int xen_gnttab::grow(const uint32_t new_shr)
{
    auto new_sts = (version == 2) ? this->shared_to_status_pages(new_shr) : 0;

    /* Shared entry pages */
    for (auto i = 0; i < new_shr; i++) {
        auto shr_page = make_page<uint8_t>();
        auto dom_page = alloc_vmm_backed_page(shr_page.get());

        shared_tab.emplace_back(std::move(shr_page));
        shared_rsrc_pages.emplace_back(dom_page);
    }

    /* Status entry pages */
    for (auto i = 0; i < new_sts; i++) {
        auto sts_page = make_page<status_gte_t>();
        auto dom_page = alloc_vmm_backed_page(sts_page.get());

        status_tab.emplace_back(std::move(sts_page));
        status_rsrc_pages.emplace_back(dom_page);
    }

    return 0;
}

int xen_gnttab::get_pages(int tabid, size_t idx, size_t count,
                          gsl::span<class page *> pages)
{
    expects(count <= pages.size());
    const auto last = idx + count - 1;

    switch (tabid) {
    case XENMEM_resource_grant_table_id_shared: {
        const auto size = shared_tab.size();
        const auto cpty = shared_tab.capacity();

        /*
         * If the last requested index is greater than the
         * last possible index, return error
         */
        if (last >= cpty) {
            return -EINVAL;
        }

        /* Grow if we need to */
        if (last >= size) {
            const auto shr_pages = last + 1 - size;
            this->grow(shr_pages);
        }

        /* Populate the page list */
        for (auto i = 0; i < count; i++) {
            pages[i] = shared_rsrc_pages[idx + i];
        }

        break;
    }
    case XENMEM_resource_grant_table_id_status: {
        const auto size = status_tab.size();
        const auto cpty = status_tab.capacity();

        /*
         * If the last requested index is greater than the
         * last possible index, return error
         */
        if (last >= cpty) {
            return -EINVAL;
        }

        /* Grow if we need to */
        if (last >= size) {
            const auto sts_pages = last + 1 - size;
            this->grow(this->status_to_shared_pages(sts_pages));
        }

        /* Populate the page list */
        for (auto i = 0; i < count; i++) {
            pages[i] = status_rsrc_pages[idx + i];
        }

        break;
    }
    default:
        bferror_nhex(0, "xen_gnttab::get_pages: unknown tabid:", tabid);
        return -EINVAL;
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
    gqs->nr_frames = gsl::narrow_cast<uint32_t>(shared_tab.size());
    gqs->max_nr_frames = max_shared_gte_pages();
    gqs->status = GNTST_okay;

    vcpu->m_uv_vcpu->set_rax(0);
    return true;
}

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
            expects(version == 1);
            bferror_info(0, "mapspace gnttab status but version is 1");
            uvv->set_rax(-EINVAL);
            return true;
        }

        idx &= ~XENMAPIDX_grant_table_status;
        if (auto rc = this->get_status_page(idx, &page); rc) {
            bferror_nhex(0, "get_status_page failed, idx=", idx);
            return rc;
        }
    } else {
        if (auto rc = this->get_shared_page(idx, &page); rc) {
            bferror_nhex(0, "get_shared_page failed, idx=", idx);
            return rc;
        }
    }

    xen_mem->add_local_page(atp->gpfn, pg_perm_rw, pg_mtype_wb, page);
    uvv->set_rax(0);

    return true;
}
}
