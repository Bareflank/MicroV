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

/*
 * has_read_access
 *
 * Check if a domain has read access to the given grant entry
 *
 * @param domid the domain to check
 * @param hdr the header of the shared grant entry to check
 * @return true iff the domain has read access
 */
static inline bool has_read_access(xen_domid_t domid,
                                   const grant_entry_header_t *hdr)
{
    return domid == hdr->domid && (hdr->flags & GTF_permit_access);
}

/*
 * has_write_access
 *
 * Check if a domain has write access to the given grant entry
 *
 * @param domid the domain to check
 * @param hdr the header of the shared grant entry to check
 * @return true iff the domain has write access
 */
static inline bool has_write_access(xen_domid_t domid,
                                    const grant_entry_header_t *hdr)
{
    return domid == hdr->domid && !(hdr->flags & GTF_readonly);
}

bool xen_gnttab_map_grant_ref(xen_vcpu *vcpu)
{
    grant_entry_header_t *fhdr;
    xen_domid_t ldomid;
    uint16_t new_flags;
    xen_pfn_t fgfn, lgfn;
    class xen_memory *fmem, *lmem;
    class xen_gnttab *lgnt;
    class xen_page *fpg;
    uint32_t perm;

    auto uvv = vcpu->m_uv_vcpu;

    /* Multiple map_grant_refs are unsupported ATM */
    expects(uvv->rdx() == 0);

    int rc = GNTST_okay;
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
    lgnt = vcpu->m_xen_dom->m_gnttab.get();
    expects(lgnt->map_handles.count(map->handle) == 0);
    lgnt->map_handles.emplace(map->handle);

    map->dev_bus_addr = 0;
    rc = GNTST_okay;

put_domain:
    put_xen_domain(fdomid);

    map->status = rc;
    uvv->set_rax(rc);
    return true;
}

/*
 * map_xen_page
 *
 * Return virtual 4k-aligned address of the host frame referenced
 * by the xen_page argument. If the xen_page is not backed, it will
 * become backed.
 *
 * @ensures(pg->backed())
 * @ensures(pg->mapped_in_vmm())
 *
 * @param pg the xen_page to map
 * @return the virtual address to access pg->page->hfn. Non-null guaranteed
 */
static uint8_t *map_xen_page(class xen_page *pg)
{
    void *ptr{};

    if (!pg->page) {
        printv("%s: FATAL: pg->page is NULL, gfn:0x%lx\n",
                __func__, pg->gfn);
        return nullptr;
    }

    if (pg->mapped_in_vmm()) {
        ptr = pg->page->ptr;
        return reinterpret_cast<uint8_t *>(ptr);
    }

    if (pg->backed()) {
        ptr = g_mm->alloc_map(UV_PAGE_SIZE);
        g_cr3->map_4k(ptr, pg->page->hfn);
        pg->page->ptr = ptr;
    } else {
        auto hfn = alloc_root_frame();

        if (hfn != XEN_INVALID_PFN) {
            pg->page->src = pg_src_root;
            pg->page->ptr = g_mm->alloc_map(UV_PAGE_SIZE);
            pg->page->hfn = hfn;
            g_cr3->map_4k(ptr, hfn);
        } else {
            pg->page->src = pg_src_vmm;
            pg->page->ptr = alloc_page();
            pg->page->hfn = xen_frame(g_mm->virtptr_to_physint(pg->page->ptr));
        }

        ptr = pg->page->ptr;
    }

    ensures(ptr);
    ensures(pg->backed());
    ensures(pg->mapped_in_vmm());

    return reinterpret_cast<uint8_t *>(ptr);
}

static void xen_gnttab_copy(xen_vcpu *vcpu, gnttab_copy_t *copy)
{
    auto src = &copy->source;
    auto dst = &copy->dest;

    /* Dest of copy must be current domain; other cases unsupported */
    expects(dst->domid == DOMID_SELF);

    /* Source of copy must be someone else; other cases unsupported */
    expects(src->domid != DOMID_SELF);

    const bool src_use_gfn = (copy->flags & GNTCOPY_source_gref) == 0;
    if (src_use_gfn && src->domid != DOMID_SELF) {
        copy->status = GNTST_permission_denied;
        return;
    }

    /*
     * This check will need to be here once the first expects
     * above is removed
     */
    const bool dst_use_gfn = (copy->flags & GNTCOPY_dest_gref) == 0;
    if (dst_use_gfn && dst->domid != DOMID_SELF) {
        copy->status = GNTST_permission_denied;
        return;
    }

    /* Check bounds */
    if (src->offset + copy->len > XEN_PAGE_SIZE) {
        copy->status = GNTST_bad_copy_arg;
    }

    if (dst->offset + copy->len > XEN_PAGE_SIZE) {
        copy->status = GNTST_bad_copy_arg;
    }

    xen_pfn_t lgfn, fgfn;
    grant_ref_t lref, fref;

    auto fdomid = src->domid;
    auto ldomid = vcpu->m_xen_dom->m_id;

    auto ldom = vcpu->m_xen_dom;
    auto lgnt = ldom->m_gnttab.get();
    auto lmem = ldom->m_memory.get();

    /* Get the local frame */
    if (dst_use_gfn) {
        lgfn = dst->u.gmfn;
    } else {
        lref = dst->u.ref;
        if (lgnt->invalid_ref(lref)) {
            printv("%s: bad lref:0x%x\n", __func__, lref);
            copy->status = GNTST_bad_gntref;
            return;
        }

        /* Ensure fdom can write to the dest frame */
        if (!has_write_access(fdomid, lgnt->shared_header(lref))) {
            printv("%s: fdom:0x%x cant write lref:0x%x\n",
                   __func__, fdomid, lref);
            copy->status = GNTST_permission_denied;
            return;
        }

        lgfn = lgnt->shared_gfn(lref);
    }

    auto fdom = get_xen_domain(fdomid);
    if (!fdom) {
        printv("%s: fdom:0x%x not found\n", __func__, fdomid);
        copy->status = GNTST_bad_domain;
        return;
    }

    auto fgnt = fdom->m_gnttab.get();
    auto fmem = fdom->m_memory.get();

    /* Get the foreign frame */
    if (src_use_gfn) {
        fgfn = src->u.gmfn;
    } else {
        fref = src->u.ref;
        if (fgnt->invalid_ref(fref)) {
            printv("%s: bad fref:0x%x\n", __func__, fref);
            copy->status = GNTST_bad_gntref;
            put_xen_domain(fdomid);
            return;
        }

        /* Ensure ldom can read the source frame */
        if (!has_read_access(ldomid, fgnt->shared_header(fref))) {
            printv("%s: ldom:0x%x cant read fref:0x%x\n",
                   __func__, ldomid, fref);
            copy->status = GNTST_permission_denied;
            put_xen_domain(fdomid);
            return;
        }

        fgfn = fgnt->shared_gfn(fref);
    }

    /* Now get the xen_page's of each gfn */
    auto lpg = lmem->find_page(lgfn);
    if (!lpg) {
        printv("%s: lgfn:0x%lx doesnt map to page\n", __func__, lgfn);
        put_xen_domain(fdomid);
        copy->status = GNTST_general_error;
        return;
    }

    auto fpg = fmem->find_page(fgfn);
    if (!fpg) {
        printv("%s: fgfn:0x%lx doesnt map to page\n", __func__, fgfn);
        put_xen_domain(fdomid);
        copy->status = GNTST_general_error;
        return;
    }

    /* Obtain a pointer to the xen_pages' underlying hfn */
    uint8_t *lbase = map_xen_page(lpg);
    if (lbase == nullptr) {
        printv("%s: failed to map lpg\n", __func__);
        put_xen_domain(fdomid);
        copy->status = GNTST_general_error;
        return;
    }

    uint8_t *fbase = map_xen_page(fpg);
    if (fbase == nullptr) {
        printv("%s: failed to map fpg\n", __func__);
        put_xen_domain(fdomid);
        copy->status = GNTST_general_error;
        return;
    }

    /* Do the copy */
    uint8_t *lptr = lbase + dst->offset;
    uint8_t *fptr = fbase + src->offset;

    memcpy(lptr, fptr, copy->len);
    copy->status = GNTST_okay;
    put_xen_domain(fdomid);

    /* Debugging info */
    printv("%s: %u bytes from (dom:0x%x,gfn:0x%lx) -> \n",
           __func__, copy->len, fdomid, fgfn);
    printv("(dom:0x%x,gfn:0x%lx)\n", ldomid, lgfn);
}

bool xen_gnttab_copy(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto num = uvv->rdx();
    auto map = uvv->map_gva_4k<gnttab_copy_t>(uvv->rsi(), num);
    auto cop = map.get();

    for (auto i = 0; i < num; i++) {
        xen_gnttab_copy(vcpu, &cop[i]);
        const auto rc = cop[i].status;

        if (rc != GNTST_okay) {
            printv("%s: op[%u] failed, rc=%u\n", __func__, i, rc);
            uvv->set_rax(rc);
            return false;
        }
    }

    uvv->set_rax(0);
    return true;
}

bool xen_gnttab_query_size(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;

    /* Multiple query_size are unsupported ATM */
    expects(uvv->rdx() == 0);

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

    /* Multiple set_version are unsupported ATM */
    expects(uvv->rdx() == 0);

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
