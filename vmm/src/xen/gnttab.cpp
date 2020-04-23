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
#include <xen/hvm.h>
#include <xen/gnttab.h>
#include <xen/domain.h>
#include <xen/vcpu.h>

#include <utility>

namespace microv {

using atomic_hdr_t = volatile std::atomic<grant_entry_header_t>;

static_assert(sizeof(atomic_hdr_t) == 4);
static_assert(atomic_hdr_t::is_always_lock_free);
static_assert(std::is_standard_layout<grant_entry_header_t>::value);

struct gnttab_copy_operand {
    uint8_t *buf{nullptr};
    class xen_page *xpg{nullptr};
    const gnttab_copy_t::gnttab_copy_ptr *copy_ptr{nullptr};
    atomic_hdr_t *gte_hdr{nullptr};
    bool is_src{false};
    bool gfn_is_direct{false};
    bool unmap_buf{false};
};

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
    return (domid == hdr->domid) && ((hdr->flags & GTF_permit_access) != 0);
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
    const bool access = hdr->flags & GTF_permit_access;
    const bool readonly = hdr->flags & GTF_readonly;

    return domid == hdr->domid && access && !readonly;
}

void xen_gnttab_unmap_grant_ref(xen_vcpu *vcpu, gnttab_unmap_grant_ref_t *unmap)
{
    const grant_handle_t hdl = unmap->handle;
    const grant_ref_t fref = hdl & 0xFFFF;
    const xen_domid_t fdomid = hdl >> 16;

    static_assert(std::atomic<uint16_t>::is_always_lock_free);
    std::atomic<uint16_t> *atomic_flags;
    uint16_t new_flags;

    auto ldom = vcpu->m_xen_dom;
    auto lgnt = ldom->m_gnttab.get();
    auto itr = lgnt->map_handles.find(hdl);

    if (itr == lgnt->map_handles.end()) {
        printv("%s: handle:%x not found\n", __func__, hdl);
        unmap->status = GNTST_bad_handle;
        return;
    } else if (itr->second != unmap->host_addr) {
        printv("%s: hdl.addr=0x%lx != unmap.addr=0x%lx\n",
                __func__, itr->second, unmap->host_addr);
        unmap->status = GNTST_bad_virt_addr;
        return;
    }

    auto fdom = get_xen_domain(fdomid);
    if (!fdom) {
        printv("%s: fdom:%x not found\n", __func__, fdomid);
        unmap->status = GNTST_bad_handle;
        return;
    }

    grant_entry_header_t *fhdr = nullptr;
    auto fgnt = fdom->m_gnttab.get();

    if (fgnt->invalid_ref(fref)) {
        printv("%s: bad fref:%x\n", __func__, fref);

        if (fdomid == DOMID_WINPV && fref == GNTTAB_RESERVED_XENSTORE) {
            goto unmap;
        }

        unmap->status = GNTST_bad_handle;
        put_xen_domain(fdomid);
        return;
    }

    fhdr = fgnt->shared_header(fref);
    new_flags = fhdr->flags & ~(GTF_reading | GTF_writing);
    atomic_flags = reinterpret_cast<std::atomic<uint16_t> *>(&fhdr->flags);
    atomic_flags->exchange(new_flags);

unmap:
    auto lmem = ldom->m_memory.get();
    auto lgfn = xen_frame(unmap->host_addr);

    if (auto rc = lmem->remove_page(lgfn, false); rc) {
        printv("%s: failed to remove gfn:%lx, rc=%d\n", __func__, lgfn, rc);
        unmap->status = GNTST_general_error;
        put_xen_domain(fdomid);
        return;
    }

    lgnt->map_handles.erase(hdl);
    unmap->status = GNTST_okay;
    put_xen_domain(fdomid);
}

static void xen_gnttab_map_grant_ref(xen_vcpu *vcpu,
                                     gnttab_map_grant_ref_t *map)
{
    grant_entry_header_t *fhdr;
    xen_domid_t ldomid;
    xen_pfn_t fgfn, lgfn;
    class xen_memory *fmem, *lmem;
    class xen_page *fpg;
    uint32_t perm;
    uint16_t new_flags;
    std::atomic<uint16_t> *atomic_flags;

    int rc = GNTST_okay;
    auto uvv = vcpu->m_uv_vcpu;

//    printv("%s: domid:%x flags:%x ref:%x gpa:%lx\n",
//           __func__, map->dom, map->flags, map->ref, map->host_addr);

    if (!supported_map_flags(map->flags)) {
        printv("%s: unsupported GNTMAP flags:0x%x\n", __func__, map->flags);
        return;
    }

    const auto fref = map->ref;
    if (fref & 0xFFFF0000) {
        printv("%s: OOB fref 0x%x would overflow map handle\n",
               __func__, fref);
        return;
    }

    const auto map_ro = (map->flags & GNTMAP_readonly) != 0;
    const auto fdomid = map->dom;
    auto lgnt = vcpu->m_xen_dom->m_gnttab.get();
    grant_handle_t new_hdl = ((uint32_t)fdomid << 16) | fref;

    /*
     * Check if the address is already mapped. It is conceivable for a
     * guest to update an existing mapping (e.g. to change permissions)
     * but for now we don't allow this.
     */
    if (lgnt->map_handles.count(new_hdl)) {
        printv("%s: handle 0x%x already maps to 0x%lx\n",
                __func__, fdomid, lgnt->map_handles[new_hdl]);
        map->status = GNTST_bad_virt_addr;
        return;
    }

    auto fdom = get_xen_domain(fdomid);
    if (!fdom) {
        printv("%s: bad dom:0x%x\n", __func__, fdomid);
        map->status = GNTST_bad_domain;
        return;
    }

    auto fgnt = fdom->m_gnttab.get();
    if (fgnt->invalid_ref(fref)) {
        printv("%s: OOB ref:0x%x for dom:0x%x\n", __func__, fref, fdomid);

        if (fdomid == DOMID_WINPV && fref == GNTTAB_RESERVED_XENSTORE) {
            fmem = fdom->m_memory.get();
            fgfn = fdom->m_hvm->get_param(HVM_PARAM_STORE_PFN);
            fpg = fmem->find_page(fgfn);

            expects(fpg);
            goto set_perms;
        }

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
        printv("%s: WARNING: remapping entry: ref:0x%x dom:0x%x\n",
               __func__, fref, fdomid);
        rc = GNTST_general_error;
        goto put_domain;
    }

    new_flags = fhdr->flags | GTF_reading | (map_ro ? 0 : GTF_writing);
    atomic_flags = reinterpret_cast<std::atomic<uint16_t> *>(&fhdr->flags);
    atomic_flags->exchange(new_flags);

    fgfn = fgnt->shared_gfn(fref);
    fmem = fdom->m_memory.get();
    fpg = fmem->find_page(fgfn);

    if (!fpg) {
        if (fdomid != DOMID_WINPV) {
            printv("%s: gfn 0x%lx not mapped in dom 0x%x\n",
                   __func__, fgfn, fdomid);
            rc = GNTST_general_error;
            goto put_domain;
        }
    }

set_perms:
    perm = (map_ro) ? pg_perm_r : pg_perm_rw;
    lmem = vcpu->m_xen_dom->m_memory.get();
    lgfn = xen_frame(map->host_addr);

    if (fpg) {
        lmem->add_foreign_page(lgfn, perm, pg_mtype_wb, fpg->page);
    } else {
        lmem->add_raw_page(lgfn, perm, pg_mtype_wb, fgfn);
    }

    map->handle = new_hdl;

    if (!lgnt->map_handles.try_emplace(new_hdl, map->host_addr).second) {
        bferror_info(0, "failed to add map_handle");
        bferror_subnhex(0, "handle", new_hdl);
        bferror_subnhex(0, "gpa", map->host_addr);
    }

    map->dev_bus_addr = 0;
    rc = GNTST_okay;

put_domain:
    put_xen_domain(fdomid);

    map->status = rc;
    uvv->set_rax(rc);
}

/*
 * map_xen_page
 *
 * Return virtual 4k-aligned address mapped rw to the host
 * frame referenced by the xen_page argument.
 *
 * @param pg the xen_page to map
 * @return the virtual address to access pg->page->hfn.
 */
static inline uint8_t *map_xen_page(const class xen_page *pg)
{
    void *ptr = g_mm->alloc_map(UV_PAGE_SIZE);
    g_cr3->map_4k(ptr, xen_addr(pg->page->hfn));

    return reinterpret_cast<uint8_t *>(ptr);
}

/*
 * unmap_xen_page
 *
 * Unmap the virtual address previously allocated with map_xen_page
 *
 * @param ptr the address previously returned from map_xen_page
 */
static inline void unmap_xen_page(uint8_t *ptr)
{
    g_cr3->unmap(ptr);
    ::x64::tlb::invlpg(ptr);
    g_mm->free_map(ptr);
}

static class xen_domain *get_copy_dom(const xen_vcpu *curv,
                                      xen_domid_t domid) noexcept
{
    if (domid == DOMID_SELF || domid == curv->m_xen_dom->m_id) {
        return curv->m_xen_dom;
    }

    /* If the source domain isn't the current domain, take out a reference */
    return get_xen_domain(domid);
}

static void put_copy_dom(const xen_vcpu *curv,
                         xen_domid_t domid) noexcept
{
    if (domid == DOMID_SELF || domid == curv->m_xen_dom->m_id) {
        return;
    }

    put_xen_domain(domid);
}

static bool valid_copy_args(gnttab_copy_t *copy)
{
    auto src = &copy->source;
    auto dst = &copy->dest;

    auto src_use_gfn = (copy->flags & GNTCOPY_source_gref) == 0;
    auto dst_use_gfn = (copy->flags & GNTCOPY_dest_gref) == 0;

    if (src_use_gfn && src->domid != DOMID_SELF) {
        copy->status = GNTST_permission_denied;
        printv("%s: src: only DOMID_SELF can use gfn-based copy", __func__);
        return false;
    }

    if (dst_use_gfn && dst->domid != DOMID_SELF) {
        printv("%s: dst: only DOMID_SELF can use gfn-based copy", __func__);
        copy->status = GNTST_permission_denied;
        return false;
    }

    if (src->offset + copy->len > XEN_PAGE_SIZE) {
        printv("%s: src: offset(%u) + len(%u) > XEN_PAGE_SIZE(%lu)",
                __func__, src->offset, copy->len, XEN_PAGE_SIZE);
        copy->status = GNTST_bad_copy_arg;
        return false;
    }

    if (dst->offset + copy->len > XEN_PAGE_SIZE) {
        printv("%s: dst: offset(%u) + len(%u) > XEN_PAGE_SIZE(%lu)",
                __func__, src->offset, copy->len, XEN_PAGE_SIZE);
        copy->status = GNTST_bad_copy_arg;
        return false;
    }

    return true;
}

static xen_page *winpv_xen_page() noexcept
{
    static page winpv_pg{0};
    static xen_page winpv_xen_pg{0, pg_perm_rw, pg_mtype_wb, &winpv_pg};

    return &winpv_xen_pg;
}

static inline bool has_access(const gnttab_copy_operand *op,
                              xen_domid_t domid,
                              const grant_entry_header_t *hdr) noexcept
{
    return op->is_src ?
           has_read_access(domid, hdr) :
           has_write_access(domid, hdr);
}

static int get_copy_access(gnttab_copy_operand *op,
                           xen_domid_t domid,
                           xen_gnttab *gnt,
                           grant_ref_t ref)
{
    auto atomic_hdr = reinterpret_cast<atomic_hdr_t *>(gnt->shared_header(ref));
    grant_entry_header_t hdr = atomic_hdr->load();

    /*
     * If a prior xen_gnttab_map_grant_ref pinned the
     * frame, we return without modifying any flags.
     */
    if (already_mapped(hdr.flags)) {
        if (!has_access(op, domid, &hdr)) {
            printv("%s: ref %u already mapped but dom 0x%x doesnt have"
                   " %s access\n", __func__, ref, domid,
                   op->is_src ? "read" : "write");
            return GNTST_permission_denied;
        }

        return GNTST_okay;
    }

    constexpr int retries = 4;
    const uint16_t desired_flags = op->is_src ? GTF_reading : GTF_writing;
    grant_entry_header_t expect = hdr;

    for (int i = 0; i < retries; i++) {
        if (!has_access(op, domid, &expect)) {
            printv("%s: dom 0x%x doesn't have %s access to ref %u\n",
                   __func__, domid, op->is_src ? "read" : "write", ref);
            return GNTST_permission_denied;
        }

        grant_entry_header_t desire = expect;
        desire.flags |= desired_flags;

        if (atomic_hdr->compare_exchange_strong(expect, desire)) {
            op->gte_hdr = atomic_hdr;
            return GNTST_okay;
        }
    }

    printv("%s: grant entry %u is unstable\n", __func__, ref);
    return GNTST_general_error;
}

static inline void put_copy_access(const gnttab_copy_operand *op) noexcept
{
    constexpr uint32_t clear_read = ~((uint32_t)GTF_reading);
    constexpr uint32_t clear_write = ~((uint32_t)GTF_writing);

    const uint32_t mask = (op->is_src) ? clear_read : clear_write;
    auto hdr = reinterpret_cast<volatile std::atomic<uint32_t> *>(op->gte_hdr);

    hdr->fetch_and(mask);
}

static int get_copy_gfn(gnttab_copy_operand *op,
                        xen_domid_t current_domid,
                        xen_domain *dom,
                        xen_pfn_t *gfn)
{
    auto ref = op->copy_ptr->u.ref;
    auto gnt = dom->m_gnttab.get();

    if (gnt->invalid_ref(ref)) {
        printv("%s: bad %s ref(%u)\n",
               __func__, (op->is_src) ? "src" : "dst", ref);
        return GNTST_bad_gntref;
    }

    int rc = get_copy_access(op, current_domid, gnt, ref);

    if (rc < 0) {
        return rc;
    }

    *gfn = gnt->shared_gfn(ref);
    return rc;
}

static inline void put_copy_gfn(gnttab_copy_operand *op) noexcept
{
    if (!op->gte_hdr) {
        return;
    }

    put_copy_access(op);
    op->gte_hdr = nullptr;
}

static int get_copy_page(xen_domain *dom, xen_pfn_t gfn, xen_page **xpg)
{
    xen_page *pg = dom->m_memory.get()->find_page(gfn);

    if (pg) {
        *xpg = pg;
        return GNTST_okay;
    }

    if (dom->m_id != DOMID_WINPV) {
        printv("%s: gfn 0x%lx doesnt map to page\n", __func__, gfn);
        return GNTST_general_error;
    }

    pg = winpv_xen_page();

    pg->page->ptr = nullptr;
    pg->page->hfn = gfn;
    pg->page->src = pg_src_root;
    pg->gfn = gfn;

    *xpg = pg;
    return GNTST_okay;
}

static int get_copy_buf(gnttab_copy_operand *op)
{
    xen_page *xpg = op->xpg;
    expects(xpg->backed());

    if (xpg->page->ptr) {
        op->buf = reinterpret_cast<uint8_t *>(xpg->page->ptr);
        return GNTST_okay;
    }

    op->buf = map_xen_page(xpg);

    if (!op->buf) {
        printv("%s: map_xen_page failed: gfn=0x%lx hfn=0x%lx\n",
               __func__, xpg->gfn, xpg->page->hfn);
        return GNTST_general_error;
    }

    op->unmap_buf = true;
    return GNTST_okay;
}

static inline void put_copy_buf(gnttab_copy_operand *op)
{
    if (op->unmap_buf) {
        unmap_xen_page(op->buf);
        op->unmap_buf = false;
    }
}

static int get_copy_operand(xen_vcpu *vcpu, gnttab_copy_operand *op)
{
    auto domid = op->copy_ptr->domid;

    auto dom = get_copy_dom(vcpu, domid);
    if (!dom) {
        printv("%s: failed to get %s dom 0x%0x\n",
               __func__, (op->is_src) ? "src" : "dst", domid);
        return GNTST_bad_domain;
    }

    xen_pfn_t gfn{0};

    if (op->gfn_is_direct) {
        gfn = op->copy_ptr->u.gmfn;
    } else {
        int rc = get_copy_gfn(op, vcpu->m_xen_dom->m_id, dom, &gfn);
        if (rc != GNTST_okay) {
            put_copy_dom(vcpu, domid);
            return rc;
        }
    }

    int rc = get_copy_page(dom, gfn, &op->xpg);
    if (rc != GNTST_okay) {
        put_copy_gfn(op);
        put_copy_dom(vcpu, domid);
        return rc;
    }

    rc = get_copy_buf(op);
    if (rc != GNTST_okay) {
        put_copy_gfn(op);
        put_copy_dom(vcpu, domid);
        return rc;
    }

    return GNTST_okay;
}

static inline int get_copy_src_operand(xen_vcpu *vcpu,
                                       const gnttab_copy_t *copy,
                                       gnttab_copy_operand *op)
{
    op->copy_ptr = &copy->source;
    op->is_src = true;
    op->gfn_is_direct = (copy->flags & GNTCOPY_source_gref) == 0;

    return get_copy_operand(vcpu, op);
}

static inline int get_copy_dst_operand(xen_vcpu *vcpu,
                                       const gnttab_copy_t *copy,
                                       gnttab_copy_operand *op)
{
    op->copy_ptr = &copy->dest;
    op->is_src = false;
    op->gfn_is_direct = (copy->flags & GNTCOPY_dest_gref) == 0;

    return get_copy_operand(vcpu, op);
}

static inline void put_copy_operand(xen_vcpu *vcpu, gnttab_copy_operand *op)
{
    put_copy_buf(op);
    put_copy_gfn(op);
    put_copy_dom(vcpu, op->copy_ptr->domid);
}

static void xen_gnttab_copy(xen_vcpu *vcpu, gnttab_copy_t *copy)
{
    if (!valid_copy_args(copy)) {
        return;
    }

    int rc{GNTST_okay};
    gnttab_copy_operand src_op{};
    gnttab_copy_operand dst_op{};

    rc = get_copy_src_operand(vcpu, copy, &src_op);
    if (rc != GNTST_okay) {
        copy->status = rc;
        return;
    }

    rc = get_copy_dst_operand(vcpu, copy, &dst_op);
    if (rc != GNTST_okay) {
        copy->status = rc;
        put_copy_operand(vcpu, &src_op);
        return;
    }

    uint8_t *src = src_op.buf + copy->source.offset;
    uint8_t *dst = dst_op.buf + copy->dest.offset;

    memcpy(dst, src, copy->len);
    copy->status = rc;

    put_copy_operand(vcpu, &dst_op);
    put_copy_operand(vcpu, &src_op);

    return;
}

bool xen_gnttab_copy(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto num = uvv->rdx();
    auto map = uvv->map_gva_4k<gnttab_copy_t>(uvv->rsi(), num);
    auto cop = map.get();

    int rc;
    int i;

    for (i = 0; i < num; i++) {
        xen_gnttab_copy(vcpu, &cop[i]);
        rc = cop[i].status;

        if (rc != GNTST_okay) {
            printv("%s: op[%u] failed, rc=%d\n", __func__, i, rc);
            break;
        }
    }

    uvv->set_rax(rc);
    return true;
}

bool xen_gnttab_map_grant_ref(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto num = uvv->rdx();
    auto map = uvv->map_gva_4k<gnttab_map_grant_ref_t>(uvv->rsi(), num);
    auto ops = map.get();

    int rc;
    int i;

    for (i = 0; i < num; i++) {
        xen_gnttab_map_grant_ref(vcpu, &ops[i]);
        rc = ops[i].status;

        if (rc != GNTST_okay) {
            printv("%s: ERROR: op[%u] failed, rc=%d\n", __func__, i, rc);
            break;
        }
    }

    if (i > 0) {
        vcpu->invept();
    }

    uvv->set_rax(rc);
    return true;
}

bool xen_gnttab_unmap_grant_ref(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto num = uvv->rdx();
    auto map = uvv->map_gva_4k<gnttab_unmap_grant_ref_t>(uvv->rsi(), num);
    auto ops = map.get();

    int rc;
    int i;

    for (i = 0; i < num; i++) {
        xen_gnttab_unmap_grant_ref(vcpu, &ops[i]);
        rc = ops[i].status;

        if (rc != GNTST_okay) {
            printv("%s: ERROR: op[%u] failed, rc=%d\n", __func__, i, rc);
            break;
        }
    }

    if (i > 0) {
        vcpu->invept();
    }

    uvv->set_rax(rc);
    return true;
}

bool xen_gnttab_query_size(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;

    /* Multiple query_size are unsupported ATM */
    expects(uvv->rdx() == 1);

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
    expects(uvv->rdx() == 1);

    auto gsv = uvv->map_arg<gnttab_set_version_t>(uvv->rsi());
    return vcpu->m_xen_dom->m_gnttab->set_version(vcpu, gsv.get());
}

xen_gnttab::xen_gnttab(xen_domain *dom, xen_memory *mem)
{
    version = 1;
    xen_dom = dom;
    xen_mem = mem;

    shared_tab.reserve(max_shared_gte_pages());

    if (dom->m_uv_info->origin == domain_info::origin_root) {
        if (dom->m_id == DOMID_WINPV) {
            shared_map.reserve(max_shared_gte_pages());
        }
    } else {
        shared_rsrc.reserve(max_shared_gte_pages());
        shared_page.reserve(max_shared_gte_pages());
        this->grow_pages(1);
    }
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

    auto gte = reinterpret_cast<shr_v1_gte_t *>(shared_tab[pg_idx]);
    return &gte[pg_off];
}

inline xen_gnttab::shr_v2_gte_t *xen_gnttab::shr_v2_entry(grant_ref_t ref)
{
    const auto pg_idx = ref >> shr_v2_gte_page_shift;
    const auto pg_off = ref & (shr_v2_gte_per_page - 1);

    expects(pg_idx < shared_tab.size());

    auto gte = reinterpret_cast<shr_v2_gte_t *>(shared_tab[pg_idx]);
    return &gte[pg_off];
}

inline xen_gnttab::status_gte_t *xen_gnttab::status_entry(grant_ref_t ref)
{
    const auto pg_idx = ref >> status_gte_page_shift;
    const auto pg_off = ref & (status_gte_per_page - 1);

    expects(pg_idx < status_tab.size());

    auto gte = reinterpret_cast<status_gte_t *>(status_tab[pg_idx]);
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

int xen_gnttab::grow_pages(const uint32_t new_shr)
{
    auto new_sts = (version == 2) ? this->shared_to_status_pages(new_shr) : 0;

    /* Shared entry pages */
    for (auto i = 0; i < new_shr; i++) {
        auto shr_page = make_page<uint8_t>();
        auto dom_page = alloc_vmm_backed_page(shr_page.get());

        shared_tab.emplace_back(shr_page.get());
        shared_page.emplace_back(std::move(shr_page));
        shared_rsrc.emplace_back(dom_page);
    }

    /* Status entry pages */
    for (auto i = 0; i < new_sts; i++) {
        auto sts_page = make_page<status_gte_t>();
        auto dom_page = alloc_vmm_backed_page(sts_page.get());

        status_tab.emplace_back(sts_page.get());
        status_page.emplace_back(std::move(sts_page));
        status_rsrc.emplace_back(dom_page);
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
        const auto size = shared_page.size();
        const auto cpty = shared_page.capacity();

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
            this->grow_pages(shr_pages);
        }

        /* Populate the page list */
        for (auto i = 0; i < count; i++) {
            pages[i] = shared_rsrc[idx + i];
        }

        break;
    }
    case XENMEM_resource_grant_table_id_status: {
        const auto size = status_page.size();
        const auto cpty = status_page.capacity();

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
            this->grow_pages(this->status_to_shared_pages(sts_pages));
        }

        /* Populate the page list */
        for (auto i = 0; i < count; i++) {
            pages[i] = status_rsrc[idx + i];
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

extern uintptr_t winpv_hole_gfn;
extern size_t winpv_hole_size;

static inline bool in_winpv_hole(uintptr_t gfn) noexcept
{
    const auto gpa = xen_addr(gfn);
    const auto hole_gpa = xen_addr(winpv_hole_gfn);

    return gpa >= hole_gpa && gpa < (hole_gpa + winpv_hole_size);
}

bool xen_gnttab::mapspace_grant_table(xen_vcpu *vcpu, xen_add_to_physmap_t *atp)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto idx = atp->idx;
    auto gfn = atp->gpfn;
    class page *page{};

    if (uvv->is_guest_vcpu()) {
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

        xen_mem->add_local_page(gfn, pg_perm_rw, pg_mtype_wb, page);
        xen_mem->invept();
        uvv->set_rax(0);

        return true;
    }

    if (uvv->is_root_vcpu()) {
        expects(xen_dom->m_id == DOMID_WINPV);
        expects(in_winpv_hole(gfn));
        expects((idx & XENMAPIDX_grant_table_status) == 0);
        expects(idx < shared_map.capacity());
        expects(idx < shared_tab.capacity());
        expects(idx == shared_map.size());
        expects(idx == shared_tab.size());

        auto gpa = xen_addr(gfn);
        auto map = uvv->map_gpa_4k<uint8_t>(gpa);

        shared_tab.emplace_back(map.get());
        shared_map.emplace_back(std::move(map));

        /* Fill in store and console entries as xl would have */
        if (idx == 0) {
            /* Grant toolstack VM read/write access to store */
            auto pfn = xen_dom->m_hvm->get_param(HVM_PARAM_STORE_PFN);
            expects(pfn != 0);

            auto gte = this->shr_v1_entry(GNTTAB_RESERVED_XENSTORE);
            gte->flags = GTF_permit_access;
            gte->domid = 0;
            gte->frame = pfn;

            /* Grant toolstack VM read/write access to console */
            pfn = xen_dom->m_hvm->get_param(HVM_PARAM_CONSOLE_PFN);
            expects(pfn != 0);

            gte = this->shr_v1_entry(GNTTAB_RESERVED_CONSOLE);
            gte->flags = GTF_permit_access;
            gte->domid = 0;
            gte->frame = pfn;

            ::intel_x64::wmb();
        }

        uvv->set_rax(0);
        return true;
    }

    printv("%s: ERROR invalid vcpu type\n", __func__);
    return false;
}
}
