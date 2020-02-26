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

#include <atomic>
#include <mutex>
#include <unordered_set>

#include <clflush.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <iommu/iommu.h>
#include <printv.h>
#include <xen/domain.h>
#include <xen/memory.h>
#include <xen/vcpu.h>

namespace microv {

uintptr_t winpv_hole_gfn;
size_t winpv_hole_size;

static std::mutex dom_pool_mtx;
static std::unordered_map<uint64_t, class page> dom_pool;
static uint64_t dom_page_id{};

static std::mutex root_pool_mtx;
static std::list<xen_pfn_t> root_pool;

/* How many free frames from the root domain are there? */
static inline size_t root_frames()
{
    std::lock_guard lock(root_pool_mtx);
    return root_pool.size();
}

/* How many free frames from the VMM are there? */
static inline size_t vmm_pool_pages()
{
    return g_mm->page_pool_pages();
}

xen_pfn_t alloc_root_frame()
{
    std::lock_guard lock(root_pool_mtx);

    xen_pfn_t pfn = XEN_INVALID_PFN;

    if (root_pool.size()) {
        pfn = root_pool.back();
        root_pool.pop_back();
    }

    return pfn;
}

class page *alloc_unbacked_page()
{
    std::lock_guard lock(dom_pool_mtx);

    auto id = dom_page_id++;
    auto it = dom_pool.try_emplace(id, page(id)).first;

    return &it->second;
}

class page *alloc_root_backed_page(xen_pfn_t hfn)
{
    std::lock_guard lock(dom_pool_mtx);

    auto id = dom_page_id++;
    auto it = dom_pool.try_emplace(id, page(id, hfn)).first;

    return &it->second;
}

class page *alloc_raw_page(xen_pfn_t hfn)
{
    std::lock_guard lock(dom_pool_mtx);

    auto id = dom_page_id++;
    auto it = dom_pool.try_emplace(id, page(id, hfn, true)).first;

    return &it->second;
}

class page *alloc_vmm_backed_page(void *ptr)
{
    std::lock_guard lock(dom_pool_mtx);

    auto id = dom_page_id++;
    auto it = dom_pool.try_emplace(id, page(id, ptr)).first;

    return &it->second;
}

void free_unbacked_page(class page *pg)
{
    expects(!pg->refcnt);
    expects(pg->src == pg_src_none);

    std::lock_guard page_lock(dom_pool_mtx);
    dom_pool.erase(pg->id);
}

void free_raw_page(class page *pg)
{
    expects(!pg->refcnt);
    expects(pg->src == pg_src_raw);

    std::lock_guard page_lock(dom_pool_mtx);
    dom_pool.erase(pg->id);
}

void free_root_page(class page *pg)
{
    expects(!pg->refcnt);
    expects(pg->src == pg_src_root);

    std::lock_guard page_lock(dom_pool_mtx);
    std::lock_guard root_lock(root_pool_mtx);

    root_pool.emplace_back(pg->hfn);
    dom_pool.erase(pg->id);
}

void free_vmm_page(class page *pg)
{
    expects(!pg->refcnt);
    expects(pg->src == pg_src_vmm);
    expects(pg->mapped_in_vmm());

    std::lock_guard page_lock(dom_pool_mtx);

    g_mm->free_page(pg->ptr);
    dom_pool.erase(pg->id);
}

const char *e820_type_str(int type)
{
    switch (type) {
    case E820_TYPE_RAM:
        return "ram";
    case E820_TYPE_RESERVED:
        return "reserved";
    case E820_TYPE_ACPI:
        return "acpi";
    case E820_TYPE_NVS:
        return "nvs";
    case E820_TYPE_UNUSABLE:
        return "unusable";
    case E820_TYPE_PMEM:
        return "pmem";
    default:
        return "unknown";
    }
}

bool xenmem_memory_map(xen_vcpu *vcpu)
{
    auto uvd = vcpu->m_uv_dom;
    auto uvv = vcpu->m_uv_vcpu;
    auto map = uvv->map_arg<xen_memory_map_t>(uvv->rsi());

    std::lock_guard e820_lock(uvd->e820_mtx);

    if (map->nr_entries < uvd->e820().size()) {
        throw std::runtime_error("guest E820 too small");
    }

    auto gva = map->buffer.p;
    auto len = map->nr_entries;
    auto tab = uvv->map_gva_4k<e820_entry_t>(gva, len);
    auto ent = tab.get();

    map->nr_entries = 0;

    for (const auto &entry : uvd->e820()) {
        ent[map->nr_entries].addr = entry.addr;
        ent[map->nr_entries].size = entry.size;
        ent[map->nr_entries].type = entry.type;

        map->nr_entries++;
    }

    uvv->set_rax(0);
    return true;
}

bool xenmem_reserved_device_memory_map(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto map = uvv->map_arg<xen_reserved_device_memory_map_t>(uvv->rsi());

    map->nr_entries = 0;
    uvv->set_rax(0);

    return true;
}

bool xenmem_set_memory_map(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto fmap = uvv->map_arg<xen_foreign_memory_map_t>(uvv->rsi());

    expects(fmap->domid != DOMID_SELF);

    auto dom = get_xen_domain(fmap->domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, fmap->domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_memory->set_memory_map(vcpu, fmap.get());
    put_xen_domain(fmap->domid);

    return ret;
}

bool xenmem_add_to_physmap(xen_vcpu *vcpu)
{
    auto dom = vcpu->m_xen_dom;
    auto uvv = vcpu->m_uv_vcpu;
    auto atp = uvv->map_arg<xen_add_to_physmap_t>(uvv->rsi());

    if (atp->domid == DOMID_SELF || atp->domid == dom->m_id) {
        return dom->m_memory->add_to_physmap(vcpu, atp.get());
    }

    dom = get_xen_domain(atp->domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, atp->domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_memory->add_to_physmap(vcpu, atp.get());
    put_xen_domain(atp->domid);

    return ret;
}

bool xenmem_add_to_physmap_batch(xen_vcpu *vcpu)
{
    auto dom = vcpu->m_xen_dom;
    auto uvv = vcpu->m_uv_vcpu;
    auto atpb = uvv->map_arg<xen_add_to_physmap_batch_t>(uvv->rsi());

    if (atpb->domid == DOMID_SELF || atpb->domid == dom->m_id) {
        return dom->m_memory->add_to_physmap_batch(vcpu, atpb.get());
    }

    dom = get_xen_domain(atpb->domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, atpb->domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_memory->add_to_physmap_batch(vcpu, atpb.get());
    put_xen_domain(atpb->domid);

    return ret;
}

bool xenmem_decrease_reservation(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto rsv = uvv->map_arg<xen_memory_reservation_t>(uvv->rsi());

    expects(rsv->domid == DOMID_SELF);

    return vcpu->m_xen_dom->m_memory->decrease_reservation(vcpu, rsv.get());
}

bool xenmem_claim_pages(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto rsv = uvv->map_arg<xen_memory_reservation_t>(uvv->rsi());

    /* TODO: domid could be DOMID_SELF */
    expects(rsv->domid != DOMID_SELF);
    expects(!rsv->extent_start.p);
    expects(!rsv->extent_order);

    auto dom = get_xen_domain(rsv->domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, rsv->domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_memory->claim_pages(vcpu, rsv.get());
    put_xen_domain(rsv->domid);

    return ret;
}

bool xenmem_populate_physmap(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto rsv = uvv->map_arg<xen_memory_reservation_t>(uvv->rsi());

    expects(rsv->extent_start.p);

    xen_domid_t domid = rsv->domid;
    if (rsv->domid == DOMID_SELF) {
        domid = vcpu->m_xen_dom->m_id;
    }

    auto dom = get_xen_domain(domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_memory->populate_physmap(vcpu, rsv.get());
    put_xen_domain(domid);

    return ret;
}

bool xenmem_remove_from_physmap(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto map = uvv->map_arg<xen_remove_from_physmap_t>(uvv->rsi());

    expects(map->domid == DOMID_SELF);
    return vcpu->m_xen_dom->m_memory->remove_from_physmap(vcpu, map.get());
}

/*
 * This implementation is very similar to acquire_resource in
 * xen/xen/common/memory.c
 */
bool xenmem_acquire_resource(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto res = uvv->map_arg<xen_mem_acquire_resource_t>(uvv->rsi());

    constexpr auto MAX_RESOURCE_PAGES = 32;
    std::array<class page *, MAX_RESOURCE_PAGES> pages{};

    /* Flags must be zero on entry */
    if (res->flags) {
        uvv->set_rax(-EINVAL);
        return true;
    }

    if (!res->frame_list.p) {
        if (res->nr_frames != 0) {
            uvv->set_rax(-EINVAL);
            return true;
        }

        /* Tell the caller the max # frames we can do at a time */
        res->nr_frames = pages.size();
        uvv->set_rax(0);
        return true;
    }

    if (res->nr_frames > pages.size()) {
        uvv->set_rax(-E2BIG);
        return true;
    }

    auto dom = get_xen_domain(res->domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, res->domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    int rc = 0;

    switch (res->type) {
    case XENMEM_resource_grant_table:
        rc = dom->acquire_gnttab_pages(res.get(), pages);
        if (rc) {
            uvv->set_rax(rc);
            bferror_nhex(0, "xenmem: acquire_gnttab failed:", rc);
            put_xen_domain(res->domid);
            return true;
        }
        break;
    case XENMEM_resource_ioreq_server:
        bferror_nhex(0, "xenmem: acquire IOREQ frame:", res->frame);
        put_xen_domain(res->domid);
        return false;
    default:
        printv("xenmem: unsupported resource acquire type: %u\n", res->type);
        put_xen_domain(res->domid);
        uvv->set_rax(-EINVAL);
        return true;
    }

    auto map = uvv->map_gva_4k<xen_pfn_t>(res->frame_list.p, res->nr_frames);
    auto gfn = map.get();
    auto mem = vcpu->m_xen_dom->m_memory.get();

    /* Now we add the pages into the caller's map */
    for (auto i = 0; i < res->nr_frames; i++) {
        mem->add_foreign_page(gfn[i], pg_perm_rw, pg_mtype_wb, pages[i]);
    }

    mem->invept();
    put_xen_domain(res->domid);
    uvv->set_rax(0);

    return true;
}

/* class xen_memory */
xen_memory::xen_memory(xen_domain *dom, class iommu *iommu) :
    m_xen_dom{dom},
    m_ept{&dom->m_uv_dom->ept()}
{
    this->bind_iommu(iommu);
}

void xen_memory::add_ept_handlers(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;

    uvv->add_ept_read_violation_handler({&xen_memory::handle_ept_read, this});
    uvv->add_ept_write_violation_handler({&xen_memory::handle_ept_write, this});
    uvv->add_ept_execute_violation_handler({&xen_memory::handle_ept_exec, this});
}

int xen_memory::back_page(class xen_page *pg)
{
    {
        std::lock_guard lock(root_pool_mtx);

        if (root_pool.size()) {
            class page *page = pg->page;

            page->hfn = root_pool.front();
            page->src = pg_src_root;
            root_pool.pop_front();

            return 0;
        }
    }

    /*
     * N.B. there is a bug in the buddy allocator that causes it to loop
     * forever if there is not enough memory to satisfy a request. Here we only
     * allocate if the # pages is well above 0 because the number could change
     * in between since we aren't taking the allocator's internal lock. This is
     * a TOCTOU problem inherent to the buddy allocator, so we bury our head
     * until it can be properly fixed.
     */

    if (vmm_pool_pages() > 64) {
        class page *page = pg->page;

        page->ptr = g_mm->alloc_page();
        page->hfn = uv_frame(g_mm->virtptr_to_physint(page->ptr));
        page->src = pg_src_vmm;

        return 0;
    } else {
        return -ENOMEM;
    }
}

bool xen_memory::handle_ept_read(base_vcpu *vcpu,
                                 ept_violation_handler::info_t &info)
{
    auto gfn = xen_frame(info.gpa);
    auto pg = this->find_page(gfn);

    if (!pg) {
        printv("EPT read: gfn %p doesnt map to a page\n", (void *)gfn);
        return false;
    }

    if ((pg->perms & pg_perm_r) == 0) {
        printv("EPT read: gfn %p doesnt have read permission\n", (void *)gfn);
        return false;
    }

    if (!pg->backed()) {
        auto err = this->back_page(pg);
        if (err) {
            printv("EPT read: back_page failed for gfn %p\n", (void *)gfn);
            return false;
        } else {
            ensures(pg->backed());
        }
    }

    if (!pg->present) {
        this->map_page(pg);
    }

    return true;
}

bool xen_memory::handle_ept_write(base_vcpu *vcpu,
                                  ept_violation_handler::info_t &info)
{
    auto gfn = xen_frame(info.gpa);
    auto pg = this->find_page(gfn);

    if (!pg) {
        printv("EPT write: gfn %p doesnt map to a page\n", (void *)gfn);
        return false;
    }

    if ((pg->perms & pg_perm_w) == 0) {
        printv("EPT write: gfn %p doesnt have write permission\n", (void *)gfn);
        return false;
    }

    if (!pg->backed()) {
        auto err = this->back_page(pg);
        if (err) {
            printv("EPT read: back_page failed for gfn %p\n", (void *)gfn);
            return false;
        } else {
            ensures(pg->backed());
        }
    }

    if (!pg->present) {
        this->map_page(pg);
    }

    return true;
}

bool xen_memory::handle_ept_exec(base_vcpu *vcpu,
                                 ept_violation_handler::info_t &info)
{
    auto gfn = xen_frame(info.gpa);
    auto pg = this->find_page(gfn);

    if (!pg) {
        printv("EPT exec: gfn %p doesnt map to a page\n", (void *)gfn);
        return false;
    }

    if ((pg->perms & pg_perm_e) == 0) {
        printv("EPT exec: gfn %p doesnt have exec permission\n", (void *)gfn);
        return false;
    }

    if (!pg->backed()) {
        auto err = this->back_page(pg);
        if (err) {
            printv("EPT read: back_page failed for gfn %p\n", (void *)gfn);
            return false;
        } else {
            ensures(pg->backed());
        }
    }

    if (!pg->present) {
        this->map_page(pg);
    }

    return true;
}

void xen_memory::bind_iommu(class iommu *new_iommu)
{
    if (!new_iommu) {
        return;
    }

    if (m_iommu && m_iommu != new_iommu) {
        throw std::runtime_error("xen_memory: only one IOMMU supported");
    }

    m_iommu = new_iommu;

    if (!iommu_snoop_ctl()) {
        return;
    }

    for (const auto &itr : m_page_map) {
        const class xen_page *page = &itr.second;
        if (page->mtype == pg_mtype_uc) {
            continue;
        }

        uint64_t *epte = page->epte;
        expects(epte);

        /* Enable snoop control */
        *epte |= 1UL << 11;

        /* Flush the entry */
        if (iommu_incoherent()) {
            clflush(epte);
        }
    }
}

bool xen_memory::iommu_incoherent() const noexcept
{
    if (m_xen_dom->m_uv_dom->id() == 0) {
        return false;
    }

    if (m_iommu) {
        return !m_iommu->coherent_page_walk();
    } else {
        return true;
    }
}

bool xen_memory::iommu_snoop_ctl() const noexcept
{
    if (m_iommu) {
        return m_iommu->snoop_ctl();
    } else {
        return false;
    }
}

void xen_memory::map_page(class xen_page *pg)
{
    const auto gpa = xen_addr(pg->gfn);
    const auto hpa = xen_addr(pg->page->hfn);
    const bool flush = iommu_incoherent();
    const bool snoop = iommu_snoop_ctl() && pg->mtype != pg_mtype_uc;

    pg->epte = &m_ept->map_4k(gpa, hpa, pg->perms, pg->mtype, flush, snoop);
    pg->present = true;
}

int xen_memory::map_page(xen_pfn_t gfn, uint32_t perms)
{
    auto pg = this->find_page(gfn);
    if (!pg) {
        return -ENXIO;
    }

    if (pg->present) {
        printv("%s: warning: gfn 0x%0lx already present, returning\n",
                __func__, gfn);
        return 0;
    }

    this->map_page(pg);
    return 0;
}

void xen_memory::add_page(xen_pfn_t gfn, uint32_t perms, uint32_t mtype)
{
    expects(m_page_map.count(gfn) == 0);

    auto pg = alloc_unbacked_page();
    m_page_map.try_emplace(gfn, xen_page(gfn, perms, mtype, pg));

    auto xenpg = this->find_page(gfn);
    auto rc = this->back_page(xenpg);
    if (rc) {
        printv("%s: failed to back gfn 0x%lx, rc=%d\n", __func__, gfn, rc);
        return;
    }

    this->map_page(xenpg);
}

/* Add a page with root backing */
void xen_memory::add_root_backed_page(xen_pfn_t gfn, uint32_t perms,
                                      uint32_t mtype, xen_pfn_t hfn,
                                      bool need_map)
{
    expects(m_page_map.count(gfn) == 0);

    auto pg = alloc_root_backed_page(hfn);
    m_page_map.try_emplace(gfn, xen_page(gfn, perms, mtype, pg));

    if (need_map) {
        this->map_page(this->find_page(gfn));
    }
}

/* Add a page with vmm backing */
void xen_memory::add_vmm_backed_page(xen_pfn_t gfn, uint32_t perms,
                                     uint32_t mtype, void *ptr,
                                     bool need_map)
{
    expects(m_page_map.count(gfn) == 0);

    auto pg = alloc_vmm_backed_page(ptr);
    m_page_map.try_emplace(gfn, xen_page(gfn, perms, mtype, pg));

    if (need_map) {
        this->map_page(this->find_page(gfn));
    }
}

/* Add a page from another domain */
void xen_memory::add_foreign_page(xen_pfn_t gfn, uint32_t perms,
                                  uint32_t mtype, class page *fpg)
{
    expects(m_page_map.count(gfn) == 0);

    fpg->refcnt++;
    m_page_map.try_emplace(gfn, xen_page(gfn, perms, mtype, fpg));

    auto xenpg = this->find_page(gfn);
    if (!xenpg->backed()) {
        if (auto rc = this->back_page(xenpg); rc) {
            printv("%s: failed to back foreign page at gfn 0x%lx, rc=%d\n",
                   __func__, gfn, rc);
            return;
        }
    }

    this->map_page(xenpg);
}

/* Add a page already created from this domain */
void xen_memory::add_local_page(xen_pfn_t gfn, uint32_t perms, uint32_t mtype,
                                class page *pg)
{
    expects(m_page_map.count(gfn) == 0);
    m_page_map.try_emplace(gfn, xen_page(gfn, perms, mtype, pg));

    auto xenpg = this->find_page(gfn);
    if (!xenpg->backed()) {
        if (auto rc = this->back_page(xenpg); rc) {
            printv("%s: failed to back local page at gfn 0x%lx, rc=%d\n",
                   __func__, gfn, rc);
            return;
        }
    }

    this->map_page(xenpg);
}

void xen_memory::add_raw_page(xen_pfn_t gfn, uint32_t perms, uint32_t mtype,
                              xen_pfn_t hfn)
{
    expects(m_page_map.count(gfn) == 0);

    auto pg = alloc_raw_page(hfn);
    m_page_map.try_emplace(gfn, xen_page(gfn, perms, mtype, pg));

    this->map_page(this->find_page(gfn));
}

class xen_page *xen_memory::find_page(xen_pfn_t gfn)
{
    auto itr = m_page_map.find(gfn);
    if (itr != m_page_map.end()) {
        return &itr->second;
    }

    return nullptr;
}

bool xen_memory::add_to_physmap(xen_vcpu *vcpu, xen_add_to_physmap_t *atp)
{
    expects(atp->domid == DOMID_SELF || atp->domid == m_xen_dom->m_id);

    if (vcpu->m_uv_vcpu->is_guest_vcpu()) {
        switch (atp->space) {
        case XENMAPSPACE_gmfn_foreign:
            vcpu->m_uv_vcpu->set_rax(-ENOSYS);
            return false;
        case XENMAPSPACE_shared_info:
            vcpu->init_shared_info(atp->gpfn);
            vcpu->m_uv_vcpu->set_rax(0);
            return true;
        case XENMAPSPACE_grant_table:
            return m_xen_dom->m_gnttab->mapspace_grant_table(vcpu, atp);
        default:
            return false;
        }
    }

    if (vcpu->m_uv_vcpu->is_root_vcpu()) {
        switch (atp->space) {
        case XENMAPSPACE_shared_info:
            vcpu->m_xen_dom->init_shared_info(vcpu, atp->gpfn);
            vcpu->m_uv_vcpu->set_rax(0);
            return true;
        case XENMAPSPACE_grant_table:
            return m_xen_dom->m_gnttab->mapspace_grant_table(vcpu, atp);
        default:
            return false;
        }
    }

    printv("%s: ERROR - invalid vcpu type\n", __func__);
    return false;
}

bool xen_memory::add_to_physmap_batch(xen_vcpu *v,
                                      xen_add_to_physmap_batch_t *atpb)
{
    expects(atpb->domid == DOMID_SELF || atpb->domid == m_xen_dom->m_id);
    expects(atpb->space == XENMAPSPACE_gmfn_foreign);
    expects(atpb->size == 1);

    auto uvd = v->m_uv_dom;
    auto uvv = v->m_uv_vcpu;
    auto fpfn = uvv->map_arg<xen_ulong_t>(atpb->idxs.p);
    auto gpfn = uvv->map_arg<xen_pfn_t>(atpb->gpfns.p);

    auto fdomid = atpb->u.foreign_domid;
    auto fdom = get_xen_domain(fdomid);

    if (!fdom) {
        printv("%s: domid 0x%x not found\n", __func__, fdomid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    try {
        auto fmem = fdom->m_memory.get();
        auto pg = fmem->find_page(*fpfn.get());

        if (!pg) {
            put_xen_domain(fdomid);
            uvv->set_rax(-ENXIO);
            return true;
        }

        this->add_foreign_page(*gpfn.get(), pg_perm_rw, pg_mtype_wb, pg->page);
        this->invept();

        uvv->set_rax(0);
        put_xen_domain(fdomid);

        return true;
    } catch (...) {
        uvv->set_rax(-EFAULT);
        put_xen_domain(fdomid);

        return false;
    }
}

void xen_memory::unmap_page(class xen_page *pg)
{
    m_ept->unmap(xen_addr(pg->gfn), iommu_incoherent());
    m_ept->release(xen_addr(pg->gfn), iommu_incoherent());
    pg->present = false;
}

int xen_memory::remove_page(xen_pfn_t gfn, bool need_invept)
{
    expects(m_xen_dom->m_id != DOMID_WINPV);

    auto itr = m_page_map.find(gfn);
    if (GSL_UNLIKELY(itr == m_page_map.end())) {
        printv("%s: gfn 0x%lx doesn't map to page\n", __func__, gfn);
        return -ENXIO;
    }

    auto pg = &itr->second;

    /* Unmap the page from our EPT mmap and drop our reference */
    this->unmap_page(pg);
    pg->page->refcnt--;

    if (need_invept) {
        this->invept();
    }

    /* Free the backing page if no other refs exist */
    if (!pg->page->refcnt) {
        switch (pg->page->src) {
        case pg_src_root:
            free_root_page(pg->page);
            break;
        case pg_src_vmm:
            free_vmm_page(pg->page);
            break;
        case pg_src_none:
            free_unbacked_page(pg->page);
            break;
        case pg_src_raw:
            free_raw_page(pg->page);
            break;
        default:
            printv("%s: unknown page src: %lu\n", __func__, pg->page->src);
            return -EINVAL;
        }
    }

    m_page_map.erase(gfn);
    return 0;
}

void xen_memory::invept() const
{
    m_xen_dom->m_uv_dom->invept();
}

bool xen_memory::decrease_reservation(xen_vcpu *v,
                                      xen_memory_reservation_t *rsv)
{
    auto uvv = v->m_uv_vcpu;
    auto gva = rsv->extent_start.p;
    auto map = uvv->map_gva_4k<xen_pfn_t>(gva, rsv->nr_extents);
    auto gfn = map.get();
    auto nr_done = 0U;

    if (uvv->is_guest_vcpu()) {
        for (auto i = 0U; i < rsv->nr_extents; i++) {
            if (this->remove_page(gfn[i], false)) {
                break;
            }
            nr_done++;
        }

        this->invept();
        uvv->set_rax(nr_done);
    } else {
        expects(v->m_xen_dom->m_id == DOMID_WINPV);
        expects(rsv->nr_extents == 1);
        expects(rsv->extent_order == 9);
        expects(m_ept->is_2m(xen_addr(gfn[0])));

        printv("Scrubbing Windows PV hole at 0x%lx\n", xen_addr(gfn[0]));
        winpv_hole_gfn = gfn[0];
        winpv_hole_size = (2 << 20);

        auto buf = uvv->map_gpa_2m<uint8_t>(xen_addr(gfn[0]));
        memset(buf.get(), 0, winpv_hole_size);

        /*
         * We assume this is from the fdo code in the Windows PV drivers
         * that is creating the hole for various interfaces. If that is
         * the case we should? be able to avoid a TLB shootdown because
         * the memory hasn't been accessed yet.
         */

//        m_ept->unmap(xen_addr(gfn[0]), iommu_incoherent());
//        m_ept->release(xen_addr(gfn[0]), iommu_incoherent());

        nr_done = 1;
        uvv->set_rax(nr_done);
    }

    return true;
}

bool xen_memory::claim_pages(xen_vcpu *v, xen_memory_reservation_t *rsv)
{
    auto uvv = v->m_uv_vcpu;

    if (!rsv->nr_extents) {
        m_xen_dom->m_out_pages = 0;
        uvv->set_rax(0);
        return true;
    }

    expects(!m_xen_dom->m_total_pages);

    /* Compare the requested amount to what we have available */
    uint64_t root_pages = root_frames();
    uint64_t vmm_pages = vmm_pool_pages();
    uint64_t avail = vmm_pages + root_pages;
    uint64_t claim = rsv->nr_extents;

    printv("%s: claimed_pages:%lu root_pages:%lu vmm_pages:%lu\n",
           __func__, claim, root_pages, vmm_pages);

    if (claim > avail) {
        printv("%s: ERROR: can't claim amount requested\n", __func__);
        uvv->set_rax(-ENOMEM);
        return true;
    }

    m_xen_dom->m_out_pages = claim;

    printv("%s: staked %ld pages (%lu MB) (flags=0x%x)\n",
            __func__, claim, (claim * XEN_PAGE_SIZE) >> 20, rsv->mem_flags);

    uvv->set_rax(0);
    return true;
}

bool xen_memory::populate_physmap(xen_vcpu *v, xen_memory_reservation_t *rsv)
{
    auto uvd = m_xen_dom->m_uv_dom;
    auto uvv = v->m_uv_vcpu;
    auto ext = uvv->map_gva_4k<xen_pfn_t>(rsv->extent_start.p, rsv->nr_extents);
    auto pages_per_ext = 1UL << rsv->extent_order;

    if (uvv->is_guest_vcpu()) {
        for (auto i = 0; i < rsv->nr_extents; i++) {
            auto gfn = ext.get()[i];

            for (auto j = 0; j < pages_per_ext; j++) {
                this->add_page(gfn + j, pg_perm_rwe, pg_mtype_wb);
            }
        }

        m_xen_dom->m_total_pages += rsv->nr_extents * pages_per_ext;
        m_xen_dom->m_out_pages -= rsv->nr_extents * pages_per_ext;

        if (m_xen_dom->m_out_pages < 0) {
            m_xen_dom->m_out_pages = 0;
        }

        this->invept();
        uvv->set_rax(rsv->nr_extents);

        return true;
    }

    if (uvv->is_root_vcpu()) {
        expects(m_xen_dom->m_id == DOMID_WINPV);
        expects(rsv->extent_order == 9);
        expects(rsv->nr_extents == 1);
        expects(ext.get()[0] == winpv_hole_gfn);

        printv("Filling Windows PV hole\n");

        int nr_done = 1;
        uvv->set_rax(nr_done);

        return true;
    }

    printv("%s: ERROR invalid vcpu type\n", __func__);
    return false;
}

bool xen_memory::set_memory_map(xen_vcpu *v, xen_foreign_memory_map_t *fmap)
{
    auto uvv = v->m_uv_vcpu;
    auto addr = fmap->map.buffer.p;
    auto size = fmap->map.nr_entries;

    auto e820_map = uvv->map_gva_4k<e820_entry_t>(addr, size);
    auto e820_buf = e820_map.get();
    auto e820_dom = &uvv->dom()->e820();

    auto total_ram = 0UL;

    for (auto i = 0U; i < size; i++) {
        auto entry = &e820_buf[i];

        printv("%s: e820: addr:0x%lx size:%luKB type:%s\n",
                __func__, entry->addr, entry->size >> 12,
                e820_type_str(entry->type));

        e820_dom->push_back(*entry);

        if (entry->type == E820_TYPE_RAM) {
            total_ram += entry->size;
        }
    }

    printv("%s: total RAM: %lu MB\n", __func__, total_ram >> 20);

    uvv->set_rax(0);
    return true;
}

bool xen_memory::remove_from_physmap(xen_vcpu *v, xen_remove_from_physmap_t *rmap)
{
    this->remove_page(rmap->gpfn, true);

    v->m_uv_vcpu->set_rax(0);
    return true;
}
}
