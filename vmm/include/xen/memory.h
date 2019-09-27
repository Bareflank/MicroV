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

#ifndef MICROV_XEN_MEMORY_H
#define MICROV_XEN_MEMORY_H

#include "page.h"
#include <public/memory.h>
#include <unordered_map>

namespace microv {

inline constexpr size_t XEN_PAGE_SIZE = 0x1000;
inline constexpr size_t XEN_PAGE_FROM = 12;
inline constexpr xen_pfn_t XEN_INVALID_PFN = ~0;

xen_pfn_t alloc_root_frame();

class page *alloc_unbacked_page();
class page *alloc_root_backed_page(xen_pfn_t hfn);
class page *alloc_vmm_backed_page(void *ptr);
void free_unbacked_page(class page *pg);
void free_root_page(class page *pg);
void free_vmm_page(class page *pg);

bool xenmem_memory_map(xen_vcpu *v);
bool xenmem_set_memory_map(xen_vcpu *v);
bool xenmem_reserved_device_memory_map(xen_vcpu *v);
bool xenmem_add_to_physmap(xen_vcpu *v);
bool xenmem_add_to_physmap_batch(xen_vcpu *v);
bool xenmem_decrease_reservation(xen_vcpu *v);
bool xenmem_claim_pages(xen_vcpu *v);
bool xenmem_populate_physmap(xen_vcpu *v);
bool xenmem_remove_from_physmap(xen_vcpu *v);
bool xenmem_acquire_resource(xen_vcpu *v);

static inline xen_pfn_t xen_frame(uintptr_t addr) noexcept
{
    return addr >> XEN_PAGE_FROM;
}

static inline uintptr_t xen_addr(xen_pfn_t frame) noexcept
{
    return frame << XEN_PAGE_FROM;
}

class xen_memory {
public:
    xen_memory(xen_domain *xen);

    /* EPT handling */
    void add_ept_handlers(xen_vcpu *v);
    bool handle_ept_read(base_vcpu *vcpu, ept_violation_handler::info_t &info);
    bool handle_ept_write(base_vcpu *vcpu, ept_violation_handler::info_t &info);
    bool handle_ept_exec(base_vcpu *vcpu, ept_violation_handler::info_t &info);

    /* Hypercall handlers */
    bool add_to_physmap(xen_vcpu *v, xen_add_to_physmap_t *atp);
    bool add_to_physmap_batch(xen_vcpu *v, xen_add_to_physmap_batch_t *atpb);
    bool decrease_reservation(xen_vcpu *v, xen_memory_reservation_t *rsv);
    bool claim_pages(xen_vcpu *v, xen_memory_reservation_t *rsv);
    bool populate_physmap(xen_vcpu *v, xen_memory_reservation_t *rsv);
    bool set_memory_map(xen_vcpu *v, xen_foreign_memory_map_t *fmap);
    bool remove_from_physmap(xen_vcpu *v, xen_remove_from_physmap_t *rmap);

    /* Page management */
    class xen_page *find_page(xen_pfn_t gfn);
    void add_unbacked_page(xen_pfn_t gfn, uint32_t perms, uint32_t mtype);
    void add_root_backed_page(xen_pfn_t gfn, uint32_t perms, uint32_t mtype,
                              xen_pfn_t hfn);
    void add_vmm_backed_page(xen_pfn_t gfn, uint32_t perms, uint32_t mtype,
                             void *ptr);
    void add_foreign_page(xen_pfn_t gfn, uint32_t perms, uint32_t mtype,
                          class page *fpg);
    void add_local_page(xen_pfn_t gfn, uint32_t perms, uint32_t mtype,
                        class page *pg);

    void map_page(class xen_page *pg);
    void unmap_page(class xen_page *pg);

    int map_page(xen_pfn_t gfn, uint32_t perms);
    int remove_page(xen_pfn_t gfn);
    int back_page(class xen_page *pg);

public:
    xen_domain *m_xen_dom{};
    bfvmm::intel_x64::ept::mmap *m_ept{};
    std::unordered_map<xen_pfn_t, class xen_page> m_page_map;
    bool m_incoherent_iommu{};
    void *m_pages{};
    uintptr_t m_pages_hpa{};
    uintptr_t m_next_hpa{};

public:
    ~xen_memory() = default;
    xen_memory(xen_memory &&) = default;
    xen_memory(const xen_memory &) = delete;
    xen_memory &operator=(xen_memory &&) = default;
    xen_memory &operator=(const xen_memory &) = delete;
};

}
#endif
