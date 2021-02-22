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

#ifndef MICROV_XEN_GNTTAB_H
#define MICROV_XEN_GNTTAB_H

#include <unordered_map>
#include "types.h"
#include "../page.h"
#include <public/grant_table.h>
#include <public/memory.h>

namespace microv {

bool xen_gnttab_copy(xen_vcpu *vcpu);
bool xen_gnttab_map_grant_ref(xen_vcpu *vcpu);
bool xen_gnttab_unmap_grant_ref(xen_vcpu *vcpu);
bool xen_gnttab_query_size(xen_vcpu *vcpu);
bool xen_gnttab_set_version(xen_vcpu *vcpu);

class xen_gnttab {

    using shr_v1_gte_t = grant_entry_v1_t;
    using shr_v2_gte_t = grant_entry_v2_t;
    using status_gte_t = grant_status_t;

    static_assert(is_power_of_2(sizeof(shr_v1_gte_t)));
    static_assert(is_power_of_2(sizeof(shr_v2_gte_t)));
    static_assert(is_power_of_2(sizeof(status_gte_t)));

    static constexpr auto shr_v1_gte_per_page = 4096 / sizeof(shr_v1_gte_t);
    static constexpr auto shr_v2_gte_per_page = 4096 / sizeof(shr_v2_gte_t);
    static constexpr auto status_gte_per_page = 4096 / sizeof(status_gte_t);

    static constexpr auto shr_v1_gte_page_shift = log2<shr_v1_gte_per_page>();
    static constexpr auto shr_v2_gte_page_shift = log2<shr_v2_gte_per_page>();
    static constexpr auto status_gte_page_shift = log2<status_gte_per_page>();

    static constexpr uint32_t max_status_gte_pages();

    uint32_t shared_to_status_pages(uint32_t shr_pages) const noexcept;
    uint32_t status_to_shared_pages(uint32_t sts_pages) const noexcept;

    shr_v1_gte_t *shr_v1_entry(grant_ref_t ref);
    shr_v2_gte_t *shr_v2_entry(grant_ref_t ref);

    int grow_pages(uint32_t shr_pages);

    uint32_t version{1};

    xen_domain *xen_dom{};
    xen_memory *xen_mem{};

    /* List of dom pages used to implement XENMEM_acquire_resource */
    std::vector<class page *> shared_rsrc{};
    std::vector<class page *> status_rsrc{};

    /* Page backing for guest domains */
    std::vector<page_ptr<uint8_t>> shared_page{};
    std::vector<page_ptr<status_gte_t>> status_page{};

    /* Map backing for root domains */
    std::vector<unique_map<uint8_t>> shared_map{};
    std::vector<unique_map<status_gte_t>> status_map{};

    /* VMM-accessible tables */
    std::vector<uint8_t *> shared_tab{};
    std::vector<status_gte_t *> status_tab{};

public:
    static constexpr uint32_t max_shared_gte_pages()
    {
        return 64;
    }

    /* Used for debug purposes to ensure maps are unique for a given domain */
    std::unordered_map<grant_handle_t, uint64_t> map_handles{};

    status_gte_t *status_entry(grant_ref_t ref);
    grant_entry_header_t *shared_header(grant_ref_t ref);
    uintptr_t shared_gfn(grant_ref_t ref);

    bool invalid_ref(grant_ref_t ref) const noexcept;
    void dump_shared_entry(grant_ref_t ref);

    int get_page(int tabid, size_t pg_idx, class page **page);
    int get_shared_page(size_t pg_idx, class page **page);
    int get_status_page(size_t pg_idx, class page **page);

    int get_pages(int tabid,
                  size_t pg_idx,
                  size_t count,
                  gsl::span<class page *> pages);
    int get_shared_pages(size_t pg_idx,
                         size_t count,
                         gsl::span<class page *> pages);
    int get_status_pages(size_t pg_idx,
                         size_t count,
                         gsl::span<class page *> pages);

    bool query_size(xen_vcpu *vcpu, gnttab_query_size_t *gqs);
    bool set_version(xen_vcpu *vcpu, gnttab_set_version_t *gsv);
    bool mapspace_grant_table(xen_vcpu *vcpu, xen_add_to_physmap_t *atp);

    xen_gnttab(xen_domain *dom, xen_memory *mem);
    ~xen_gnttab() = default;
    xen_gnttab(xen_gnttab &&) = default;
    xen_gnttab(const xen_gnttab &) = delete;
    xen_gnttab &operator=(xen_gnttab &&) = default;
    xen_gnttab &operator=(const xen_gnttab &) = delete;
};

}
#endif
