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

#ifndef MICROV_XEN_PAGE_H
#define MICROV_XEN_PAGE_H

#include <bftypes.h>
#include <bfvmm/hve/arch/intel_x64/ept/mmap.h>
#include <bfvmm/memory_manager/memory_manager.h>

#include "types.h"
#include "memory.h"
#include "../page.h"

namespace microv {

/* xen_pg_mtype - memory type of a page mapping */
enum xen_pg_mtype : uint64_t {
    pg_mtype_uc = xen_mmap_t::memory_type::uncacheable,
    pg_mtype_wc = xen_mmap_t::memory_type::write_combining,
    pg_mtype_wt = xen_mmap_t::memory_type::write_through,
    pg_mtype_wp = xen_mmap_t::memory_type::write_protected,
    pg_mtype_wb = xen_mmap_t::memory_type::write_back
};

/* xen_pg_perms - access rights to a page */
enum xen_pg_perms : uint64_t {
    pg_perm_none = xen_mmap_t::attr_type::none,
    pg_perm_r = xen_mmap_t::attr_type::read_only,
    pg_perm_w = xen_mmap_t::attr_type::write_only,
    pg_perm_e = xen_mmap_t::attr_type::execute_only,
    pg_perm_rw = xen_mmap_t::attr_type::read_write,
    pg_perm_rwe = xen_mmap_t::attr_type::read_write_execute,
};

class xen_page {
public:
    static constexpr xen_pfn_t invalid_frame = ~0U;

    xen_page(xen_pfn_t gfn,
             uint32_t perms,
             uint32_t mtype,
             class page *pg) noexcept
    {
        this->gfn = gfn;
        this->perms = perms;
        this->mtype = mtype;
        this->page = pg;
    }

    bool mapped_in_vmm() const noexcept
    {
        return page && page->mapped_in_vmm();
    }

    bool backed() const noexcept
    {
        return page && page->backed();
    }

    xen_pfn_t gfn{invalid_frame};
    uint64_t perms{pg_perm_none};
    uint64_t mtype{pg_mtype_wb};
    uint64_t *epte{nullptr};
    class page *page{nullptr};
    bool present{false};
};

}
#endif
