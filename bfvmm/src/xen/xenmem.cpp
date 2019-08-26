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
#include <xen/xenmem.h>
#include <xen/xen.h>

namespace microv {

xenmem::xenmem(xen *xen) : m_xen{xen}, m_vcpu{xen->m_vcpu}
{
}

/* Called from xl create path */
bool xenmem::get_sharing_freed_pages()
{
    m_vcpu->set_rax(0);
    return true;
}

bool xenmem::get_sharing_shared_pages()
{
    m_vcpu->set_rax(0);
    return true;
}

/* Called from boot path */
bool xenmem::memory_map()
{
    auto map = m_vcpu->map_arg<xen_memory_map_t>(m_vcpu->rsi());
    if (map->nr_entries < m_vcpu->dom()->e820().size()) {
        throw std::runtime_error("guest E820 too small");
    }

    auto addr = map->buffer.p;
    auto size = map->nr_entries;

    auto e820 = m_vcpu->map_gva_4k<e820_entry_t>(addr, size);
    auto e820_view = gsl::span<e820_entry_t>(e820.get(), size);

    map->nr_entries = 0;

    for (const auto &entry : m_vcpu->dom()->e820()) {
        e820_view[map->nr_entries].addr = entry.addr;
        e820_view[map->nr_entries].size = entry.size;
        e820_view[map->nr_entries].type = entry.type;

        map->nr_entries++;
    }

    m_vcpu->set_rax(0);
    return true;
}

bool xenmem::add_to_physmap()
{
    auto xatp = m_vcpu->map_arg<xen_add_to_physmap_t>(m_vcpu->rsi());
    if (xatp->domid != DOMID_SELF) {
        m_vcpu->set_rax(-EINVAL);
        return true;
    }

    switch (xatp->space) {
    case XENMAPSPACE_gmfn_foreign:
        m_vcpu->set_rax(-ENOSYS);
        return true;
    case XENMAPSPACE_shared_info:
        m_xen->init_shared_info(xatp.get()->gpfn);
        m_vcpu->set_rax(0);
        return true;
    case XENMAPSPACE_grant_table:
        return m_xen->m_gnttab->mapspace_grant_table(xatp.get());
    default:
        return false;
    }

    return false;
}

bool xenmem::decrease_reservation()
{
    auto arg = m_vcpu->map_arg<xen_memory_reservation_t>(m_vcpu->rsi());

    expects(arg->domid == DOMID_SELF);
    expects(arg->extent_order == 0);

    auto gva = arg->extent_start.p;
    auto len = arg->nr_extents * sizeof(xen_pfn_t);
    auto map = m_vcpu->map_gva_4k<xen_pfn_t>(gva, len);
    auto gfn = map.get();

    for (auto i = 0U; i < arg->nr_extents; i++) {
        auto dom = m_vcpu->dom();
        auto gpa = (gfn[i] << 12);
        dom->unmap(gpa);
        dom->release(gpa);
    }

    m_vcpu->set_rax(arg->nr_extents);
    return true;
}

}
