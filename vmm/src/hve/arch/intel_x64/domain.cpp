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

#include <bfdebug.h>
#include <microv/gpalayout.h>
#include <microv/hypercall.h>
#include <microv/builderinterface.h>
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <pci/dev.h>
#include <xen/domain.h>
#include <xen/platform_pci.h>
#include <printv.h>

using namespace bfvmm::intel_x64;
using namespace microv;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace microv::intel_x64
{

/*
 * Note a domain is not a per-cpu structure, but this code is using the EPT
 * capability MSR of the CPU it happens to run on. However the value of this
 * MSR is likely to be the same for each CPU. One way to be certain would be to
 * have each vcpu that belongs to this domain check the value from its CPU
 * against this one.
 */
static uint64_t init_eptp(uint64_t pml4_phys)
{
    expects(pml4_phys);

    using namespace ::intel_x64::msrs::ia32_vmx_ept_vpid_cap;
    const auto ept_caps = get();

    expects(invept_support::is_enabled(ept_caps));
    expects(invept_all_context_support::is_enabled(ept_caps));
    expects(invept_single_context_support::is_enabled(ept_caps));

    using namespace vmcs_n::ept_pointer;
    uint64_t eptp = 0;

    memory_type::set(eptp, memory_type::write_back);
    accessed_and_dirty_flags::disable(eptp);
    page_walk_length_minus_one::set(eptp, 3U);
    phys_addr::set(eptp, pml4_phys);

    return eptp;
}

domain::domain(id_t domainid, struct domain_info *info) :
    microv::domain{domainid}
{
    m_sod_info.copy(info);
    m_eptp = init_eptp(m_ept_map.pml4_phys());

    if (domainid == 0) {
        this->setup_dom0();
    }
    else {
        this->setup_domU();
    }
}

domain::~domain()
{
    if (m_xen_dom) {
        put_xen_domain(m_xen_domid);
        destroy_xen_domain(m_xen_domid);
        m_xen_dom = nullptr;
    }
}

void domain::setup_dom0()
{
    // TODO:
    //
    // This should be changes to fix a couple of issues:
    // - We should calculate the max physical address range using CPUID
    //   and fill in EPT all the way to the end of addressable memory.
    // - We should fill in EPT using 1 gig pages and then when we donate memory
    //   the logic for doing this should be able to handle 1 gig pages.
    // - 1 gig pages should be used because VMWare is not supported anways,
    //   so we should assume that 1 gig page support is required. Once again,
    //   legacy support is not a focus of this project
    //

    ept::identity_map(m_ept_map, MAX_PHYS_ADDR);

    if (g_enable_winpv) {
        m_sod_info.ram = MAX_PHYS_ADDR;
        m_sod_info.origin = domain_info::origin_root;
        m_sod_info.xen_domid = DOMID_WINPV;
        m_sod_info.flags = DOMF_EXEC_XENPVH;

        m_xen_domid = create_xen_domain(this, nullptr);
        m_xen_dom = get_xen_domain(m_xen_domid);

        if (g_disable_xen_pfd) {
            disable_xen_platform_pci();
        } else {
            enable_xen_platform_pci();
        }
    }
}

void domain::setup_domU()
{
    if (m_sod_info.is_xen_dom()) {
        class iommu *iommu{};

        if (m_sod_info.is_ndvm()) {
            for (auto pdev : pci_passthru_list) {
                if (!pdev->is_netdev()) {
                    continue;
                }

                if (!iommu) {
                    iommu = pdev->m_iommu;
                } else {
                    /* Every net device should have the same IOMMU */
                    expects(pdev->m_iommu == iommu);
                }
            }

            if (!iommu) {
                bfalert_info(0, "No passthrough network devices found");
            }
        }

        m_xen_domid = create_xen_domain(this, iommu);
        m_xen_dom = get_xen_domain(m_xen_domid);
    }
}

void
domain::add_e820_entry(uintptr_t base, uintptr_t end, uint32_t type)
{
    struct e820_entry_t ent = { base, end - base, type};
    m_e820.push_back(ent);
}

void
domain::share_root_page(vcpu *root, uint64_t perm, uint64_t mtype)
{
    expects(root->is_root_vcpu());

    auto this_gpa = root->rdx();
    auto root_gpa = root->rcx();
    auto [hpa, from] = root->gpa_to_hpa(root_gpa);

    if (m_sod_info.is_xen_dom()) {
        m_xen_dom->add_root_page(this_gpa, hpa, perm, mtype);
    } else {
        m_ept_map.map_4k(this_gpa, hpa, perm, mtype);
    }
}

static domain::page_range_iterator
find_page_range(domain::page_range_set *range_set, uint64_t page_gpa)
{
    if (range_set->empty()) {
        return range_set->end();
    }

    auto range = range_set->lower_bound(page_gpa);
    if (range == range_set->cbegin()) {
        return range->contains(page_gpa) ? range : range_set->end();
    }

    if (range == range_set->cend()) {
        range = std::prev(range);
        return range->contains(page_gpa) ? range : range_set->end();
    }

    if (range->contains(page_gpa)) {
        return range;
    }

    range = std::prev(range);
    return range->contains(page_gpa) ? range : range_set->end();
}

static void
extend_page_range_above(domain::page_range_iterator &range)
{
    auto range_ptr = (page_range *)&(*range);

    range_ptr->m_page_count++;
}

static void
extend_page_range_below(domain::page_range_iterator &range)
{
    auto range_ptr = (page_range *)&(*range);

    range_ptr->m_page_start -= UV_PAGE_SIZE;
    range_ptr->m_page_count++;
}

bool
domain::page_already_donated(domainid_t guest_domid, uint64_t page_gpa)
{
    auto itr = m_donated_page_map.find(guest_domid);
    if (itr == m_donated_page_map.end()) {
        return false;
    }

    auto range_set = itr->second.get();

    return find_page_range(range_set, page_gpa) != range_set->end();
}

void
domain::add_page_to_donated_range(domainid_t guest_domid, uint64_t page_gpa)
{
    auto itr = m_donated_page_map.find(guest_domid);
    if (itr == m_donated_page_map.end()) {
        m_donated_page_map[guest_domid] = std::make_unique<page_range_set>();
        itr = m_donated_page_map.find(guest_domid);
    }

    auto range_set = itr->second.get();
    if (range_set->empty()) {
        range_set->emplace(page_gpa, 1);
        return;
    }

    auto range = range_set->lower_bound(page_gpa);
    if (range == range_set->end()) {
        range = std::prev(range);

        if (range->contiguous_below(page_gpa)) {
            extend_page_range_above(range);
            return;
        }

        range_set->emplace_hint(range, page_gpa, 1);
        return;
    }

    if (range->contiguous_above(page_gpa)) {
        extend_page_range_below(range);
        return;
    }

    if (range != range_set->begin()) {
        range = std::prev(range);

        if (range->contiguous_below(page_gpa)) {
            extend_page_range_above(range);
            return;
        }
    }

    range_set->emplace_hint(range, page_gpa, 1);
    return;
}

void
domain::remove_page_from_donated_range(domainid_t guest_domid, uint64_t page_gpa)
{
    auto itr = m_donated_page_map.find(guest_domid);
    if (itr == m_donated_page_map.end()) {
        return;
    }

    auto range_set = itr->second.get();
    auto range = find_page_range(range_set, page_gpa);

    if (range == range_set->end()) {
        return;
    }

    if (range->top_page(page_gpa)) {
        if (range->count() == 1) {
            range_set->erase(range);
            return;
        }

        auto range_ptr = (page_range *)&(*range);
        range_ptr->m_page_count--;

        return;
    }

    if (range->middle_page(page_gpa)) {
        uint64_t upper_start = page_gpa + UV_PAGE_SIZE;
        uint64_t upper_count = (range->limit() - upper_start) >> UV_PAGE_FROM;

        uint64_t lower_start = range->start();
        uint64_t lower_count = (page_gpa - lower_start) >> UV_PAGE_FROM;

        range = range_set->erase(range);
        range = range_set->emplace_hint(range, upper_start, upper_count);
        range_set->emplace_hint(range, lower_start, lower_count);

        return;
    }

    if (range->bottom_page(page_gpa)) {
        if (range->count() == 1) {
            range_set->erase(range);
            return;
        }

        auto range_ptr = (page_range *)&(*range);

        range_ptr->m_page_start += UV_PAGE_SIZE;
        range_ptr->m_page_count--;

        return;
    }
}

int64_t
domain::donate_root_page(vcpu *root,
                         uint64_t root_gpa,
                         domain *guest_dom,
                         uint64_t guest_gpa,
                         uint64_t perm,
                         uint64_t mtype)
{
    expects(this->id() == 0);

    int64_t rc = SUCCESS;

    auto root_gpa_2m = bfn::upper(root_gpa, ::x64::pd::from);
    auto root_gpa_4k = bfn::upper(root_gpa, ::x64::pt::from);

    if (!this->page_already_donated(guest_dom->id(), root_gpa_4k)) {
        try {
            auto [hpa, from] = root->gpa_to_hpa(root_gpa_4k);
            expects(hpa == root_gpa_4k);

            rc = root->begin_tlb_shootdown();
            if (rc == AGAIN) {
                return AGAIN;
            }

            if (from == ::x64::pd::from) {
                identity_map_convert_2m_to_4k(this->ept(), root_gpa_2m);
            }

            this->unmap(root_gpa_4k);
            root->end_tlb_shootdown();
            root->invept();

            this->add_page_to_donated_range(guest_dom->id(), root_gpa_4k);

        } catch (std::exception &e) {
            printv("%s: failed to get hpa @ gpa=0x%lx, what=%s\n",
                   __func__, root_gpa_4k, e.what());
            return FAILURE;
        }
    }

    if (guest_dom->is_xen_dom()) {
        guest_dom->xen_dom()->add_root_page(guest_gpa, root_gpa_4k, perm, mtype);
    } else {
        guest_dom->ept().map_4k(guest_gpa, root_gpa_4k, perm, mtype);
    }

    return SUCCESS;
}

int64_t
domain::reclaim_root_page(domainid_t guest_domid, uint64_t root_gpa)
{
    /* Pages cant be reclaimed while the guest is still alive */
    if (get_domain(guest_domid) != nullptr) {
        return FAILURE;
    }

    auto root_gpa_4k = bfn::upper(root_gpa, ::x64::pt::from);

    if (!this->page_already_donated(guest_domid, root_gpa_4k)) {
        return FAILURE;
    }

    /*
     * It is assumed that every donated page was previously mapped as
     * write-back and RWE. It is also expects()'d in donate_root_page that the
     * donation is identity mapped in the root. All of that information is
     * used here.
     *
     * Also note that no TLB invalidation is needed because donate_root_page
     * marks the page as not present, and the CPU does not populate TLB
     * entries of non-present pages.
     */

    this->remove_page_from_donated_range(guest_domid, root_gpa_4k);
    this->map_4k_rwe(root_gpa_4k, root_gpa_4k);

    return SUCCESS;
}

int64_t
domain::reclaim_root_pages(domainid_t guest_domid)
{
    /* Reclaim must happen by the root itself */
    if (this->id() != 0) {
        return FAILURE;
    }

    /* Pages cant be reclaimed while the guest is still alive */
    if (get_domain(guest_domid) != nullptr) {
        return FAILURE;
    }

    auto itr = m_donated_page_map.find(guest_domid);
    if (itr == m_donated_page_map.end()) {
        return FAILURE;
    }

    for (const auto &range : *itr->second.get()) {
        const auto start = range.start();
        const auto limit = range.limit();

        for (auto gpa = start; gpa < limit; gpa += UV_PAGE_SIZE) {
            this->map_4k_rwe(gpa, gpa);
        }
    }

    m_donated_page_map.erase(itr);

    return SUCCESS;
}

void
domain::map_1g_r(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_only); }

void
domain::map_2m_r(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_only); }

void
domain::map_4k_r(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_only); }

void
domain::map_1g_rw(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_write); }

void
domain::map_2m_rw(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_write); }

void
domain::map_4k_rw(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_write); }

void
domain::map_4k_rw_uc(uintptr_t gpa, uintptr_t hpa)
{
    m_ept_map.map_4k(gpa, hpa,
                     ept::mmap::attr_type::read_write,
                     ept::mmap::memory_type::uncacheable);
}

void
domain::map_1g_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::map_2m_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::map_4k_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::unmap(uintptr_t gpa)
{ m_ept_map.unmap(gpa); }

void
domain::release(uintptr_t gpa)
{ m_ept_map.release(gpa); }

uint64_t
domain::exec_mode() const noexcept
{
    if (m_sod_info.flags & DOMF_EXEC_XENPVH) {
        return VM_EXEC_XENPVH;
    }

    return VM_EXEC_NATIVE;
}

void
domain::set_uart(uart::port_type uart) noexcept
{ m_uart_port = uart; }

void
domain::set_pt_uart(uart::port_type uart) noexcept
{ m_pt_uart_port = uart; }

void
domain::setup_vcpu_uarts(gsl::not_null<vcpu *> vcpu)
{
    // Note:
    //
    // We explicitly disable the 4 default com ports. This is because the
    // Linux guest will attempt to probe these ports so they need to be
    // handled by something.
    //

    m_uart_3F8.disable(vcpu);
    m_uart_2F8.disable(vcpu);
    m_uart_3E8.disable(vcpu);
    m_uart_2E8.disable(vcpu);

    if (m_pt_uart_port == 0) {
        switch (m_uart_port) {
            case 0x3F8: m_uart_3F8.enable(vcpu); break;
            case 0x2F8: m_uart_2F8.enable(vcpu); break;
            case 0x3E8: m_uart_3E8.enable(vcpu); break;
            case 0x2E8: m_uart_2E8.enable(vcpu); break;

            default:
                break;
        };
    }
    else {
        m_pt_uart = std::make_unique<uart>(m_pt_uart_port);
        m_pt_uart->pass_through(vcpu);
    }
}

uint64_t
domain::dump_uart(const gsl::span<char> &buffer)
{
    if (m_pt_uart) {
        m_pt_uart->dump(buffer);
    }
    else {
        switch (m_uart_port) {
            case 0x3F8: return m_uart_3F8.dump(buffer);
            case 0x2F8: return m_uart_2F8.dump(buffer);
            case 0x3E8: return m_uart_3E8.dump(buffer);
            case 0x2E8: return m_uart_2E8.dump(buffer);

            default:
                break;
        };
    }

    return 0;
}

#define domain_reg(reg)                                                         \
    uint64_t                                                                    \
    domain::reg() const noexcept                                                \
    { return m_ ## reg; }

#define domain_set_reg(reg)                                                     \
    void                                                                        \
    domain::set_ ## reg(uint64_t val) noexcept                                  \
    { m_ ## reg = val; }

domain_reg(rax);
domain_set_reg(rax);
domain_reg(rbx);
domain_set_reg(rbx);
domain_reg(rcx);
domain_set_reg(rcx);
domain_reg(rdx);
domain_set_reg(rdx);
domain_reg(rbp);
domain_set_reg(rbp);
domain_reg(rsi);
domain_set_reg(rsi);
domain_reg(rdi);
domain_set_reg(rdi);
domain_reg(r08);
domain_set_reg(r08);
domain_reg(r09);
domain_set_reg(r09);
domain_reg(r10);
domain_set_reg(r10);
domain_reg(r11);
domain_set_reg(r11);
domain_reg(r12);
domain_set_reg(r12);
domain_reg(r13);
domain_set_reg(r13);
domain_reg(r14);
domain_set_reg(r14);
domain_reg(r15);
domain_set_reg(r15);
domain_reg(rip);
domain_set_reg(rip);
domain_reg(rsp);
domain_set_reg(rsp);
domain_reg(gdt_base);
domain_set_reg(gdt_base);
domain_reg(gdt_limit);
domain_set_reg(gdt_limit);
domain_reg(idt_base);
domain_set_reg(idt_base);
domain_reg(idt_limit);
domain_set_reg(idt_limit);
domain_reg(cr0);
domain_set_reg(cr0);
domain_reg(cr3);
domain_set_reg(cr3);
domain_reg(cr4);
domain_set_reg(cr4);
domain_reg(ia32_efer);
domain_set_reg(ia32_efer);
domain_reg(ia32_pat);
domain_set_reg(ia32_pat);

domain_reg(es_selector);
domain_set_reg(es_selector);
domain_reg(es_base);
domain_set_reg(es_base);
domain_reg(es_limit);
domain_set_reg(es_limit);
domain_reg(es_access_rights);
domain_set_reg(es_access_rights);
domain_reg(cs_selector);
domain_set_reg(cs_selector);
domain_reg(cs_base);
domain_set_reg(cs_base);
domain_reg(cs_limit);
domain_set_reg(cs_limit);
domain_reg(cs_access_rights);
domain_set_reg(cs_access_rights);
domain_reg(ss_selector);
domain_set_reg(ss_selector);
domain_reg(ss_base);
domain_set_reg(ss_base);
domain_reg(ss_limit);
domain_set_reg(ss_limit);
domain_reg(ss_access_rights);
domain_set_reg(ss_access_rights);
domain_reg(ds_selector);
domain_set_reg(ds_selector);
domain_reg(ds_base);
domain_set_reg(ds_base);
domain_reg(ds_limit);
domain_set_reg(ds_limit);
domain_reg(ds_access_rights);
domain_set_reg(ds_access_rights);
domain_reg(fs_selector);
domain_set_reg(fs_selector);
domain_reg(fs_base);
domain_set_reg(fs_base);
domain_reg(fs_limit);
domain_set_reg(fs_limit);
domain_reg(fs_access_rights);
domain_set_reg(fs_access_rights);
domain_reg(gs_selector);
domain_set_reg(gs_selector);
domain_reg(gs_base);
domain_set_reg(gs_base);
domain_reg(gs_limit);
domain_set_reg(gs_limit);
domain_reg(gs_access_rights);
domain_set_reg(gs_access_rights);
domain_reg(tr_selector);
domain_set_reg(tr_selector);
domain_reg(tr_base);
domain_set_reg(tr_base);
domain_reg(tr_limit);
domain_set_reg(tr_limit);
domain_reg(tr_access_rights);
domain_set_reg(tr_access_rights);
domain_reg(ldtr_selector);
domain_set_reg(ldtr_selector);
domain_reg(ldtr_base);
domain_set_reg(ldtr_base);
domain_reg(ldtr_limit);
domain_set_reg(ldtr_limit);
domain_reg(ldtr_access_rights);
domain_set_reg(ldtr_access_rights);

}
