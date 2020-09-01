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

#include <list>
#include <memory>
#include <errno.h>

#include <arch/x64/cache.h>
#include <acpi.h>
#include <microv/acpi.h>
#include <iommu/dmar.h>
#include <iommu/iommu.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/domain.h>
#include <pci/dev.h>
#include <printv.h>

extern microv::intel_x64::vcpu *vcpu0;
using namespace bfvmm::x64;
using namespace bfvmm::intel_x64;

namespace microv {

static struct acpi_table *dmar{};
static bfvmm::x64::unique_map<char> dmar_map{};
static std::list<std::unique_ptr<class iommu>> iommu_list;
static std::list<class iommu *> iommu_view;
static uint32_t iommu_count{0};
static uint32_t rmrr_count{0};

static void make_iommus(const struct acpi_table *dmar)
{
    auto drs = dmar_map.get() + drs_offset;
    auto end = dmar_map.get() + dmar->len;

    while (drs < end) {
        /* Read the type and size of the DMAR remapping structure */
        auto drs_hdr = reinterpret_cast<struct drs_hdr *>(drs);

        /* Compliant firmware enumerates DRHDs before anything else */
        expects(drs_hdr->type == drs_drhd);

        auto drhd = reinterpret_cast<struct drhd *>(drs);
        auto iommu = std::make_unique<class iommu>(drhd, iommu_count);

        iommu_count++;
        iommu_view.push_back(iommu.get());
        iommu_list.push_back(std::move(iommu));

        /*
         * Compliant firmware places the INCLUDE_PCI_ALL DRHD at the
         * end of the DRHD list, so we can return when we reach it.
         */
        if (drhd->flags & DRHD_FLAG_PCI_ALL) {
            return;
        }

        drs += drs_hdr->length;
    }
}

void parse_rmrrs(const struct acpi_table *dmar)
{
    auto drs = dmar_map.get() + drs_offset;
    auto end = dmar_map.get() + dmar->len;

    while (drs < end) {
        /* Read the type and size of the DMAR remapping structure */
        auto drs_hdr = reinterpret_cast<const struct drs_hdr *>(drs);

        /* Skip over non-RMRR structures */
        if (drs_hdr->type != drs_rmrr) {
            drs += drs_hdr->length;
            continue;
        }

        auto rmrr = reinterpret_cast<const struct rmrr *>(drs);
        printv("rmrr[%u]: 0x%lx-0x%lx, segment 0x%04x, scopes ", rmrr_count,
               rmrr->base, rmrr->limit, rmrr->seg_nr);

        rmrr_count++;

        const auto rmrr_len = rmrr->hdr.length;
        const auto rmrr_end = drs + rmrr_len;

        /* Get the address of the first device scope */
        auto ds = drs + sizeof(*rmrr);
        uint64_t dev_count = 0;

        /* Iterate over each device scope */
        while (ds + sizeof(struct dmar_devscope) < rmrr_end) {
            auto scope = reinterpret_cast<struct dmar_devscope *>(ds);
            if (ds + scope->length > rmrr_end) {
                break;
            }

            auto path_len = (scope->length - sizeof(*scope)) / 2;
            auto path = reinterpret_cast<struct dmar_devscope_path *>(
                            ds + sizeof(*scope));

            auto bus = scope->start_bus;
            auto dev = path[0].dev;
            auto fun = path[0].fun;

            for (auto i = 1; i < path_len; i++) {
                const auto addr = pci_cfg_bdf_to_addr(bus, dev, fun);
                const auto reg6 = pci_cfg_read_reg(addr, 6);

                bus = pci_bridge_sec_bus(reg6);
                dev = path[i].dev;
                fun = path[i].fun;
            }

            auto str = dmar_devscope_type_str(scope->type);

            if (dev_count == 0) {
                printf("%02x:%02x.%1x (%s)", bus, dev, fun, str);
            } else {
                printf(", %02x:%02x.%1x (%s)", bus, dev, fun, str);
            }

            auto addr = pci_cfg_bdf_to_addr(bus, dev, fun);
            auto pdev = find_passthru_dev(addr);

            if (pdev) {
                printf(" disabling passthrough");
                pdev->m_passthru_dev = false;
                remove_passthru_dev(pdev);
            }

            dev_count++;
            ds += scope->length;
        }

        printf("\n");
        drs += rmrr_len;
    }
}

void init_vtd()
{
    dmar = find_acpi_table("DMAR");
    if (!dmar) {
        bferror_info(0, "init_vtd: DMAR not found");
        return;
    }
    dmar_map = vcpu0->map_gpa_4k<char>(dmar->gpa, dmar->len);

    if (memcmp(dmar_map.get(), "DMAR", 4)) {
        bferror_info(0, "init_vtd: Invalid DMAR signature");
        return;
    }

    hide_acpi_table(dmar);
    make_iommus(dmar);
    parse_rmrrs(dmar);
}

void iommu_dump()
{
    for (const auto iommu : iommu_view) {
        iommu->ack_faults();
    }
}

void iommu::map_regs_into_vmm()
{
    auto base_hpa = vcpu0->gpa_to_hpa(m_drhd->base_gpa).first;
    auto base_hva = g_mm->alloc_map(UV_PAGE_SIZE);

    // We dont use the map_gpa_4k interface because the registers need
    // to be mapped uncacheable

    g_cr3->map_4k(base_hva,
                  base_hpa,
                  cr3::mmap::attr_type::read_write,
                  cr3::mmap::memory_type::uncacheable);

    m_reg_hva = reinterpret_cast<uintptr_t>(base_hva);
    m_cap = this->read64(cap_offset);
    m_ecap = this->read64(ecap_offset);

    m_frcd_reg_off = ((m_cap & cap_fro_mask) >> cap_fro_from) << 4;
    m_frcd_reg_num = ((m_cap & cap_nfr_mask) >> cap_nfr_from) + 1;
    m_frcd_reg_bytes = m_frcd_reg_num * frcd_reg_len;
    m_iotlb_reg_off = ((m_ecap & ecap_iro_mask) >> ecap_iro_from) << 4;

    uint64_t ioreg_end = m_reg_hva + m_iotlb_reg_off + iotlb_reg_bytes - 1;
    uint64_t frreg_end = m_reg_hva + m_frcd_reg_off + m_frcd_reg_bytes - 1;
    uint64_t max_end = 0;

    if (ioreg_end >= frreg_end) {
        max_end = ioreg_end;
    } else {
        max_end = frreg_end;
    }

    uint64_t max_end_4k = bfn::upper(max_end, ::x64::pt::from);
    m_reg_page_count = 1 + ((max_end_4k - m_reg_hva) >> UV_PAGE_FROM);

    if (m_reg_page_count > 1) {
        // The registers span multiple pages. Note that footnote 1 under section
        // 10.4 in the VT-d spec states that the register pages will be
        // contiguous, so we just need to make the map bigger.

        g_cr3->unmap(m_reg_hva);
        ::x64::tlb::invlpg(m_reg_hva);
        g_mm->free_map(reinterpret_cast<void *>(m_reg_hva));

        uint64_t size = UV_PAGE_SIZE * m_reg_page_count;

        base_hva = g_mm->alloc_map(size);
        m_reg_hva = reinterpret_cast<uintptr_t>(base_hva);

        for (auto i = 0UL; i < size; i += UV_PAGE_SIZE) {
            g_cr3->map_4k(m_reg_hva + i,
                          vcpu0->gpa_to_hpa(m_drhd->base_gpa + i).first,
                          cr3::mmap::attr_type::read_write,
                          cr3::mmap::memory_type::uncacheable);
        }
    }

    printv("iommu[%u]: mapped registers at 0x%lx-0x%lx\n",
           m_id,
           m_drhd->base_gpa,
           m_drhd->base_gpa + (m_reg_page_count * UV_PAGE_SIZE) - 1);
}

void iommu::unmap_regs_from_root_dom()
{
    using namespace bfvmm::intel_x64::ept;

    auto root_dom = vcpu0->dom();
    auto root_ept = &root_dom->ept();
    auto regs_2m = bfn::upper(m_drhd->base_gpa, ::x64::pd::from);

    if (root_ept->is_2m(regs_2m)) {
        identity_map_convert_2m_to_4k(*root_ept, regs_2m);
    }

    auto size = m_reg_page_count * UV_PAGE_SIZE;

    for (auto i = 0U; i < size; i += UV_PAGE_SIZE) {
        root_dom->unmap(m_drhd->base_gpa + i);
    }

    for (auto i = 0U; i < size; i += UV_PAGE_SIZE) {
        root_dom->release(m_drhd->base_gpa + i);
    }
}

void iommu::init_regs()
{
    m_ver = this->read32(ver_offset);

    m_did_bits = (uint8_t)(4 + ((m_cap & cap_nd_mask) << 1));
    m_mgaw = ((m_cap & cap_mgaw_mask) >> cap_mgaw_from) + 1;
    m_sagaw = ((m_cap & cap_sagaw_mask) >> cap_sagaw_from);

    /* Ensure 4-level paging is supported since EPT uses 4-level */
    expects(m_sagaw & 0x4);
    m_aw = 2;

    /* CM = 1 is not supported right now */
    ensures(((m_cap & cap_cm_mask) >> cap_cm_from) == 0);

    /* Required write-buffer flushing is not supported */
    ensures(((m_cap & cap_rwbf_mask) >> cap_rwbf_from) == 0);

    m_psi_supported = ((m_cap & cap_psi_mask) >> cap_psi_from) == 1U;
    m_max_slpg_size = (m_cap & cap_sllps_mask) >> cap_sllps_from;

    printv("iommu[%u]: supported second-level page sizes: 4KB %s %s\n",
           m_id,
           (m_max_slpg_size > 0) ? "2MB" : "",
           (m_max_slpg_size > 2) ? "1GB" : "");

    if (m_psi_supported) {
        m_mamv = ((m_cap & cap_mamv_mask) >> cap_mamv_from);
        printv("iommu[%u]: page-selective invalidation supported (mamv=%u)\n",
               m_id, m_mamv);
    } else {
        m_mamv = 0;
        printv("iommu[%u]: page-selective invalidation not supported\n", m_id);
    }

    if (this->snoop_ctl()) {
        printv("iommu[%u]: snoop control supported\n", m_id);
    } else {
        printv("iommu[%u]: snoop control not supported\n", m_id);
    }

    if (this->coherent_page_walk()) {
        printv("iommu[%u]: coherent page walk supported\n", m_id);
    } else {
        printv("iommu[%u]: coherent page walk not supported\n", m_id);
    }
}

void iommu::bind_device(struct pci_dev *pdev)
{
    pdev->m_iommu = this;
    m_pci_devs.push_back(pdev);
}

void iommu::bind_bus(uint32_t b)
{
    for (uint32_t d = 0; d < pci_nr_dev; d++) {
        for (uint32_t f = 0; f < pci_nr_fun; f++) {
            auto cf8 = pci_cfg_bdf_to_addr(b, d, f);
            auto itr = pci_map.find(cf8);

            if (itr == pci_map.end()) {
                continue;
            }

            auto pdev = itr->second.get();
            this->bind_device(pdev);

            if (pdev->is_pci_bridge()) {
                auto reg6 = pci_cfg_read_reg(cf8, 6);
                auto secondary = pci_bridge_sec_bus(reg6);
                auto subordinate = pci_bridge_sub_bus(reg6);

                for (auto next = secondary; next <= subordinate; next++) {
                    this->bind_bus(next);
                }
            }
        }
    }
}

void iommu::bind_devices()
{
    m_scope_all = (m_drhd->flags & DRHD_FLAG_PCI_ALL) != 0;

    if (!m_scope_all) {
        auto drhd_end = reinterpret_cast<uint8_t *>(m_drhd) +
                        m_drhd->hdr.length;

        /* First device scope entry */
        uint8_t *ds = reinterpret_cast<uint8_t *>(m_scope);

        /* Iterate over each device scope */
        while (ds + sizeof(struct dmar_devscope) < drhd_end) {
            auto scope = reinterpret_cast<struct dmar_devscope *>(ds);
            if (ds + scope->length > drhd_end) {
                break;
            }

            auto path_len = (scope->length - sizeof(*scope)) / 2;
            auto path = reinterpret_cast<struct dmar_devscope_path *>(
                            ds + sizeof(*scope));

            auto bus = scope->start_bus;
            auto dev = path[0].dev;
            auto fun = path[0].fun;

            for (auto i = 1; i < path_len; i++) {
                const auto addr = pci_cfg_bdf_to_addr(bus, dev, fun);
                const auto reg6 = pci_cfg_read_reg(addr, 6);

                bus = pci_bridge_sec_bus(reg6);
                dev = path[i].dev;
                fun = path[i].fun;
            }

            for (auto pdev : pci_list) {
                if (pdev->m_iommu) {
                    continue;
                }

                const auto addr = pci_cfg_bdf_to_addr(bus, dev, fun);
                if (pdev->matches(addr)) {
                    this->bind_device(pdev);

                    if (scope->type == ds_pci_subhierarchy) {
                        expects(pdev->is_pci_bridge());
                        const auto reg6 = pci_cfg_read_reg(addr, 6);
                        this->bind_bus(pci_bridge_sec_bus(reg6));
                    }
                }
            }

            ds += scope->length;
        }

        ensures(!m_pci_devs.empty());
    } else {
        for (auto pdev : pci_list) {
            if (pdev->m_iommu) {
                continue;
            }
            this->bind_device(pdev);
        }
    }
}

void iommu::dump_devices()
{
    printv("iommu[%u]: scopes %lu devices:\n", m_id, m_pci_devs.size());

    for (const auto pdev : m_pci_devs) {
        printv("iommu[%u]:  %s\n", m_id, pdev->bdf_str());
    }
}

static void dump_caps(uint32_t id, uint64_t caps)
{
    printv("iommu[%u]: caps -> afl:%lu rwbf:%lu plmr:%lu phmr:%lu cm:%lu"
           " sagaw:0x%lx mgaw:%lu zlr:%lu psi:%lu dwd:%lu drd:%lu pi:%lu\n",
           id,
           (caps & cap_afl_mask) >> cap_afl_from,
           (caps & cap_rwbf_mask) >> cap_rwbf_from,
           (caps & cap_plmr_mask) >> cap_plmr_from,
           (caps & cap_phmr_mask) >> cap_phmr_from,
           (caps & cap_cm_mask) >> cap_cm_from,
           (caps & cap_sagaw_mask) >> cap_sagaw_from,
           ((caps & cap_mgaw_mask) >> cap_mgaw_from) + 1,
           (caps & cap_zlr_mask) >> cap_zlr_from,
           (caps & cap_psi_mask) >> cap_psi_from,
           (caps & cap_dwd_mask) >> cap_dwd_from,
           (caps & cap_drd_mask) >> cap_drd_from,
           (caps & cap_pi_mask) >> cap_pi_from);
}

static void dump_ecaps(uint32_t id, uint64_t ecaps)
{
    printv("iommu[%u]: ecaps -> c:%lu qi:%lu dt:%lu ir:%lu pt:%lu sc:%lu"
           " nest:%lu pasid:%lu smts:%lu\n",
           id,
           (ecaps & ecap_c_mask) >> ecap_c_from,
           (ecaps & ecap_qi_mask) >> ecap_qi_from,
           (ecaps & ecap_dt_mask) >> ecap_dt_from,
           (ecaps & ecap_ir_mask) >> ecap_ir_from,
           (ecaps & ecap_pt_mask) >> ecap_pt_from,
           (ecaps & ecap_sc_mask) >> ecap_sc_from,
           (ecaps & ecap_nest_mask) >> ecap_nest_from,
           (ecaps & ecap_pasid_mask) >> ecap_pasid_from,
           (ecaps & ecap_smts_mask) >> ecap_smts_from);
}

#define FSTS_FRI (0xFF00UL)
#define FSTS_ERR (0x7FUL)
#define FSTS_PPF (1UL << 1)

#define FRCD_F (1UL << 63)
#define FRCD_T1 (1UL << 62)
#define FRCD_T2 (1UL << 28)
#define FRCD_FR (0xFFUL << 32)
#define FRCD_BUS (0xFF00UL)
#define FRCD_DEV (0x00F8UL)
#define FRCD_FUN (0x0007UL)

static inline const char *fault_name(int t1t2)
{
    switch (t1t2) {
    case 0:
        return "write";
    case 1:
        return "page";
    case 2:
        return "read";
    case 3:
        return "atomicop";
    default:
        return "UNKNOWN";
    }
}

void iommu::ack_faults()
{
    if (!m_reg_hva) {
        return;
    }

    auto fsts = this->read32(fsts_offset);

    /* Check the first byte for any error indicators, return if 0 */
    if ((fsts & FSTS_ERR) == 0) {
        return;
    }

    /* Dump primary pending faults */
    if (fsts & FSTS_PPF) {
        /* Grab the head of the fault record queue */
        auto fri = (fsts & FSTS_FRI) >> 8;
        expects(fri < m_frcd_reg_num);

        auto frcd_base = (struct iommu_entry *)(m_reg_hva + m_frcd_reg_off);
        volatile auto frcd = &frcd_base[fri];

        /* Process each fault record */
        while (frcd->data[1] & FRCD_F) {
            auto bus = (frcd->data[1] & FRCD_BUS) >> 8;
            auto dev = (frcd->data[1] & FRCD_DEV) >> 3;
            auto fun = (frcd->data[1] & FRCD_FUN);
            auto t1 = (frcd->data[1] & FRCD_T1) >> 62;
            auto t2 = (frcd->data[1] & FRCD_T2) >> 28;
            auto reason = (frcd->data[1] & FRCD_FR) >> 32;
            auto addr = frcd->data[0];
            const char *str = fault_name((t1 << 1) | t2);

            printv("iommu[%u]: fault: %02lx:%02lx.%1lx addr:0x%lx reason:0x%lx (%s)\n",
                   m_id, bus, dev, fun, addr, reason, str);

            /* Ack the fault */
            frcd->data[1] |= FRCD_F;

            /* Update the index in circular fashion */
            fri = (fri == m_frcd_reg_num - 1) ? 0 : fri + 1;
            frcd = &frcd_base[fri];
        }
    }

    if (fsts & 0xFC) {
        printv("iommu[%u]: unsupported errors pending: fsts=%x",
               m_id, fsts);
    }

    /* Ack all faults */
    this->write32(fsts_offset, fsts);
}

void iommu::map_bdf(uint32_t bus, uint32_t devfn, dom_t *dom)
{
    expects(bus < table_size);
    expects(devfn < table_size);
    expects(this->did(dom) < nr_domains());

    entry_t *ctx_hva = nullptr;
    uintptr_t ctx_hpa = 0;

    auto itr = m_bdf_ctxt_map.find(bus);
    if (itr == m_bdf_ctxt_map.end()) {
        m_bdf_ctxt_map.insert({bus, make_page<entry_t>()});
        itr = m_bdf_ctxt_map.find(bus);
        ctx_hva = itr->second.get();
        ctx_hpa = g_mm->virtptr_to_physint(ctx_hva);

        this->clflush_range(ctx_hva, UV_PAGE_SIZE);
    } else {
        ctx_hva = itr->second.get();
        ctx_hpa = rte_ctp(&m_root.get()[bus]);
    }

    ensures(ctx_hva);
    ensures(ctx_hpa);

    auto cte = &ctx_hva[devfn];

    cte_set_tt(cte, CTE_TT_U);
    cte_set_slptptr(cte, dom->ept().pml4_phys());
    cte_set_aw(cte, m_aw);
    cte_set_did(cte, this->did(dom));
    cte_set_present(cte);

    this->clflush_range(cte, sizeof(*cte));

    auto rte = &m_root.get()[bus];
    if (!rte_ctp(rte)) {
        rte_set_ctp(rte, ctx_hpa);
        rte_set_present(rte);

        this->clflush_range(rte, sizeof(*rte));
    }
}

void iommu::map_bus(uint32_t bus, dom_t *dom)
{
    expects(bus < table_size);
    expects(this->did(dom) < nr_domains());

    auto itr = m_dom_ctxt_map.find(dom->id());
    if (itr == m_dom_ctxt_map.end()) {
        m_dom_ctxt_map.insert({dom->id(), make_page<entry_t>()});
        itr = m_dom_ctxt_map.find(dom->id());
    }

    entry_t *ctx_table = itr->second.get();

    for (auto i = 0; i < table_size; i++) {
        entry_t *cte = &ctx_table[i];

        cte_set_tt(cte, CTE_TT_U);
        cte_set_slptptr(cte, dom->ept().pml4_phys());
        cte_set_aw(cte, m_aw);
        cte_set_did(cte, this->did(dom));
        cte_set_present(cte);
    }

    this->clflush_range(ctx_table, UV_PAGE_SIZE);

    auto rte = &m_root.get()[bus];
    if (!rte_ctp(rte)) {
        rte_set_ctp(rte, g_mm->virtptr_to_physint(ctx_table));
        rte_set_present(rte);

        this->clflush_range(rte, sizeof(*rte));
    }
}

/* Global invalidation of the context-cache */
void iommu::flush_ctx_cache()
{
    const uint64_t ccmd = ccmd_icc | ccmd_cirg_global;

    this->write_ccmd(ccmd);

    while ((this->read_ccmd() & ccmd_icc) != 0) {
        ::intel_x64::pause();
    }
}

/* Domain-selective invalidation of context-cache */
void iommu::flush_ctx_cache(const dom_t *dom)
{
    const uint64_t domid = this->did(dom);

    /* Fallback to global invalidation if domain is out of range */
    if (domid >= nr_domains()) {
        printv("iommu[%u]: %s: WARNING: did:0x%lx out of range\n",
               m_id, __func__, domid);
        this->flush_ctx_cache();
        return;
    }

    const uint64_t ccmd = ccmd_icc | ccmd_cirg_domain | domid;

    this->write_ccmd(ccmd);

    while ((this->read_ccmd() & ccmd_icc) != 0) {
        ::intel_x64::pause();
    }
}

/* Device-selective invalidation of context-cache */
void iommu::flush_ctx_cache(const dom_t *dom,
                          uint32_t bus,
                          uint32_t dev,
                          uint32_t fun)
{
    const uint64_t domid = this->did(dom);

    /* Fallback to global invalidation if domain is out of range */
    if (domid >= nr_domains()) {
        printv("iommu[%u]: %s: WARNING: did:0x%lx out of range\n",
               m_id, __func__, domid);
        this->flush_ctx_cache();
        return;
    }

    uint64_t sid = bus << 8 | dev << 3 | fun;
    uint64_t ccmd = ccmd_icc | ccmd_cirg_device | (sid << 16) | domid;

    this->write_ccmd(ccmd);

    while ((this->read_ccmd() & ccmd_icc) != 0) {
        ::intel_x64::pause();
    }
}

/* Global invalidation of IOTLB */
[[maybe_unused]] uint64_t iommu::flush_iotlb()
{
    uint64_t iotlb = this->read_iotlb() & 0xFFFFFFFF;

    iotlb |= iotlb_ivt;
    iotlb |= iotlb_iirg_global;
    iotlb |= iotlb_dr;
    iotlb |= iotlb_dw;

    this->write_iotlb(iotlb);
    iotlb = this->read_iotlb();

    while ((iotlb & iotlb_ivt) != 0) {
        ::intel_x64::pause();
        iotlb = this->read_iotlb();
    }

    uint64_t iaig = (iotlb & iotlb_iaig_mask) >> iotlb_iaig_from;

    if (iaig == IOTLB_INVG_RESERVED) {
        printv("iommu[%u]: BUG: global IOTLB invalidation failed\n", m_id);
    }

    return iaig;
}

/* Domain-selective invalidation of IOTLB */
[[maybe_unused]] uint64_t iommu::flush_iotlb(const dom_t *dom)
{
    const uint64_t domid = this->did(dom);

    /* Fallback to global invalidation if domain is out of range */
    if (domid >= nr_domains()) {
        printv("iommu[%u]: %s: WARNING: did:0x%lx out of range\n",
               m_id, __func__, domid);
        return this->flush_iotlb();
    }

    uint64_t iotlb = this->read_iotlb() & 0xFFFFFFFF;

    iotlb |= iotlb_ivt;
    iotlb |= iotlb_iirg_domain;
    iotlb |= iotlb_dr;
    iotlb |= iotlb_dw;
    iotlb |= (domid << iotlb_did_from);

    this->write_iotlb(iotlb);
    iotlb = this->read_iotlb();

    while ((iotlb & iotlb_ivt) != 0) {
        ::intel_x64::pause();
        iotlb = this->read_iotlb();
    }

    return (iotlb & iotlb_iaig_mask) >> iotlb_iaig_from;
}

uint64_t iommu::flush_iotlb_4k(const dom_t *dom,
                               uint64_t addr,
                               bool flush_nonleaf)
{
    constexpr uint64_t order = 0;
    return this->flush_iotlb_page_order(dom, addr, flush_nonleaf, order);
}

uint64_t iommu::flush_iotlb_2m(const dom_t *dom,
                               uint64_t addr,
                               bool flush_nonleaf)
{
    constexpr uint64_t order = 9;
    return this->flush_iotlb_page_order(dom, addr, flush_nonleaf, order);
}

uint64_t iommu::flush_iotlb_page_order(const dom_t *dom,
                                       uint64_t addr,
                                       bool flush_nonleaf,
                                       uint64_t order)
{
    expects(order <= m_mamv);

    /* Fallback to global invalidation if domain is out of range */
    const uint64_t domid = this->did(dom);
    if (domid >= nr_domains()) {
        printv("iommu[%u]: %s: WARNING: did:0x%lx out of range\n",
               m_id, __func__, domid);
        return this->flush_iotlb();
    }

    uint64_t iotlb = this->read_iotlb() & 0xFFFFFFFF;

    iotlb |= iotlb_ivt;
    iotlb |= iotlb_iirg_page;
    iotlb |= iotlb_dr;
    iotlb |= iotlb_dw;
    iotlb |= (domid << iotlb_did_from);

    const uint64_t ih = flush_nonleaf ? 0 : (1UL << 6);
    const uint64_t iva = uv_align_page(addr) | ih | order;

    this->write_iva(iva);
    ::intel_x64::wmb();

    this->write_iotlb(iotlb);
    iotlb = this->read_iotlb();

    while ((iotlb & iotlb_ivt) != 0) {
        ::intel_x64::pause();
        iotlb = this->read_iotlb();
    }

    return (iotlb & iotlb_iaig_mask) >> iotlb_iaig_from;
}

void iommu::flush_iotlb_page_range(const dom_t *dom,
                                   uint64_t gpa,
                                   uint64_t bytes)
{
    if (!m_psi_supported) {
        this->flush_iotlb(dom);
        return;
    }

    uint64_t i = 0;

    if (bytes >= ::x64::pd::page_size && m_mamv >= 9) {
        uint64_t gpa_2m = bfn::upper(gpa, ::x64::pd::from);

        if (gpa_2m != gpa) {
            bytes += gpa - gpa_2m;
            gpa = gpa_2m;
        }

        for (; i < bytes; i += ::x64::pd::page_size) {
            const uint64_t iaig = this->flush_iotlb_2m(dom, gpa + i, true);

            switch (iaig) {
            case IOTLB_INVG_RESERVED:
                printv("iommu[%u]: %s: invalidation failed for range 0x%lx-0x%lx\n",
                       m_id, __func__, gpa, gpa + bytes - 1);
                printv("iommu[%u]: %s: falling back to domain invalidation\n",
                       m_id, __func__);
                this->flush_iotlb(dom);
                return;
            case IOTLB_INVG_GLOBAL:
            case IOTLB_INVG_DOMAIN:
                return;
            default:
                expects(iaig == IOTLB_INVG_PAGE);
                break;
            }
        }

        if (i == bytes) {
            return;
        }

        i -= ::x64::pd::page_size;
    }

    for (; i < bytes; i += UV_PAGE_SIZE) {
        const uint64_t iaig = this->flush_iotlb_4k(dom, gpa + i, true);

        switch (iaig) {
        case IOTLB_INVG_RESERVED:
            printv("iommu[%u]: %s: invalidation failed for range 0x%lx-0x%lx\n",
                   m_id, __func__, gpa, gpa + bytes - 1);
            printv("iommu[%u]: %s: falling back to domain invalidation\n",
                   m_id, __func__);
            this->flush_iotlb(dom);
            return;
        case IOTLB_INVG_GLOBAL:
        case IOTLB_INVG_DOMAIN:
            return;
        default:
            expects(iaig == IOTLB_INVG_PAGE);
            break;
        }
    }
}

void iommu::enable_dma_remapping()
{
    if (m_remapping_dma) {
        return;
    }

    this->clflush_range(m_root.get(), UV_PAGE_SIZE);
    this->write_rtaddr(g_mm->virtptr_to_physint(m_root.get()));

    ::intel_x64::wmb();

    /* Set the root table pointer */
    uint32_t gsts = this->read_gsts() & 0x96FF'FFFF;
    uint32_t gcmd = gsts | gcmd_srtp;

    this->write_gcmd(gcmd);
    ::intel_x64::mb();
    while ((this->read_gsts() & gsts_rtps) != gsts_rtps) {
        ::intel_x64::pause();
    }

    this->flush_ctx_cache();
    this->flush_iotlb();

    /* Enable DMA translation */
    gsts = this->read_gsts() & 0x96FF'FFFF;
    gcmd = gsts | gcmd_te;

    ::intel_x64::mb();
    this->write_gcmd(gcmd);
    ::intel_x64::mb();

    while ((this->read_gsts() & gsts_tes) != gsts_tes) {
        ::intel_x64::pause();
    }

    m_remapping_dma = true;
    printv("iommu[%u]: enabled dma remapping\n", m_id);
}

void iommu::clflush_range(void *p, unsigned int bytes)
{
    if (!(m_ecap & ecap_c_mask)) {
        x64::cache::clflush_range(p, bytes);
    }
}

iommu::iommu(struct drhd *drhd, uint32_t id) :
    m_id{id},
    m_root{make_page<entry_t>()}
{
    this->m_drhd = drhd;

    auto scope = reinterpret_cast<uintptr_t>(drhd) + sizeof(*drhd);
    this->m_scope = reinterpret_cast<struct dmar_devscope *>(scope);

    this->bind_devices();
    this->map_regs_into_vmm();
    this->unmap_regs_from_root_dom();
    this->init_regs();
    this->dump_devices();
    this->ack_faults();

    dump_caps(m_id, m_cap);
    dump_ecaps(m_id, m_ecap);
}
}
