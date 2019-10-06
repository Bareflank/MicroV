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

#include <acpi.h>
#include <microv/acpi.h>
#include <clflush.h>
#include <iommu/dmar.h>
#include <iommu/iommu.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/domain.h>
#include <pci/dev.h>
#include <printv.h>

constexpr auto PAGE_SIZE_4K = (1UL << 12);
constexpr auto PAGE_SIZE_2M = (1UL << 21);

extern microv::intel_x64::vcpu *vcpu0;
using namespace bfvmm::x64;
using namespace bfvmm::intel_x64;

namespace microv {

static struct acpi_table *dmar{};
static std::list<std::unique_ptr<class iommu>> iommu_list;
static std::list<class iommu *> iommu_view;

static void make_iommus(const struct acpi_table *dmar)
{
    auto drs = dmar->hva + drs_offset;
    auto end = dmar->hva + dmar->len;

    while (drs < end) {
        /* Read the type and size of the DMAR remapping structure */
        auto drs_hdr = reinterpret_cast<struct drs_hdr *>(drs);

        /* Compliant firmware enumerates DRHDs before anything else */
        expects(drs_hdr->type == drs_drhd);

        auto drhd = reinterpret_cast<struct drhd *>(drs);
        auto iommu = std::make_unique<class iommu>(drhd);
        iommu_view.push_front(iommu.get());
        iommu_list.push_front(std::move(iommu));

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
    auto drs = dmar->hva + drs_offset;
    auto end = dmar->hva + dmar->len;

    while (drs < end) {
        /* Read the type and size of the DMAR remapping structure */
        auto drs_hdr = reinterpret_cast<const struct drs_hdr *>(drs);

        /* Skip over non-RMRR structures */
        if (drs_hdr->type != drs_rmrr) {
            drs += drs_hdr->length;
            continue;
        }

        auto rmrr = reinterpret_cast<const struct rmrr *>(drs);
        printv("RMRR: [0x%lx-0x%lx] (segment 0x%04x)\n",
               rmrr->base, rmrr->limit, rmrr->seg_nr);

        const auto rmrr_len = rmrr->hdr.length;
        const auto rmrr_end = drs + rmrr_len;

        /* Get the address of the first device scope */
        auto ds = drs + sizeof(*rmrr);

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

            printv("   -> %02x:%02x.%02x\n", bus, dev, fun);
            ds += scope->length;
        }

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

    if (memcmp(dmar->hva, "DMAR", 4)) {
        bferror_info(0, "init_vtd: Invalid DMAR signature");
    }

    hide_acpi_table(dmar);
    make_iommus(dmar);
    parse_rmrrs(dmar);
}

void iommu_dump()
{
    for (const auto iommu : iommu_view) {
        iommu->dump_faults();
    }
}

void iommu::map_regs()
{
    auto base_hpa = vcpu0->gpa_to_hpa(m_drhd->base_gpa).first;
    auto base_hva = g_mm->alloc_map(page_size);

    g_cr3->map_4k(base_hva,
                  base_hpa,
                  cr3::mmap::attr_type::read_write,
                  cr3::mmap::memory_type::uncacheable);

    m_reg_hva = reinterpret_cast<uintptr_t>(base_hva);
}

void iommu::init_regs()
{
    m_ver = this->read32(ver_offset);
    m_cap = this->read64(cap_offset);
    m_ecap = this->read64(ecap_offset);

    m_frcd_reg_off = ((m_cap & cap_fro_mask) >> cap_fro_from) << 4;
    m_frcd_reg_num = ((m_cap & cap_nfr_mask) >> cap_nfr_from) + 1;
    m_frcd_reg_bytes = m_frcd_reg_num * frcd_reg_len;

    m_iotlb_reg_off = ((m_ecap & ecap_iro_mask) >> ecap_iro_from) << 4;

    auto ioreg_end = m_reg_hva + m_iotlb_reg_off + iotlb_reg_bytes - 1;
    auto frreg_end = m_reg_hva + m_frcd_reg_off + m_frcd_reg_bytes - 1;

    auto ioreg_end_4k = ioreg_end & ~(page_size - 1);
    auto frreg_end_4k = frreg_end & ~(page_size - 1);

    expects(m_reg_hva == ioreg_end_4k);
    expects(m_reg_hva == frreg_end_4k);

    m_did_bits = (uint8_t)(4 + ((m_cap & cap_nd_mask) << 1));
    m_mgaw = ((m_cap & cap_mgaw_mask) >> cap_mgaw_from) + 1;
    m_sagaw = ((m_cap & cap_sagaw_mask) >> cap_sagaw_from);

    /* Ensure 4-level paging is supported since EPT uses 4-level */
    expects(m_sagaw & 0x4);
    m_aw = 2;

    /* CM = 1 is not supported right now */
    ensures(((m_cap & cap_cm_mask) >> cap_cm_from) == 0);

    /* Required write-buffer flushing is not supported */
    ensures(((m_cap & cap_rwbf_mask) >> cap_rwbf_mask) == 0);
}

void iommu::bind_device(struct pci_dev *pdev)
{
    pdev->m_iommu = this;
    if (pdev->m_guest_owned) {
        m_guest_devs.push_back(pdev);
    } else {
        m_root_devs.push_back(pdev);
    }
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
                auto next = pci_bridge_sec_bus(reg6);
                this->bind_bus(next);
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

        ensures(!m_root_devs.empty() || !m_guest_devs.empty());
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
    printv("iommu: scopes %lu devices\n",
            m_root_devs.size() + m_guest_devs.size());

    for (const auto pdev : m_root_devs) {
        printv("iommu:    %s (root)\n", pdev->bdf_str());
    }

    for (const auto pdev : m_guest_devs) {
        printv("iommu:    %s (guest)\n", pdev->bdf_str());
    }
}

static void dump_caps(uint64_t caps)
{
    printv("iommu: caps -> afl:%lu rwbf:%lu plmr:%lu phmr:%lu cm:%lu"
           " sagaw:0x%lx mgaw:%lu zlr:%lu psi:%lu dwd:%lu drd:%lu pi:%lu\n",
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

static void dump_ecaps(uint64_t ecaps)
{
    printv("iommu: ecaps -> c:%lu qi:%lu dt:%lu ir:%lu pt:%lu sc:%lu"
           " nest:%lu pasid:%lu smts:%lu\n",
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

void iommu::dump_faults()
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

            printv("iommu: fault: %02lx:%02lx.%02lx addr:0x%lx reason:0x%lx (%s)\n",
                    bus, dev, fun, addr, reason, str);

            /* Ack the fault */
            frcd->data[1] |= FRCD_F;

            /* Update the index in circular fashion */
            fri = (fri == m_frcd_reg_num - 1) ? 0 : fri + 1;
            frcd = &frcd_base[fri];
        }
    }

    if (fsts & 0xFC) {
        bferror_nhex(0, "iommu: unsupported errors pending: fsts=", fsts);
    }

    /* Ack all faults */
    this->write32(fsts_offset, fsts);
}

void iommu::map_dma(uint32_t bus, uint32_t devfn, dom_t *dom)
{
    expects(bus < table_size);
    expects(devfn < table_size);
    expects(this->did(dom) < nr_domains());

    bool flush_slpt = true;
    entry_t *ctx_hva = nullptr;
    uintptr_t ctx_hpa = 0;

    auto itr = m_ctxt_map.find(bus);
    if (itr == m_ctxt_map.end()) {
        m_ctxt_map.insert({bus, make_page<entry_t>()});
        itr = m_ctxt_map.find(bus);
        ctx_hva = itr->second.get();
        ctx_hpa = g_mm->virtptr_to_physint(ctx_hva);
        this->clflush_range(ctx_hva, page_size);
    } else {
        ctx_hva = itr->second.get();
        ctx_hpa = rte_ctp(&m_root.get()[bus]);
    }

    ensures(ctx_hva);
    ensures(ctx_hpa);

    auto cte = &ctx_hva[devfn];
    if (dom->id() == 0 && (m_ecap & ecap_pt_mask) != 0) {
        cte_set_tt(cte, CTE_TT_PT);
        cte_set_aw(cte, (m_sagaw & 0x8) ? 3 : m_aw);
        flush_slpt = false;
    } else {
        cte_set_tt(cte, CTE_TT_U);
        cte_set_slptptr(cte, dom->ept().pml4_phys());
        cte_set_aw(cte, m_aw);
    }
    cte_set_did(cte, this->did(dom));
    cte_set_present(cte);
    this->clflush_range(cte, sizeof(*cte));

    auto rte = &m_root.get()[bus];
    if (!rte_ctp(rte)) {
        rte_set_ctp(rte, ctx_hpa);
        rte_set_present(rte);
        this->clflush_range(rte, sizeof(*rte));
    }

    if (flush_slpt) {
        this->clflush_slpt();
    }
}

/* Global invalidation of the context-cache */
void iommu::invalidate_ctx_cache()
{
    const uint64_t ccmd = ccmd_icc | ccmd_cirg_global;
    this->write_ccmd(ccmd);

    while ((this->read_ccmd() & ccmd_icc) != 0) {
        ::intel_x64::pause();
    }
}

/* Domain-selective invalidation of context-cache */
void iommu::invalidate_ctx_cache(const dom_t *dom)
{
    const uint64_t domid = this->did(dom);

    /* Fallback to global invalidation if domain is out of range */
    if (domid >= nr_domains()) {
        printv("%s: WARNING: did:0x%lx out of range\n", __func__, domid);
        this->invalidate_ctx_cache();
        return;
    }

    const uint64_t ccmd = ccmd_icc | ccmd_cirg_domain | domid;
    this->write_ccmd(ccmd);

    while ((this->read_ccmd() & ccmd_icc) != 0) {
        ::intel_x64::pause();
    }
}

/* Global invalidation of IOTLB */
void iommu::invalidate_iotlb()
{
    uint64_t iotlb = this->read_iotlb() & 0xFFFFFFFF;

    iotlb |= iotlb_ivt;
    iotlb |= iotlb_iirg_global;
    iotlb |= iotlb_dr;
    iotlb |= iotlb_dw;

    this->write_iotlb(iotlb);

    while ((this->read_iotlb() & iotlb_ivt) != 0) {
        ::intel_x64::pause();
    }
}

/* Domain-selective invalidation of IOTLB */
void iommu::invalidate_iotlb(const dom_t *dom)
{
    const uint64_t domid = this->did(dom);

    /* Fallback to global invalidation if domain is out of range */
    if (domid >= nr_domains()) {
        printv("%s: WARNING: did:0x%lx out of range\n", __func__, domid);
        this->invalidate_iotlb();
        return;
    }

    uint64_t iotlb = this->read_iotlb() & 0xFFFFFFFF;

    iotlb |= iotlb_ivt;
    iotlb |= iotlb_iirg_domain;
    iotlb |= iotlb_dr;
    iotlb |= iotlb_dw;
    iotlb |= (domid << iotlb_did_from);

    this->write_iotlb(iotlb);

    while ((this->read_iotlb() & iotlb_ivt) != 0) {
        ::intel_x64::pause();
    }
}

void iommu::enable_dma_remapping()
{
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

    this->invalidate_ctx_cache();
    this->invalidate_iotlb();

    /* Enable DMA translation */
    gsts = this->read_gsts() & 0x96FF'FFFF;
    gcmd = gsts | gcmd_te;
    ::intel_x64::mb();
    this->write_gcmd(gcmd);
    ::intel_x64::mb();
    while ((this->read_gsts() & gsts_tes) != gsts_tes) {
        ::intel_x64::pause();
    }

    printv("iommu: enabled dma remapping\n");
}

void iommu::clflush(void *p)
{
    if (!(m_ecap & ecap_c_mask)) {
        ::clflush(p);
    }
}

void iommu::clflush_range(void *p, unsigned int bytes)
{
    if (!(m_ecap & ecap_c_mask)) {
        ::clflush_range(p, bytes);
    }
}

void iommu::clflush_slpt()
{
    if (!(m_ecap & ecap_c_mask)) {
        /*
         * Whenever the IOMMU page walk is not coherent (i.e. ECAP.C == 0),
         * we have to ensure that all the second-level paging structures are
         * written to memory. The easiest (but most expensive) way of doing
         * this is through wbinvd.  Two alternatives would be to handle faults
         * as they arrive due to the stale data or to modify the EPT code to
         * clflush any time an entry is changed.
         */

        ::intel_x64::mb();
        ::x64::cache::wbinvd();
        ::intel_x64::mb();
    }
}

iommu::iommu(struct drhd *drhd) : m_root{make_page<entry_t>()}
{
    this->clflush_range(m_root.get(), page_size);
    this->m_drhd = drhd;

    auto scope = reinterpret_cast<uintptr_t>(drhd) + sizeof(*drhd);
    this->m_scope = reinterpret_cast<struct dmar_devscope *>(scope);
    this->bind_devices();
    this->dump_devices();

    /* Leave early if this doesn't scope a passthrough device */
    if (!m_guest_devs.size()) {
        return;
    }

    this->map_regs();
    this->init_regs();

    printv("iommu: nr_devs=%lu nr_doms=0x%lx\n",
           m_root_devs.size() + m_guest_devs.size(), nr_domains());
    dump_caps(m_cap);
    dump_ecaps(m_ecap);

    expects(vcpu0);

    for (auto pdev : m_root_devs) {
        auto dom = vcpu0->dom();
        auto bus = pci_cfg_bus(pdev->m_cf8);
        auto devfn = pci_cfg_devfn(pdev->m_cf8);

        this->map_dma(bus, devfn, dom);
    }

    this->enable_dma_remapping();
}
}
