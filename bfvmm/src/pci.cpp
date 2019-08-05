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

#include <memory>
#include <unordered_map>

#include <acpi.h>
#include <bfvcpuid.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <pci/dev.h>
#include <pci/pci.h>

#define HANDLE_CFG_ACCESS(ptr, memfn, dir) \
vcpu->add_pci_cfg_handler(ptr->m_cf8, {&pci_dev::memfn, ptr}, dir)

extern microv::intel_x64::vcpu *vcpu0;

using namespace bfvmm::x64;
using base_vcpu = bfvmm::intel_x64::vcpu;
using vcpu = microv::intel_x64::vcpu;
using cfg_hdlr = microv::intel_x64::pci_cfg_handler;
using cfg_info = microv::intel_x64::pci_cfg_handler::info;
using cfg_key = uint64_t;

namespace microv {

/*
 * Owner of PCI devices enumerated on the platform. Each key
 * is a PCI CONFIG_ADDR value with the enable bit (bit 31),
 * bus, device, and function set. All other bits are zero.
 */
static std::unordered_map<uint32_t, std::unique_ptr<struct pci_dev>> dev_map;

/* List of all PCI devices */
static std::list<struct pci_dev *> dev_list;

/* List of PCI devices to pass through */
std::list<struct pci_dev *> dev_list_pt;

/* Passthrough vendor/device IDs */
static constexpr uint32_t passthru_vendor{0xBFBF};
static uint32_t passthru_device{};

/* Emulation constants */
static constexpr uint32_t INTX_DISABLE = (1UL << 10);

/* PCIe enhanced configuration access mechanism (ECAM) */
struct mcfg_alloc {
    uint64_t base_gpa;
    uint16_t segment;
    uint8_t start_bus;
    uint8_t end_bus;
    uint32_t rsvd;
} __attribute__((packed));

static struct acpi_table *mcfg{};
static struct mcfg_alloc *mca_list{};
static size_t mca_list_size{};

/*
 * Return the base address of the enhanced config space page of
 * the PCIe device given by addr. The formula can be found in the PCI
 * spec or at https://wiki.osdev.org/PCI_Express
 */
static inline uintptr_t ecam_gpa(struct mcfg_alloc *mca, uint32_t addr)
{
    const auto b = pci_cfg_bus(addr);
    const auto d = pci_cfg_dev(addr);
    const auto f = pci_cfg_fun(addr);
    const auto base = mca->base_gpa;
    const auto start = mca->start_bus;

    return base | ((b - start) << 20) | (d << 15) | (f << 12);
}

/*
 * Search the MCFG allocation structure list for the ECAM
 * page of the PCIe device given by addr
 */
static uintptr_t find_ecam_page(uint32_t addr, uint16_t sgmt = 0)
{
    expects(mca_list);
    expects(mca_list_size);

    for (auto i = 0; i < mca_list_size; i++) {
        auto mca = &mca_list[i];
        if (sgmt != mca->segment) {
            continue;
        }

        auto bus = pci_cfg_bus(addr);
        if (bus < mca->start_bus || bus > mca->end_bus) {
            continue;
        }

        return ecam_gpa(mca, addr);
    }

    return 0;
}

static void init_mcfg()
{
    mcfg = find_acpi_table("MCFG");
    if (!mcfg) {
        bferror_info(0, "probe_pci: MCFG table not found");
    }

    constexpr auto mca_offset = 44;
    mca_list_size = (mcfg->len - mca_offset) / sizeof(struct mcfg_alloc);
    mca_list = reinterpret_cast<struct mcfg_alloc *>(mcfg->hva + mca_offset);
}

static void probe_bus(uint32_t b, struct pci_dev *bridge)
{
    for (auto d = (!b) ? 1 : 0; d < pci_nr_dev; d++) {
        for (auto f = 0; f < pci_nr_fun; f++) {
            const auto addr = pci_cfg_bdf_to_addr(b, d, f);
            const auto reg0 = pci_cfg_read_reg(addr, 0);
            if (!pci_cfg_is_present(reg0)) {
                continue;
            }

            dev_map[addr] = std::make_unique<struct pci_dev>(addr, bridge);
            auto pdev = dev_map[addr].get();
            dev_list.push_back(pdev);

            if (pdev->is_pci_bridge()) {
                auto reg6 = pci_cfg_read_reg(addr, 6);
                auto next = pci_bridge_sec_bus(reg6);
                probe_bus(next, pdev);
            } else if (pdev->is_netdev()) {
                pci_passthru = true;
                pdev->m_guest_owned = true;
                pdev->parse_cap_regs();
                pdev->init_host_vcfg();
                pdev->remap_ecam();
                dev_list_pt.push_back(pdev);
            }
        }
    }
}

static inline void probe_bus()
{
    auto addr = pci_cfg_bdf_to_addr(0, 0, 0);
    dev_map[addr] = std::make_unique<struct pci_dev>(addr);
    probe_bus(0, dev_map[addr].get());
}

void init_pci()
{
    init_mcfg();
    probe_bus();
}

void init_pci_on_vcpu(microv::intel_x64::vcpu *vcpu)
{
    for (auto pdev : dev_list_pt) {
        if (vcpuid::is_host_vm_vcpu(vcpu->id())) {
            pdev->add_host_handlers(vcpu);
        } else {
            pdev->add_guest_handlers(vcpu);
        }
    }
}

pci_dev::pci_dev(uint32_t addr, struct pci_dev *parent_bridge)
{
    addr |= pci_en_mask;
    addr &= ~(pci_reg_mask | pci_off_mask);

    expects(pci_cfg_is_present(pci_cfg_read_reg(addr, 0)));

    m_cf8 = addr;
    snprintf(m_bdf_str, sizeof(m_bdf_str), "%02x:%02x.%02x",
             pci_cfg_bus(m_cf8),
             pci_cfg_dev(m_cf8),
             pci_cfg_fun(m_cf8));
    ensures(!m_bdf_str[sizeof(m_bdf_str) - 1]);

    for (auto i = 0; i < m_cfg_reg.size(); i++) {
        m_cfg_reg[i] = pci_cfg_read_reg(addr, i);
    }

    m_bridge = parent_bridge;
    if (!m_bridge) {
        ensures(this->is_host_bridge());
    } else {
        ensures(m_bridge->is_host_bridge() || m_bridge->is_pci_bridge());
    }
}

void pci_dev::remap_ecam()
{
    using namespace ::intel_x64::ept;
    using namespace bfvmm::intel_x64::ept;

    expects(m_vcfg);
    auto dom0 = vcpu0->dom();

    m_ecam_gpa = find_ecam_page(m_cf8);
    if (!m_ecam_gpa) {
        bfalert_info(0, "ECAM page not found");
        bfalert_subnhex(0, "bus", pci_cfg_bus(m_cf8));
        bfalert_subnhex(0, "dev", pci_cfg_dev(m_cf8));
        bfalert_subnhex(0, "fun", pci_cfg_fun(m_cf8));
        return;
    }

    m_ecam_hpa = dom0->ept().virt_to_phys(m_ecam_gpa).first;

    auto ecam_2m = bfn::upper(m_ecam_gpa, pd::from);
    if (dom0->ept().is_2m(ecam_2m)) {
        identity_map_convert_2m_to_4k(dom0->ept(), ecam_2m);
    }

    auto vcfg_hpa = g_mm->virtptr_to_physint(m_vcfg.get());
    dom0->unmap(m_ecam_gpa);
    dom0->ept().map_4k(m_ecam_gpa,
                       vcfg_hpa,
                       mmap::attr_type::read_write,
                       mmap::memory_type::uncacheable);
    ::intel_x64::vmx::invept_global();
}

void pci_dev::parse_cap_regs()
{
    if (m_msi_cap) {
        return;
    }

    constexpr auto CAP_PTR_REG = 0xDUL;
    constexpr auto MSI_64BIT = 0x80UL << 16;
    constexpr auto CAP_ID_MSI = 0x05UL;
    constexpr auto CAP_ID_PCIE = 0x10UL;

    expects(pci_cfg_is_normal(m_cfg_reg[3]));
    expects(pci_cfg_has_caps(m_cfg_reg[1]));

    auto ptr = pci_cfg_read_reg(m_cf8, CAP_PTR_REG) & 0xFF;
    auto reg = ptr >> 2;

    while (reg) {
        auto cap = pci_cfg_read_reg(m_cf8, reg);
        auto id = cap & 0xFF;

        switch (id) {
        case CAP_ID_MSI:
            m_msi_cap = reg;
            break;
        case CAP_ID_PCIE:
            m_pcie_cap = reg;
            break;
        default:
            break;
        }

        reg = (cap & 0xFF00) >> (8 + 2);
    }

    ensures(m_msi_cap);
    ensures(pci_cfg_read_reg(m_cf8, m_msi_cap) & MSI_64BIT);
}

void pci_dev::init_host_vcfg()
{
    expects(pci_cfg_is_normal(m_cfg_reg[3]));
    expects(m_guest_owned);
    expects(m_msi_cap);

    m_vcfg = std::make_unique<uint32_t[]>(vcfg_size);
    ensures(bfn::lower(m_vcfg.get(), 12) == 0);
    memset(m_vcfg.get(), 0, vcfg_size * sizeof(*m_vcfg.get()));

    auto ven = passthru_vendor;
    auto dev = passthru_device++;

    m_vcfg[0] = (dev << 16) | ven;
    m_vcfg[1] = m_cfg_reg[1] | INTX_DISABLE;
    m_vcfg[2] = m_cfg_reg[2];
    m_vcfg[3] = m_cfg_reg[3];

    /* Remove all caps except MSI */
    m_vcfg[0xD] = m_msi_cap << 2;
    m_vcfg[m_msi_cap] = pci_cfg_read_reg(m_cf8, m_msi_cap) & 0xFFFF00FF;
    m_vcfg[m_msi_cap + 1] = pci_cfg_read_reg(m_cf8, m_msi_cap + 1);
    m_vcfg[m_msi_cap + 2] = pci_cfg_read_reg(m_cf8, m_msi_cap + 2);
    m_vcfg[m_msi_cap + 3] = pci_cfg_read_reg(m_cf8, m_msi_cap + 3);

    m_vcfg[0xF] = 0xFF;
}

void pci_dev::add_host_handlers(vcpu *vcpu)
{
    expects(vcpuid::is_host_vm_vcpu(vcpu->id()));
    expects(m_guest_owned);

    HANDLE_CFG_ACCESS(this, host_cfg_in, pci_dir_in);
    HANDLE_CFG_ACCESS(this, host_cfg_out, pci_dir_out);
}

void pci_dev::add_guest_handlers(vcpu *vcpu)
{
    expects(this->is_normal());
    expects(!this->is_host_bridge());
    expects(vcpuid::is_guest_vm_vcpu(vcpu->id()));
    expects(m_hdlrs_added.count(vcpu->id()) == 0);

    if (m_bars.empty()) {
        this->parse_bars();
    }

    HANDLE_CFG_ACCESS(this, guest_normal_cfg_in, pci_dir_in);
    HANDLE_CFG_ACCESS(this, guest_normal_cfg_out, pci_dir_out);
    m_hdlrs_added[vcpu->id()] = true;

    printf("PCI: added handlers @ %s\n", this->bdf_str());

    for (const auto &bar : m_bars) {
        if (bar.type == pci_bar_io) {
            for (auto p = 0; p < bar.size; p++) {
                vcpu->pass_through_io_accesses(bar.addr + p);
            }
            continue;
        }

        for (auto i = 0; i < bar.size; i += 4096) {
            auto dom = vcpu->dom();
            dom->map_4k_rw_uc(bar.addr + i, bar.addr + i);
        }
    }
}

bool pci_dev::guest_normal_cfg_in(base_vcpu *vcpu, cfg_info &info)
{
    uint32_t val = 0;

    switch (info.reg) {
    case 0x1:
        val = pci_cfg_read_reg(m_cf8, 0x1) | INTX_DISABLE;
        break;
    case 0xA:
    case 0xC:
        val = 0;
        break;
    case 0xD:
        val = m_msi_cap << 2;
        break;
    case 0xF:
        val = 0xFF;
        break;
    default:
        val = pci_cfg_read_reg(m_cf8, info.reg);
        break;
    }

    /* Expose the MSI capability only */
    if (info.reg == m_msi_cap) {
        val &= 0xFFFF00FF;
    }

    cfg_hdlr::write_cfg_info(val, info);
    return true;
}

bool pci_dev::guest_normal_cfg_out(base_vcpu *vcpu, cfg_info &info)
{
    auto old = pci_cfg_read_reg(m_cf8, info.reg);
    auto val = cfg_hdlr::read_cfg_info(old, info);
    pci_cfg_write_reg(m_cf8, info.reg, val);

    if (info.reg == m_msi_cap && (val & (1UL << 16)) != 0) {
        uint32_t data = pci_cfg_read_reg(m_cf8, info.reg + 3);
        uint64_t addr = pci_cfg_read_reg(m_cf8, info.reg + 1);
        addr |= (uint64_t)pci_cfg_read_reg(m_cf8, info.reg + 2) << 32;

        printf("PCI: %s: MSI enabled, vector %u, apic_dest 0x%x\n",
              this->bdf_str(), data & 0xFF, (addr & 0xFF000) >> 12);

        expects((addr >> 32) == 0);
        expects((addr & 0x8) == 0); /* redirection hint must be zero */
        expects((data & 0x700) == 0); /* delivery mode must be fixed */
        expects((data & 0x8000) == 0); /* trigger mode must be edge */
    }

    return true;
}

/*
 * For each pass-through device, we need to get a vector from the host OS. This
 * is done by exposing the MSI capability. We also need the host to comprehend
 * and assign memory to the BARs so that we know the region is safe to be
 * remapped later when the the device is actually passed-through
 */
bool pci_dev::host_cfg_in(base_vcpu *vcpu, cfg_info &info)
{
    expects(m_guest_owned);
    expects(pci_cfg_is_normal(m_cfg_reg[3]));

    constexpr auto bar_base = 4;
    constexpr auto bar_last = 9;
    const auto reg = info.reg;

    if (reg >= 0x40) {
        bfalert_nhex(0, "OOB PCI config in access, reg offset = ", reg);
        info.exit_info.val = 0;
        return true;
    }

    if (reg >= bar_base && reg <= bar_last) {
        const auto bar = pci_cfg_read_reg(m_cf8, reg);
        cfg_hdlr::write_cfg_info(bar, info);
        return true;
    }

    cfg_hdlr::write_cfg_info(m_vcfg[reg], info);
    return true;
}

bool pci_dev::host_cfg_out(base_vcpu *vcpu, cfg_info &info)
{
    expects(m_guest_owned);
    expects(pci_cfg_is_normal(m_cfg_reg[3]));

    constexpr auto bar_base = 4;
    constexpr auto bar_last = 9;
    const auto reg = info.reg;

    if (reg >= 0x40) {
        bfalert_nhex(0, "OOB PCI config out access, reg offset = ", reg);
        return true;
    }

    if (reg >= bar_base && reg <= bar_last) {
        auto old = pci_cfg_read_reg(m_cf8, reg);
        auto val = cfg_hdlr::read_cfg_info(old, info);
        pci_cfg_write_reg(m_cf8, reg, val);
        return true;
    }

    m_vcfg[reg] = cfg_hdlr::read_cfg_info(m_vcfg[reg], info);
    return true;
}

}
