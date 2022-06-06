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
#include <unordered_set>

#include <acpi.h>
#include <bfvcpuid.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <pci/dev.h>
#include <pci/msi.h>
#include <pci/pci.h>
#include <printv.h>

#define HANDLE_CFG_ACCESS(ptr, memfn, dir)                                     \
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
std::unordered_map<uint32_t, std::unique_ptr<struct pci_dev>> pci_map;

/* List of all PCI devices */
std::list<struct pci_dev *> pci_list;

/* List of PCI devices to pass through */
std::list<struct pci_dev *> pci_passthru_list;
std::unordered_set<uint32_t> pci_passthru_busses;

/* Passthrough vendor/device IDs */
static constexpr uint32_t passthru_vendor{0xBFBF};
static uint32_t passthru_device{};

/* Emulation constants */
static constexpr uint32_t INTX_DISABLE = (1UL << 10);
static constexpr uint32_t PMIO_SPACE_ENABLE = (1UL << 0);
static constexpr uint32_t MMIO_SPACE_ENABLE = (1UL << 1);
static constexpr uint32_t BUS_MASTER_ENABLE = (1UL << 2);

/* PCIe enhanced configuration access mechanism (ECAM) */
struct mcfg_alloc {
    uint64_t base_gpa;
    uint16_t segment;
    uint8_t start_bus;
    uint8_t end_bus;
    uint32_t rsvd;
} __attribute__((packed));

static struct acpi_table *mcfg{};
static bfvmm::x64::unique_map<char> mcfg_map{};
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
uintptr_t find_ecam_page(uint32_t addr, uint16_t sgmt)
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

bool pci_bus_has_passthru_dev(uint32_t bus)
{
    return pci_passthru_busses.count(bus) != 0;
}

static void init_mcfg()
{
    mcfg = find_acpi_table("MCFG");
    if (!mcfg) {
        bferror_info(0, "probe_pci: MCFG table not found");
        return;
    }
    mcfg_map = vcpu0->map_gpa_4k<char>(mcfg->gpa, mcfg->len);

    constexpr auto mca_offset = 44;
    auto mcfg_hva = mcfg_map.get() + mca_offset;
    mca_list_size = (mcfg->len - mca_offset) / sizeof(struct mcfg_alloc);
    mca_list = reinterpret_cast<struct mcfg_alloc *>(mcfg_hva);
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

            auto [itr, new_dev] = pci_map.try_emplace(
                addr, std::make_unique<pci_dev>(addr, bridge));

            if (!new_dev) {
                continue;
            }

            pci_dev *pdev = itr->second.get();
            pci_list.push_back(pdev);

            if (pdev->is_pci_bridge()) {
                auto reg6 = pci_cfg_read_reg(addr, 6);
                auto secondary = pci_bridge_sec_bus(reg6);
                auto subordinate = pci_bridge_sub_bus(reg6);

                for (auto next = secondary; next <= subordinate; next++) {
                    probe_bus(next, pdev);
                }
            } else if (pdev->is_netdev()) {
                if (g_no_pci_pt.count(addr)) {
                    printv("pci: %s: passthrough disabled via boot option\n",
                           pdev->bdf_str());
                    continue;
                }

                if (pdev->is_netdev_eth()) {
                    printv(
                        "pci: %s: passthrough disabled for ethernet device\n",
                        pdev->bdf_str());
                    continue;
                }

                bool misaligned_bar = false;
                pdev->parse_bars();

                for (const auto &pair : pdev->m_bars) {
                    const auto reg = pair.first;
                    const auto &bar = pair.second;

                    if (bar.type == microv::pci_bar_io) {
                        continue;
                    }

                    if (bar.addr != bfn::upper(bar.addr, ::x64::pt::from)) {
                        misaligned_bar = true;
                        printv(
                            "pci: %s: MMIO BAR[%u] at 0x%lx-0x%lx is not"
                            " 4K-aligned, disabling passthrough\n",
                            pdev->bdf_str(),
                            reg - 4,
                            bar.addr,
                            bar.last());
                        break;
                    }
                }

                if (misaligned_bar) {
                    continue;
                }

                pdev->m_passthru_dev = true;
                pdev->parse_capabilities();
                pdev->init_root_vcfg();

                pci_passthru_list.push_back(pdev);
                pci_passthru_busses.emplace(b);
            }
        }
    }

    pci_passthru = !pci_passthru_list.empty();
}

static inline void probe_bus()
{
    auto addr = pci_cfg_bdf_to_addr(0, 0, 0);
    pci_map[addr] = std::make_unique<struct pci_dev>(addr);
    pci_list.push_back(pci_map[addr].get());
    probe_bus(0, pci_map[addr].get());
}

void init_pci()
{
    init_mcfg();
    probe_bus();
}

void init_pci_on_vcpu(microv::intel_x64::vcpu *vcpu)
{
    for (auto pdev : pci_passthru_list) {
        if (vcpuid::is_root_vcpu(vcpu->id())) {
            pdev->add_root_handlers(vcpu);
        } else {
            pdev->add_guest_handlers(vcpu);
        }
    }
}

/*
 * Allocate an empty slot from bus 0. Note that the resulting address
 * may conflict with hidden PCI devices (e.g. those part of the chipset),
 * so in general it is not safe for emulation at this device to pass-through
 * access to underlying hardware.
 */
uint32_t alloc_pci_cfg_addr() noexcept
{
    /* Scan bus 0 for empty slots starting at device 1 */
    for (uint32_t devfn = 0x8; devfn < pci_nr_devfn; devfn += 0x8) {
        const auto addr = pci_cfg_bdf_to_addr(0, devfn);
        const auto reg0 = pci_cfg_read_reg(addr, 0);

        if (pci_cfg_is_present(reg0)) {
            continue;
        }

        return addr;
    }

    return pci_cfg_addr_inval;
}

struct pci_dev *find_passthru_dev(uint64_t bdf)
{
    for (auto pdev : pci_passthru_list) {
        if (pdev->matches(bdf)) {
            return pdev;
        }
    }

    return nullptr;
}

void remove_passthru_dev(struct pci_dev *pdev)
{
    pci_passthru_list.remove(pdev);
    pci_passthru = !pci_passthru_list.empty();
}

static void map_pmio_bar(::microv::intel_x64::vcpu *vcpu,
                         const struct pci_bar *bar)
{
    for (auto port = bar->addr; port <= bar->last(); port++) {
        vcpu->pass_through_io_accesses(port);
    }
}

static void unmap_pmio_bar(::microv::intel_x64::vcpu *vcpu,
                           const struct pci_bar *bar)
{
    for (auto port = bar->addr; port <= bar->last(); port++) {
        vcpu->trap_io_accesses(port);
    }
}

static void map_mmio_bar(::bfvmm::intel_x64::ept::mmap *ept,
                         const struct pci_bar *bar)
{
    using namespace ::bfvmm::intel_x64::ept;

    for (auto gpa = bar->addr; gpa <= bar->last(); gpa += 4096) {
        const auto memtype = bar->prefetchable
                                 ? mmap::memory_type::write_combining
                                 : mmap::memory_type::uncacheable;

        const auto perms = mmap::attr_type::read_write;

        ept->map_4k(gpa, gpa, perms, memtype);
    }
}

static void unmap_mmio_bar(::bfvmm::intel_x64::ept::mmap *ept,
                           struct pci_bar *bar)
{
    using namespace ::intel_x64::ept;
    using namespace ::bfvmm::intel_x64::ept;

    for (auto gpa = bar->addr; gpa <= bar->last(); gpa += 4096) {
        const auto gpa_2m = bfn::upper(gpa, pd::from);

        if (ept->is_2m(gpa_2m)) {
            identity_map_convert_2m_to_4k(*ept, gpa_2m);
        }

        ept->unmap(gpa);
        ept->release(gpa);
    }
}

pci_dev::pci_dev(uint32_t addr, struct pci_dev *parent_bridge)
{
    addr |= pci_en_mask;
    addr &= ~(pci_reg_mask | pci_off_mask);

    expects(pci_cfg_is_present(pci_cfg_read_reg(addr, 0)));

    m_cf8 = addr;

    snprintf(m_bdf_str,
             sizeof(m_bdf_str),
             "%02x:%02x.%01x",
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

    m_root_msi.pdev = this;
    m_guest_msi.pdev = this;
}

void pci_dev::parse_capabilities()
{
    if (m_msi_cap) {
        return;
    }

    constexpr auto CAP_PTR_REG = 0xDUL;
    constexpr auto CAP_ID_MSI = 0x05UL;
    constexpr auto CAP_ID_PCIE = 0x10UL;
    constexpr auto CAP_ID_MSIX = 0x11UL;

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
        case CAP_ID_MSIX:
            m_msix_cap = reg;
        default:
            break;
        }

        reg = (cap & 0xFF00) >> (8 + 2);
    }

    ensures(m_msi_cap);

    auto msi = pci_cfg_read_reg(m_cf8, m_msi_cap);
    auto nr_vectors = msi_nr_msg_capable(msi);
    auto per_vector_mask = msi_per_vector_masking(msi);
    auto is_64bit = msi_64bit(msi);

    printv("pci: %s: MSI %s-bit, vectors:%u, masking%s\n",
           bdf_str(),
           is_64bit ? "64" : "32",
           nr_vectors,
           per_vector_mask ? "+" : "-");

    if (msi_enabled(msi)) {
        printv("pci: %s: MSI is enabled...disabling\n", bdf_str());
        pci_cfg_write_reg(m_cf8, m_msi_cap, msi_disable(msi));
    }
}

void pci_dev::init_root_vcfg()
{
    expects(pci_cfg_is_normal(m_cfg_reg[3]));
    expects(m_passthru_dev);
    expects(m_msi_cap);

    m_vcfg = std::make_unique<uint32_t[]>(vcfg_size);
    ensures(bfn::lower(m_vcfg.get(), 12) == 0);

    auto ven = passthru_vendor;
    auto dev = passthru_device++;
    auto sts_cmd = pci_cfg_read_reg(m_cf8, 1);

    sts_cmd &= ~(BUS_MASTER_ENABLE | MMIO_SPACE_ENABLE | PMIO_SPACE_ENABLE);
    sts_cmd |= INTX_DISABLE;

    pci_cfg_write_reg(m_cf8, 1, sts_cmd);

    for (auto i = 0; i < 0x40; i++) {
        m_vcfg[i] = pci_cfg_read_reg(m_cf8, i);
    }

    m_vcfg[0x0] = (dev << 16) | ven;
    m_vcfg[0x1] |= (BUS_MASTER_ENABLE | MMIO_SPACE_ENABLE | PMIO_SPACE_ENABLE);
    m_vcfg[0xD] = m_msi_cap * 4;
    m_vcfg[0xF] = 0xFF;

    /*
     * Disable multi-message and terminate the capability list at the MSI capability.
     * This means no other capability (including PCIe) other than MSI will be
     * seen by vcpus.
     */
    m_vcfg[m_msi_cap] &= 0xFF8100FF;

    m_root_msi.reg[0] = m_vcfg[m_msi_cap];
    m_guest_msi.reg[0] = m_vcfg[m_msi_cap];
}

void pci_dev::add_root_handlers(vcpu *vcpu)
{
    expects(vcpuid::is_root_vcpu(vcpu->id()));
    expects(m_passthru_dev);

    HANDLE_CFG_ACCESS(this, root_cfg_in, pci_dir_in);
    HANDLE_CFG_ACCESS(this, root_cfg_out, pci_dir_out);

    ::intel_x64::rmb();

    expects(!m_bars.empty());

    for (const auto &pair : m_bars) {
        const auto reg = pair.first;
        const auto &bar = pair.second;

        if (bar.type != pci_bar_io) {
            continue;
        }

        unmap_pmio_bar(vcpu, &bar);

        if (vcpu->id() == 0) {
            printv("pci: %s: PMIO BAR[%u] at 0x%lx-0x%lx\n",
                   this->bdf_str(),
                   reg - 4,
                   bar.addr,
                   bar.last());
        }
    }

    if (vcpu->id() != 0) {
        return;
    }

    for (auto &pair : m_bars) {
        const auto reg = pair.first;
        auto &bar = pair.second;

        if (bar.type == pci_bar_io) {
            continue;
        }

        unmap_mmio_bar(&vcpu->dom()->ept(), &bar);

        printv("pci: %s: MMIO BAR[%u] at 0x%lx-0x%lx (%s, %s)\n",
               this->bdf_str(),
               reg - 4,
               bar.addr,
               bar.last(),
               bar.type == microv::pci_bar_mm_64bit ? "64-bit" : "32-bit",
               bar.prefetchable ? "prefetchable" : "non-prefetchable");
    }
}

/*
 * In general there is a race between BAR relocations done by the root VM
 * and the BARs' values being mapped into the guest below. I think this can
 * be addressed by moving this code out of the g_vcm->create() path and
 * into its own hypercall so that it can be easily restarted. Some
 * synchronization primitive could be used to signal to either party to
 * retry while the other is using it.
 *
 * Another related issue is what happens if the root relocates the BARs
 * while the device is in use by the guest? In theory this could happen
 * any time, but in practice I would think it would be rare, maybe e.g.
 * in response to a hotplug event that causes the root to rebalance IO
 * windows. In this case, the BAR relocation code would need to:
 *
 *   1. detect that the guest is running
 *   2. pause the guest
 *   3. somehow ensure that the device doesn't go off the rails if
 *      its BARs are remapped.
 *   4. do the relocation
 *     4.1. unmap the BARs from the root vm
 *     4.2. remap the MMIO BAR in the guest to point to the new hpa
 *          (if changed) and trap the PMIO ports and forward them to
 *          the new ones (if changed).
 *   5. unpause the guest
 *
 * The only one that concerns me is 3. That seems very device-specific to me
 * and difficult to come up with a generic solution.  Maybe you could get away
 * with disabling DMA/IO/Memory spaces and interrupts (which could be done
 * generically), then somehow drain in-flight transactions, then do the
 * relocation, but I'm not sure.
 */

void pci_dev::add_guest_handlers(vcpu *vcpu)
{
    expects(this->is_normal());
    expects(!this->is_host_bridge());
    expects(vcpuid::is_guest_vcpu(vcpu->id()));

    HANDLE_CFG_ACCESS(this, guest_normal_cfg_in, pci_dir_in);
    HANDLE_CFG_ACCESS(this, guest_normal_cfg_out, pci_dir_out);

    auto dom = vcpu->dom();
    if (!dom->has_passthrough_dev()) {
        return;
    }

    m_guest_vcpuid = vcpu->id();
    ::intel_x64::rmb();

    for (const auto &pair : m_bars) {
        const auto &bar = pair.second;

        if (bar.type == pci_bar_io) {
            map_pmio_bar(vcpu, &bar);
        } else {
            map_mmio_bar(&dom->ept(), &bar);
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
        val = m_msi_cap * 4;
        break;
    case 0xF:
        val = 0xFF;
        break;
    default:
        val = pci_cfg_read_reg(m_cf8, info.reg);
        break;
    }

    /*
     * Only expose MSI capability (zero the ptr to next capability, bits 15:8)
     * and only expose one message (zero bits 17:22).
     */
    if (info.reg == m_msi_cap) {
        val &= 0xFF8100FF;
    }

    cfg_hdlr::write_cfg_info(val, info);
    return true;
}

bool pci_dev::guest_normal_cfg_out(base_vcpu *vcpu, cfg_info &info)
{
    auto guest = vcpu_cast(vcpu);
    auto old = pci_cfg_read_reg(m_cf8, info.reg);
    auto val = cfg_hdlr::read_cfg_info(old, info);

    /* TODO: Ensure guest doesn't remap BARs */

    if (info.reg < m_msi_cap || info.reg > m_msi_cap + 3) {
        pci_cfg_write_reg(m_cf8, info.reg, val);
        return true;
    }

    std::lock_guard msi_lock(m_msi_mtx);

    expects(m_root_msi.is_64bit() == m_guest_msi.is_64bit());
    bool msi_is_64bit = m_root_msi.is_64bit();

    if (info.reg == m_msi_cap + 1) {
        expects(msi_rh(val) == 0);
        m_guest_msi.reg[1] = val;

        return true;
    } else if (info.reg == m_msi_cap + 2) {
        if (!msi_is_64bit) {
            expects(msi_trig_mode(val) == 0);
            expects(msi_deliv_mode(val) == 0);
        }

        m_guest_msi.reg[2] = val;

        return true;
    } else if (info.reg == m_msi_cap + 3) {
        expects(msi_trig_mode(val) == 0);
        expects(msi_deliv_mode(val) == 0);

        m_guest_msi.reg[3] = val;

        return true;
    }

    expects(msi_nr_msg_enabled(val) == 1);

    const bool was_enabled = m_guest_msi.is_enabled();
    m_guest_msi.reg[0] = val;
    const bool now_enabled = m_guest_msi.is_enabled();

    if (now_enabled && !m_root_msi.is_enabled()) {
        printv(
            "pci: %s: MSI root disabled on guest enable. "
            "MSI messages will not be delivered!\n",
            bdf_str());
        return true;
    }

    if (!was_enabled && now_enabled && !m_msi_mapped) {
        expects(m_root_msi.trigger_mode() == 0); /* edge triggered */

        /* Create a root->guest MSI mapping */
        guest->map_msi(&m_root_msi, &m_guest_msi);
        m_msi_mapped = true;

        /* Write the root-specified address and data to the device */
        pci_cfg_write_reg(m_cf8, info.reg + 1, m_root_msi.reg[1]);
        pci_cfg_write_reg(m_cf8, info.reg + 2, m_root_msi.reg[2]);

        if (m_root_msi.is_64bit()) {
            pci_cfg_write_reg(m_cf8, info.reg + 3, m_root_msi.reg[3]);
        }

        printv("pci: %s: enabling MSI: ctrl:0x%04x addr:0x%016lx data:0x%08x\n",
               bdf_str(),
               val >> 16,
               m_root_msi.addr(),
               m_root_msi.data());
    }

    pci_cfg_write_reg(m_cf8, info.reg, val);
    return true;
}

/*
 * For each pass-through device, we need to get a vector from the root OS. This
 * is done by exposing the MSI capability. We also need the root to comprehend
 * and assign memory to the BARs so that we know the region is safe to be
 * remapped later when the the device is actually passed-through
 */
bool pci_dev::root_cfg_in(base_vcpu *vcpu, cfg_info &info)
{
    expects(m_passthru_dev);
    expects(pci_cfg_is_normal(m_cfg_reg[3]));

    constexpr auto bar_base = 4;
    constexpr auto bar_last = 9;
    const auto reg = info.reg;

    if (reg >= 0x40) {
        bfalert_nhex(0, "OOB PCI config in access, reg offset = ", reg);
        cfg_hdlr::write_cfg_info(0, info);
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

inline bool access_to_msi_data(uint32_t offset, struct msi_desc *msi) noexcept
{
    return ((offset == 3) && msi->is_64bit()) ||
           ((offset == 2) && !msi->is_64bit());
}

inline bool access_to_command_reg_low(const cfg_info &info) noexcept
{
    return info.reg == 1 && cfg_hdlr::access_port(info) == 0xCFC;
}

void pci_dev::get_relocated_bars(bool type_pmio, pci_bar_list &relocated_bars)
{
    for (const auto &pair : m_bars) {
        const auto reg = pair.first;
        const auto &old_bar = pair.second;

        if ((type_pmio && (old_bar.type != microv::pci_bar_io)) ||
            (!type_pmio && (old_bar.type == microv::pci_bar_io))) {
            continue;
        }

        struct pci_bar new_bar {};

        __parse_bar(m_cf8, reg, &new_bar);

        expects(old_bar.type == new_bar.type);
        expects(old_bar.prefetchable == new_bar.prefetchable);

        if (old_bar.addr == new_bar.addr) {
            continue;
        }

        if (!type_pmio) {
            expects(new_bar.addr == bfn::upper(new_bar.addr, ::x64::pt::from));
        }

        relocated_bars[reg] = new_bar;
    }
}

void pci_dev::show_relocated_bars(bool type_pmio,
                                  const pci_bar_list &relocated_bars)
{
    for (const auto &pair : relocated_bars) {
        const auto reg = pair.first;
        const auto &bar = m_bars[reg];

        if (type_pmio) {
            printv("pci: %s: PMIO BAR[%u] relocated to 0x%lx-0x%lx\n",
                   this->bdf_str(),
                   reg - 4,
                   bar.addr,
                   bar.last());
        } else {
            printv("pci: %s: MMIO BAR[%u] relocated to 0x%lx-0x%lx (%s, %s)\n",
                   this->bdf_str(),
                   reg - 4,
                   bar.addr,
                   bar.last(),
                   bar.type == microv::pci_bar_mm_64bit ? "64-bit" : "32-bit",
                   bar.prefetchable ? "prefetchable" : "nonprefetchable");
        }
    }
}

void pci_dev::relocate_pmio_bars(base_vcpu *vcpu, cfg_info &info)
{
    pci_bar_list relocated_bars{};

    ::intel_x64::rmb();

    this->get_relocated_bars(true, relocated_bars);
    if (relocated_bars.size() == 0) {
        return;
    }

    auto root = vcpu_cast(vcpu);
    expects(root->is_root_vcpu());

    auto rc = root->begin_shootdown(IPI_CODE_SHOOTDOWN_IO_BITMAP);
    if (rc == AGAIN) {
        info.again = true;
        return;
    }

    for (const auto &pair : relocated_bars) {
        const auto reg = pair.first;
        const auto &new_bar = pair.second;
        auto &old_bar = m_bars[reg];

        for (auto id = 0U; id < nr_root_vcpus; id++) {
            /*
             * get_vcpu/put_vcpu aren't actually needed since we're dealing with
             * root vcpus, but they are used throughout microv for guest vcpus
             * (and root vcpus), so in an effort to stay consistent, just use them.
             */

            auto v = get_vcpu(id);
            if (!v) {
                printv("%s: failed to get_vcpu %u\n", __func__, id);
                continue;
            }

            auto put = gsl::finally([&] { put_vcpu(id); });

            map_pmio_bar(v, &old_bar);
            unmap_pmio_bar(v, &new_bar);
        }

        old_bar = new_bar;
    }

    ::intel_x64::wmb();

    root->end_shootdown();

    this->show_relocated_bars(true, relocated_bars);
    info.again = false;

    return;
}

void pci_dev::relocate_mmio_bars(base_vcpu *vcpu, cfg_info &info)
{
    pci_bar_list relocated_bars{};

    ::intel_x64::rmb();

    this->get_relocated_bars(false, relocated_bars);
    if (relocated_bars.size() == 0) {
        return;
    }

    auto root = vcpu_cast(vcpu);
    expects(root->is_root_vcpu());

    auto ept = &root->dom()->ept();
    auto rc = root->begin_shootdown(IPI_CODE_SHOOTDOWN_TLB);

    if (rc == AGAIN) {
        info.again = true;
        return;
    }

    for (auto &pair : relocated_bars) {
        const auto reg = pair.first;
        auto &new_bar = pair.second;
        auto &old_bar = m_bars[reg];

        map_mmio_bar(ept, &old_bar);
        unmap_mmio_bar(ept, &new_bar);

        old_bar = new_bar;
    }

    ::intel_x64::wmb();

    root->end_shootdown();
    root->invept();
    root->dom()->flush_iotlb();

    this->show_relocated_bars(false, relocated_bars);
    info.again = false;

    return;
}

bool pci_dev::root_cfg_out(base_vcpu *vcpu, cfg_info &info)
{
    expects(m_passthru_dev);
    expects(pci_cfg_is_normal(m_cfg_reg[3]));

    constexpr auto bar_base = 4;
    constexpr auto bar_last = 9;
    const auto reg = info.reg;

    if (reg >= 0x40) {
        bfalert_nhex(0, "OOB PCI config out access, reg offset = ", reg);
        return true;
    }

    if (access_to_command_reg_low(info)) {
        auto old_val = m_vcfg[reg];
        auto new_val = cfg_hdlr::read_cfg_info(old_val, info);

        auto pmio_enabled = !(old_val & 0x1) && (new_val & 0x1);
        auto mmio_enabled = !(old_val & 0x2) && (new_val & 0x2);

        if (pmio_enabled) {
            this->relocate_pmio_bars(vcpu, info);

            if (info.again) {
                return true;
            }
        }

        if (mmio_enabled) {
            this->relocate_mmio_bars(vcpu, info);

            if (info.again) {
                return true;
            }
        }
    }

    if (reg >= bar_base && reg <= bar_last) {
        expects(cfg_hdlr::access_size(info) == 4);
        ::intel_x64::rmb();

        auto old = pci_cfg_read_reg(m_cf8, reg);
        auto val = cfg_hdlr::read_cfg_info(old, info);
        auto itr = m_bars.find(reg);

        if (itr != m_bars.end()) {
            const auto &bar = itr->second;

            if (bar.type == microv::pci_bar_io) {
                val |= 0x1U;
            } else {
                if (bar.type == microv::pci_bar_mm_64bit) {
                    val |= 0x4U;
                }

                if (bar.prefetchable) {
                    val |= 0x8U;
                }
            }
        }

        pci_cfg_write_reg(m_cf8, reg, val);

        //printv("pci: %s: bar %x written: value=0x%x\n", bdf_str(), reg, val);
        return true;
    }

    m_vcfg[reg] = cfg_hdlr::read_cfg_info(m_vcfg[reg], info);

    if (reg >= m_msi_cap && reg <= m_msi_cap + 3) {
        std::lock_guard msi_lock(m_msi_mtx);

        uint32_t offset = reg - m_msi_cap;
        m_root_msi.reg[offset] = m_vcfg[reg];

        if (access_to_msi_data(offset, &m_root_msi)) {
            constexpr uint32_t rsvd_bits = 0xFFFF3800;
            uint32_t data = m_root_msi.data();

            /* Clear reserved bits in data register (Windows sets some) */
            data &= ~rsvd_bits;
            m_root_msi.set_data(data);
            m_vcfg[reg] = data;
        }
    }

    return true;
}

}
