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

#ifndef MICROV_PCI_DEV_H
#define MICROV_PCI_DEV_H

#include <array>
#include <memory>
#include <mutex>

#include <bfgsl.h>
#include <bfvcpuid.h>
#include <hve/arch/intel_x64/vcpu.h>

#include "bar.h"
#include "cfg.h"
#include "msi.h"

namespace microv {

struct iommu;

struct pci_dev {
    using domain = intel_x64::domain;
    using vcpu = intel_x64::vcpu;
    using base_vcpu = ::bfvmm::intel_x64::vcpu;
    using cfg_info = intel_x64::pci_cfg_handler::info;

    static constexpr size_t vcfg_size = 1024;

    uint32_t m_cf8{};
    uint32_t m_msi_cap{};
    uint32_t m_msix_cap{};
    uint32_t m_pcie_cap{};
    char m_bdf_str[8]{};
    bool m_passthru_dev{};
    vcpuid_t m_guest_vcpuid{};

    std::mutex m_msi_mtx{};
    struct msi_desc m_guest_msi {};
    struct msi_desc m_root_msi {};
    bool m_msi_mapped{};

    struct pci_dev *m_bridge{};
    struct iommu *m_iommu{};

    pci_bar_list m_bars{};
    std::array<uint32_t, 4> m_cfg_reg{};
    std::unique_ptr<uint32_t[]> m_vcfg{};

    void parse_bars()
    {
        pci_parse_bars(m_cf8, m_bars);
        ::intel_x64::wmb();
    }

    bool is_netdev() const
    {
        return pci_cfg_is_netdev(m_cfg_reg[2]);
    }

    bool is_netdev_eth() const
    {
        return pci_cfg_is_netdev_eth(m_cfg_reg[2]);
    }

    bool is_host_bridge() const
    {
        return pci_cfg_is_host_bridge(m_cfg_reg[2]);
    }

    bool is_pci_bridge() const
    {
        return pci_cfg_is_pci_bridge(m_cfg_reg[3]);
    }

    bool is_normal() const
    {
        return pci_cfg_is_normal(m_cfg_reg[3]);
    }

    const char *bdf_str() const
    {
        return &m_bdf_str[0];
    }

    bool matches(uint64_t bdf) const
    {
        return (pci_en_mask | bdf) == m_cf8;
    }

    uint32_t devfn() const
    {
        return (m_cf8 & (pci_dev_mask | pci_fun_mask)) >> 8;
    }

    void parse_capabilities();
    void init_root_vcfg();
    void add_root_handlers(vcpu *vcpu);
    void add_guest_handlers(vcpu *vcpu);
    void get_relocated_bars(bool type_pmio, pci_bar_list &relocated_bars);
    void show_relocated_bars(bool type_pmio,
                             const pci_bar_list &relocated_bars);
    void relocate_pmio_bars(base_vcpu *vcpu, cfg_info &info);
    void relocate_mmio_bars(base_vcpu *vcpu, cfg_info &info);

    bool root_cfg_in(base_vcpu *vcpu, cfg_info &info);
    bool root_cfg_out(base_vcpu *vcpu, cfg_info &info);
    bool guest_normal_cfg_in(base_vcpu *vcpu, cfg_info &info);
    bool guest_normal_cfg_out(base_vcpu *vcpu, cfg_info &info);

    pci_dev(uint32_t addr, struct pci_dev *parent_bridge = nullptr);
    ~pci_dev() = default;
    pci_dev(const pci_dev &) = delete;
    pci_dev(pci_dev &&) = delete;
    pci_dev &operator=(const pci_dev &) = delete;
    pci_dev &operator=(pci_dev &&) = delete;
};

extern std::unordered_map<uint32_t, std::unique_ptr<struct pci_dev>> pci_map;
extern std::list<struct pci_dev *> pci_list;
extern std::list<struct pci_dev *> pci_passthru_list;

struct pci_dev *find_passthru_dev(uint64_t bdf);
void remove_passthru_dev(struct pci_dev *pdev);

}
#endif
