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
#include <bfgsl.h>

#include "bar.h"
#include "cfg.h"

namespace microv {

namespace intel_x64 {
    class vcpu;
}

struct pci_dev {
    uint32_t cf8{};
    uint32_t bus{};
    uint32_t dev{};
    uint32_t fun{};
    uint32_t msi_base{};

    bool passthru{};
    struct pci_dev *bridge{};
    std::array<uint32_t, 4> cfg_reg{};
    pci_bar_list bars{};

    void parse_bars()
    {
        pci_parse_bars(cf8, bars);
    }

    bool is_netdev() const
    {
        return pci_cfg_is_netdev(cfg_reg[2]);
    }

    bool is_pci_bridge() const
    {
        return pci_cfg_is_pci_bridge(cfg_reg[3]);
    }

    bool is_host_bridge() const
    {
        return pci_cfg_is_host_bridge(cfg_reg[2]);
    }

    void parse_cap_regs()
    {
        if (msi_base) {
            return;
        }

        constexpr auto CAP_PTR_REG = 0xD;
        constexpr auto MSI_ID = 0x05;

        expects(pci_cfg_is_normal(cfg_reg[3]));
        expects(pci_cfg_has_caps(cfg_reg[1]));

        auto ptr = pci_cfg_read_reg(cf8, CAP_PTR_REG) & 0xFF;
        auto reg = ptr >> 2;

        while (reg) {
            auto cap = pci_cfg_read_reg(cf8, reg);
            auto id = cap & 0xFF;

            if (id == MSI_ID) {
                msi_base = reg;
                break;
            }

            reg = (cap & 0xFF00) >> (8 + 2);
        }

        ensures(msi_base);
    }

    pci_dev(uint32_t addr, struct pci_dev *parent_bridge = nullptr)
    {
        addr |= pci_en_mask;
        addr &= ~(pci_reg_mask | pci_off_mask);

        expects(pci_cfg_is_present(addr));

        cf8 = addr;
        bus = pci_cfg_bus(addr);
        dev = pci_cfg_dev(addr);
        fun = pci_cfg_fun(addr);

        for (auto i = 0; i < cfg_reg.size(); i++) {
            cfg_reg[i] = pci_cfg_read_reg(addr, i);
        }

        bridge = parent_bridge;
        if (!bridge) {
            ensures(this->is_host_bridge());
        }
    }

    ~pci_dev() = default;
    pci_dev(pci_dev &&) = default;
    pci_dev &operator=(pci_dev &&) = default;
    pci_dev(const pci_dev &) = delete;
    pci_dev &operator=(const pci_dev &) = delete;
};

int probe_pci();

}
#endif
