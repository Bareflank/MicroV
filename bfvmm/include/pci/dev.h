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

#include "config.h"
#include "bar.h"

namespace microv {

struct pci_dev {
    uint32_t cf8{};
    uint32_t bus{};
    uint32_t dev{};
    uint32_t fun{};
    uint32_t classc{};
    uint32_t subclassc{};
    pci_bar_list bars{};

    void parse_bars()
    {
        pci_parse_bars(cf8, bars);
    }

    bool is_netdev() const
    {
        return classc == pci_cc_network;
    }

    pci_dev(uint32_t addr)
    {
        expects(pci_cfg_addr_enabled(addr));
        expects(pci_cfg_is_present(addr));

        cf8 = addr;
        bus = pci_cfg_bus(addr);
        dev = pci_cfg_dev(addr);
        fun = pci_cfg_fun(addr);

        const auto reg = pci_cfg_read_reg(addr, 2);
        classc = (reg & 0xFF000000) >> 24;
        subclassc = (reg & 0x00FF0000) >> 16;
    }

    ~pci_dev() = default;

    pci_dev(pci_dev &&) = default;
    pci_dev &operator=(pci_dev &&) = default;

    pci_dev(const pci_dev &) = delete;
    pci_dev &operator=(const pci_dev &) = delete;
};

}
#endif
