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

#ifndef MICROV_PCI_BAR_H
#define MICROV_PCI_BAR_H

#include <map>
#include <vector>
#include <bfdebug.h>

#include "cfg.h"

namespace microv {

constexpr uint32_t pci_pmio_addr_mask = 0xFFFFFFFCU;
constexpr uint32_t pci_mmio_addr_mask = 0xFFFFFFF0U;

enum pci_bar_type {
    pci_bar_invalid,
    pci_bar_mm_32bit,
    pci_bar_mm_64bit,
    pci_bar_io
};

struct pci_bar {
    uint64_t addr{0};
    uint64_t size{0};
    uint8_t type{pci_bar_invalid};
    bool prefetchable{false};

    bool contains(uint64_t addr) const noexcept
    {
        return (addr >= this->addr) && (addr <= last());
    }

    uint64_t last() const noexcept
    {
        return addr + size - 1;
    }
};

/* Map config register offset to corresponding BAR */
using pci_bar_list = std::map<uint32_t, struct pci_bar>;

inline void __parse_bar_size(uint32_t cf8,
                             uint32_t reg,
                             uint32_t orig,
                             uint32_t addr_mask,
                             uint64_t *size)
{
    constexpr uint32_t pci_bar_size_mask = 0xFFFFFFFFU;

    pci_cfg_write_reg(cf8, reg, pci_bar_size_mask);
    *size = ~(pci_cfg_read_reg(cf8, reg) & addr_mask) + 1U;
    pci_cfg_write_reg(cf8, reg, orig);
}

inline void __parse_bar(uint32_t cf8, uint32_t reg, struct pci_bar *bar)
{
    const auto val = pci_cfg_read_reg(cf8, reg);

    if (val == 0U) {
        bar->type = pci_bar_invalid;
        return;
    }

    /* BAR with bit 0 set is in IO space */
    if ((val & 0x1U) != 0U) {
        __parse_bar_size(cf8, reg, val, pci_pmio_addr_mask, &bar->size);

        bar->addr = val & pci_pmio_addr_mask;
        bar->type = pci_bar_io;
        bar->prefetchable = false;

        return;
    }

    /* Otherwise it is in Memory space */
    __parse_bar_size(cf8, reg, val, pci_mmio_addr_mask, &bar->size);

    bar->addr = val & pci_mmio_addr_mask;
    bar->prefetchable = (val & 0x8U) != 0U;

    /* Type 2 means 64-bit */
    if (val & 0x4U) {
        bar->addr |= (uint64_t)pci_cfg_read_reg(cf8, reg + 1U) << 32;
        bar->type = pci_bar_mm_64bit;
    } else {
        bar->type = pci_bar_mm_32bit;
    }

    return;
}

inline void __parse_bars(uint32_t cf8,
                         const std::vector<uint8_t> &bar_regs,
                         pci_bar_list &bars)
{
    for (auto i = 0; i < bar_regs.size(); i++) {
        struct pci_bar bar {};
        const auto reg = bar_regs[i];

        __parse_bar(cf8, reg, &bar);

        if (bar.type == pci_bar_invalid) {
            continue;
        } else if (bar.type == pci_bar_mm_64bit) {
            i++;
        }

        bars[reg] = bar;
    }
}

inline void __parse_normal_bars(uint32_t cf8, pci_bar_list &bars)
{
    const std::vector<uint8_t> bar_regs = {0x4, 0x5, 0x6, 0x7, 0x8, 0x9};
    __parse_bars(cf8, bar_regs, bars);
}

inline void __parse_pci_bridge_bars(uint32_t cf8, pci_bar_list &bars)
{
    const std::vector<uint8_t> bar_regs = {0x4, 0x5};
    __parse_bars(cf8, bar_regs, bars);
}

inline void pci_parse_bars(uint32_t cf8, pci_bar_list &bars)
{
    const auto hdr = pci_cfg_header(pci_cfg_read_reg(cf8, 0x3));

    switch (hdr) {
    case pci_hdr_normal:
    case pci_hdr_normal_multi:
        __parse_normal_bars(cf8, bars);
        return;
    case pci_hdr_pci_bridge:
    case pci_hdr_pci_bridge_multi:
        __parse_pci_bridge_bars(cf8, bars);
        return;
    default:
        bfalert_info(0, "Unsupported header type for PCI bar parsing");
        bfalert_subnhex(0, "bus", pci_cfg_bus(cf8));
        bfalert_subnhex(0, "dev", pci_cfg_dev(cf8));
        bfalert_subnhex(0, "fun", pci_cfg_fun(cf8));
        bfalert_subnhex(0, "header", hdr);
        return;
    }
}

}
#endif
