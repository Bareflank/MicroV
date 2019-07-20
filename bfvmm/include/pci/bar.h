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

#include <list>
#include <vector>
#include <bfdebug.h>

#include "cfg.h"

namespace microv {

enum pci_bar_type {
    pci_bar_mm_32bit,
    pci_bar_mm_64bit,
    pci_bar_io
};

struct pci_bar {
    uintptr_t addr{};
    uint64_t size{};
    uint8_t type{};
    bool prefetchable{};
};

using pci_bar_list = std::list<struct pci_bar>;

inline void __parse_bar_size(uint32_t cf8,
                             uint32_t reg,
                             uint32_t orig,
                             uint32_t mask,
                             uint64_t *size)
{
    pci_cfg_write_reg(cf8, reg, 0xFFFFFFFF);
    *size = ~(pci_cfg_read_reg(cf8, reg) & mask) + 1U;
    pci_cfg_write_reg(cf8, reg, orig);
}

inline void __parse_bars(uint32_t cf8,
                         const std::vector<uint8_t> &bar_regs,
                         pci_bar_list &bars)
{
    for (auto i = 0; i < bar_regs.size(); i++) {
        const auto reg = bar_regs[i];
        const auto val = pci_cfg_read_reg(cf8, reg);

        if (val == 0) {
            continue;
        }

        struct pci_bar bar{};

        if ((val & 0x1) != 0) { // IO bar
            __parse_bar_size(cf8, reg, val, 0xFFFFFFFC, &bar.size);
            bar.addr = val & 0xFFFFFFFC;
            bar.type = pci_bar_io;
        } else {                // MM bar
            __parse_bar_size(cf8, reg, val, 0xFFFFFFF0, &bar.size);
            bar.addr = (val & 0xFFFFFFF0);
            bar.prefetchable = (val & 0x8) != 0;
            if (((val & 0x6) >> 1) == 2) {
                bar.addr |= (gsl::narrow_cast<uintptr_t>(pci_cfg_read_reg(cf8, bar_regs.at(++i))) << 32);
                bar.type = pci_bar_mm_64bit;
            } else {
                bar.type = pci_bar_mm_32bit;
            }
        }

        bars.push_back(bar);
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
    const auto hdr = pci_cfg_header(cf8);

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
