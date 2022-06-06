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

#ifndef MICROV_PCI_CONFIG_H
#define MICROV_PCI_CONFIG_H

#include <bftypes.h>
#include <arch/x64/portio.h>
#include <printv.h>

namespace microv {

enum pci_header_t {
    pci_hdr_normal = 0x00,
    pci_hdr_pci_bridge = 0x01,
    pci_hdr_cardbus_bridge = 0x02,
    pci_hdr_normal_multi = 0x80 | pci_hdr_normal,
    pci_hdr_pci_bridge_multi = 0x80 | pci_hdr_pci_bridge,
    pci_hdr_cardbus_bridge_multi = 0x80 | pci_hdr_cardbus_bridge,
    pci_hdr_nonexistant = 0xFF
};

enum pci_class_code_t {
    pci_cc_unclass = 0x00,
    pci_cc_storage = 0x01,
    pci_cc_network = 0x02,
    pci_cc_display = 0x03,
    pci_cc_multimedia = 0x04,
    pci_cc_memory = 0x05,
    pci_cc_bridge = 0x06,
    pci_cc_simple_comms = 0x07,
    pci_cc_input = 0x09,
    pci_cc_processor = 0x0B,
    pci_cc_serial_bus = 0x0C,
    pci_cc_wireless = 0x0D
};

enum pci_subclass_bridge_t {
    pci_sc_bridge_host = 0x00,
    pci_sc_bridge_isa = 0x01,
    pci_sc_bridge_eisa = 0x02,
    pci_sc_bridge_mca = 0x03,
    pci_sc_bridge_pci_decode = 0x04,
    pci_sc_bridge_pcmcia = 0x05,
    pci_sc_bridge_nubus = 0x06,
    pci_sc_bridge_cardbus = 0x07,
    pci_sc_bridge_raceway = 0x08,
    pci_sc_bridge_pci_semi_trans = 0x09,
    pci_sc_bridge_infiniband = 0x0A,
    pci_sc_bridge_other = 0x80
};

constexpr uint32_t pci_nr_bus = 256;
constexpr uint32_t pci_nr_dev = 32;
constexpr uint32_t pci_nr_fun = 8;
constexpr uint32_t pci_nr_devfn = 256;

constexpr uint32_t pci_en_mask = 0x80000000;
constexpr uint32_t pci_bus_mask = 0x00FF0000;
constexpr uint32_t pci_dev_mask = 0x0000F800;
constexpr uint32_t pci_fun_mask = 0x00000700;
constexpr uint32_t pci_reg_mask = 0x000000FC;
constexpr uint32_t pci_off_mask = 0x00000003;

constexpr uint32_t pci_cfg_addr_inval = ~pci_en_mask;

enum { pci_dir_in, pci_dir_out };

constexpr bool pci_cfg_addr_enabled(uint32_t addr)
{
    return (addr & pci_en_mask) != 0;
}

constexpr uint32_t pci_cfg_bus(uint32_t addr)
{
    return (addr & pci_bus_mask) >> 16;
}

constexpr uint32_t pci_cfg_dev(uint32_t addr)
{
    return (addr & pci_dev_mask) >> 11;
}

constexpr uint32_t pci_cfg_fun(uint32_t addr)
{
    return (addr & pci_fun_mask) >> 8;
}

constexpr uint32_t pci_cfg_reg(uint32_t addr)
{
    return (addr & pci_reg_mask) >> 2;
}

constexpr uint32_t pci_cfg_bdf_to_addr(uint32_t b, uint32_t d, uint32_t f)
{
    return (1UL << 31) | (b << 16) | (d << 11) | (f << 8);
}

constexpr uint32_t pci_cfg_bdf_to_addr(uint32_t bus, uint32_t devfn)
{
    const uint32_t d = (devfn & 0xF8) >> 3;
    const uint32_t f = devfn & 0x07;

    return (1UL << 31) | (bus << 16) | (d << 11) | (f << 8);
}

constexpr uint32_t pci_cfg_devfn(uint32_t dev, uint32_t fn)
{
    return (dev << 3) | fn;
}

constexpr uint32_t pci_cfg_devfn(uint32_t addr)
{
    return (pci_cfg_dev(addr) << 3) | pci_cfg_fun(addr);
}

inline uint32_t pci_cfg_read_reg(uint32_t addr, uint32_t reg)
{
    const auto cf8 = ::x64::portio::ind(0xCF8);

    ::x64::portio::outd(0xCF8, (addr & ~pci_reg_mask) | (reg << 2));
    const auto ret = ::x64::portio::ind(0xCFC);

    ::x64::portio::outd(0xCF8, cf8);

    return ret;
}

inline void pci_cfg_write_reg(uint32_t addr, uint32_t reg, uint32_t val)
{
    const auto cf8 = ::x64::portio::ind(0xCF8);

    ::x64::portio::outd(0xCF8, (addr & ~pci_reg_mask) | (reg << 2));
    ::x64::portio::outd(0xCFC, val);

    ::x64::portio::outd(0xCF8, cf8);
}

/* Query config register 0 */

inline bool pci_cfg_is_present(uint32_t reg0)
{
    return reg0 != 0xFFFF'FFFF;
}

/* Query config register 1 */

inline bool pci_cfg_has_caps(uint32_t reg1)
{
    return (reg1 & 0x0010'0000) != 0;
}

/* Query config register 2 */

inline bool pci_cfg_is_netdev(uint32_t reg2)
{
    const auto cc = (reg2 & 0xFF00'0000) >> 24;
    return cc == pci_cc_network;
}

inline bool pci_cfg_is_netdev_eth(uint32_t reg2)
{
    const auto cc = (reg2 & 0xFF00'0000) >> 24;
    const auto sc = (reg2 & 0x00FF'0000) >> 16;
    const auto ret = cc == pci_cc_network && sc == 00;
    printv("pci_cfg_is_netdev_eth: [class:subclass] [%02x:%02x] %s\n",
           cc,
           sc,
           ret ? "eth" : "wireless");
    return ret;
}

inline bool pci_cfg_is_host_bridge(uint32_t reg2)
{
    const auto cc = (reg2 & 0xFF00'0000) >> 24;
    const auto sc = (reg2 & 0x00FF'0000) >> 16;

    return cc == pci_cc_bridge && sc == pci_sc_bridge_host;
}

/* Query config register 3 */

inline uint32_t pci_cfg_header(uint32_t reg3)
{
    return (reg3 & 0x00FF'0000) >> 16;
}

inline bool pci_cfg_is_pci_bridge(uint32_t reg3)
{
    const auto hdr = pci_cfg_header(reg3);
    return hdr == pci_hdr_pci_bridge || hdr == pci_hdr_pci_bridge_multi;
}

inline bool pci_cfg_is_multifun(uint32_t reg3)
{
    const auto hdr = pci_cfg_header(reg3);
    return (hdr & 0x80) != 0;
}

inline bool pci_cfg_is_normal(uint32_t reg3)
{
    const auto hdr = pci_cfg_header(reg3);
    return hdr == pci_hdr_normal || hdr == pci_hdr_normal_multi;
}

/* Query config register 6 */

inline uint32_t pci_bridge_sec_bus(uint32_t reg6)
{
    return (reg6 & 0xFF00) >> 8;
}

inline uint32_t pci_bridge_sub_bus(uint32_t reg6)
{
    return (reg6 & 0xFF0000) >> 16;
}

}
#endif
