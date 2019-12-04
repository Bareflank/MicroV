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

#include <array>
#include <mutex>

#include <hve/arch/intel_x64/vcpu.h>
#include <pci/cfg.h>
#include <pci/pci.h>
#include <printv.h>
#include <xen/platform_pci.h>
#include <xen/types.h>
#include <xen/vcpu.h>

using pci_cfg_hdlr = microv::intel_x64::pci_cfg_handler;
using pci_cfg_info = microv::intel_x64::pci_cfg_handler::info;

namespace microv {

/* Platform device IO ports */
static constexpr uint16_t XEN_IOPORT = 0xE9;
static constexpr uint16_t PFD_IOPORT = 0x10;
static constexpr uint16_t PFD_IOPORT_MAGIC = 0x49D2;

/* Platform device PCI config space values */
static constexpr uint32_t PCI_VENDOR = 0x5853;
static constexpr uint32_t PCI_DEVICE = 0x0001;
static constexpr uint32_t PCI_STATUS = 0x0000;
static constexpr uint32_t PCI_COMMAND = 0x0403;
static constexpr uint32_t PCI_SUBCLASS = 0x80;
static constexpr uint32_t PCI_CLASS = 0xFF;
static constexpr uint32_t PCI_HEADER = 0x00;
static constexpr uint32_t PCI_IRQ_PIN = 0x00;
static constexpr uint32_t PCI_IRQ_LINE = 0xFF;

static constexpr uint32_t PCI_PMIO_BAR = 0x1;
static constexpr uint32_t PCI_PMIO_BAR_DISABLED = 0x0;
static constexpr uint32_t PCI_PMIO_BAR_SIZE = 0x100;

static constexpr uint32_t PCI_MMIO_BAR = 0x8;
static constexpr uint32_t PCI_MMIO_BAR_DISABLED = 0x0;
static constexpr uint32_t PCI_MMIO_BAR_SIZE = (16 << 20);

static constexpr uint32_t PCI_NR_CFG_REGS = 64;
static constexpr uint32_t PCI_PMIO_BAR_REG = 0x4;
static constexpr uint32_t PCI_MMIO_BAR_REG = 0x5;

static uint32_t pci_cfg_addr = pci_cfg_addr_inval;
static std::array<uint32_t, PCI_NR_CFG_REGS> pci_cfg{};
static char bdf_str[9]{};

static std::mutex mutex{};
static bool enabled{};

static void reset_pci_cfg() noexcept
{
    for (auto i = 0; i < pci_cfg.size(); i++) {
        pci_cfg[i] = 0;
    }

    pci_cfg[0x0] = (PCI_DEVICE << 16) | PCI_VENDOR;
    pci_cfg[0x1] = (PCI_STATUS << 16) | PCI_COMMAND;
    pci_cfg[0x2] = (PCI_CLASS << 24) | (PCI_SUBCLASS << 16);
    pci_cfg[0x3] = PCI_HEADER << 16;
    pci_cfg[0x4] = PCI_PMIO_BAR_DISABLED;
    pci_cfg[0x5] = PCI_MMIO_BAR_DISABLED;
    pci_cfg[0xF] = (PCI_IRQ_PIN << 8) | PCI_IRQ_LINE;
}

static bool pfd_ioport_in(base_vcpu *vcpu, io_insn_handler::info_t &info)
{
    auto port = info.port_number;
    auto size = info.size_of_access + 1;

    if (port == PFD_IOPORT && size == 2) {
        info.val = PFD_IOPORT_MAGIC;
        printv("xen-pfd: guest read magic\n");
        return true;
    }

    if (port == PFD_IOPORT + 2 && size == 1) {
        info.val = 0;
        printv("xen-pfd: guest read version\n");
        return true;
    }

    printv("xen-pfd: invalid read: port=0x%lx, size=%lu\n", port, size);
    return false;
}

static bool pfd_ioport_out(base_vcpu *vcpu, io_insn_handler::info_t &info)
{
    auto port = info.port_number;
    auto size = info.size_of_access + 1;

    if (port == PFD_IOPORT && size == 2) {
        const char *unplug_str;

        switch (info.val) {
        case 0x0001:
            unplug_str = "disks";
            break;
        case 0x0002:
            unplug_str = "nics";
            break;
        case 0x0004:
            unplug_str = "aux disks";
            break;
        default:
            unplug_str = "unknown";
            break;
        }

        printv("xen-pfd: received %s unplug request\n", unplug_str);
        return true;
    }

    if (port == PFD_IOPORT + 2 && size == 1) {

        expects(info.reps >= 1);
        expects(info.reps <= 255);

        char buf[256]{};
        auto len = info.reps + 1;
        auto data = vcpu->map_gva_4k<char>(info.address, info.reps);

        memcpy(buf, data.get(), info.reps);

        if (buf[info.reps - 1] != '\n') {
            buf[info.reps - 1] = '\n';
        }

        buf[len - 1] = 0;
        printv("[winpv] %s", buf);

        return true;
    }

    printv("xen-pfd: invalid write: port=0x%lx, size=%lu\n", port, size);
    return false;
}

static bool ioport_in(base_vcpu *vcpu, io_insn_handler::info_t &info)
{
    switch (info.port_number) {
    case XEN_IOPORT:
        printv("xen-pfd: read from xen debug port unsupported\n");
        return false;
    case PFD_IOPORT:
    case PFD_IOPORT + 2:
        return pfd_ioport_in(vcpu, info);
    default:
        return false;
    }
}

static bool ioport_out(base_vcpu *vcpu, io_insn_handler::info_t &info)
{
    switch (info.port_number) {
    case XEN_IOPORT:
        printv("xen-pfd: write to xen debug port unsupported\n");
        return false;
    case PFD_IOPORT:
    case PFD_IOPORT + 2:
        return pfd_ioport_out(vcpu, info);
    default:
        return false;
    }
}

static bool pci_cfg_in(base_vcpu *vcpu, pci_cfg_info &info)
{
    expects(info.reg < pci_cfg.size());

    std::lock_guard lock(mutex);

    if (!enabled) {
        if (info.reg == 0) {
            pci_cfg_hdlr::write_cfg_info(~0, info);
        } else {
            pci_cfg_hdlr::write_cfg_info(0, info);
        }
        return true;
    }

    pci_cfg_hdlr::write_cfg_info(pci_cfg[info.reg], info);
    return true;
}

static bool pci_cfg_out(base_vcpu *vcpu, pci_cfg_info &info)
{
    expects(info.reg < pci_cfg.size());

    std::lock_guard lock(mutex);

    if (!enabled) {
        return true;
    }

    if (info.reg == PCI_PMIO_BAR_REG || info.reg == PCI_MMIO_BAR_REG) {
        return true;
    }

    uint32_t oldval = pci_cfg[info.reg];
    uint32_t newval = pci_cfg_hdlr::read_cfg_info(oldval, info);

    pci_cfg[info.reg] = newval;
    return true;
}

void init_xen_platform_pci(xen_vcpu *vcpu)
{
    std::lock_guard lock(mutex);

    if (pci_cfg_addr == pci_cfg_addr_inval) {
        pci_cfg_addr = alloc_pci_cfg_addr();
        if (pci_cfg_addr == pci_cfg_addr_inval) {
            printv("xen-pfd: failed to allocate BDF\n");
            return;
        }

        reset_pci_cfg();

        const auto b = pci_cfg_bus(pci_cfg_addr);
        const auto d = pci_cfg_dev(pci_cfg_addr);
        const auto f = pci_cfg_fun(pci_cfg_addr);

        snprintf(bdf_str, sizeof(bdf_str), "%02x:%02x.%02x", b, d, f);
        printv("xen-pfd: using BDF %s\n", bdf_str);
    }

    auto uvv = vcpu->m_uv_vcpu;

    uvv->add_pci_cfg_handler(pci_cfg_addr, {pci_cfg_in}, pci_dir_in);
    uvv->add_pci_cfg_handler(pci_cfg_addr, {pci_cfg_out}, pci_dir_out);

    uvv->emulate_io_instruction(XEN_IOPORT, {ioport_in}, {ioport_out});
    uvv->emulate_io_instruction(PFD_IOPORT, {ioport_in}, {ioport_out});
    uvv->emulate_io_instruction(PFD_IOPORT + 2, {ioport_in}, {ioport_out});
}

void enable_xen_platform_pci()
{
    std::lock_guard lock(mutex);

    if (!enabled) {
        printv("xen-pfd: enabled\n");
        enabled = true;
    }
}

void disable_xen_platform_pci()
{
    std::lock_guard lock(mutex);

    if (enabled) {
        printv("xen-pfd: disabled\n");
        enabled = false;
    }
}

}
