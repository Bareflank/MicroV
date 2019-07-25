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

#include <bfvcpuid.h>
#include <pci/dev.h>
#include <hve/arch/intel_x64/vcpu.h>

extern microv::intel_x64::vcpu *vcpu0;
using namespace bfvmm::x64;

namespace microv {

extern char *mcfg_hva;
extern size_t mcfg_len;

/*
 * Owner of PCI devices enumerated on the platform. Each key
 * is a PCI CONFIG_ADDR value with the enable bit (bit 31),
 * bus, device, and function set. The register and offset bits are 0.
 */
static std::unordered_map<uint32_t, std::unique_ptr<class pci_dev>> pci_dev_map;

/* List of all PCI devices */
static std::list<class pci_dev *> pci_devs;

/* List of PCI devices to passthru */
std::list<class pci_dev *> pci_devs_pt;

static int probe_bus(uint32_t b, struct pci_dev *bridge)
{
    for (auto d = 0; d < pci_nr_dev; d++) {
        for (auto f = 0; f < pci_nr_fun; f++) {
            auto addr = pci_cfg_bdf_to_addr(b, d, f);
            if (!pci_cfg_is_present(addr)) {
                continue;
            }

            pci_dev_map[addr] = std::make_unique<class pci_dev>(addr, bridge);
            auto pdev = pci_dev_map[addr].get();
            pci_devs.push_back(pdev);

            if (pdev->is_pci_bridge()) {
                auto reg6 = pci_cfg_read_reg(addr, 6);
                auto next = pci_bridge_sec_bus(reg6);
                probe_bus(next, pdev);
            } else if (pdev->is_netdev()) {
                pci_devs_pt.push_back(pdev);
                pdev->passthru = true;
                pdev->parse_cap_regs();
            }
        }
    }

    return 0;
}

int probe_pci()
{
    expects(mcfg_hva);
    expects(mcfg_len);

    auto addr = pci_cfg_bdf_to_addr(0, 0, 0);
    pci_dev_map[addr] = std::make_unique<class pci_dev>(addr);

    return probe_bus(0, pci_dev_map[addr].get());
}

}
