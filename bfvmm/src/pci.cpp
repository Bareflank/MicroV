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
#include <pci/dev.h>
#include <hve/arch/intel_x64/vcpu.h>

extern microv::intel_x64::vcpu *vcpu0;
using namespace bfvmm::x64;

namespace microv {

/*
 * Owner of PCI devices enumerated on the platform. Each key
 * is a PCI CONFIG_ADDR value with the enable bit (bit 31),
 * bus, device, and function set. The register and offset bits are 0.
 */
static std::unordered_map<uint32_t, std::unique_ptr<class pci_dev>> pci_devs;

static int probe_bus(uint32_t b, struct pci_dev *bridge)
{
    for (auto d = 0; d < pci_nr_dev; d++) {
        for (auto f = 0; f < pci_nr_fun; f++) {
            auto addr = pci_cfg_bdf_to_addr(b, d, f);

            if (pci_cfg_is_present(addr)) {
                pci_devs[addr] = std::make_unique<class pci_dev>(addr, bridge);
                printf("added pci device: %02x:%02x.%02x\n", b, d, f);

                auto pdev = pci_devs[addr].get();
                if (pdev->is_pci_bridge()) {
                    auto reg6 = pci_cfg_read_reg(addr, 6);
                    auto next = pci_bridge_sec_bus(reg6);
                    probe_bus(next, pdev);
                }
            }
        }
    }

    return 0;
}

int probe_pci()
{
    auto addr = pci_cfg_bdf_to_addr(0, 0, 0);
    pci_devs[addr] = std::make_unique<class pci_dev>(addr);

    return probe_bus(0, pci_devs[addr].get());
}

}
