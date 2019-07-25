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

#ifndef PCI_CFG_HANDLER_MICROV_H
#define PCI_CFG_HANDLER_MICROV_H

#include "../vcpu.h"
#include "io_instruction.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace microv::intel_x64
{

class vcpu;

class pci_cfg_handler {
public:
    using base_vcpu = bfvmm::intel_x64::vcpu;
    using base_hdlr = bfvmm::intel_x64::io_instruction_handler;
    using base_info = base_hdlr::info_t;

    struct info {
        base_info &exit_info;
        uint32_t reg;
    };

    using delegate_t = delegate<bool(base_vcpu *, struct info &info)>;

    void enable();
    void add_in_handler(uint64_t addr, const delegate_t &hdlr);
    void add_out_handler(uint64_t addr, const delegate_t &hdlr);

    pci_cfg_handler(vcpu *vcpu);

    ~pci_cfg_handler() = default;
    pci_cfg_handler(pci_cfg_handler &&) = default;
    pci_cfg_handler &operator=(pci_cfg_handler &&) = default;
    pci_cfg_handler(const pci_cfg_handler &) = delete;
    pci_cfg_handler &operator=(const pci_cfg_handler &) = delete;

private:
    bool addr_in(base_vcpu *vcpu, base_info &info);
    bool data_in(base_vcpu *vcpu, base_info &info);

    bool addr_out(base_vcpu *vcpu, base_info &info);
    bool data_out(base_vcpu *vcpu, base_info &info);

    bool host_def_in(base_vcpu *vcpu, struct info &info);
    bool host_def_out(base_vcpu *vcpu, struct info &info);

    delegate_t m_default_in;
    delegate_t m_default_out;

    vcpu *m_vcpu{};
    uint64_t m_cf8{};

    std::unordered_map<uint64_t, delegate_t> m_in_hdlrs;
    std::unordered_map<uint64_t, delegate_t> m_out_hdlrs;
};

}
#endif
