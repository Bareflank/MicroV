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

#include "../disassembler.h"
#include "../vcpu.h"
#include "io_instruction.h"

#include <unordered_map>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace microv::intel_x64
{

class vcpu;

class pci_cfg_handler {
public:
    using base_vcpu = bfvmm::intel_x64::vcpu;
    using pmio_hdlr = bfvmm::intel_x64::io_instruction_handler;
    using mmio_hdlr = bfvmm::intel_x64::ept_violation_handler;
    using pmio_info = pmio_hdlr::info_t;
    using mmio_info = mmio_hdlr::info_t;

    struct info {
        pmio_info &exit_info;
        uint32_t reg;
    };

    using delegate_t = delegate<bool(base_vcpu *, struct info &info)>;

    static uint32_t read_cfg_info(uint32_t val, const struct info &info);
    static void write_cfg_info(uint32_t val, struct info &info);

    void enable();

    void add_in_handler(uint64_t addr, const delegate_t &hdlr);
    void add_out_handler(uint64_t addr, const delegate_t &hdlr);

    pci_cfg_handler(vcpu *vcpu);
    ~pci_cfg_handler();
    pci_cfg_handler(pci_cfg_handler &&) = default;
    pci_cfg_handler &operator=(pci_cfg_handler &&) = default;
    pci_cfg_handler(const pci_cfg_handler &) = delete;
    pci_cfg_handler &operator=(const pci_cfg_handler &) = delete;

private:
    bool pmio_addr_in(base_vcpu *vcpu, pmio_info &info);
    bool pmio_addr_out(base_vcpu *vcpu, pmio_info &info);

    bool pmio_data_in(base_vcpu *vcpu, pmio_info &info);
    bool pmio_data_out(base_vcpu *vcpu, pmio_info &info);

    bool mmio_data_in(base_vcpu *vcpu, mmio_info &info);
    bool mmio_data_out(base_vcpu *vcpu, mmio_info &info);

    bool root_def_in(base_vcpu *vcpu, struct info &info);
    bool root_def_out(base_vcpu *vcpu, struct info &info);
    bool guest_def_in(base_vcpu *vcpu, struct info &info);
    bool guest_def_out(base_vcpu *vcpu, struct info &info);

    disassembler::operand_t *disasm_ecam_read();
    disassembler::operand_t *disasm_ecam_write();

    void map_bdf_to_ecam(uint32_t bdf);

    delegate_t m_default_in;
    delegate_t m_default_out;

    vcpu *m_vcpu{};
    uint64_t m_cf8{};

    std::unordered_map<uint64_t, delegate_t> m_in_hdlrs;
    std::unordered_map<uint64_t, delegate_t> m_out_hdlrs;

    /* Map ECAM address to bus/device/function */
    std::unordered_map<uint64_t, uint32_t> m_ecam_map;

    /* Cache for already-disassembled instructions */
    std::unordered_map<uint64_t, disassembler::insn_t *> m_insn_cache;
};

}
#endif
