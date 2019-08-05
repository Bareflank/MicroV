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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vmexit/pci_cfg.h>
#include <mutex>
#include <pci/dev.h>

#define STATIC_HDL_IO(p, i, o) m_vcpu->add_io_instruction_handler(p, {i}, {o})
#define STATIC_EMU_IO(p, i, o) m_vcpu->emulate_io_instruction(p, {i}, {o});

#define MEMBER_HDL_IO(p, i, o) \
m_vcpu->add_io_instruction_handler(p, \
                                   {&pci_cfg_handler::i, this}, \
                                   {&pci_cfg_handler::o, this});

#define MEMBER_EMU_IO(p, i, o) \
m_vcpu->emulate_io_instruction(p, \
                               {&pci_cfg_handler::i, this}, \
                               {&pci_cfg_handler::o, this});

using namespace ::x64::portio;
using base_vcpu = microv::intel_x64::pci_cfg_handler::base_vcpu;
using base_info = microv::intel_x64::pci_cfg_handler::base_info;
using cfg_info = microv::intel_x64::pci_cfg_handler::info;
using cfg_key = uint64_t;
namespace ioqual = vmcs_n::exit_qualification::io_instruction;

namespace microv::intel_x64 {

static constexpr cfg_key make_cfg_key(uint64_t port, uint32_t size)
{
    return (port << 32) | size;
}

static inline cfg_key make_cfg_key(const cfg_info &info)
{
    const uint64_t port = info.exit_info.port_number;
    const uint32_t size = info.exit_info.size_of_access + 1;

    return make_cfg_key(port, size);
}

struct cfg_access {
    uint32_t mask;
    uint32_t shift;
};

static const std::unordered_map<cfg_key, struct cfg_access> cfg_map = {
    {make_cfg_key(0xCFC, 1), {0x000000FF, 0}},
    {make_cfg_key(0xCFC, 2), {0x0000FFFF, 0}},
    {make_cfg_key(0xCFC, 4), {0xFFFFFFFF, 0}},
    {make_cfg_key(0xCFD, 1), {0x0000FF00, 8}},
    {make_cfg_key(0xCFD, 2), {0x00FFFF00, 8}},
    {make_cfg_key(0xCFE, 1), {0x00FF0000, 16}},
    {make_cfg_key(0xCFE, 2), {0xFFFF0000, 16}},
    {make_cfg_key(0xCFF, 1), {0xFF000000, 24}}
};

static inline void phys_in(uint32_t addr, cfg_info &info)
{
    outd(0xCF8, addr);
    pci_cfg_handler::write_cfg_info(ind(0xCFC), info);
}

static inline void phys_out(uint32_t addr, cfg_info &info)
{
    outd(0xCF8, addr);
    outd(0xCFC, pci_cfg_handler::read_cfg_info(ind(0xCFC), info));
}

uint32_t pci_cfg_handler::read_cfg_info(uint32_t oldval, const cfg_info &info)
{
    const auto key = make_cfg_key(info);
    const auto itr = cfg_map.find(key);

    if (itr == cfg_map.end()) {
        bfalert_info(0, "Unexpected PCI config out access");
        bfalert_subnhex(0, "port:", info.exit_info.port_number);
        bfalert_subnhex(0, "size:", info.exit_info.size_of_access + 1);
        return 0;
    }

    const auto access = itr->second;
    return (oldval & ~access.mask) | (info.exit_info.val << access.shift);
}

void pci_cfg_handler::write_cfg_info(uint32_t val, cfg_info &info)
{
    const auto key = make_cfg_key(info);
    const auto itr = cfg_map.find(key);

    if (itr == cfg_map.end()) {
        bfalert_info(0, "Unexpected PCI config in access");
        bfalert_subnhex(0, "port:", info.exit_info.port_number);
        bfalert_subnhex(0, "size:", info.exit_info.size_of_access + 1);
        info.exit_info.val = 0;
        return;
    }

    const auto access = itr->second;
    info.exit_info.val = (val & access.mask) >> access.shift;
}

pci_cfg_handler::pci_cfg_handler(vcpu *vcpu) : m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpuid::is_host_vm_vcpu(vcpu->id())) {
        m_default_in = {&pci_cfg_handler::host_def_in, this};
        m_default_out = {&pci_cfg_handler::host_def_out, this};
        return;
    }

    m_default_in = {&pci_cfg_handler::guest_def_in, this};
    m_default_out = {&pci_cfg_handler::guest_def_out, this};
    this->enable();
}

void pci_cfg_handler::enable()
{
    MEMBER_EMU_IO(0xCF8, addr_in, addr_out);

    if (vcpuid::is_host_vm_vcpu(m_vcpu->id())) {
        MEMBER_EMU_IO(0xCFC, data_in, data_out);
        MEMBER_EMU_IO(0xCFD, data_in, data_out);
        MEMBER_EMU_IO(0xCFE, data_in, data_out);
        MEMBER_EMU_IO(0xCFF, data_in, data_out);
        return;
    }

    MEMBER_EMU_IO(0xCFA, data_in, data_out);
    MEMBER_EMU_IO(0xCFB, data_in, data_out);
    MEMBER_EMU_IO(0xCFC, data_in, data_out);
    MEMBER_EMU_IO(0xCFD, data_in, data_out);
    MEMBER_EMU_IO(0xCFE, data_in, data_out);
    MEMBER_EMU_IO(0xCFF, data_in, data_out);
}

void pci_cfg_handler::add_in_handler(uint64_t addr, const delegate_t &hdlr)
{
    const auto bdf = (addr & ~(pci_reg_mask | pci_off_mask)) | pci_en_mask;
    m_in_hdlrs[bdf] = std::move(hdlr);
}

void pci_cfg_handler::add_out_handler(uint64_t addr, const delegate_t &hdlr)
{
    const auto bdf = (addr & ~(pci_reg_mask | pci_off_mask)) | pci_en_mask;
    m_out_hdlrs[bdf] = std::move(hdlr);
}

bool pci_cfg_handler::addr_in(base_vcpu *vcpu, base_info &info)
{
    info.val = m_cf8;
    return true;
}

bool pci_cfg_handler::addr_out(base_vcpu *vcpu, base_info &info)
{
    m_cf8 = info.val;
    return true;
}

bool pci_cfg_handler::data_in(base_vcpu *vcpu, base_info &info)
{
    const auto bdf = m_cf8 & ~(pci_reg_mask | pci_off_mask);
    const auto iter = m_in_hdlrs.find(bdf);

    cfg_info ci = {
        .exit_info = info,
        .reg = pci_cfg_reg(m_cf8)
    };

    if (iter == m_in_hdlrs.end()) {
        return m_default_in(vcpu, ci);
    }

    return iter->second(vcpu, ci);
}

bool pci_cfg_handler::data_out(base_vcpu *vcpu, base_info &info)
{
    const auto bdf = m_cf8 & ~(pci_reg_mask | pci_off_mask);
    const auto iter = m_out_hdlrs.find(bdf);

    cfg_info ci = {
        .exit_info = info,
        .reg = pci_cfg_reg(m_cf8)
    };

    if (iter == m_out_hdlrs.end()) {
        return m_default_out(vcpu, ci);
    }

    return iter->second(vcpu, ci);
}

bool pci_cfg_handler::host_def_in(base_vcpu *vcpu, cfg_info &info)
{
    phys_in(m_cf8, info);
    return true;
}

bool pci_cfg_handler::host_def_out(base_vcpu *vcpu, cfg_info &info)
{
    phys_out(m_cf8, info);
    return true;
}

bool pci_cfg_handler::guest_def_in(base_vcpu *vcpu, cfg_info &info)
{
    const auto reg0 = pci_cfg_read_reg(m_cf8, 0x0);
    if (!pci_cfg_is_present(reg0)) {
        phys_in(m_cf8, info);
        return true;
    }

    const auto reg2 = pci_cfg_read_reg(m_cf8, 0x2);
    const auto reg3 = pci_cfg_read_reg(m_cf8, 0x3);
    const bool host_bridge = pci_cfg_is_host_bridge(reg2);
    const bool pci_bridge = pci_cfg_is_pci_bridge(reg3);
    const bool normal = pci_cfg_is_normal(reg3);
    const bool multfn = pci_cfg_is_multifun(reg3);

    if (host_bridge) {
        switch (info.reg) {
        case 0x0:
            write_cfg_info(~0, info);
            break;
        case 0x2:
            write_cfg_info(reg2, info);
            break;
        case 0x3:
            if (multfn) {
                write_cfg_info(reg3, info);
            }
            break;
        default:
            write_cfg_info(0, info);
            break;
        }
        return true;
    } else if (pci_bridge) {
        switch (info.reg) {
        case 0x0:
        case 0x6 ... 0xC:
            phys_in(m_cf8, info);
            break;
        case 0x2:
            write_cfg_info(reg2, info);
            break;
        case 0x3:
            write_cfg_info(reg3, info);
            break;
        default:
            write_cfg_info(0, info);
            break;
        }
        return true;
    } else if (normal) {
        if (multfn) {
            switch (info.reg) {
            case 0:
            case 3:
                phys_in(m_cf8, info);
                break;
            default:
                write_cfg_info(0, info);
                break;
            }
        } else {
            write_cfg_info((!info.reg) ? ~0 : 0, info);
        }
        return true;
    }

    printf("PCI: unknown header: 0x%02x\n", pci_cfg_header(reg3));
    info.exit_info.val = (!info.reg) ? ~0 : 0;
    return true;
}

bool pci_cfg_handler::guest_def_out(base_vcpu *vcpu, cfg_info &info)
{
    return true;
}
}
