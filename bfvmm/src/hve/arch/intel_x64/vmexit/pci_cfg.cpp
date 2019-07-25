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

using base_vcpu = microv::intel_x64::pci_cfg_handler::base_vcpu;
using base_info = microv::intel_x64::pci_cfg_handler::base_info;
using cfg_info = microv::intel_x64::pci_cfg_handler::info;
using namespace ::x64::portio;
namespace ioqual = vmcs_n::exit_qualification::io_instruction;

static std::mutex cfg_mutex;

static void phys_in(uint32_t addr, cfg_info &info)
{
    auto &exit_info = info.exit_info;
    const auto port = gsl::narrow_cast<uint16_t>(exit_info.port_number);

    std::lock_guard<std::mutex> lock(cfg_mutex);
    outd(0xCF8, addr);

    switch (exit_info.size_of_access) {
    case ioqual::size_of_access::one_byte:
        exit_info.val = inb(port);
        break;
    case ioqual::size_of_access::two_byte:
        exit_info.val = inw(port);
        break;
    default:
        exit_info.val = ind(port);
        break;
    }
}

static void phys_out(uint32_t addr, cfg_info &info)
{
    using namespace ::x64::portio;

    const auto &exit_info = info.exit_info;
    const auto port = gsl::narrow_cast<uint16_t>(exit_info.port_number);

    std::lock_guard<std::mutex> lock(cfg_mutex);
    outd(0xCF8, addr);

    switch (exit_info.size_of_access) {
    case ioqual::size_of_access::one_byte:
        outb(port, gsl::narrow_cast<uint8_t>(exit_info.val));
        break;
    case ioqual::size_of_access::two_byte:
        outw(port, gsl::narrow_cast<uint16_t>(exit_info.val));
        break;
    default:
        outd(port, exit_info.val);
        break;
    }
}

static bool guest_def_in(base_vcpu *vcpu, cfg_info &info)
{
    bfignored(vcpu);

    info.exit_info.val = 0xFFFFFFFF;
    return true;
}

static bool guest_def_out(base_vcpu *vcpu, cfg_info &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

namespace microv::intel_x64 {

/*
 * An io emulator does not do any portio from the base
 * An in emulator stores the value of info.val to rax
 * An out emulator writes the vcpu register to info.val
 */

pci_cfg_handler::pci_cfg_handler(vcpu *vcpu) : m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpuid::is_host_vm_vcpu(vcpu->id())) {
        m_default_in = {&pci_cfg_handler::host_def_in, this};
        m_default_out = {&pci_cfg_handler::host_def_out, this};
        return;
    }

    m_default_in = {guest_def_in};
    m_default_out = {guest_def_out};
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

}
