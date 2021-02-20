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

#include <hve/arch/intel_x64/disassembler.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vmexit/pci_cfg.h>
#include <mutex>
#include <pci/dev.h>
#include <pci/pci.h>
#include <printv.h>

#define MEMBER_EMU_IO(p, i, o)                                                 \
    m_vcpu->emulate_io_instruction(                                            \
        p, {&pci_cfg_handler::i, this}, {&pci_cfg_handler::o, this});

using namespace ::x64::portio;
using base_vcpu = microv::intel_x64::pci_cfg_handler::base_vcpu;
using cfg_info = microv::intel_x64::pci_cfg_handler::info;
using hdlr_itr_type = microv::intel_x64::pci_cfg_handler::hdlr_itr_type;
using cfg_key = uint64_t;

namespace microv::intel_x64 {

static uint8_t *reg_to_state_8(base_vcpu *vcpu, int reg) noexcept
{
    auto state = vcpu->state();

    switch (reg) {
    case X86_REG_AH:
        return (uint8_t *)&state->rax + 1;
    case X86_REG_AL:
        return (uint8_t *)&state->rax;
    case X86_REG_BH:
        return (uint8_t *)&state->rbx + 1;
    case X86_REG_BL:
        return (uint8_t *)&state->rbx;
    case X86_REG_BPL:
        return (uint8_t *)&state->rbp;
    case X86_REG_CH:
        return (uint8_t *)&state->rcx + 1;
    case X86_REG_CL:
        return (uint8_t *)&state->rcx;
    case X86_REG_DH:
        return (uint8_t *)&state->rdx + 1;
    case X86_REG_DIL:
        return (uint8_t *)&state->rdi;
    case X86_REG_DL:
        return (uint8_t *)&state->rdx;
    case X86_REG_SIL:
        return (uint8_t *)&state->rsi;
    case X86_REG_R8B:
        return (uint8_t *)&state->r08;
    case X86_REG_R9B:
        return (uint8_t *)&state->r09;
    case X86_REG_R10B:
        return (uint8_t *)&state->r10;
    case X86_REG_R11B:
        return (uint8_t *)&state->r11;
    case X86_REG_R12B:
        return (uint8_t *)&state->r12;
    case X86_REG_R13B:
        return (uint8_t *)&state->r13;
    case X86_REG_R14B:
        return (uint8_t *)&state->r14;
    case X86_REG_R15B:
        return (uint8_t *)&state->r15;
    default:
        return nullptr;
    }
}

static uint16_t *reg_to_state_16(base_vcpu *vcpu, int reg) noexcept
{
    auto state = vcpu->state();

    switch (reg) {
    case X86_REG_AX:
        return (uint16_t *)&state->rax;
    case X86_REG_BP:
        return (uint16_t *)&state->rbp;
    case X86_REG_BX:
        return (uint16_t *)&state->rbx;
    case X86_REG_CX:
        return (uint16_t *)&state->rcx;
    case X86_REG_DI:
        return (uint16_t *)&state->rdi;
    case X86_REG_DX:
        return (uint16_t *)&state->rdx;
    case X86_REG_SI:
        return (uint16_t *)&state->rsi;
    case X86_REG_R8W:
        return (uint16_t *)&state->r08;
    case X86_REG_R9W:
        return (uint16_t *)&state->r09;
    case X86_REG_R10W:
        return (uint16_t *)&state->r10;
    case X86_REG_R11W:
        return (uint16_t *)&state->r11;
    case X86_REG_R12W:
        return (uint16_t *)&state->r12;
    case X86_REG_R13W:
        return (uint16_t *)&state->r13;
    case X86_REG_R14W:
        return (uint16_t *)&state->r14;
    case X86_REG_R15W:
        return (uint16_t *)&state->r15;
    default:
        return nullptr;
    }
}

static uint32_t *reg_to_state_32(base_vcpu *vcpu, int reg) noexcept
{
    auto state = vcpu->state();

    switch (reg) {
    case X86_REG_EAX:
        return (uint32_t *)&state->rax;
    case X86_REG_EBP:
        return (uint32_t *)&state->rbp;
    case X86_REG_EBX:
        return (uint32_t *)&state->rbx;
    case X86_REG_ECX:
        return (uint32_t *)&state->rcx;
    case X86_REG_EDI:
        return (uint32_t *)&state->rdi;
    case X86_REG_EDX:
        return (uint32_t *)&state->rdx;
    case X86_REG_ESI:
        return (uint32_t *)&state->rsi;
    case X86_REG_R8D:
        return (uint32_t *)&state->r08;
    case X86_REG_R9D:
        return (uint32_t *)&state->r09;
    case X86_REG_R10D:
        return (uint32_t *)&state->r10;
    case X86_REG_R11D:
        return (uint32_t *)&state->r11;
    case X86_REG_R12D:
        return (uint32_t *)&state->r12;
    case X86_REG_R13D:
        return (uint32_t *)&state->r13;
    case X86_REG_R14D:
        return (uint32_t *)&state->r14;
    case X86_REG_R15D:
        return (uint32_t *)&state->r15;
    default:
        return nullptr;
    }
}

/*
 * Update the destination of the ECAM read access. The destination is
 * previously verified in valid_ecam_read to be a register operand, so
 * this function figures out the portion of the vcpu_state_t that is
 * implied by the register and updates it.
 */
static void update_ecam_read_mov(base_vcpu *vcpu,
                                 const disassembler::operand_t *dst,
                                 uint32_t val) noexcept
{
    switch (dst->size) {
    case 1: {
        uint8_t *ptr = reg_to_state_8(vcpu, dst->reg);
        if (!ptr) {
            printv("%s: unable to map reg %u to state\n", __func__, dst->reg);
            return;
        }

        *ptr = (uint8_t)val;
        return;
    }
    case 2: {
        uint16_t *ptr = reg_to_state_16(vcpu, dst->reg);
        if (!ptr) {
            printv("%s: unable to map reg %u to state\n", __func__, dst->reg);
            return;
        }

        *ptr = (uint16_t)val;
        return;
    }
    case 4: {
        uint32_t *ptr = reg_to_state_32(vcpu, dst->reg);
        if (!ptr) {
            printv("%s: unable to map reg %u to state\n", __func__, dst->reg);
            return;
        }

        *ptr = (uint32_t)val;
        return;
    }
    default:
        printv(
            "%s: destination operand size=%u invalid\n", __func__, dst->size);
        return;
    }
}

static void update_ecam_read_cmp_rflags(const disassembler::insn_t *insn,
                                        uint32_t src1,
                                        uint32_t src2)
{
    /* Flags updated by the cmp instruction */
    constexpr uint64_t status_flags =
        ::x64::rflags::carry_flag::mask | ::x64::rflags::parity_flag::mask |
        ::x64::rflags::auxiliary_carry_flag::mask |
        ::x64::rflags::zero_flag::mask | ::x64::rflags::sign_flag::mask |
        ::x64::rflags::overflow_flag::mask;

    uint64_t size = insn->detail->x86.operands[0].size;
    uint64_t cmp_rflags = 0;

    if (size == 1) {
        asm volatile(
            "movb %1, %%al \t\n"
            "movb %2, %%dl \t\n"
            "cmp %%al, %%dl \t\n"
            "pushfq \t\n"
            "popq %0\t\n"
            : "=r"(cmp_rflags)
            : "g"((uint8_t)src1), "g"((uint8_t)src2)
            : "cc");
    } else if (size == 2) {
        asm volatile(
            "movw %1, %%ax \t\n"
            "movw %2, %%dx \t\n"
            "cmp %%ax, %%dx \t\n"
            "pushfq \t\n"
            "popq %0\t\n"
            : "=r"(cmp_rflags)
            : "g"((uint16_t)src1), "g"((uint16_t)src2)
            : "cc");
    } else {
        asm volatile(
            "movl %1, %%eax \t\n"
            "movl %2, %%edx \t\n"
            "cmp %%eax, %%edx \t\n"
            "pushfq \t\n"
            "popq %0\t\n"
            : "=r"(cmp_rflags)
            : "g"(src1), "g"(src2)
            : "cc");
    }

    uint64_t rflags = vmcs_n::guest_rflags::get();

    rflags &= ~status_flags;
    rflags |= (cmp_rflags & status_flags);

    vmcs_n::guest_rflags::set(rflags);
}

static void update_ecam_read_test_rflags(const disassembler::insn_t *insn,
                                         uint32_t src1,
                                         uint32_t src2)
{
    /* Flags updated by the test instruction */
    constexpr uint64_t status_flags =
        ::x64::rflags::carry_flag::mask | ::x64::rflags::parity_flag::mask |
        ::x64::rflags::zero_flag::mask | ::x64::rflags::sign_flag::mask |
        ::x64::rflags::overflow_flag::mask;

    uint64_t size = insn->detail->x86.operands[0].size;
    uint64_t test_rflags = 0;

    if (size == 1) {
        asm volatile(
            "movb %1, %%al \t\n"
            "movb %2, %%dl \t\n"
            "test %%al, %%dl \t\n"
            "pushfq \t\n"
            "popq %0\t\n"
            : "=r"(test_rflags)
            : "g"((uint8_t)src1), "g"((uint8_t)src2)
            : "cc");
    } else if (size == 2) {
        asm volatile(
            "movw %1, %%ax \t\n"
            "movw %2, %%dx \t\n"
            "test %%ax, %%dx \t\n"
            "pushfq \t\n"
            "popq %0\t\n"
            : "=r"(test_rflags)
            : "g"((uint16_t)src1), "g"((uint16_t)src2)
            : "cc");
    } else {
        asm volatile(
            "movl %1, %%eax \t\n"
            "movl %2, %%edx \t\n"
            "test %%eax, %%edx \t\n"
            "pushfq \t\n"
            "popq %0\t\n"
            : "=r"(test_rflags)
            : "g"(src1), "g"(src2)
            : "cc");
    }

    uint64_t rflags = vmcs_n::guest_rflags::get();

    rflags &= ~status_flags;
    rflags |= (test_rflags & status_flags);

    vmcs_n::guest_rflags::set(rflags);
}

static int64_t extract_reg_value(base_vcpu *vcpu,
                                 const disassembler::operand_t *src,
                                 uint32_t *val)
{
    switch (src->size) {
    case 1: {
        uint8_t *ptr = reg_to_state_8(vcpu, src->reg);
        if (!ptr) {
            printv("%s: unable to map reg %u to state\n", __func__, src->reg);
            return -EINVAL;
        }

        *(uint8_t *)val = *ptr;
        return 0;
    }
    case 2: {
        uint16_t *ptr = reg_to_state_16(vcpu, src->reg);
        if (!ptr) {
            printv("%s: unable to map reg %u to state\n", __func__, src->reg);
            return -EINVAL;
        }

        *(uint16_t *)val = *ptr;
        return 0;
    }
    case 4: {
        uint32_t *ptr = reg_to_state_32(vcpu, src->reg);
        if (!ptr) {
            printv("%s: unable to map reg %u to state\n", __func__, src->reg);
            return -EINVAL;
        }

        *val = *ptr;
        return 0;
    }
    default:
        printv("%s: source operand size=%u invalid\n", __func__, src->size);
        return -EINVAL;
    }
}

static bool valid_ecam_read_mov(const disassembler::insn_t *insn) noexcept
{
    cs_x86 *x86 = &insn->detail->x86;
    if (x86->op_count != 2) {
        printv("%s: insn does not have two operands\n", __func__);
        return false;
    }

    cs_x86_op *op = &x86->operands[0];
    if (op->type != X86_OP_REG) {
        printv("%s: destination operand is not a register\n", __func__);
        return false;
    }

    if (op->access != CS_AC_WRITE) {
        printv("%s: destination operand is not written\n", __func__);
        return false;
    }

    return true;
}

static bool valid_ecam_read_cmp(const disassembler::insn_t *insn) noexcept
{
    cs_x86 *x86 = &insn->detail->x86;
    if (x86->op_count != 2) {
        printv("%s: insn does not have two operands\n", __func__);
        return false;
    }

    cs_x86_op *src1 = &x86->operands[0];
    cs_x86_op *src2 = &x86->operands[1];

    if (src1->type != X86_OP_MEM && src2->type != X86_OP_MEM) {
        printv("%s: insn has no memory operands\n", __func__);
        return false;
    }

    if (src1->size != src2->size) {
        printv("%s: insn operands have different sizes: src1=%u, src2=%u\n",
               __func__,
               src1->size,
               src2->size);
        return false;
    }

    if (src1->size != 1 && src1->size != 2 && src1->size != 4) {
        printv("%s: insn has invalid operand size=%u\n", __func__, src1->size);
        return false;
    }

    return true;
}

static bool valid_ecam_read_test(const disassembler::insn_t *insn) noexcept
{
    cs_x86 *x86 = &insn->detail->x86;
    if (x86->op_count != 2) {
        printv("%s: insn does not have two operands\n", __func__);
        return false;
    }

    cs_x86_op *src1 = &x86->operands[0];
    cs_x86_op *src2 = &x86->operands[1];

    if (src1->type != X86_OP_REG && src1->type != X86_OP_MEM) {
        printv("%s: invaid src1 operand type\n", __func__);
        return false;
    }

    if (src2->type != X86_OP_IMM && src2->type != X86_OP_REG) {
        printv("%s: invaid src2 operand type\n", __func__);
        return false;
    }

    if (src1->size != src2->size) {
        printv("%s: insn operands have different sizes: src1=%u, src2=%u\n",
               __func__,
               src1->size,
               src2->size);
        return false;
    }

    if (src1->size != 1 && src1->size != 2 && src1->size != 4) {
        printv("%s: insn has invalid operand size=%u\n", __func__, src1->size);
        return false;
    }

    return true;
}

static bool ecam_read_get_op(uint64_t index,
                             const disassembler::insn_t *insn,
                             base_vcpu *vcpu,
                             uint64_t gpa,
                             const hdlr_itr_type &hdlr_itr,
                             uint32_t *val)
{
    cs_x86 *x86 = &insn->detail->x86;
    cs_x86_op *op = &x86->operands[index];

    if (op->type == X86_OP_MEM) {
        uint64_t gpa_4k = bfn::upper(gpa, ::x64::pt::from);
        uint64_t gpa_4b = bfn::upper(gpa, 2);

        pci_cfg_handler::pmio_info pi = {
            .port_number = 0xCFC + (gpa - gpa_4b),
            .size_of_access = static_cast<uint64_t>(op->size - 1),
            .address = 0, /* unused */
            .val = 0,
            .ignore_write = false,   /* unused */
            .ignore_advance = false, /* unused */
            .reps = 1                /* unused */
        };

        cfg_info ci = {
            .exit_info = pi,
            .reg = static_cast<uint32_t>(gpa_4b - gpa_4k) >> 2,
            .again = false /* unused */
        };

        /* Call the handler registered via vcpu::add_pci_cfg_handler */
        if (!hdlr_itr->second(vcpu, ci)) {
            return false;
        }

        *val = pi.val;
        return true;
    }

    if (op->type == X86_OP_REG) {
        if (extract_reg_value(vcpu, op, val)) {
            printv("%s: failed to extract register value\n", __func__);
            return false;
        }

        return true;
    }

    if (op->type == X86_OP_IMM) {
        *val = (uint32_t)op->imm;
        return true;
    }

    return false;
}

static bool valid_ecam_read(const disassembler::insn_t *insn) noexcept
{
    if (!insn->detail) {
        printv("%s: insn detail not available\n", __func__);
        return false;
    }

    switch (insn->id) {
    case X86_INS_MOV:
        return valid_ecam_read_mov(insn);
    case X86_INS_CMP:
        return valid_ecam_read_cmp(insn);
    case X86_INS_TEST:
        return valid_ecam_read_test(insn);
    default:
        printv("%s: unexpected ECAM read insn: %s %s\n",
               __func__,
               insn->mnemonic,
               insn->op_str);
        return false;
    }
}

static bool valid_ecam_write(const disassembler::insn_t *insn) noexcept
{
    if (insn->id != X86_INS_MOV) {
        printv("%s: insn is not a mov\n", __func__);
        return false;
    }

    if (!insn->detail) {
        printv("%s: insn detail not available\n", __func__);
        return false;
    }

    cs_x86 *x86 = &insn->detail->x86;
    if (x86->op_count != 2) {
        printv("%s: insn does not have two operands\n", __func__);
        return false;
    }

    cs_x86_op *op = &x86->operands[1];
    if (op->type != X86_OP_REG) {
        printv("%s: source operand is not a register\n", __func__);
        return false;
    }

    if (op->access != CS_AC_READ) {
        printv("%s: source operand is not read\n", __func__);
        return false;
    }

    return true;
}

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
    {make_cfg_key(0xCFF, 1), {0xFF000000, 24}}};

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

uint32_t pci_cfg_handler::access_size(const cfg_info &info)
{
    return info.exit_info.size_of_access + 1;
}

uint32_t pci_cfg_handler::access_port(const cfg_info &info)
{
    return info.exit_info.port_number;
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

    if (vcpuid::is_root_vcpu(vcpu->id())) {
        m_default_in = {&pci_cfg_handler::root_def_in, this};
        m_default_out = {&pci_cfg_handler::root_def_out, this};
        return;
    }

    m_default_in = {&pci_cfg_handler::guest_def_in, this};
    m_default_out = {&pci_cfg_handler::guest_def_out, this};
    this->enable();
}

pci_cfg_handler::~pci_cfg_handler()
{
    for (const auto &p : m_insn_cache) {
        disasm()->free_insn(p.second);
    }
}

void pci_cfg_handler::enable()
{
    MEMBER_EMU_IO(0xCF8, pmio_addr_in, pmio_addr_out);

    if (vcpuid::is_root_vcpu(m_vcpu->id())) {
        MEMBER_EMU_IO(0xCFC, pmio_data_in, pmio_data_out);
        MEMBER_EMU_IO(0xCFD, pmio_data_in, pmio_data_out);
        MEMBER_EMU_IO(0xCFE, pmio_data_in, pmio_data_out);
        MEMBER_EMU_IO(0xCFF, pmio_data_in, pmio_data_out);
        return;
    }

    MEMBER_EMU_IO(0xCFA, pmio_data_in, pmio_data_out);
    MEMBER_EMU_IO(0xCFB, pmio_data_in, pmio_data_out);
    MEMBER_EMU_IO(0xCFC, pmio_data_in, pmio_data_out);
    MEMBER_EMU_IO(0xCFD, pmio_data_in, pmio_data_out);
    MEMBER_EMU_IO(0xCFE, pmio_data_in, pmio_data_out);
    MEMBER_EMU_IO(0xCFF, pmio_data_in, pmio_data_out);
}

void pci_cfg_handler::map_bdf_to_ecam(uint32_t bdf)
{
    const auto ecam_addr = find_ecam_page(bdf);

    /* Make sure the ECAM page is nonzero, 4K aligned */
    expects(ecam_addr != 0);
    expects(ecam_addr == bfn::upper(ecam_addr, ::x64::pt::from));

    /*
     * Associate the ECAM page with its corresponding bus/device/function
     * and unmap it from dom0's EPT.
     */
    const auto itr = m_ecam_map.find(ecam_addr);
    if (itr == m_ecam_map.end()) {
        m_ecam_map[ecam_addr] = bdf;

        auto ept = &m_vcpu->dom()->ept();
        auto ecam_2m = bfn::upper(ecam_addr, ::x64::pd::from);

        if (ept->is_2m(ecam_2m)) {
            bfvmm::intel_x64::ept::identity_map_convert_2m_to_4k(*ept, ecam_2m);
        }

        ept->unmap(ecam_addr);
        ept->release(ecam_addr);
    }
}

void pci_cfg_handler::add_in_handler(uint64_t addr, const delegate_t &hdlr)
{
    const auto bdf = (addr & ~(pci_reg_mask | pci_off_mask)) | pci_en_mask;
    m_in_hdlrs[bdf] = std::move(hdlr);

    if (m_vcpu->is_guest_vcpu()) {
        return;
    }

    this->map_bdf_to_ecam(bdf);
    m_vcpu->add_ept_read_violation_handler(
        {&pci_cfg_handler::mmio_data_in, this});
}

void pci_cfg_handler::add_out_handler(uint64_t addr, const delegate_t &hdlr)
{
    const auto bdf = (addr & ~(pci_reg_mask | pci_off_mask)) | pci_en_mask;
    m_out_hdlrs[bdf] = std::move(hdlr);

    if (m_vcpu->is_guest_vcpu()) {
        return;
    }

    this->map_bdf_to_ecam(bdf);
    m_vcpu->add_ept_write_violation_handler(
        {&pci_cfg_handler::mmio_data_out, this});
}

disassembler::insn_t *pci_cfg_handler::disasm_ecam_read(uint32_t bdf)
{
    auto rip = m_vcpu->rip();
    auto itr = m_insn_cache.find(rip);

    if (itr != m_insn_cache.end()) {
        return itr->second;
    }

    auto len = vmcs_n::vm_exit_instruction_length::get();
    constexpr auto MAX_X86_INSN_LEN = 15U;

    if (len > MAX_X86_INSN_LEN) {
        printv("%s: instruction length %lu is invalid, rip=0x%lx\n",
               __func__,
               len,
               rip);
        return nullptr;
    }

    auto map = m_vcpu->map_gva_4k<uint8_t>(rip, len);
    auto mode = m_vcpu->insn_mode();
    auto insn = disasm()->disasm_single(map.get(), rip, len, mode);

    if (!insn) {
        printv("%s: disasm_single failed, rip=0x%lx\n", __func__, rip);
        return nullptr;
    }

    printv("%s: %02x:%02x.%x: %s %s\n",
           __func__,
           pci_cfg_bus(bdf),
           pci_cfg_dev(bdf),
           pci_cfg_fun(bdf),
           insn->mnemonic,
           insn->op_str);

    if (!valid_ecam_read(insn)) {
        printv("%s: invalid ECAM read, rip=0x%lx: %s %s\n",
               __func__,
               rip,
               insn->mnemonic,
               insn->op_str);
        return nullptr;
    }

    m_insn_cache[rip] = insn;
    return insn;
}

disassembler::operand_t *pci_cfg_handler::disasm_ecam_write()
{
    auto rip = m_vcpu->rip();
    auto itr = m_insn_cache.find(rip);

    if (itr != m_insn_cache.end()) {
        auto insn = itr->second;
        return &insn->detail->x86.operands[1];
    }

    auto len = vmcs_n::vm_exit_instruction_length::get();
    constexpr auto MAX_X86_INSN_LEN = 15U;

    if (len > MAX_X86_INSN_LEN) {
        printv("%s: instruction length %lu is invalid, rip=0x%lx\n",
               __func__,
               len,
               rip);
        return nullptr;
    }

    auto map = m_vcpu->map_gva_4k<uint8_t>(rip, len);
    auto mode = m_vcpu->insn_mode();
    auto insn = disasm()->disasm_single(map.get(), rip, len, mode);

    if (!insn) {
        printv("%s: disasm_single failed, rip=0x%lx\n", __func__, rip);
        return nullptr;
    }

    if (!valid_ecam_write(insn)) {
        printv("%s: invalid ECAM write, rip=0x%lx\n", __func__, rip);
        return nullptr;
    }

    m_insn_cache[rip] = insn;
    return &insn->detail->x86.operands[1];
}

bool pci_cfg_handler::mmio_data_in(base_vcpu *vcpu, mmio_info &info)
{
    auto ecam_addr = bfn::upper(info.gpa, ::x64::pt::from);
    auto ecam_itr = m_ecam_map.find(ecam_addr);

    if (ecam_itr == m_ecam_map.end()) {
        printv("%s: ECAM page 0x%lx does not have an assigned BDF\n",
               __func__,
               ecam_addr);
        return false;
    }

    auto ecam_bdf = ecam_itr->second;
    auto hdlr_itr = m_in_hdlrs.find(ecam_bdf);

    if (hdlr_itr == m_in_hdlrs.end()) {
        printv(
            "%s: ECAM page 0x%lx does not have handler\n", __func__, ecam_addr);
        return false;
    }

    auto insn = this->disasm_ecam_read(ecam_bdf);
    if (!insn) {
        printv("%s: disasm_ecam_read failed @ gpa=0x%lx\n", __func__, info.gpa);
        return true;
    }

    if (insn->id == X86_INS_MOV) {
        /*
         * Translate this memory-mapped access into a port-mapped access. The
         * pmio_info is passed to the registered handler which uses the port-mapped
         * centric {read,write}_cfg_info interface provided by this class.
         */

        uint64_t gpa_4b = bfn::upper(info.gpa, 2);
        uint64_t size = insn->detail->x86.operands[0].size;

        pmio_info pi = {
            .port_number = 0xCFC + (info.gpa - gpa_4b),
            .size_of_access = size - 1,
            .address = 0, /* unused */
            .val = 0,
            .ignore_write = false,   /* unused */
            .ignore_advance = false, /* unused */
            .reps = 1                /* unused */
        };

        cfg_info ci = {
            .exit_info = pi,
            .reg = static_cast<uint32_t>(gpa_4b - ecam_addr) >> 2,
            .again = false /* unused */
        };

        /* Call the handler registered via vcpu::add_pci_cfg_handler */
        if (!hdlr_itr->second(vcpu, ci)) {
            return false;
        }

        /* Update vcpu state */
        update_ecam_read_mov(vcpu, &insn->detail->x86.operands[0], pi.val);
        info.ignore_advance = false;

        return true;
    }

    if (insn->id == X86_INS_CMP) {
        uint32_t src1 = 0;
        uint32_t src2 = 0;

        if (!ecam_read_get_op(0, insn, vcpu, info.gpa, hdlr_itr, &src1)) {
            printv("%s: failed to get src1 op of cmp\n", __func__);
            return false;
        }

        if (!ecam_read_get_op(1, insn, vcpu, info.gpa, hdlr_itr, &src2)) {
            printv("%s: failed to get src2 op of cmp\n", __func__);
            return false;
        }

        update_ecam_read_cmp_rflags(insn, src1, src2);
        info.ignore_advance = false;

        return true;
    }

    if (insn->id == X86_INS_TEST) {
        uint32_t src1 = 0;
        uint32_t src2 = 0;

        if (!ecam_read_get_op(0, insn, vcpu, info.gpa, hdlr_itr, &src1)) {
            printv("%s: failed to get src1 op of cmp\n", __func__);
            return false;
        }

        if (!ecam_read_get_op(1, insn, vcpu, info.gpa, hdlr_itr, &src2)) {
            printv("%s: failed to get src2 op of cmp\n", __func__);
            return false;
        }

        update_ecam_read_test_rflags(insn, src1, src2);
        info.ignore_advance = false;

        return true;
    }

    return false;
}

bool pci_cfg_handler::mmio_data_out(base_vcpu *vcpu, mmio_info &info)
{
    auto ecam_addr = bfn::upper(info.gpa, ::x64::pt::from);
    auto ecam_itr = m_ecam_map.find(ecam_addr);

    if (ecam_itr == m_ecam_map.end()) {
        printv("%s: ECAM page 0x%lx does not have an assigned BDF\n",
               __func__,
               ecam_addr);
        return false;
    }

    auto ecam_bdf = ecam_itr->second;
    auto hdlr_itr = m_out_hdlrs.find(ecam_bdf);

    if (hdlr_itr == m_out_hdlrs.end()) {
        printv(
            "%s: ECAM page 0x%lx does not have handler\n", __func__, ecam_addr);
        return false;
    }

    auto src_op = this->disasm_ecam_write();
    if (!src_op) {
        printv(
            "%s: disasm_ecam_write failed @ gpa=0x%lx\n", __func__, info.gpa);
        return true;
    }

    uint32_t val = 0;
    if (extract_reg_value(vcpu, src_op, &val)) {
        printv("%s: failed to extract value written to ECAM\n", __func__);
        return true;
    }

    /*
     * Translate this memory-mapped access into a port-mapped access. The
     * pmio_info is passed to the registered handler which uses the port-mapped
     * centric {read,write}_cfg_info interface provided by this class.
     */

    uint64_t gpa_4b = bfn::upper(info.gpa, 2);

    pmio_info pi = {
        .port_number = 0xCFC + (info.gpa - gpa_4b),
        .size_of_access = static_cast<uint64_t>(src_op->size - 1),
        .address = 0, /* unused */
        .val = val,
        .ignore_write = false,   /* unused */
        .ignore_advance = false, /* unused */
        .reps = 1                /* unused */
    };

    cfg_info ci = {.exit_info = pi,
                   .reg = static_cast<uint32_t>(gpa_4b - ecam_addr) >> 2,
                   .again = false};

    if (!hdlr_itr->second(vcpu, ci)) {
        return false;
    }

    if (ci.again) {
        info.ignore_advance = true;
        return true;
    }

    info.ignore_advance = false;
    return true;
}

bool pci_cfg_handler::pmio_addr_in(base_vcpu *vcpu, pmio_info &info)
{
    info.val = m_cf8;
    return true;
}

bool pci_cfg_handler::pmio_addr_out(base_vcpu *vcpu, pmio_info &info)
{
    m_cf8 = info.val;
    return true;
}

bool pci_cfg_handler::pmio_data_in(base_vcpu *vcpu, pmio_info &info)
{
    const auto bdf = m_cf8 & ~(pci_reg_mask | pci_off_mask);
    const auto iter = m_in_hdlrs.find(bdf);

    cfg_info ci = {
        .exit_info = info,
        .reg = pci_cfg_reg(m_cf8),
        .again = false /* unused */
    };

    if (iter == m_in_hdlrs.end()) {
        return m_default_in(vcpu, ci);
    }

    return iter->second(vcpu, ci);
}

bool pci_cfg_handler::pmio_data_out(base_vcpu *vcpu, pmio_info &info)
{
    const auto bdf = m_cf8 & ~(pci_reg_mask | pci_off_mask);
    const auto iter = m_out_hdlrs.find(bdf);

    cfg_info ci = {
        .exit_info = info, .reg = pci_cfg_reg(m_cf8), .again = false};

    bool handled = false;

    if (iter == m_out_hdlrs.end()) {
        handled = m_default_out(vcpu, ci);
    } else {
        handled = iter->second(vcpu, ci);
    }

    if (!handled) {
        return false;
    }

    info.ignore_advance = ci.again;

    return true;
}

bool pci_cfg_handler::root_def_in(base_vcpu *vcpu, cfg_info &info)
{
    phys_in(m_cf8, info);
    return true;
}

bool pci_cfg_handler::root_def_out(base_vcpu *vcpu, cfg_info &info)
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
