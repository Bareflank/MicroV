//
// Copyright (C) 2018 Assured Information Security, Inc.
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

#include <bfdebug.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/uart.h>

#include <iostream>

//--------------------------------------------------------------------------
// Implementation
//--------------------------------------------------------------------------

#define make_delegate(a,b)                                                                          \
    eapis::intel_x64::a::handler_delegate_t::create<uart, &uart::b>(this)

#define EMULATE_IO_INSTRUCTION(a,b,c)                                                               \
    vcpu->emulate_io_instruction(                                                                   \
            a, make_delegate(io_instruction_handler, b), make_delegate(io_instruction_handler, c))

namespace boxy::intel_x64
{

uart::uart(port_type port) :
    m_port{port}
{ }

void
uart::enable(gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->is_dom0()) {
        bfdebug_nhex(1, "uart: dom0 not supported", m_port);
        return;
    }

    bfdebug_nhex(1, "uart: enabling", m_port);
    EMULATE_IO_INSTRUCTION(m_port + 0, reg0_in_handler, reg0_out_handler);
    EMULATE_IO_INSTRUCTION(m_port + 1, reg1_in_handler, reg1_out_handler);
    EMULATE_IO_INSTRUCTION(m_port + 2, reg2_in_handler, reg2_out_handler);
    EMULATE_IO_INSTRUCTION(m_port + 3, reg3_in_handler, reg3_out_handler);
    EMULATE_IO_INSTRUCTION(m_port + 4, reg4_in_handler, reg4_out_handler);
    EMULATE_IO_INSTRUCTION(m_port + 5, reg5_in_handler, reg5_out_handler);
    EMULATE_IO_INSTRUCTION(m_port + 6, reg6_in_handler, reg6_out_handler);
    EMULATE_IO_INSTRUCTION(m_port + 7, reg7_in_handler, reg7_out_handler);

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(uart, vmcall_dispatch)
    );
}

void
uart::disable(gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->is_dom0()) {
        bfdebug_nhex(1, "uart: dom0 not supported", m_port);
        return;
    }

    bfdebug_nhex(1, "uart: disabling", m_port);
    EMULATE_IO_INSTRUCTION(m_port + 0, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(m_port + 1, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(m_port + 2, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(m_port + 3, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(m_port + 4, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(m_port + 5, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(m_port + 6, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(m_port + 7, io_zero_handler, io_ignore_handler);

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(uart, vmcall_dispatch)
    );
}

void
uart::pass_through(gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->is_dom0()) {
        bfdebug_nhex(1, "uart: dom0 not supported", m_port);
        return;
    }

    bfdebug_nhex(1, "uart: passing through", m_port);
    vcpu->pass_through_io_accesses(m_port + 0);
    vcpu->pass_through_io_accesses(m_port + 1);
    vcpu->pass_through_io_accesses(m_port + 2);
    vcpu->pass_through_io_accesses(m_port + 3);
    vcpu->pass_through_io_accesses(m_port + 4);
    vcpu->pass_through_io_accesses(m_port + 5);
    vcpu->pass_through_io_accesses(m_port + 6);
    vcpu->pass_through_io_accesses(m_port + 7);

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(uart, vmcall_dispatch)
    );
}

uint64_t
uart::dump(const gsl::span<char> &buffer)
{
    uint64_t i;
    std::lock_guard lock(m_mutex);

    for (i = 0; i < m_index; i++) {
        buffer.at(static_cast<std::ptrdiff_t>(i)) = m_buffer.at(i);
    }

    m_index = 0;
    return i;
}

bool
uart::io_zero_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x0;
    return true;
}

bool
uart::io_ignore_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
uart::reg0_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    std::lock_guard lock(m_mutex);

    if (this->dlab()) {
        info.val = m_baud_rate_l;
    }
    else {
        info.val = 0x0;
    }

    return true;
}

bool
uart::reg1_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    std::lock_guard lock(m_mutex);

    if (this->dlab()) {
        info.val = m_baud_rate_h;
    }
    else {
        info.val = 0x0;
    }

    return true;
}

bool
uart::reg2_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x0;
    bfalert_info(1, "uart: reg2 read not supported");

    return true;
}

bool
uart::reg3_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    std::lock_guard lock(m_mutex);

    info.val = m_line_control_register;
    return true;
}

bool
uart::reg4_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x0;
    bfalert_info(1, "uart: reg4 read not supported");

    return true;
}

bool
uart::reg5_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x60;
    return true;
}

bool
uart::reg6_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x0;
    bfalert_info(1, "uart: reg6 read not supported");

    return true;
}

bool
uart::reg7_in_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0x0;
    bfalert_info(1, "uart: reg7 read not supported");

    return true;
}

bool
uart::reg0_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    std::lock_guard lock(m_mutex);

    if (this->dlab()) {
        m_baud_rate_l = gsl::narrow<data_type>(info.val);
    }
    else {
        this->write(gsl::narrow<char>(info.val));
    }

    return true;
}

bool
uart::reg1_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    std::lock_guard lock(m_mutex);

    if (this->dlab()) {
        m_baud_rate_h = gsl::narrow<data_type>(info.val);
    }
    else {
        if (info.val != 0) {
            bfalert_info(1, "uart: none-zero write to reg1 unsupported");
        }
    }

    return true;
}

bool
uart::reg2_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
uart::reg3_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    std::lock_guard lock(m_mutex);

    m_line_control_register = gsl::narrow<data_type>(info.val);
    return true;
}

bool
uart::reg4_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
uart::reg5_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    bfalert_info(1, "uart: reg5 write not supported");
    return true;
}

bool
uart::reg6_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    bfalert_info(1, "uart: reg6 write not supported");
    return true;
}

bool
uart::reg7_out_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    bfalert_info(1, "uart: reg7 write not supported");
    return true;
}

void
uart::write(const char c)
{
    if (m_index < m_buffer.size()) {
        m_buffer.at(m_index++) = c;
    }
}

void
uart::write(const char *str)
{
    for (auto i = 0U; i < strlen(str); i++) {
        this->write(str[i]);
    }
}

bool
uart::vmcall_dispatch(
    gsl::not_null<vcpu *> vcpu)
{
    if (bfopcode(vcpu->rax()) != __enum_uart_op) {
        return false;
    }

    if (vcpu->rcx() != m_port) {
        return false;
    }

    switch (vcpu->rbx()) {
        case __enum_uart_op__char:
            this->write(gsl::narrow_cast<char>(vcpu->rdx()));
            break;

        case __enum_uart_op__nhex:
            this->write(bfn::to_string(vcpu->rdx(), 16).c_str());
            break;

        case __enum_uart_op__ndec:
            this->write(bfn::to_string(vcpu->rdx(), 10).c_str());
            break;

        default:
            vcpu->halt("unknown uart op");
    };

    return true;
}

}
