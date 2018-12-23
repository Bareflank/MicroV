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
#include <bfgpalayout.h>

#include <hve/arch/intel_x64/domain.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

domain::domain(domainid_type domainid) :
    hyperkernel::domain{domainid}
{
    if (domainid == 0) {
        this->setup_dom0();
    }
    else {
        this->setup_domU();
    }
}

void
domain::setup_dom0()
{
    // TODO:
    //
    // This should be changes to fix a couple of issues:
    // - We should calculate the max physical address range using CPUID
    //   and fill in EPT all the way to the end of addressable memory.
    // - We should fill in EPT using 1 gig pages and then when we donate memory
    //   the logic for doing this should be able to handle 1 gig pages.
    // - 1 gig pages should be used because VMWare is not supported anways,
    //   so we should assume that 1 gig page support is required. Once again,
    //   legacy support is not a focus of this project
    //

    ept::identity_map(
        m_ept_map, MAX_PHYS_ADDR
    );
}

void
domain::setup_domU()
{ }

void
domain::map_1g_ro(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_only); }

void
domain::map_2m_ro(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_only); }

void
domain::map_4k_ro(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_only); }

void
domain::map_1g_rw(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_write); }

void
domain::map_2m_rw(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_write); }

void
domain::map_4k_rw(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_write); }

void
domain::map_1g_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::map_2m_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::map_4k_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::unmap(uintptr_t gpa)
{ m_ept_map.unmap(gpa); }

void
domain::release(uintptr_t gpa)
{ m_ept_map.release(gpa); }

void
domain::set_uart(uart::port_type uart) noexcept
{ m_uart_port = uart; }

void
domain::set_pt_uart(uart::port_type uart) noexcept
{ m_pt_uart_port = uart; }

void
domain::setup_vcpu_uarts(gsl::not_null<vcpu *> vcpu)
{
    // Note:
    //
    // We explicitly disable the 4 default com ports. This is because the
    // Linux guest will attempt to probe these ports so they need to be
    // handled by something.
    //

    m_uart_3F8.disable(vcpu);
    m_uart_2F8.disable(vcpu);
    m_uart_3E8.disable(vcpu);
    m_uart_2E8.disable(vcpu);

    if (m_pt_uart_port == 0) {
        switch (m_uart_port) {
            case 0x3F8: m_uart_3F8.enable(vcpu); break;
            case 0x2F8: m_uart_2F8.enable(vcpu); break;
            case 0x3E8: m_uart_3E8.enable(vcpu); break;
            case 0x2E8: m_uart_2E8.enable(vcpu); break;

            default:
                break;
        };
    }
    else {
        m_pt_uart = std::make_unique<uart>(m_pt_uart_port);
        m_pt_uart->pass_through(vcpu);
    }
}

uint64_t
domain::dump_uart(const gsl::span<char> &buffer)
{
    if (m_pt_uart) {
        m_pt_uart->dump(buffer);
    }
    else {
        switch (m_uart_port) {
            case 0x3F8: return m_uart_3F8.dump(buffer);
            case 0x2F8: return m_uart_2F8.dump(buffer);
            case 0x3E8: return m_uart_3E8.dump(buffer);
            case 0x2E8: return m_uart_2E8.dump(buffer);

            default:
                break;
        };
    }

    return 0;
}

}
