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

#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <xen/xencon.h>
#include <xen/xen.h>

namespace microv {

xencon::xencon(xen *xen) :
    m_xen{xen},
    m_vcpu{xen->m_vcpu},
    m_dom{xen->m_dom}
{

}

bool xencon::handle_console_io()
{
    uint64_t len = m_vcpu->rsi();
    auto buf = m_vcpu->map_gva_4k<char>(m_vcpu->rdx(), len);

    switch (m_vcpu->rdi()) {
    case CONSOLEIO_read: {
        auto n = m_dom->hvc_rx_get(gsl::span(buf.get(), len));
        m_vcpu->set_rax(n);
        //if (n) {
        //    printf("console read: ");
        //    for (auto i = 0; i < n; i++) {
        //        printf("%c", buf.get()[i]);
        //    }
        //    printf("\n");
        //}
        return true;
    }
    case CONSOLEIO_write: {
        auto n = m_dom->hvc_tx_put(gsl::span(buf.get(), len));
        m_vcpu->set_rax(n);
        return true;
    }
    default:
        return false;
    }
}

}
