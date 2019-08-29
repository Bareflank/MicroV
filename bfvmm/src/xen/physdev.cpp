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
#include <printv.h>
#include <xen/physdev.h>
#include <xen/vcpu.h>

namespace microv {

xen_physdev::xen_physdev(xen_vcpu *xen) :
    m_xen_vcpu{xen},
    m_uv_vcpu{xen->m_uv_vcpu}
{
}

bool xen_physdev::pci_device_add()
{
    auto pda = m_uv_vcpu->map_arg<physdev_pci_device_add_t>(m_uv_vcpu->rsi());

    printv("pci_device_add: %04x:%02x:%02x.%02x, flags: 0x%x\n",
        pda->seg, pda->bus, pda->devfn >> 3, pda->devfn & 7, pda->flags);

    m_uv_vcpu->set_rax(0);
    return true;
}

}
