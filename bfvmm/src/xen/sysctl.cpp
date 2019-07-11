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

#include <xen/sysctl.h>
#include <xen/xen.h>

#include <public/domctl.h>
#include <public/errno.h>

namespace microv {

sysctl::sysctl(xen *xen) : m_xen{xen}, m_vcpu{xen->m_vcpu}
{

}

bool sysctl::getdomaininfolist(xen_sysctl_t *ctl)
{
    auto info = ctl->u.getdomaininfolist;
    // map buffer

    return false;
}

bool sysctl::handle(xen_sysctl_t *ctl)
{
    if (ctl->interface_version != XEN_SYSCTL_INTERFACE_VERSION) {
        m_vcpu->set_rax(-EACCES);
        return true;
    }

    switch (ctl->cmd) {
    case XEN_SYSCTL_getdomaininfolist:
        return this->getdomaininfolist(ctl);
    default:
        bfalert_nhex(0, "unhandled sysctl", ctl->cmd);
    }

    return false;
}
}
