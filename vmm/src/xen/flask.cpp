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
#include <xen/flask.h>
#include <xen/vcpu.h>

namespace microv {

xen_flask::xen_flask(xen_vcpu *xen) :
    m_uv_vcpu{xen->m_uv_vcpu}
{ }

bool xen_flask::handle(xen_flask_op_t *fop)
{
    if (fop->interface_version != XEN_FLASK_INTERFACE_VERSION) {
        m_uv_vcpu->set_rax(-EACCES);
        return true;
    }

    switch (fop->cmd) {
    case FLASK_SID_TO_CONTEXT:
        break;
    default:
        bfalert_nhex(0, "unhandled flask op", fop->cmd);
        break;
    }

    m_uv_vcpu->set_rax(-ENOSYS);
    return true;
}
}
