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

#ifndef MICROV_XEN_CONSOLE_H
#define MICROV_XEN_CONSOLE_H

#include "types.h"
#include <public/io/console.h>
#include <public/xen.h>

namespace microv {

class xencon {
    xen *m_xen{};
    xen_vcpu *m_vcpu{};
    xen_domain *m_dom{};

    alignas(4096) struct xencons_interface m_intf{};


public:
    /*
     * CONSOLE_IO hypercall handler. For some reason, Xen chose to
     * support two different console read/write mechanism. One is through
     * hypercalls, used for dom0; the other uses shared memory & events
     * via HVM_PARAM_CONSOLE_{PFN,EVTCHN}. This function is for the
     * hypercall version.
     */
    bool handle_console_io();

    xencon(xen *xen);
    ~xencon() = default;

    xencon(xencon &&) = default;
    xencon &operator=(xencon &&) = default;

    xencon(const xencon &) = delete;
    xencon &operator=(const xencon &) = delete;
};

}
#endif
