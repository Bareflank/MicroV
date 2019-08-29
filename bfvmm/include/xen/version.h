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

#ifndef MICROV_XEN_VERSION_H
#define MICROV_XEN_VERSION_H

#include "types.h"
#include <public/version.h>

namespace microv {

class xen_version {
private:
    xen_vcpu *m_xen{};
    microv_vcpu *m_vcpu{};

public:
    bool build_id();
    bool capabilities();
    bool changeset();
    bool commandline();
    bool compile_info();
    bool extraversion();
    bool get_features();
    bool guest_handle();
    bool pagesize();
    bool platform_parameters();
    bool version();

    xen_version(xen_vcpu *xen);
    ~xen_version() = default;
    xen_version(xen_version &&) = default;
    xen_version(const xen_version &) = delete;
    xen_version &operator=(xen_version &&) = default;
    xen_version &operator=(const xen_version &) = delete;
};

}
#endif
