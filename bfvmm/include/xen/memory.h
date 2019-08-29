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

#ifndef MICROV_XEN_MEMORY_H
#define MICROV_XEN_MEMORY_H

#include "types.h"
#include <public/memory.h>

namespace microv {

class xen_memory {
    xen_vcpu *m_xen_vcpu{};
    microv_vcpu *m_uv_vcpu{};

public:
    /* boot */
    bool memory_map();
    bool add_to_physmap();
    bool decrease_reservation();

    /* xl create */
    bool get_sharing_freed_pages();
    bool get_sharing_shared_pages();

    xen_memory(xen_vcpu *xen);
    ~xen_memory() = default;

    xen_memory(xen_memory &&) = default;
    xen_memory(const xen_memory &) = delete;
    xen_memory &operator=(xen_memory &&) = default;
    xen_memory &operator=(const xen_memory &) = delete;
};

}
#endif
