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

#ifndef MICROV_XEN_HVM_H
#define MICROV_XEN_HVM_H

#include "types.h"
#include <public/hvm/params.h>

namespace microv {

bool xen_hvm_set_param(xen_vcpu *vcpu);
bool xen_hvm_get_param(xen_vcpu *vcpu);
bool xen_hvm_pagetable_dying(xen_vcpu *vcpu);
bool xen_hvm_set_evtchn_upcall_vector(xen_vcpu *vcpu);

class xen_hvm {
public:
    xen_hvm(xen_domain *dom, xen_memory *mem);

    bool set_param(xen_vcpu *vcpu, xen_hvm_param_t *param);
    bool get_param(xen_vcpu *vcpu, xen_hvm_param_t *param);
    uint64_t get_param(uint32_t index) const;

    ~xen_hvm() = default;
    xen_hvm(xen_hvm &&) = default;
    xen_hvm(const xen_hvm &) = delete;
    xen_hvm &operator=(xen_hvm &&) = default;
    xen_hvm &operator=(const xen_hvm &) = delete;

    xen_domain *xen_dom{};
    xen_memory *xen_mem{};
    std::array<uint64_t, HVM_NR_PARAMS> params{};
};

}
#endif
