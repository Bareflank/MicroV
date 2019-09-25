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

#include <stdexcept>

#include "domain.h"
#include "vcpu.h"

vcpuid_t uvc_domain::create_vcpu()
{
    auto newid = __vcpu_op__create_vcpu(id);
    if (newid == INVALID_VCPUID) {
        throw std::runtime_error("create_vcpu failed");
    }

    std::lock_guard lock(vcpu_mtx);
    vcpu_list.emplace_front(newid, this);

    return newid;
}

void uvc_domain::launch_vcpu(vcpuid_t vcpuid)
{
    std::lock_guard lock(vcpu_mtx);

    for (auto v = vcpu_list.begin(); v != vcpu_list.end(); v++) {
        if (v->id == vcpuid) {
            v->launch();
            return;
        }
    }
}
