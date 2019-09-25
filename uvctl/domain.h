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

#ifndef UVCTL_DOMAIN_H
#define UVCTL_DOMAIN_H

#include <list>
#include <mutex>
#include <thread>
#include <microv/hypercall.h>

struct uvc_vcpu;

struct uvc_domain {
    domainid_t id{INVALID_DOMAINID};

    bool enable_uart{};
    bool enable_hvc{};

    std::thread uart_recv{};
    std::thread hvc_recv{};
    std::thread hvc_send{};

    std::mutex vcpu_mtx{};
    std::list<struct uvc_vcpu> vcpu_list{};

    std::mutex child_mtx{};
    std::list<struct uvc_domain> child_list{};

    vcpuid_t create_vcpu();
    void launch_vcpu(vcpuid_t id);
    void destroy_vcpu(vcpuid_t id);

    void kill();
    void kill_vcpus();
    void kill_children();
};

#endif
