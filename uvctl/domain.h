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
#include <condition_variable>
#include <microv/hypercall.h>

struct uvc_vcpu;

struct uvc_domain {
    domainid_t id{INVALID_DOMAINID};
    struct uvc_domain *parent{};

    bool enable_uart{};
    bool enable_hvc{};
    bool enable_events{};

    std::thread uart_recv{};
    std::thread hvc_recv{};
    std::thread hvc_send{};

    std::mutex vcpu_mtx{};
    std::list<struct uvc_vcpu> vcpu_list{};
    std::list<struct uvc_domain> child_list{};

    std::mutex event_mtx{};
    std::thread event_thread{};
    std::condition_variable event_cond{};
    uint64_t event_code{};
    uint64_t event_data{};

    uvc_domain();
    uvc_domain(domainid_t id, struct uvc_domain *parent);

    void create_vcpu();
    void destroy_vcpus();
    void launch();

    void handle_events();
    void create_child(domainid_t domid);
    void pause_child(domainid_t domid);
    void unpause_child(domainid_t domid);
    void destroy_child(domainid_t domid);

    void pause();
    void unpause();
    void destroy();

    void recv_uart();
    void recv_hvc();
    void send_hvc();

    bool is_root() const noexcept;
};

#endif
