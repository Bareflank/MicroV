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

#ifndef UVCTL_VCPU_H
#define UVCTL_VCPU_H

#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>

#include <microv/hypercall.h>

struct uvc_domain;

struct uvc_vcpu {
    enum runstate {
        running,
        paused,
        halted
    };

    vcpuid_t id{INVALID_VCPUID};
    enum runstate state{halted};
    struct uvc_domain *domain{};
    mutable std::unique_lock<std::mutex> event_lock{};
    std::thread run_thread{};

    uvc_vcpu(vcpuid_t id, struct uvc_domain *dom);
    void launch();
    void halt() noexcept;
    void pause() noexcept;
    void unpause() noexcept;

private:
    void init_events();
    void run() const;
    void fault(uint64_t err) const noexcept;
    void usleep(const std::chrono::microseconds &us) const;
    void notify_mgmt_event(uint64_t event_code, uint64_t event_data) const;
    void notify_send_event(domainid_t domain) const;
    void wait(uint64_t us) const;
};

#endif
