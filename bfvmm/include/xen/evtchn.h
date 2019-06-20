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

#ifndef MICROV_EVTCHN_H
#define MICROV_EVTCHN_H

#include <public/xen.h>
#include <public/event_channel.h>
#include <bfhypercall.h>

namespace microv::xen {

struct evtchn {
    enum state : uint8_t {
        state_free,
        state_reserved,
        state_unbound,
        state_interdomain,
        state_pirq,
        state_virq,
        state_ipi
    };

    using state_t = enum state;

    union evtdata {
        uint32_t virq;
        // TODO:
        // unbound-specific data
        // interdomain-specific data
        // pirq-specific data
    } data;

    bool is_pending{};
    enum state state{state_free};

    uint8_t priority{EVTCHN_FIFO_PRIORITY_DEFAULT};
    uint8_t prev_priority{EVTCHN_FIFO_PRIORITY_DEFAULT};

    vcpuid_t vcpuid{};
    vcpuid_t prev_vcpuid{};

    evtchn_port_t port{};
    /// TODO mutable std::mutex mutex{};
};

}
#endif
