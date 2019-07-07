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

#ifndef MICROV_XEN_H
#define MICROV_XEN_H

#include <memory>
#include "evtchn.h"
#include "gnttab.h"

namespace bfvmm::intel_x64 {
    class vcpu;
}

namespace microv::intel_x64 {
    class domain;
    class vcpu;
}

namespace microv::xen {

class xen {
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu of the xen
    ///
    xen(microv::intel_x64::vcpu *vcpu, microv::intel_x64::domain *dom);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~xen() = default;

private:
    friend class microv::intel_x64::vcpu;

    bool xen_leaf4(bfvmm::intel_x64::vcpu *vcpu);

    bool handle_hypercall(microv::intel_x64::vcpu *vcpu);
    bool handle_memory_op();
    bool handle_xen_version();
    bool handle_hvm_op();
    bool handle_event_channel_op();
    bool handle_grant_table_op();
    bool handle_platform_op();
    bool handle_console_io();

    microv::intel_x64::vcpu *m_vcpu{};
    microv::intel_x64::domain *m_dom{};

    std::unique_ptr<gnttab> m_gnttab;
    std::unique_ptr<evtchn> m_evtchn;

    bfvmm::x64::unique_map<struct shared_info> m_shinfo{};
    bfvmm::x64::unique_map<uint8_t> m_console{};
    bfvmm::x64::unique_map<uint8_t> m_store{};

public:

    uint32_t domid{};
    uint32_t vcpuid{};
    uint32_t apicid{};
    uint32_t acpiid{};

    /// @cond

    xen(xen &&) = default;
    xen &operator=(xen &&) = default;

    xen(const xen &) = delete;
    xen &operator=(const xen &) = delete;

    /// @endcond
};
}

#endif
