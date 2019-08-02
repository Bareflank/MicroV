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

#include "types.h"
#include "evtchn.h"
#include "gnttab.h"
#include "physdev.h"
#include "sysctl.h"
#include "xenmem.h"
#include "xenver.h"

#include <public/domctl.h>
#include <public/io/console.h>
#include <public/platform.h>
#include <public/vcpu.h>
#include <public/xen.h>

namespace microv {

class xen {
public:
    void queue_virq(uint32_t virq);

private:
    int set_timer();
    void stop_timer();
    void steal_pet_ticks();
    void system_time();
    void init_shared_info(uintptr_t shinfo_gpfn);

    bool vmexit_save_tsc(base_vcpu *vcpu);
    void resume_update(bfobject *obj);
    void update_runstate(int new_state);
    void update_wallclock(const struct xenpf_settime64 *time);

    bool xen_leaf4(base_vcpu *vcpu);
    bool handle_pet(base_vcpu *vcpu);
    bool handle_hlt(base_vcpu *vcpu, hlt_handler::info_t &);
    bool handle_interrupt(base_vcpu *vcpu, interrupt_handler::info_t &);

    /* Hypercall handlers */
    bool hypercall(xen_vcpu *vcpu);
    bool handle_memory_op();
    bool handle_xen_version();
    bool handle_hvm_op();
    bool handle_event_channel_op();
    bool handle_grant_table_op();
    bool handle_platform_op();
    bool handle_xsm_op();
    bool handle_console_io();
    bool handle_sysctl();
    bool handle_physdev_op();
    bool handle_vcpu_op();
    bool handle_vm_assist();

    xen_vcpu *m_vcpu{};
    xen_domain *m_dom{};

    friend class gnttab;
    friend class evtchn;
    friend class sysctl;
    friend class xenmem;
    friend class xenver;
    friend class physdev;

    std::unique_ptr<class gnttab> m_gnttab;
    std::unique_ptr<class evtchn> m_evtchn;
    std::unique_ptr<class sysctl> m_sysctl;
    std::unique_ptr<class xenmem> m_xenmem;
    std::unique_ptr<class xenver> m_xenver;
    std::unique_ptr<class physdev> m_physdev;

    bfvmm::x64::unique_map<struct shared_info> m_shinfo{};
    bfvmm::x64::unique_map<struct xencons_interface> m_console{};
    bfvmm::x64::unique_map<uint8_t> m_store{};
    bfvmm::x64::unique_map<struct vcpu_time_info> m_user_vti{};
    bfvmm::x64::unique_map<struct vcpu_runstate_info> m_runstate{};

    xen_domain_handle_t xdh{};
    struct xen_domctl_getdomaininfo info{};
    uintptr_t m_shinfo_gpfn{};

    uint64_t m_tsc_shift{};
    uint64_t m_tsc_khz{};
    uint64_t m_tsc_mul{};
    uint64_t m_tsc_at_exit{};

    uint64_t m_pet_shift{};
    bool m_pet_enabled{};
    bool m_pet_hdlrs_added{};
    bool m_runstate_assist{};

public:

    uint32_t domid{};
    uint32_t vcpuid{};
    uint32_t apicid{};
    uint32_t acpiid{};

    xen(xen_vcpu *vcpu, xen_domain *dom);
    ~xen() = default;

    xen(xen &&) = default;
    xen &operator=(xen &&) = default;

    xen(const xen &) = delete;
    xen &operator=(const xen &) = delete;
};
}

#endif
