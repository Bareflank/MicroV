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

#ifndef MICROV_XEN_VCPU_H
#define MICROV_XEN_VCPU_H

#include "types.h"
#include "domain.h"
#include "flask.h"
#include "gnttab.h"
#include "memory.h"
#include "physdev.h"
#include "version.h"

#include <public/domctl.h>
#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>
#include <public/io/console.h>
#include <public/platform.h>
#include <public/vcpu.h>
#include <public/xen.h>

namespace microv {

namespace intel_x64 {
    class vmcall_event_op_handler;
}

class xen_vcpu {
public:
    xen_vcpu(microv_vcpu *vcpu);

    bool is_xenstore();
    void queue_virq(uint32_t virq);
    void init_shared_info(uintptr_t shinfo_gpfn);
    uint64_t runstate_time(int state);

    void invept() const { m_uv_dom->invept(); }

    void push_external_interrupt(uint64_t vector);
    void queue_external_interrupt(uint64_t vector);
    void inject_external_interrupt(uint64_t vector);

    /*
     * Provides raw access. Use only when certain the pointer is
     * valid (e.g. xen_vcpu hypercall context).
     */
    microv_vcpu *m_uv_vcpu{};
    microv_domain *m_uv_dom{};
    xen_domain *m_xen_dom{};
    xen_vcpuid_t m_id{};
    uint32_t m_upcall_vector{};
    int m_origin{};
    std::unique_ptr<intel_x64::vmcall_event_op_handler> m_event_op_hdlr{};

private:
    friend class xen_memory;

    bool m_debug_hypercalls{true};
    bool debug_hypercall(microv_vcpu *vcpu);

    int set_timer();
    void stop_timer();
    void steal_pet_ticks();
    struct vcpu_time_info *vcpu_time();

    bool vmexit_save_tsc(base_vcpu *vcpu);
    void resume_update(bfobject *obj);

    bool register_vcpu_time();
    bool register_runstate();
    void update_runstate(int new_state);
    void update_wallclock(const struct xenpf_settime64 *time);

    bool xen_leaf4(base_vcpu *vcpu);
    bool handle_pet(base_vcpu *vcpu);
    bool handle_hlt(base_vcpu *vcpu, hlt_handler::info_t &);
    bool handle_interrupt(base_vcpu *vcpu, interrupt_handler::info_t &);
    bool init_hypercall_page(base_vcpu *vcpu, wrmsr_handler::info_t &);

    bool hvm_set_param(xen_hvm_param_t *param);
    bool hvm_get_param(xen_hvm_param_t *param);

    /* Hypercall handlers */
    bool guest_hypercall(microv_vcpu *vcpu);
    bool root_hypercall(microv_vcpu *vcpu);

    bool handle_memory_op();
    bool handle_xen_version();
    bool handle_hvm_op();
    bool handle_event_channel_op();
    bool handle_grant_table_op();
    bool handle_platform_op();
    bool handle_xsm_op();
    bool handle_console_io();
    bool handle_sysctl();
    bool handle_domctl();
    bool handle_physdev_op();
    bool handle_vcpu_op();
    bool handle_vm_assist();
    bool handle_sched_op();

    friend class xen_domain;
    friend class xen_flask;
    friend class xen_gnttab;
    friend class xen_version;
    friend class xen_physdev;

    std::unique_ptr<class xen_flask> m_flask;
    std::unique_ptr<class xen_version> m_xenver;
    std::unique_ptr<class xen_physdev> m_physdev;

    unique_map<struct shared_info> m_shinfo{};
    unique_map<struct xencons_interface> m_console{};
    unique_map<uint8_t> m_store{};
    unique_map<struct vcpu_time_info> m_user_vti{};

    std::mutex m_runstate_mtx;
    unique_map<struct vcpu_runstate_info> m_runstate{};

    uintptr_t m_shinfo_gpfn{};

    uint64_t m_tsc_shift{};
    uint64_t m_tsc_khz{};
    uint64_t m_tsc_mul{};
    uint64_t m_tsc_at_exit{};

    uint64_t m_pet_shift{};
    bool m_pet_enabled{};
    bool m_pet_hdlrs_added{};
    bool m_runstate_assist{};

    uint32_t m_apicid{};
    uint32_t m_acpiid{};

public:
    ~xen_vcpu() = default;
    xen_vcpu(xen_vcpu &&) = delete;
    xen_vcpu(const xen_vcpu &) = delete;
    xen_vcpu &operator=(xen_vcpu &&) = delete;
    xen_vcpu &operator=(const xen_vcpu &) = delete;

};
}

#endif
