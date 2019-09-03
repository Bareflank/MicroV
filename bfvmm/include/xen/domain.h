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

#ifndef MICROV_XEN_DOMAIN_H
#define MICROV_XEN_DOMAIN_H

#include "../ring.h"
#include "../domain/domain.h"
#include "types.h"

#include <public/domctl.h>
#include <public/sysctl.h>
#include <public/platform.h>

namespace microv {

xen_domid_t create_xen_domain(microv_domain *uv_dom);
xen_domain *get_xen_domain(xen_domid_t id) noexcept;
void put_xen_domain(xen_domid_t id) noexcept;
void destroy_xen_domain(xen_domid_t id);

/* syctls */
bool xen_domain_numainfo(xen_vcpu *vcpu, struct xen_sysctl *ctl);
bool xen_domain_cputopoinfo(xen_vcpu *vcpu, struct xen_sysctl *ctl);
bool xen_domain_getinfolist(xen_vcpu *vcpu, struct xen_sysctl *ctl);

/* domctls */
bool xen_domain_createdomain(xen_vcpu *vcpu, struct xen_domctl *ctl);
bool xen_domain_setvcpuaffinity(xen_vcpu *vcpu, struct xen_domctl *ctl);
bool xen_domain_max_mem(xen_vcpu *vcpu, struct xen_domctl *ctl);

/**
 * xen_domain
 *
 * This is the primary structure that contains information specific
 * to xen domains. There are two paths from which a xen domain can
 * be created:
 *   - domain_op__create_domain hypercall from a bareflank root vcpu
 *   - domctl::createdomain hypercall from a xen guest dom0
 *
 * TODO: add locks to protect readers (e.g. get_info) from updates
 * (e.g. move_cpupool). This isn't strictly necessary until we have
 * multiple domains reading and writing domain data.
 */
class xen_domain {
public:
    xen_domain(microv_domain *domain);
    ~xen_domain();

    void queue_virq(int virq);
    void bind_vcpu(xen_vcpu *xen);
    void get_info(struct xen_domctl_getdomaininfo *info);
    uint64_t runstate_time(int state);
    uint32_t nr_online_vcpus();
    xen_vcpuid_t max_vcpu_id();

    size_t hvc_rx_put(const gsl::span<char> &span);
    size_t hvc_rx_get(const gsl::span<char> &span);
    size_t hvc_tx_put(const gsl::span<char> &span);
    size_t hvc_tx_get(const gsl::span<char> &span);

    /* Hypercalls from xl create path */
    bool numainfo(xen_vcpu *v, struct xen_sysctl_numainfo *numa);
    bool cputopoinfo(xen_vcpu *v, struct xen_sysctl_cputopoinfo *topo);
    bool setvcpuaffinity(xen_vcpu *v, struct xen_domctl_vcpuaffinity *aff);
    bool set_max_mem(xen_vcpu *v, struct xen_domctl_max_mem *max);
    bool physinfo(xen_vcpu *v, struct xen_sysctl *ctl);
    bool move_cpupool(xen_vcpu *v, struct xen_sysctl *ctl);
    bool get_sharing_freed_pages(xen_vcpu *v);
    bool get_sharing_shared_pages(xen_vcpu *v);

    /* Hypercalls from vcpu boot path */
    uint64_t init_shared_info(xen_vcpu *v, uintptr_t shinfo_gpfn);
    void update_wallclock(xen_vcpu *v,
                          const struct xenpf_settime64 *time) noexcept;

private:
    friend class xen_evtchn;
    class xen_vcpu *get_xen_vcpu() noexcept;
    void put_xen_vcpu() noexcept;

public:
    microv::domain_info *m_uv_info{};
    microv_domain *m_uv_dom{};
    microv_vcpuid m_uv_vcpuid{};

    xen_domid_t m_id{};
    xen_uuid_t m_uuid{};
    uint32_t m_ssid{};     /* flask id */

    /* Tunables */
    uint32_t m_max_pcpus{1};
    uint32_t m_max_vcpus{};
    uint32_t m_max_evtchns{};
    uint32_t m_max_evtchn_port{};
    uint32_t m_max_grant_frames{};
    uint32_t m_max_maptrack_frames{};

    /* Memory */
    uint64_t m_total_ram{};
    uint32_t m_total_pages{}; /* nr pages possessed */
    uint32_t m_max_pages{};   /* max value for total_pages */
    uint32_t m_free_pages{};
    uint32_t m_max_mfn{};
    uint32_t m_shr_pages{};   /* nr shared pages */
    uint32_t m_out_pages{};   /* nr claimed-but-not-possessed pages */
    uint32_t m_paged_pages{}; /* nr paged-out pages */

    /* Scheduling */
    xen_cpupoolid_t m_cpupool_id{};

    bool m_ndvm{};      /* is this an NDVM? */
    uint32_t m_flags{}; /* DOMINF_ flags, used for {sys,dom}ctls */
    struct xen_arch_domainconfig m_arch_config{};

    /* Console IO */
    std::unique_ptr<microv::ring<HVC_RX_SIZE>> m_hvc_rx_ring{};
    std::unique_ptr<microv::ring<HVC_TX_SIZE>> m_hvc_tx_ring{};

    /* Shared info page */
    unique_map<struct shared_info> m_shinfo{};
    uintptr_t m_shinfo_gpfn{};

    /* Event channel */
    std::unique_ptr<xen_evtchn> m_evtchn{};

    /* TSC params */
    uint64_t m_tsc_khz;
    uint64_t m_tsc_mul;
    uint64_t m_tsc_shift;

    /* NUMA parms */
    uint32_t m_numa_nodes;

public:
    xen_domain(xen_domain &&) = delete;
    xen_domain(const xen_domain &) = delete;
    xen_domain &operator=(xen_domain &&) = delete;
    xen_domain &operator=(const xen_domain &) = delete;
};

}

#endif
