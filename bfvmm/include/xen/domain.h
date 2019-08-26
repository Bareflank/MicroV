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
#include <public/xen.h>

namespace microv {

using xen_domid_t = domid_t;

/**
 * xen_domain
 *
 * This is the primary structure that contains information specific
 * to xen domains. There are two paths from which a xen domain can
 * be created:
 *   - domain_op__create_domain hypercall from a Bareflank host vcpu
 *   - domctl::createdomain hypercall from a Xen guest dom0
 */
struct xen_domain {
    xen_domid_t id{};
    xen_uuid_t uuid{};
    uint32_t ssid_ref{};     /* flask id */

    /* Tunables */
    uint32_t max_vcpus{};
    uint32_t max_evtchns{};
    uint32_t max_grant_frames{};
    uint32_t max_maptrack_frames{};

    /* Memory */
    uint64_t total_ram{};
    uint32_t total_pages{}; /* nr pages possessed */
    uint32_t max_pages{};   /* max value for total_pages */
    uint32_t max_mfn{};
    uint32_t shr_pages{};   /* nr shared pages */
    uint32_t out_pages{};   /* nr claimed-but-not-possessed pages */
    uint32_t paged_pages{}; /* nr paged-out pages */
    uint64_t shinfo_gmfn{};

    /* Scheduling */
    uint64_t running_time{}; /* time in the RUNNING state */
    uint32_t nr_online_vcpus{};
    uint32_t cpupool{};

    bool ndvm{};             /* is this an NDVM? */
    uint32_t dominf_flags{}; /* DOMINF_ flags, used for {sys,dom}ctls */
    struct xen_arch_domainconfig arch_config{};

    /* Console IO */
    std::unique_ptr<microv::ring<HVC_RX_SIZE>> hvc_rx_ring;
    std::unique_ptr<microv::ring<HVC_TX_SIZE>> hvc_tx_ring;

    size_t hvc_rx_put(const gsl::span<char> &span);
    size_t hvc_rx_get(const gsl::span<char> &span);
    size_t hvc_tx_put(const gsl::span<char> &span);
    size_t hvc_tx_get(const gsl::span<char> &span);

    xen_domain(xen_domid_t id, const microv::domain_info *uv_info);

    ~xen_domain() = default;
    xen_domain(xen_domain &&) = delete;
    xen_domain(const xen_domain &) = delete;
    xen_domain &operator=(xen_domain &&) = delete;
    xen_domain &operator=(const xen_domain &) = delete;
};

xen_domid_t create_xen_domain(const microv::domain_info *domain);
xen_domain *get_xen_domain(xen_domid_t id);
void put_xen_domain(xen_domid_t id);
void destroy_xen_domain(xen_domid_t id);

}

#endif
