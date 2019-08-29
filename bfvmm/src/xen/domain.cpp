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

#include <atomic>
#include <cstring>
#include <mutex>
#include <unordered_map>

#include <hve/arch/intel_x64/domain.h>
#include <public/domctl.h>
#include <public/vcpu.h>
#include <xen/domain.h>
#include <xen/evtchn.h>
#include <xen/gnttab.h>
#include <xen/util.h>
#include <xen/vcpu.h>

#define DEFAULT_MAPTRACK_FRAMES 1024
#define DEFAULT_CPUPOOLID (-1)

namespace microv {

static xen_domid_t make_domid() noexcept
{
    static_assert(std::atomic<xen_domid_t>::is_always_lock_free);
    static std::atomic<xen_domid_t> domid = 1;

    return domid.fetch_add(1);
}

xen_domain::xen_domain(microv_domain *domain)
{
    m_uv_info = &domain->m_sod_info;
    m_uv_dom = domain;

    m_id = (m_uv_info->is_xenstore()) ? 0 : make_domid();
    make_xen_uuid(&m_uuid);
    m_ssid = 0;

    m_max_vcpus = 1;
    m_max_evtchns = xen_evtchn::max_channels;
    m_max_grant_frames = xen_gnttab::max_nr_frames;
    m_max_maptrack_frames = DEFAULT_MAPTRACK_FRAMES;

    m_total_ram = m_uv_info->total_ram();
    m_total_pages = m_uv_info->total_ram_pages();
    m_max_pages = m_total_pages;
    m_max_mfn = m_max_pages - 1;
    m_shr_pages = 0;
    m_out_pages = 0;
    m_paged_pages = 0;

    m_cpupool = DEFAULT_CPUPOOLID;
    m_arch_config.emulation_flags = XEN_X86_EMU_LAPIC;
    m_ndvm = m_uv_info->is_ndvm();

    m_flags = XEN_DOMINF_hvm_guest;
    m_flags |= XEN_DOMINF_hap;

    if (m_uv_info->is_xenstore()) {
        m_flags |= XEN_DOMINF_xs_domain;
    }

    if (m_uv_info->using_hvc()) {
        m_hvc_rx_ring = std::make_unique<microv::ring<HVC_RX_SIZE>>();
        m_hvc_tx_ring = std::make_unique<microv::ring<HVC_TX_SIZE>>();
    }
}

void xen_domain::bind_vcpu(microv_vcpuid uv_vcpuid)
{
    expects(vcpuid::is_guest_vcpu(uv_vcpuid));
    m_uv_vcpuid = uv_vcpuid;
}

uint64_t xen_domain::shinfo_gpfn()
{
    return 0;
}

uint64_t xen_domain::runstate_time(int state)
{
    return 0;
}

uint32_t xen_domain::nr_online_vcpus()
{
    return 0;
}

xen_vcpuid_t xen_domain::max_vcpu_id()
{
    return 0;
}

void xen_domain::get_arch_config(struct xen_arch_domainconfig *cfg)
{
}

void xen_domain::get_domctl_info(struct xen_domctl_getdomaininfo *info)
{
    info->domain = m_id;
    info->flags = m_flags;
    info->tot_pages = m_total_pages;
    info->max_pages = m_max_pages;
    info->outstanding_pages = m_out_pages;
    info->shr_pages = m_shr_pages;
    info->paged_pages = m_paged_pages;
    info->shared_info_frame = this->shinfo_gpfn();
    info->cpu_time = this->runstate_time(RUNSTATE_running);
    info->nr_online_vcpus = this->nr_online_vcpus();
    info->max_vcpu_id = this->max_vcpu_id();
    info->ssidref = m_ssid;

    static_assert(sizeof(m_uuid) == sizeof(info->handle));
    memcpy(&info->handle, &m_uuid, sizeof(m_uuid));

    info->cpupool = m_cpupool;
    this->get_arch_config(&info->arch_config);
}

size_t xen_domain::hvc_rx_put(const gsl::span<char> &span)
{
    return m_hvc_rx_ring->put(span);
}

size_t xen_domain::hvc_rx_get(const gsl::span<char> &span)
{
    return m_hvc_rx_ring->get(span);
}

size_t xen_domain::hvc_tx_put(const gsl::span<char> &span)
{
    return m_hvc_tx_ring->put(span);
}

size_t xen_domain::hvc_tx_get(const gsl::span<char> &span)
{
    return m_hvc_tx_ring->get(span);
}

}
