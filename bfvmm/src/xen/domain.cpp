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
#include <xen/util.h>
#include <xen/vcpu.h>

namespace microv {

static xen_domid_t make_domid() noexcept
{
    static_assert(std::atomic<xen_domid_t>::is_always_lock_free);
    static std::atomic<xen_domid_t> domid = 1;

    return domid.fetch_add(1);
}

xen_domain::xen_domain(microv_domain *domain)
{
    uv_info = &domain->m_sod_info;
    uv_dom = domain;

    this->id = (uv_info->is_xenstore()) ? 0 : make_domid();
    this->ssid_ref = 0;
    this->max_vcpus = 1;

    make_xen_uuid(&this->uuid);

    this->total_ram = uv_info->total_ram();
    this->total_pages = uv_info->total_ram_pages();
    this->max_pages = this->total_pages;
    this->max_mfn = this->max_pages - 1;
    this->shr_pages = 0;
    this->out_pages = 0;
    this->paged_pages = 0;

    this->cpupool = -1; /* CPUPOOLID_NONE */
    this->arch_config.emulation_flags = XEN_X86_EMU_LAPIC;
    this->ndvm = uv_info->is_ndvm();

    this->flags = XEN_DOMINF_hvm_guest;
    this->flags |= XEN_DOMINF_hap;

    if (uv_info->is_xenstore()) {
        this->flags |= XEN_DOMINF_xs_domain;
    }

    if (uv_info->using_hvc()) {
        this->hvc_rx_ring = std::make_unique<microv::ring<HVC_RX_SIZE>>();
        this->hvc_tx_ring = std::make_unique<microv::ring<HVC_TX_SIZE>>();
    }
}

void xen_domain::bind_vcpu(class xen_vcpu *vcpu)
{
    this->xen_vcpu = vcpu;
    uv_vcpu = vcpu->m_vcpu;
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
    info->domain = id;
    info->flags = flags;
    info->tot_pages = total_pages;
    info->max_pages = max_pages;
    info->outstanding_pages = out_pages;
    info->shr_pages = shr_pages;
    info->paged_pages = paged_pages;
    info->shared_info_frame = this->shinfo_gpfn();
    info->cpu_time = this->runstate_time(RUNSTATE_running);
    info->nr_online_vcpus = this->nr_online_vcpus();
    info->max_vcpu_id = this->max_vcpu_id();
    info->ssidref = ssid_ref;

    static_assert(sizeof(uuid) == sizeof(info->handle));
    memcpy(&info->handle, &uuid, sizeof(uuid));

    info->cpupool = cpupool;
    this->get_arch_config(&info->arch_config);
}

size_t xen_domain::hvc_rx_put(const gsl::span<char> &span)
{
    return hvc_rx_ring->put(span);
}

size_t xen_domain::hvc_rx_get(const gsl::span<char> &span)
{
    return hvc_rx_ring->get(span);
}

size_t xen_domain::hvc_tx_put(const gsl::span<char> &span)
{
    return hvc_tx_ring->put(span);
}

size_t xen_domain::hvc_tx_get(const gsl::span<char> &span)
{
    return hvc_tx_ring->get(span);
}

}
