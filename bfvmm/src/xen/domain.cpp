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
#include <xen/domain.h>
#include <xen/util.h>

namespace microv {

static xen_domid_t make_domid() noexcept
{
    static_assert(std::atomic<xen_domid_t>::is_always_lock_free);
    static std::atomic<xen_domid_t> domid = 1;

    return domid.fetch_add(1);
}

xen_domain::xen_domain(microv::intel_x64::domain *domain)
{
    uv_dom = domain;
    uv_info = &domain->m_sod_info;

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

    this->nr_online_vcpus = 0;
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
