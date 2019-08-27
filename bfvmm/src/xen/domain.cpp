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

#include <hve/arch/intel_x64/domain.h>
#include <public/domctl.h>
#include <unordered_map>
#include <xen/domain.h>
#include <xen/util.h>

namespace microv {

using ref_t = std::atomic<uint32_t>;
using map_t = std::pair<std::unique_ptr<xen_domain>, std::unique_ptr<ref_t>>;
static_assert(ref_t::is_always_lock_free);

static std::mutex xen_dom_mutex;
static std::mutex xen_ref_mutex;
static std::unordered_map<xen_domid_t, map_t> xen_dom_map;
static std::unordered_map<xen_domid_t, ref_t *> xen_ref_map;

/* Construct from the domain_op__create_domain root vcpu path */
xen_domain::xen_domain(xen_domid_t id, const microv::domain_info *uv_info)
{
    this->id = id;
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

    this->shinfo_gmfn = 0;
    this->running_time = 0;
    this->nr_online_vcpus = 0;
    this->cpupool = -1; /* CPUPOOLID_NONE */
    this->arch_config.emulation_flags = XEN_X86_EMU_LAPIC;
    this->ndvm = uv_info->is_ndvm();

    this->dominf_flags = XEN_DOMINF_hvm_guest;
    this->dominf_flags |= XEN_DOMINF_hap;
    this->dominf_flags |= XEN_DOMINF_running;

    if (uv_info->is_xenstore()) {
        this->dominf_flags |= XEN_DOMINF_xs_domain;
        ensures(this->id == 0);
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

xen_domid_t create_xen_domain(const microv::domain_info *uv_info)
{
    auto id = make_xen_domid();
    auto dom = std::make_unique<struct xen_domain>(id, uv_info);
    auto ref = std::make_unique<ref_t>(0);

    std::lock_guard<std::mutex> lock(xen_dom_mutex);
    xen_dom_map[id] = std::make_pair(std::move(dom), std::move(ref));

    return id;
}

xen_domain *get_xen_domain(xen_domid_t id)
{
    std::lock_guard<std::mutex> dom_lock(xen_dom_mutex);

    auto itr = xen_dom_map.find(id);
    if (itr != xen_dom_map.end()) {
        auto ref = itr->second.second.get();
        ref->fetch_add(1);
        {
            std::lock_guard<std::mutex> ref_lock(xen_ref_mutex);
            if (xen_ref_map.count(id) == 0) {
                xen_ref_map[id] = ref;
            }
        }
        asm volatile("mfence");
        return itr->second.first.get();
    } else {
        return nullptr;
    }
}

void put_xen_domain(xen_domid_t id)
{
    std::lock_guard<std::mutex> ref_lock(xen_ref_mutex);

    auto itr = xen_ref_map.find(id);
    expects(itr != xen_ref_map.end());
    itr->second->fetch_sub(1);
}

void destroy_xen_domain(xen_domid_t id)
{
    std::lock_guard<std::mutex> dom_lock(xen_dom_mutex);

    auto itr = xen_dom_map.find(id);
    if (itr != xen_dom_map.end()) {
        auto refs = itr->second.second.get();
        while (refs->load() != 0) {
            asm volatile("pause");
        }

        xen_dom_map.erase(id);
        xen_ref_map.erase(id);
        asm volatile("mfence");
    }
}
}
