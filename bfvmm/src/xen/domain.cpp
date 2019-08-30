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
#include <map>
#include <mutex>

#include <arch/intel_x64/barrier.h>
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <printv.h>
#include <public/domctl.h>
#include <public/vcpu.h>
#include <xen/domain.h>
#include <xen/evtchn.h>
#include <xen/gnttab.h>
#include <xen/time.h>
#include <xen/util.h>
#include <xen/vcpu.h>

#define DEFAULT_MAPTRACK_FRAMES 1024
#define DEFAULT_CPUPOOLID (-1)

namespace microv {

using ref_t = std::atomic<uint64_t>;
using dom_t = std::pair<std::unique_ptr<xen_domain>, std::unique_ptr<ref_t>>;

static_assert(ref_t::is_always_lock_free);

std::mutex dom_mutex;
std::mutex ref_mutex;

std::map<xen_domid_t, dom_t> dom_map;
std::map<xen_domid_t, ref_t *> ref_map;

xen_domid_t create_xen_domain(microv_domain *uv_dom)
{
    std::lock_guard lock(dom_mutex);

    auto dom = std::make_unique<class xen_domain>(uv_dom);
    auto ref = std::make_unique<ref_t>(0);

    expects(!dom_map.count(dom->m_id));

    auto id = dom->m_id;
    dom_map[id] = std::make_pair(std::move(dom), std::move(ref));

    return id;
}

void destroy_xen_domain(xen_domid_t id)
{
    std::lock_guard lock(dom_mutex);

    auto itr = dom_map.find(id);
    if (itr != dom_map.end()) {

        auto ref = itr->second.second.get();
        while (ref->load() != 0) {
            asm volatile("pause");
        }

        dom_map.erase(id);
        ref_map.erase(id);
        asm volatile("mfence");
    }
}

xen_domain *get_xen_domain(xen_domid_t id) noexcept
{
    try {
        std::lock_guard lock(dom_mutex);

        auto itr = dom_map.find(id);
        if (itr != dom_map.end()) {
            auto ref = itr->second.second.get();
            ref->fetch_add(1);
            {
                std::lock_guard lock(ref_mutex);
                if (!ref_map.count(id)) {
                    ref_map[id] = ref;
                }
            }
            asm volatile("mfence");
            return itr->second.first.get();
        } else {
            return nullptr;
        }
    } catch (...) {
        printv("%s: threw exception for id 0x%x\n", __func__, id);
        return nullptr;
    }
}

void put_xen_domain(xen_domid_t id) noexcept
{
    try {
        std::lock_guard lock(ref_mutex);

        auto itr = ref_map.find(id);
        if (itr != ref_map.end()) {
            itr->second->fetch_sub(1);
        }
    } catch (...) {
        printv("%s: threw exception for id 0x%x\n", __func__, id);
    }
}

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
    m_uv_vcpuid = 0; /* the valid ID is bound with bind_vcpu */

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

class xen_vcpu *xen_domain::get_xen_vcpu() noexcept
{
    if (!m_uv_vcpuid) {
        return nullptr;
    }

    auto uv_vcpu = get_vcpu(m_uv_vcpuid);
    if (!uv_vcpu) {
        return nullptr;
    }

    return uv_vcpu->xen_vcpu();
}

void xen_domain::put_xen_vcpu() noexcept
{
    put_vcpu(m_uv_vcpuid);
}

/*
 * N.B. this is called from the xen_vcpu constructor, which is called from the
 * g_vcm->create() path. This means the bfmanager's m_mutex is already locked,
 * so doing a get_xen_vcpu() here would cause deadlock.
 */
void xen_domain::bind_vcpu(xen_vcpu *xen)
{
    m_uv_vcpuid = xen->m_uv_vcpu->id();

    m_tsc_khz = xen->m_tsc_khz;
    m_tsc_mul = xen->m_tsc_mul;
    m_tsc_shift = xen->m_tsc_shift;
}

uint64_t xen_domain::init_shared_info(xen_vcpu *xen, uintptr_t shinfo_gpfn)
{
    expects(!m_shinfo);

    m_shinfo = xen->m_uv_vcpu->map_gpa_4k<struct shared_info>(shinfo_gpfn << 12);
    m_shinfo_gpfn = shinfo_gpfn;

    /* Set wallclock from start-of-day info */
    auto now = ::x64::read_tsc::get();
    auto wc_nsec = tsc_to_ns(now - m_uv_info->tsc, m_tsc_shift,  m_tsc_mul);
    auto wc_sec = wc_nsec / 1000000000ULL;

    wc_nsec += m_uv_info->wc_nsec;
    wc_sec += m_uv_info->wc_sec;
    m_shinfo->wc_nsec = gsl::narrow_cast<uint32_t>(wc_nsec);
    m_shinfo->wc_sec = gsl::narrow_cast<uint32_t>(wc_sec);
    m_shinfo->wc_sec_hi = gsl::narrow_cast<uint32_t>(wc_sec >> 32);

    return now;
}

void xen_domain::update_wallclock(
    xen_vcpu *vcpu,
    const struct xenpf_settime64 *time) noexcept
{
    m_shinfo->wc_version++;
    wmb();

    uint64_t x = s_to_ns(time->secs) + time->nsecs - time->system_time;
    uint32_t y = do_div(x, 1000000000);

    m_shinfo->wc_sec = (uint32_t)x;
    m_shinfo->wc_sec_hi = (uint32_t)(x >> 32);
    m_shinfo->wc_nsec = (uint32_t)y;

    wmb();
    m_shinfo->wc_version++;
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
    info->shared_info_frame = m_shinfo_gpfn;
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
