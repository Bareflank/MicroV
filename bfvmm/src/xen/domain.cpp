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

#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <mutex>

#include <arch/intel_x64/barrier.h>
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <printv.h>
#include <public/domctl.h>
#include <public/sysctl.h>
#include <public/vcpu.h>
#include <xen/cpupool.h>
#include <xen/domain.h>
#include <xen/evtchn.h>
#include <xen/gnttab.h>
#include <xen/memory.h>
#include <xen/time.h>
#include <xen/util.h>
#include <xen/vcpu.h>

#define DEFAULT_MAPTRACK_FRAMES 1024
#define DEFAULT_RAM_SIZE (256UL << 20)
#define DEFAULT_EVTCHN_PORTS 1024

#ifndef typeof
#define typeof decltype
#endif

#include <public/arch-x86/hvm/save.h>
#include <public/hvm/save.h>


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

bool xen_domain_getinfolist(xen_vcpu *vcpu, struct xen_sysctl *ctl)
{
    expects(vcpu->is_xenstore());

    auto gdil = &ctl->u.getdomaininfolist;
    auto uvv = vcpu->m_uv_vcpu;
    auto gva = gdil->buffer.p;

    std::lock_guard lock(dom_mutex);

    /* Actual number to map is min(requested, number of domains) */
    auto len = std::min((unsigned long)gdil->max_domains, dom_map.size());
    auto buf = uvv->map_gva_4k<xen_domctl_getdomaininfo_t>(gva, len);

    auto num = 0U;
    auto id = gdil->first_domain;

    for (auto itr = dom_map.find(id); itr != dom_map.end(); itr++) {
        if (num == len) {
            break;
        }

        auto info = &buf.get()[num];
        auto dom = itr->second.first.get();

        dom->get_info(info);
        num++;
    }

    gdil->num_domains = num;
    uvv->set_rax(0);
    return true;
}

bool xen_domain_gethvmcontext(xen_vcpu *vcpu, struct xen_domctl *ctl)
{
    expects(vcpu->is_xenstore());

    auto domid = ctl->domain;
    if (domid == DOMID_SELF) {
        domid = vcpu->m_xen_dom->m_id;
    }

    auto dom = get_xen_domain(domid);
    if (!dom) {
        bferror_nhex(0, "xen_domain not found:", domid);
        return false;
    }

    auto ctx = &ctl->u.hvmcontext;
    auto ret = dom->gethvmcontext(vcpu, ctx);
    put_xen_domain(domid);

    return ret;
}

bool xen_domain_sethvmcontext(xen_vcpu *vcpu, struct xen_domctl *ctl)
{
    expects(vcpu->is_xenstore());

    auto domid = ctl->domain;
    if (domid == DOMID_SELF) {
        domid = vcpu->m_xen_dom->m_id;
    }

    auto dom = get_xen_domain(domid);
    if (!dom) {
        bferror_nhex(0, "xen_domain not found:", domid);
        return false;
    }

    auto ctx = &ctl->u.hvmcontext;
    auto ret = dom->sethvmcontext(vcpu, ctx);
    put_xen_domain(domid);

    return ret;
}

bool xen_domain_setvcpuaffinity(xen_vcpu *vcpu, struct xen_domctl *ctl)
{
    auto dom = get_xen_domain(ctl->domain);
    if (!dom) {
        bferror_nhex(0, "xen_domain not found:", ctl->domain);
        return false;
    }

    auto aff = &ctl->u.vcpuaffinity;
    expects(aff->vcpu == 0);
    printv("setvcpuaffinity: vcpu:0x%x flags:0x%x\n", aff->vcpu, aff->flags);

    auto ret = dom->setvcpuaffinity(vcpu, aff);
    put_xen_domain(ctl->domain);

    return ret;
}

bool xen_domain_max_mem(xen_vcpu *vcpu, struct xen_domctl *ctl)
{
    auto dom = get_xen_domain(ctl->domain);
    if (!dom) {
        bferror_nhex(0, "xen_domain not found:", ctl->domain);
        return false;
    }

    auto ret = dom->set_max_mem(vcpu, &ctl->u.max_mem);
    put_xen_domain(ctl->domain);

    return ret;
}

bool xen_domain_set_tsc_info(xen_vcpu *vcpu, struct xen_domctl *ctl)
{
    auto dom = get_xen_domain(ctl->domain);
    if (!dom) {
        bferror_nhex(0, "xen_domain not found:", ctl->domain);
        return false;
    }

    auto ret = dom->set_tsc_info(vcpu, &ctl->u.tsc_info);
    put_xen_domain(ctl->domain);

    return ret;
}

bool xen_domain_shadow_op(xen_vcpu *vcpu, struct xen_domctl *ctl)
{
    auto dom = get_xen_domain(ctl->domain);
    if (!dom) {
        bferror_nhex(0, "xen_domain not found:", ctl->domain);
        return false;
    }

    auto ret = dom->shadow_op(vcpu, &ctl->u.shadow_op);
    put_xen_domain(ctl->domain);

    return ret;
}

bool xen_domain_getdomaininfo(xen_vcpu *vcpu, struct xen_domctl *ctl)
{
    auto dom = get_xen_domain(ctl->domain);
    if (!dom) {
        bferror_nhex(0, "xen_domain not found:", ctl->domain);
        return false;
    }

    dom->get_info(&ctl->u.getdomaininfo);
    put_xen_domain(ctl->domain);

    return true;
}

bool xen_domain_createdomain(xen_vcpu *vcpu, struct xen_domctl *ctl)
{
    auto cd = &ctl->u.createdomain;

    expects(vcpu->is_xenstore());
    expects(cd->flags & XEN_DOMCTL_CDF_hvm_guest);
    expects(cd->flags & XEN_DOMCTL_CDF_hap);
    expects((cd->flags & XEN_DOMCTL_CDF_s3_integrity) == 0);
    expects((cd->flags & XEN_DOMCTL_CDF_oos_off) == 0);
    expects((cd->flags & XEN_DOMCTL_CDF_xs_domain) == 0);

    auto tsc_shift = vcpu->m_xen_dom->m_tsc_shift;
    auto tsc_mult = vcpu->m_xen_dom->m_tsc_mul;
    auto uv_info = vcpu->m_xen_dom->m_uv_info;

    auto wc_nsec = uv_info->wc_nsec;
    auto wc_sec =  uv_info->wc_sec;
    auto tsc = uv_info->tsc;

    auto now = ::x64::read_tsc::get();
    auto nsec = tsc_to_ns(now - tsc, tsc_shift, tsc_mult);
    auto sec = wc_nsec / 1000000000ULL;

    wc_nsec += nsec;
    wc_sec += sec;

    struct microv::domain_info info{};
    info.flags = DOMF_EXEC_XENPVH;
    info.wc_sec = wc_sec;
    info.wc_nsec = wc_nsec;
    info.tsc = now;
    info.ram = DEFAULT_RAM_SIZE;
    info.xen_info_valid = 1;
    info.xen_domid = make_xen_domid();

    static_assert(sizeof(*cd) == sizeof(info.xen_create_dom));
    memcpy(&info.xen_create_dom, cd, sizeof(*cd));

    auto uv_domid = domain::generate_domainid();
    g_dm->create(uv_domid, &info);
    ctl->domain = info.xen_domid;
    vcpu->m_uv_vcpu->set_rax(0);

    printv("createdomain: id:%u flags:0x%x vcpus:%u evtchn:%u grant:%u maptrack:%u\n",
            ctl->domain, cd->flags, cd->max_vcpus,
            cd->max_evtchn_port, cd->max_grant_frames,
            cd->max_maptrack_frames);

    return true;
}

bool xen_domain_numainfo(xen_vcpu *vcpu, xen_sysctl_t *ctl)
{
    auto numa = &ctl->u.numainfo;

    printv("numainfo: num_nodes:%u, meminfo.p:%p, distance.p:%p\n",
            numa->num_nodes, numa->meminfo.p, numa->distance.p);

    auto dom0 = get_xen_domain(0);
    if (!dom0) {
        bferror_info(0, "numainfo: dom0 not found");
        return false;
    }

    auto ret = dom0->numainfo(vcpu, numa);
    put_xen_domain(0);

    return ret;
}

bool xen_domain_cputopoinfo(xen_vcpu *vcpu, xen_sysctl_t *ctl)
{
    auto topo = &ctl->u.cputopoinfo;
    auto dom0 = get_xen_domain(0);
    if (!dom0) {
        bferror_info(0, "cputopoinfo: dom0 not found");
        return false;
    }

    auto ret = dom0->cputopoinfo(vcpu, topo);
    put_xen_domain(0);

    return ret;
}

xen_domain::xen_domain(microv_domain *domain) :
    m_shinfo_page{make_page<struct shared_info>()},
    m_shinfo{m_shinfo_page.get()}
{
    m_uv_info = &domain->m_sod_info;
    m_uv_dom = domain;
    m_uv_vcpuid = 0; /* the valid ID is bound with bind_vcpu */

    if (m_uv_info->xen_info_valid) {
        auto cd = &m_uv_info->xen_create_dom;
        m_id = m_uv_info->xen_domid;
        memcpy(&m_uuid, &cd->handle, sizeof(m_uuid));
        m_ssid = cd->ssidref;
        // TODO: m_max_pcpus = cd->max_pcpus;
        m_max_pcpus = 1;
        m_max_vcpus = cd->max_vcpus;
        m_max_evtchn_port = cd->max_evtchn_port;
        m_max_grant_frames = cd->max_grant_frames;
        m_max_maptrack_frames = cd->max_maptrack_frames;
        memcpy(&m_arch_config, &cd->arch, sizeof(cd->arch));
    } else {
        m_id = (m_uv_info->is_xenstore()) ? 0 : make_xen_domid();
        make_xen_uuid(&m_uuid);
        m_ssid = 0;
        m_max_pcpus = 1;
        m_max_vcpus = 1;
        m_max_evtchn_port = DEFAULT_EVTCHN_PORTS - 1;
        m_max_grant_frames = xen_gnttab::max_nr_frames;
        m_max_maptrack_frames = DEFAULT_MAPTRACK_FRAMES;
        m_arch_config.emulation_flags = XEN_X86_EMU_LAPIC;
    }

    /* Max supported by the ABI */
    m_max_evtchns = xen_evtchn::max_channels;

    m_total_ram = m_uv_info->total_ram();
    m_total_pages = m_uv_info->total_ram_pages();
    m_max_pages = m_total_pages;
    m_free_pages = m_max_pages - m_total_pages; /* ??? */
    m_max_mfn = m_max_pages - 1;
    m_shr_pages = 0;
    m_out_pages = 0;
    m_paged_pages = 0;

    if (m_uv_info->xen_info_valid) {
        m_total_pages = 0;
        m_free_pages = 0;
    }

    m_cpupool_id = xen_cpupool::id_none;
    xen_cpupool_add_domain(m_cpupool_id, m_id);

    m_flags = XEN_DOMINF_hvm_guest;
    m_flags |= XEN_DOMINF_hap;

    if (m_uv_info->is_xenstore()) {
        m_flags |= XEN_DOMINF_xs_domain;
        m_flags |= XEN_DOMINF_running;
    } else {
        m_flags |= XEN_DOMINF_paused;
    }

    if (m_uv_info->using_hvc()) {
        m_hvc_rx_ring = std::make_unique<microv::ring<HVC_RX_SIZE>>();
        m_hvc_tx_ring = std::make_unique<microv::ring<HVC_TX_SIZE>>();
    }

    m_numa_nodes = 1;
    m_ndvm = m_uv_info->is_ndvm();
    m_evtchn = std::make_unique<xen_evtchn>(this);
    m_memory = std::make_unique<xen_memory>(this);
}

xen_domain::~xen_domain()
{
    xen_cpupool_rm_domain(m_cpupool_id, m_id);
}

void xen_domain::share_root_page(uintptr_t gpa, uintptr_t hpa,
                                 uint32_t perm, uint32_t mtype)
{
    xen_pfn_t gfn = xen_frame(gpa);
    xen_pfn_t hfn = xen_frame(hpa);

    m_memory->add_root_backed_page(gfn, perm, mtype, hfn);
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

void xen_domain::set_timer_mode(uint64_t mode)
{
    const char *mode_str[4] = {
        "delay_for_missed_ticks",
        "no_delay_for_missed_ticks",
        "no_missed_ticks_pending",
        "one_missed_tick_pending",
    };

    expects(mode < 4);
    printv("domain: set timer mode to %s\n", mode_str[mode]);
    m_timer_mode = mode;
}

void xen_domain::queue_virq(int virq)
{
    m_evtchn->queue_virq(virq);
}

/*
 * N.B. this is called from the xen_vcpu constructor, which is called from the
 * g_vcm->create() path. This means the bfmanager's m_mutex is already locked,
 * so doing a get_xen_vcpu() here would cause deadlock.
 */
void xen_domain::bind_vcpu(xen_vcpu *xen)
{
    expects(vcpuid::is_guest_vcpu(xen->m_uv_vcpu->id()));
    m_uv_vcpuid = xen->m_uv_vcpu->id();

    m_tsc_khz = xen->m_tsc_khz;
    m_tsc_mul = xen->m_tsc_mul;
    m_tsc_shift = xen->m_tsc_shift;

    m_memory->add_ept_handlers(xen);
}

uint64_t xen_domain::init_shared_info(xen_vcpu *xen, uintptr_t shinfo_gpfn)
{
    expects(m_shinfo);

    const auto perms = pg_perm_rw;
    const auto mtype = pg_mtype_wb;

    if (m_memory->find_page(shinfo_gpfn)) {
        m_memory->remove_page(shinfo_gpfn);
    }

    m_memory->add_vmm_backed_page(shinfo_gpfn, perms, mtype, m_shinfo);
    xen->m_uv_vcpu->invept();

    /* Set wallclock from start-of-day info */
    auto now = ::x64::read_tsc::get();
    auto wc_nsec = tsc_to_ns(now - m_uv_info->tsc, m_tsc_shift,  m_tsc_mul);
    auto wc_sec = wc_nsec / 1000000000ULL;

    wc_nsec += m_uv_info->wc_nsec;
    wc_sec += m_uv_info->wc_sec;
    m_shinfo->wc_nsec = gsl::narrow_cast<uint32_t>(wc_nsec);
    m_shinfo->wc_sec = gsl::narrow_cast<uint32_t>(wc_sec);
    m_shinfo->wc_sec_hi = gsl::narrow_cast<uint32_t>(wc_sec >> 32);
    m_shinfo_gpfn = shinfo_gpfn;

    return now;
}



void xen_domain::update_wallclock(
    xen_vcpu *vcpu,
    const struct xenpf_settime64 *time) noexcept
{
    m_shinfo->wc_version++;
    ::intel_x64::wmb();

    uint64_t x = s_to_ns(time->secs) + time->nsecs - time->system_time;
    uint32_t y = do_div(x, 1000000000);

    m_shinfo->wc_sec = (uint32_t)x;
    m_shinfo->wc_sec_hi = (uint32_t)(x >> 32);
    m_shinfo->wc_nsec = (uint32_t)y;

    ::intel_x64::wmb();
    m_shinfo->wc_version++;
}

uint64_t xen_domain::runstate_time(int state)
{
    auto xv = this->get_xen_vcpu();

    if (!xv) {
        return 0;
    } else {
        const auto time = xv->runstate_time(state);
        this->put_xen_vcpu();
        return time;
    }
}

uint32_t xen_domain::nr_online_vcpus()
{
    auto xv = this->get_xen_vcpu();

    if (!xv) {
        return 0;
    } else {
        this->put_xen_vcpu();
        return 1;
    }
}

xen_vcpuid_t xen_domain::max_vcpu_id()
{
    auto xv = this->get_xen_vcpu();

    if (!xv) {
        return XEN_INVALID_MAX_VCPU_ID;
    } else {
        auto id = xv->m_id;
        this->put_xen_vcpu();
        return id;
    }
}

void xen_domain::get_info(struct xen_domctl_getdomaininfo *info)
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
    info->cpupool = m_cpupool_id;

    static_assert(sizeof(info->handle) == sizeof(m_uuid));
    memcpy(&info->handle, &m_uuid, sizeof(m_uuid));

    static_assert(sizeof(info->arch_config) == sizeof(m_arch_config));
    memcpy(&info->arch_config, &m_arch_config, sizeof(m_arch_config));
}

bool xen_domain::move_cpupool(xen_vcpu *v, struct xen_sysctl *ctl)
{
    auto uvv = v->m_uv_vcpu;
    auto op = &ctl->u.cpupool_op;

    expects(op->op == XEN_SYSCTL_CPUPOOL_OP_MOVEDOMAIN);
    expects(op->domid == m_id);

    auto old_pool = m_cpupool_id;
    auto new_pool = op->cpupool_id;

    auto err = xen_cpupool_mv_domain(old_pool, new_pool, m_id);
    if (err) {
        uvv->set_rax(err);
        return true;
    }

    m_cpupool_id = op->cpupool_id;
    uvv->set_rax(0);
    return true;
}

/* Note that the microv_domain and/or vcpu will need this
 * as well */
static void init_hvm_hw_cpu(struct hvm_hw_cpu *cpu)
{
    memset(cpu, 0, sizeof(*cpu));

    cpu->cr0 = 0x10037;
    cpu->cr4 = 0x02000;

    cpu->cs_limit = 0xFFFFFFFF;
    cpu->ds_limit = 0xFFFFFFFF;
    cpu->es_limit = 0xFFFFFFFF;
    cpu->ss_limit = 0xFFFFFFFF;
    cpu->tr_limit = 0x67;

    cpu->cs_arbytes = 0xc09b;
    cpu->ds_arbytes = 0xc093;
    cpu->es_arbytes = 0xc093;
    cpu->ss_arbytes = 0xc093;

    cpu->fs_arbytes = 0x10000;
    cpu->gs_arbytes = 0x10000;
    cpu->ldtr_arbytes = 0x10000;
    cpu->tr_arbytes = 0x008b;

    cpu->tsc = ::x64::read_tsc::get();
    cpu->rflags = 2;
}

static void init_hvm_hw_lapic(struct hvm_hw_lapic *lapic)
{
    memset(lapic, 0, sizeof(*lapic));

    lapic->apic_base_msr = 0xFEE00000;
    lapic->apic_base_msr |= (1UL << 11); /* apic enable */
    lapic->apic_base_msr |= (1UL << 10); /* x2apic enable */
    lapic->apic_base_msr |= (1UL << 8);  /* BSP */
}

/* TODO consolidate with mtrr_handler. These are different */
static void init_hvm_hw_mtrr(struct hvm_hw_mtrr *mtrr)
{
    memset(mtrr, 0, sizeof(*mtrr));

    mtrr->msr_pat_cr = 0x0606060606060606;

    /* MTRR caps:
     *
     * 1 variable range
     * disable fixed ranges
     * disable wc
     * disable smrr
     */
    mtrr->msr_mtrr_cap = 1;

    /* Enable variable range with WB default */
    mtrr->msr_mtrr_def_type = 0x806;
}

/*
 * We need to update our own copy of HVM_SAVE fields in response
 * to the toolstack sethvmcontext
 */
static void dump_hvm_hw_mtrr(struct hvm_hw_mtrr *mtrr)
{
    printv("  MTRR: pat:0x%lx\n", mtrr->msr_pat_cr);
    printv("  MTRR: cap:0x%lx\n", mtrr->msr_mtrr_cap);
    printv("  MTRR: def:0x%lx\n", mtrr->msr_mtrr_def_type);

    for (auto i = 0; i < MTRR_VCNT; i += 2) {
        auto base = mtrr->msr_mtrr_var[i];
        auto mask = mtrr->msr_mtrr_var[i + 1];
        printv("  MTRR: physbase[%d]:0x%lx physmask[%d]:0x%lx\n", i, base, i, mask);
    }

    for (auto i = 0; i < NUM_FIXED_MSR; i++) {
        printv("  MTRR: fixed[%d]:0x%lx\n", i, mtrr->msr_mtrr_fixed[i]);
    }
}

static void dump_hvm_hw_cpu(struct hvm_hw_cpu *cpu)
{
    printv("  CPU: rax:0x%lx\n", cpu->rax);
    printv("  CPU: rbx:0x%lx\n", cpu->rbx);
    printv("  CPU: rcx:0x%lx\n", cpu->rcx);
    printv("  CPU: rdx:0x%lx\n", cpu->rdx);
    printv("  CPU: rbp:0x%lx\n", cpu->rbp);
    printv("  CPU: rsi:0x%lx\n", cpu->rsi);
    printv("  CPU: rdi:0x%lx\n", cpu->rdi);
    printv("  CPU: rsp:0x%lx\n", cpu->rsp);
    printv("  CPU: r8:0x%lx\n", cpu->r8);
    printv("  CPU: r9:0x%lx\n", cpu->r9);
    printv("  CPU: r10:0x%lx\n", cpu->r10);
    printv("  CPU: r11:0x%lx\n", cpu->r11);
    printv("  CPU: r12:0x%lx\n", cpu->r12);
    printv("  CPU: r13:0x%lx\n", cpu->r13);
    printv("  CPU: r14:0x%lx\n", cpu->r14);
    printv("  CPU: r15:0x%lx\n", cpu->r15);

    printv("  CPU: rip:0x%lx\n", cpu->rip);
    printv("  CPU: rflags:0x%lx\n", cpu->rflags);

    printv("  CPU: cr0:0x%lx\n", cpu->cr0);
    printv("  CPU: cr2:0x%lx\n", cpu->cr2);
    printv("  CPU: cr3:0x%lx\n", cpu->cr3);
    printv("  CPU: cr4:0x%lx\n", cpu->cr4);

    printv("  CPU: dr0:0x%lx\n", cpu->dr0);
    printv("  CPU: dr1:0x%lx\n", cpu->dr1);
    printv("  CPU: dr2:0x%lx\n", cpu->dr2);
    printv("  CPU: dr3:0x%lx\n", cpu->dr3);
    printv("  CPU: dr6:0x%lx\n", cpu->dr6);
    printv("  CPU: dr7:0x%lx\n", cpu->dr7);

    printv("  CPU: cs_sel:0x%x\n", cpu->cs_sel);
    printv("  CPU: ds_sel:0x%x\n", cpu->ds_sel);
    printv("  CPU: es_sel:0x%x\n", cpu->es_sel);
    printv("  CPU: fs_sel:0x%x\n", cpu->fs_sel);
    printv("  CPU: gs_sel:0x%x\n", cpu->gs_sel);
    printv("  CPU: ss_sel:0x%x\n", cpu->ss_sel);
    printv("  CPU: tr_sel:0x%x\n", cpu->tr_sel);
    printv("  CPU: ldtr_sel:0x%x\n", cpu->ldtr_sel);

    printv("  CPU: cs_limit:0x%x\n", cpu->cs_limit);
    printv("  CPU: ds_limit:0x%x\n", cpu->ds_limit);
    printv("  CPU: es_limit:0x%x\n", cpu->es_limit);
    printv("  CPU: fs_limit:0x%x\n", cpu->fs_limit);
    printv("  CPU: gs_limit:0x%x\n", cpu->gs_limit);
    printv("  CPU: ss_limit:0x%x\n", cpu->ss_limit);
    printv("  CPU: tr_limit:0x%x\n", cpu->tr_limit);
    printv("  CPU: ldtr_limit:0x%x\n", cpu->ldtr_limit);
    printv("  CPU: idtr_limit:0x%x\n", cpu->idtr_limit);
    printv("  CPU: gdtr_limit:0x%x\n", cpu->gdtr_limit);

    printv("  CPU: cs_base:0x%lx\n", cpu->cs_base);
    printv("  CPU: ds_base:0x%lx\n", cpu->ds_base);
    printv("  CPU: es_base:0x%lx\n", cpu->es_base);
    printv("  CPU: fs_base:0x%lx\n", cpu->fs_base);
    printv("  CPU: gs_base:0x%lx\n", cpu->gs_base);
    printv("  CPU: ss_base:0x%lx\n", cpu->ss_base);
    printv("  CPU: tr_base:0x%lx\n", cpu->tr_base);
    printv("  CPU: ldtr_base:0x%lx\n", cpu->ldtr_base);
    printv("  CPU: idtr_base:0x%lx\n", cpu->idtr_base);
    printv("  CPU: gdtr_base:0x%lx\n", cpu->gdtr_base);

    printv("  CPU: cs_arbytes:0x%x\n", cpu->cs_arbytes);
    printv("  CPU: ds_arbytes:0x%x\n", cpu->ds_arbytes);
    printv("  CPU: es_arbytes:0x%x\n", cpu->es_arbytes);
    printv("  CPU: fs_arbytes:0x%x\n", cpu->fs_arbytes);
    printv("  CPU: gs_arbytes:0x%x\n", cpu->gs_arbytes);
    printv("  CPU: ss_arbytes:0x%x\n", cpu->ss_arbytes);
    printv("  CPU: tr_arbytes:0x%x\n", cpu->tr_arbytes);
    printv("  CPU: ldtr_arbytes:0x%x\n", cpu->ldtr_arbytes);

    printv("  CPU: sysenter_cs:0x%lx\n", cpu->sysenter_cs);
    printv("  CPU: sysenter_esp:0x%lx\n", cpu->sysenter_esp);
    printv("  CPU: sysenter_eip:0x%lx\n", cpu->sysenter_eip);

    printv("  CPU: shadow_gs:0x%lx\n", cpu->shadow_gs);

    printv("  CPU: msr_flags:0x%lx\n", cpu->msr_flags);
    printv("  CPU: msr_lstar:0x%lx\n", cpu->msr_lstar);
    printv("  CPU: msr_star:0x%lx\n", cpu->msr_star);
    printv("  CPU: msr_cstar:0x%lx\n", cpu->msr_cstar);
    printv("  CPU: msr_syscall_mask:0x%lx\n", cpu->msr_syscall_mask);
}

bool xen_domain::gethvmcontext(xen_vcpu *v,
                               struct xen_domctl_hvmcontext *ctx)
{
    auto uvv = v->m_uv_vcpu;

    /* The HVM context we provide is (in order):
     *
     * HVM_SAVE_TYPE(HEADER)
     * HVM_SAVE_TYPE(CPU)
     * HVM_SAVE_TYPE(LAPIC)
     * HVM_SAVE_TYPE(MTRR)
     * HVM_SAVE_TYPE(END)
     *
     * We may need to provide XSAVE in the cpu portion but it looks
     * like that requires XRSTOR exiting to be enabled.
     */

    constexpr auto DESC_SIZE = sizeof(struct hvm_save_descriptor);
    auto size = DESC_SIZE + HVM_SAVE_LENGTH(HEADER);
    size += DESC_SIZE + HVM_SAVE_LENGTH(CPU);
    size += DESC_SIZE + HVM_SAVE_LENGTH(LAPIC);
    size += DESC_SIZE + HVM_SAVE_LENGTH(MTRR);
    size += DESC_SIZE + HVM_SAVE_LENGTH(END);

    /* Asking for the buffer size */
    if (!ctx->buffer.p) {
        ctx->size = size;
        uvv->set_rax(0);
        return true;
    }

    if (ctx->size != size) {
        uvv->set_rax(-ENOSPC);
        return true;
    }

    auto map = uvv->map_gva_4k<uint8_t>(ctx->buffer.p, size);
    auto buf = map.get();
    auto off = 0UL;

    auto hsd = reinterpret_cast<struct hvm_save_descriptor *>(buf + off);
    hsd->typecode = HVM_SAVE_CODE(HEADER);
    hsd->instance = 0;
    hsd->length = HVM_SAVE_LENGTH(HEADER);
    off += sizeof(*hsd);

    auto hdr = reinterpret_cast<struct hvm_save_header *>(buf + off);
    hdr->magic = HVM_FILE_MAGIC;
    hdr->version = HVM_FILE_VERSION;
    hdr->changeset = 0xBF000000CAFEBABE;
    hdr->cpuid = ::x64::cpuid::eax::get(1);
    hdr->gtsc_khz = m_tsc_khz;
    off += HVM_SAVE_LENGTH(HEADER);

    hsd = reinterpret_cast<struct hvm_save_descriptor *>(buf + off);
    hsd->typecode = HVM_SAVE_CODE(CPU);
    hsd->instance = 0;
    hsd->length = HVM_SAVE_LENGTH(CPU);
    off += sizeof(*hsd);

    auto cpu = reinterpret_cast<struct hvm_hw_cpu *>(buf + off);
    init_hvm_hw_cpu(cpu);
    off += HVM_SAVE_LENGTH(CPU);

    hsd = reinterpret_cast<struct hvm_save_descriptor *>(buf + off);
    hsd->typecode = HVM_SAVE_CODE(LAPIC);
    hsd->instance = 0;
    hsd->length = HVM_SAVE_LENGTH(LAPIC);
    off += sizeof(*hsd);

    auto lapic = reinterpret_cast<struct hvm_hw_lapic *>(buf + off);
    init_hvm_hw_lapic(lapic);
    off += HVM_SAVE_LENGTH(LAPIC);

    hsd = reinterpret_cast<struct hvm_save_descriptor *>(buf + off);
    hsd->typecode = HVM_SAVE_CODE(MTRR);
    hsd->instance = 0;
    hsd->length = HVM_SAVE_LENGTH(MTRR);
    off += sizeof(*hsd);

    auto mtrr = reinterpret_cast<struct hvm_hw_mtrr *>(buf + off);
    init_hvm_hw_mtrr(mtrr);
    off += HVM_SAVE_LENGTH(MTRR);

    hsd = reinterpret_cast<struct hvm_save_descriptor *>(buf + off);
    hsd->typecode = HVM_SAVE_CODE(END);
    hsd->instance = 0;
    hsd->length = HVM_SAVE_LENGTH(END);

    return true;
}

void xen_domain::set_uv_dom_ctx(struct hvm_hw_cpu *cpu)
{
    auto dom = m_uv_dom;

    dom->set_rip(cpu->rip);
    dom->set_rbx(cpu->rbx);

    dom->set_cr0(0x10037);
    dom->set_cr4(0x02000);

    dom->set_cs_limit(0xFFFFFFFF);
    dom->set_ds_limit(0xFFFFFFFF);
    dom->set_es_limit(0xFFFFFFFF);
    dom->set_ss_limit(0xFFFFFFFF);
    dom->set_tr_limit(0x67);

    dom->set_cs_access_rights(0xc09b);
    dom->set_ds_access_rights(0xc093);
    dom->set_es_access_rights(0xc093);
    dom->set_ss_access_rights(0xc093);
    dom->set_fs_access_rights(0x10000);
    dom->set_gs_access_rights(0x10000);
    dom->set_tr_access_rights(0x008b);
    dom->set_ldtr_access_rights(0x10000);

    dom->set_ia32_pat(0x0606060606060606);
}

bool xen_domain::sethvmcontext(xen_vcpu *v,
                               struct xen_domctl_hvmcontext *ctx)
{
    expects(ctx->size);
    expects(ctx->buffer.p);

    auto uvv = v->m_uv_vcpu;
    auto map = uvv->map_gva_4k<uint8_t>(ctx->buffer.p, ctx->size);
    auto buf = map.get();
    auto off = 0U;

    auto hsd = reinterpret_cast<struct hvm_save_descriptor *>(buf + off);
    while (hsd->typecode != HVM_SAVE_CODE(END)) {
        printv("HVM set type: %d\n", hsd->typecode);
        printv("HVM set size: %d\n", hsd->length);

        off += sizeof(*hsd);
        switch (hsd->typecode) {
        case HVM_SAVE_CODE(MTRR):
            dump_hvm_hw_mtrr((struct hvm_hw_mtrr *)(buf + off));
            break;
        case HVM_SAVE_CODE(CPU): {
            this->set_uv_dom_ctx((struct hvm_hw_cpu *)(buf + off));
            uvv->set_rax(0);
            uvv->save_xstate();

            auto root = uvv->root_vcpu();
            expects(root->is_root_vcpu());
            put_xen_domain(m_id);

            root->load();
            root->return_new_domain(m_uv_dom->id());

            /*
             * This should be unreachable, but if for whatever reason we return
             * here, we need to get_xen_domain before the corresponding put in
             * xen_domain_sethvmcontext
             */
            bferror_info(0, "returned from return_new_domain");
            get_xen_domain(m_id);

            return false;
        }
        case HVM_SAVE_CODE(HEADER):
            break;
        default:
            return false;
        }

        off += hsd->length;
        hsd = reinterpret_cast<struct hvm_save_descriptor *>(buf + off);
    }

    uvv->set_rax(0);
    return true;
}

bool xen_domain::setvcpuaffinity(xen_vcpu *v,
                                 struct xen_domctl_vcpuaffinity *aff)
{
    auto uvv = v->m_uv_vcpu;
    auto hard = &aff->cpumap_hard;
    auto soft = &aff->cpumap_soft;

    expects(hard->nr_bits == 8);
    expects(soft->nr_bits == 8);

    if (hard->bitmap.p) {
        auto hard_map = uvv->map_arg<uint8_t>(aff->cpumap_hard.bitmap.p);
        expects(*hard_map.get() == 1);
    }

    if (soft->bitmap.p) {
        auto soft_map = uvv->map_arg<uint8_t>(aff->cpumap_soft.bitmap.p);
        expects(*soft_map.get() == 1);
    }

    uvv->set_rax(0);
    return true;
}

bool xen_domain::set_max_mem(xen_vcpu *v, struct xen_domctl_max_mem *mem)
{
    printv("domain: max_mem: %lu MB\n", mem->max_memkb >> 8);
    v->m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_domain::set_tsc_info(xen_vcpu *v, struct xen_domctl_tsc_info *info)
{
    printv("domain: settscinfo: mode:%u gtsc_khz:%u incarnation:%u elapsed_nsec:%lu\n",
            info->tsc_mode, info->gtsc_khz, info->incarnation, info->elapsed_nsec);

    /* 0 is the default when TSC is monotonic and guest access tsc directly */
    expects(!info->tsc_mode);
    info->gtsc_khz = m_tsc_khz;

    v->m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_domain::shadow_op(xen_vcpu *v, struct xen_domctl_shadow_op *shadow)
{
    switch (shadow->op) {
    case XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION:
        break;
    default:
        bferror_nhex(0, "unhandled shadow_op:", shadow->op);
        return false;
    }

    v->m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_domain::numainfo(xen_vcpu *v, struct xen_sysctl_numainfo *numa)
{
    expects(!m_id);
    auto uvv = v->m_uv_vcpu;

    if (!numa->meminfo.p && !numa->distance.p) {
        numa->num_nodes = m_numa_nodes;
        uvv->set_rax(0);
        return true;
    }

    /* If this fails, then the mapping below will need to account for it */
    expects(numa->num_nodes == 1);

    if (numa->meminfo.p) {
        auto map = uvv->map_arg<xen_sysctl_meminfo_t>(numa->meminfo.p);
        auto mem = map.get();
        mem->memsize = m_max_pages * XEN_PAGE_SIZE;
        mem->memfree = m_free_pages * XEN_PAGE_SIZE;
    }

    if (numa->distance.p) {
        auto map =  uvv->map_arg<uint32_t>(numa->distance.p);
        auto dist = map.get();
        *dist = 0;
    }

    uvv->set_rax(0);
    return true;
}

bool xen_domain::cputopoinfo(xen_vcpu *v, struct xen_sysctl_cputopoinfo *topo)
{
    expects(!m_id);
    auto uvv = v->m_uv_vcpu;

    if (!topo->cputopo.p) {
        topo->num_cpus = m_max_pcpus;
        uvv->set_rax(0);
        return true;
    }

    /* If this fails, then the mapping below will need to account for it */
    expects(topo->num_cpus == 1);

    auto map = uvv->map_arg<xen_sysctl_cputopo_t>(topo->cputopo.p);
    auto cpu = map.get();

    cpu->core = 0;
    cpu->socket = 0;
    cpu->node = 0;

    uvv->set_rax(0);
    return true;
}

bool xen_domain::physinfo(xen_vcpu *v, struct xen_sysctl *ctl)
{
    expects(v->is_xenstore());

    auto info = &ctl->u.physinfo;

    static bool print_xl = true;
    if (print_xl) {
        printv("XL CREATE BEGIN\n");
        print_xl = false;
        hypercall_debug = true;
    }

    info->threads_per_core = 1;
    info->cores_per_socket = 1;
    info->nr_cpus = 1;
    info->max_cpu_id = 0;
    info->nr_nodes = m_numa_nodes;
    info->max_node_id = m_numa_nodes -1;
    info->cpu_khz = m_tsc_khz;
    info->capabilities = XEN_SYSCTL_PHYSCAP_hvm;
    info->capabilities |= XEN_SYSCTL_PHYSCAP_directio; /* IOMMU support */
    info->total_pages = m_total_pages; /* domain RAM size */
    info->free_pages = m_free_pages; /* ??? */
    info->scrub_pages = 0; /* ??? (appear in calc of free memory) */
    info->outstanding_pages = m_out_pages;
    info->max_mfn = m_max_mfn;

    v->m_uv_vcpu->set_rax(0);
    return true;
}

/* Called from xl create path */
bool xen_domain::get_sharing_freed_pages(xen_vcpu *v)
{
    expects(v->is_xenstore());
    v->m_uv_vcpu->set_rax(0);

    return true;
}

/* Called from xl create path */
bool xen_domain::get_sharing_shared_pages(xen_vcpu *v)
{
    expects(v->is_xenstore());
    v->m_uv_vcpu->set_rax(m_shr_pages);

    return true;
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
