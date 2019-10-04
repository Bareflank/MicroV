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

#include <microv/gpalayout.h>
#include <compiler.h>
#include <mutex>
#include <stdlib.h>

#include <arch/x64/rdtsc.h>
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vcpu.h>

#include <pci/cfg.h>
#include <pci/bar.h>
#include <pci/dev.h>
#include <printv.h>

#include <xen/cpupool.h>
#include <xen/evtchn.h>
#include <xen/flask.h>
#include <xen/gnttab.h>
#include <xen/hvm.h>
#include <xen/physdev.h>
#include <xen/util.h>
#include <xen/time.h>
#include <xen/memory.h>
#include <xen/version.h>
#include <xen/vcpu.h>

#include <public/arch-x86/cpuid.h>
#include <public/errno.h>
#include <public/memory.h>
#include <public/platform.h>
#include <public/sched.h>
#include <public/sysctl.h>
#include <public/version.h>
#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>
#include <public/xsm/flask_op.h>

namespace microv {

static constexpr auto self_ipi_msr = 0x83F;
static constexpr auto hcall_page_msr = 0xC0000500;
static constexpr auto xen_leaf_base = 0x40000100;
static constexpr auto xen_leaf(int i) { return xen_leaf_base + i; }

/* exits specific to xl-created vcpu boot */
static bool xlboot_io_insn_in(base_vcpu *v, io_insn_handler::info_t &info)
{
//    bfdebug_nhex(0, "xl boot: io_insn in", info.port_number);
    return true;
}

static bool xlboot_io_insn_out(base_vcpu *v, io_insn_handler::info_t &info)
{
//    bfdebug_nhex(0, "xl boot: io_insn out", info.port_number);
    return true;
}

/* end xl-created boot exits */

static bool handle_exception(base_vcpu *vcpu)
{
    namespace int_info = vmcs_n::vm_exit_interruption_information;

    auto info = int_info::get();
    auto type = int_info::interruption_type::get(info);

    if (type == int_info::interruption_type::non_maskable_interrupt) {
        return false;
    }

    auto vec = int_info::vector::get(info);
    bfdebug_info(0, "Guest exception");
    bfdebug_subnhex(0, "vector", vec);
    bfdebug_subnhex(0, "rip", vcpu->rip());

    auto rip = vcpu->map_gva_4k<uint8_t>(vcpu->rip(), 32);
    auto buf = rip.get();

    printf("        - bytes: ");
    for (auto i = 0; i < 32; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    vmcs_n::exception_bitmap::set(0);

    return true;
}

static bool handle_tsc_deadline(base_vcpu *vcpu, wrmsr_handler::info_t &info)
{
    bfalert_info(0, "TSC deadline write after SSHOTTMR set");
    return true;
}

static bool xen_leaf0(base_vcpu *vcpu)
{
    vcpu->set_rax(xen_leaf(5));
    vcpu->set_rbx(XEN_CPUID_SIGNATURE_EBX);
    vcpu->set_rcx(XEN_CPUID_SIGNATURE_ECX);
    vcpu->set_rdx(XEN_CPUID_SIGNATURE_EDX);

    vcpu->advance();
    return true;
}

static bool xen_leaf1(base_vcpu *vcpu)
{
    vcpu->set_rax(0x00040D00);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    vcpu->advance();
    return true;
}

static bool xen_leaf2(base_vcpu *vcpu)
{
    vcpu->set_rax(1);
    vcpu->set_rbx(hcall_page_msr);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    vcpu->advance();
    return true;
}

constexpr auto PSN_LEAF = 3;
constexpr auto MWAIT_LEAF = 5;
constexpr auto DCA_LEAF = 9;

static bool cpuid_zeros(base_vcpu *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    vcpu->advance();
    return true;
}

constexpr auto CLSIZE_LEAF = 0x80000006;
constexpr auto INVARIANT_TSC_LEAF = 0x80000007;
constexpr auto ADDR_SIZE_LEAF = 0x80000008;

static bool cpuid_passthrough(base_vcpu *vcpu)
{
    vcpu->execute_cpuid();
    vcpu->advance();

    return true;
}

bool xen_vcpu::xen_leaf4(base_vcpu *vcpu)
{
    uint32_t rax = 0;

//  rax |= XEN_HVM_CPUID_APIC_ACCESS_VIRT;
    rax |= XEN_HVM_CPUID_X2APIC_VIRT;
//  rax |= XEN_HVM_CPUID_IOMMU_MAPPINGS;
    rax |= XEN_HVM_CPUID_VCPU_ID_PRESENT;
    rax |= XEN_HVM_CPUID_DOMID_PRESENT;

    vcpu->set_rax(rax);
    vcpu->set_rbx(m_id);
    vcpu->set_rcx(m_xen_dom->m_id);

    vcpu->advance();
    return true;
}

bool xen_vcpu::init_hypercall_page(base_vcpu *vcpu, wrmsr_handler::info_t &info)
{
    const auto gfn = xen_frame(info.val);
    const auto err = m_xen_dom->m_memory->map_page(gfn, pg_perm_rwe);

    if (err) {
        vcpu->set_rax(err);
        return false;
    }

    auto map = vcpu->map_gpa_4k<uint8_t>(info.val);
    auto buf = gsl::span(map.get(), 0x1000);

    for (uint8_t i = 0; i < 55; i++) {
        auto entry = buf.subspan(i * 32, 32);

        entry[0] = 0xB8U;
        entry[1] = i;
        entry[2] = 0U;
        entry[3] = 0U;
        entry[4] = 0U;
        entry[5] = 0x0FU;
        entry[6] = 0x01U;
        entry[7] = 0xC1U;
        entry[8] = 0xC3U;
    }

    return true;
}

static bool wrmsr_self_ipi(base_vcpu *vcpu, wrmsr_handler::info_t &info)
{
    vcpu->queue_external_interrupt(info.val);
    return true;
}

bool xen_vcpu::handle_physdev_op()
{
    try {
        switch (m_uv_vcpu->rdi()) {
        case PHYSDEVOP_pci_device_add:
            return m_physdev->pci_device_add();
        default:
            return false;
        }
    } catchall ({
        return false;
    })
}

bool xen_vcpu::handle_console_io()
{
    expects(m_uv_dom->is_xsvm());

    uint64_t len = m_uv_vcpu->rsi();
    auto buf = m_uv_vcpu->map_gva_4k<char>(m_uv_vcpu->rdx(), len);

    switch (m_uv_vcpu->rdi()) {
    case CONSOLEIO_read: {
        auto n = m_xen_dom->hvc_rx_get(gsl::span(buf.get(), len));
        m_uv_vcpu->set_rax(n);
//        if (n) {
//            printf("console read: ");
//            for (auto i = 0; i < n; i++) {
//                printf("%c", buf.get()[i]);
//            }
//            printf("\n");
//        }
        return true;
    }
    case CONSOLEIO_write: {
        auto n = m_xen_dom->hvc_tx_put(gsl::span(buf.get(), len));
        m_uv_vcpu->set_rax(n);
        return true;
    }
    default:
        return false;
    }
}

bool xen_vcpu::handle_memory_op()
{
    try {
        switch (m_uv_vcpu->rdi()) {
        case XENMEM_memory_map:
            return xenmem_memory_map(this);
        case XENMEM_set_memory_map:
            return xenmem_set_memory_map(this);
        case XENMEM_reserved_device_memory_map:
            return xenmem_reserved_device_memory_map(this);
        case XENMEM_add_to_physmap:
            return xenmem_add_to_physmap(this);
        case XENMEM_add_to_physmap_batch:
            return xenmem_add_to_physmap_batch(this);
        case XENMEM_decrease_reservation:
            return xenmem_decrease_reservation(this);
        case XENMEM_get_sharing_freed_pages:
            return m_xen_dom->get_sharing_freed_pages(this);
        case XENMEM_get_sharing_shared_pages:
            return m_xen_dom->get_sharing_shared_pages(this);
        case XENMEM_claim_pages:
            return xenmem_claim_pages(this);
        case XENMEM_populate_physmap:
            return xenmem_populate_physmap(this);
        case XENMEM_remove_from_physmap:
            return xenmem_remove_from_physmap(this);
        case XENMEM_acquire_resource:
            return xenmem_acquire_resource(this);
        default:
            break;
        }
    } catchall ({
        return false;
    })

    return false;
}

bool xen_vcpu::handle_xen_version()
{
    try {
        switch (m_uv_vcpu->rdi()) {
        case XENVER_version:
            return m_xenver->version();
        case XENVER_extraversion:
            return m_xenver->extraversion();
        case XENVER_compile_info:
            return m_xenver->compile_info();
        case XENVER_capabilities:
            return m_xenver->capabilities();
        case XENVER_changeset:
            return m_xenver->changeset();
        case XENVER_platform_parameters:
            return m_xenver->platform_parameters();
        case XENVER_get_features:
            return m_xenver->get_features();
        case XENVER_pagesize:
            return m_xenver->pagesize();
        case XENVER_guest_handle:
            return m_xenver->guest_handle();
        case XENVER_commandline:
            return m_xenver->commandline();
        case XENVER_build_id:
            return m_xenver->build_id();
        default:
            return false;
        }
    } catchall ({
        return false;
    })
}

bool xen_vcpu::handle_hvm_op()
{
    switch (m_uv_vcpu->rdi()) {
    case HVMOP_set_param:
        return xen_hvm_set_param(this);
    case HVMOP_get_param:
        return xen_hvm_get_param(this);
    case HVMOP_pagetable_dying:
        return xen_hvm_pagetable_dying(this);
    default:
        return false;
    }
}

bool xen_vcpu::handle_event_channel_op()
{
    try {
        switch (m_uv_vcpu->rdi()) {
        case EVTCHNOP_unmask:
            return xen_evtchn_unmask(this);
        case EVTCHNOP_status:
            return xen_evtchn_status(this);
        case EVTCHNOP_init_control:
            return xen_evtchn_init_control(this);
        case EVTCHNOP_set_priority:
            return xen_evtchn_set_priority(this);
        case EVTCHNOP_alloc_unbound:
            return xen_evtchn_alloc_unbound(this);
        case EVTCHNOP_expand_array:
            return xen_evtchn_expand_array(this);
        case EVTCHNOP_bind_virq:
            return xen_evtchn_bind_virq(this);
        case EVTCHNOP_send:
            return xen_evtchn_send(this);
        case EVTCHNOP_bind_interdomain:
            return xen_evtchn_bind_interdomain(this);
        case EVTCHNOP_close:
            return xen_evtchn_close(this);
        case EVTCHNOP_bind_vcpu:
            return xen_evtchn_bind_vcpu(this);
        default:
            return false;
        }
    } catchall({
        return false;
    })

    return false;
}

bool xen_vcpu::handle_sysctl()
{
    try {
        auto ctl = m_uv_vcpu->map_arg<xen_sysctl_t>(m_uv_vcpu->rdi());
        if (ctl->interface_version != XEN_SYSCTL_INTERFACE_VERSION) {
            m_uv_vcpu->set_rax(-EACCES);
            return true;
        }

        switch (ctl->cmd) {
        case XEN_SYSCTL_getdomaininfolist:
            return xen_domain_getinfolist(this, ctl.get());
        case XEN_SYSCTL_get_cpu_featureset:
            return xen_domain_get_cpu_featureset(this, ctl.get());
        case XEN_SYSCTL_physinfo:
            return m_xen_dom->physinfo(this, ctl.get());
        case XEN_SYSCTL_cpupool_op:
            return xen_cpupool_op(this, ctl.get());
        case XEN_SYSCTL_numainfo:
            return xen_domain_numainfo(this, ctl.get());
        case XEN_SYSCTL_cputopoinfo:
            return xen_domain_cputopoinfo(this, ctl.get());

        default:
            bfalert_nhex(0, "unimplemented sysctl", ctl->cmd);
            return false;
        }
    } catchall({
        return false;
    })
}

/* xl create */
bool xen_vcpu::handle_domctl()
{
    auto uvv = m_uv_vcpu;

    try {
        auto ctl = uvv->map_arg<xen_domctl_t>(uvv->rdi());
        if (ctl->interface_version != XEN_DOMCTL_INTERFACE_VERSION) {
            uvv->set_rax(-EACCES);
            return true;
        }

        switch (ctl->cmd) {
        case XEN_DOMCTL_createdomain:
            expects(ctl->domain == 0xFFFF);
            return xen_domain_createdomain(this, ctl.get());
        case XEN_DOMCTL_destroydomain:
            return xen_domain_destroydomain(this, ctl.get());
        case XEN_DOMCTL_unpausedomain:
            return xen_domain_unpausedomain(this, ctl.get());
        case XEN_DOMCTL_pausedomain:
            return xen_domain_pausedomain(this, ctl.get());
        case XEN_DOMCTL_max_vcpus:
            expects(ctl->u.max_vcpus.max == 1);
            uvv->set_rax(0);
            return true;
        case XEN_DOMCTL_set_cpuid:
            return xen_domain_set_cpuid(this, ctl.get());
        case XEN_DOMCTL_setvcpuaffinity:
            return xen_domain_setvcpuaffinity(this, ctl.get());
        case XEN_DOMCTL_getvcpuextstate:
            return xen_domain_getvcpuextstate(this, ctl.get());
        case XEN_DOMCTL_setnodeaffinity:
            uvv->set_rax(0);
            return true;
        case XEN_DOMCTL_max_mem:
            return xen_domain_max_mem(this, ctl.get());
        case XEN_DOMCTL_settscinfo:
            return xen_domain_set_tsc_info(this, ctl.get());
        case XEN_DOMCTL_shadow_op:
            return xen_domain_shadow_op(this, ctl.get());
        case XEN_DOMCTL_getdomaininfo:
            return xen_domain_getdomaininfo(this, ctl.get());
        case XEN_DOMCTL_gethvmcontext:
            return xen_domain_gethvmcontext(this, ctl.get());
        case XEN_DOMCTL_sethvmcontext:
            return xen_domain_sethvmcontext(this, ctl.get());
        case XEN_DOMCTL_ioport_permission:
            return xen_domain_ioport_perm(this, ctl.get());
        case XEN_DOMCTL_iomem_permission:
            return xen_domain_iomem_perm(this, ctl.get());
        case XEN_DOMCTL_assign_device:
            return xen_domain_assign_device(this, ctl.get());
        default:
            bfalert_nhex(0, "unimplemented domctl", ctl->cmd);
            return false;
        }
    } catchall({
        return false;
    })
}

bool xen_vcpu::handle_grant_table_op()
{
    try {
        expects(m_uv_vcpu->rdx() > 0);

        switch (m_uv_vcpu->rdi()) {
        case GNTTABOP_map_grant_ref:
            return xen_gnttab_map_grant_ref(this);
        case GNTTABOP_unmap_grant_ref:
            return xen_gnttab_unmap_grant_ref(this);
        case GNTTABOP_copy:
            return xen_gnttab_copy(this);
        case GNTTABOP_query_size:
            return xen_gnttab_query_size(this);
        case GNTTABOP_set_version:
            return xen_gnttab_set_version(this);
        default:
            return false;
        }
    } catchall ({
        return false;
    })
}

bool xen_vcpu::handle_platform_op()
{
    auto xpf = m_uv_vcpu->map_arg<xen_platform_op_t>(m_uv_vcpu->rdi());
    if (xpf->interface_version != XENPF_INTERFACE_VERSION) {
        m_uv_vcpu->set_rax(-EACCES);
        return true;
    }

    switch (xpf->cmd) {
    case XENPF_get_cpuinfo: {
        expects(m_uv_dom->is_xsvm());
        struct xenpf_pcpuinfo *info = &xpf->u.pcpu_info;
        info->max_present = 1;
        info->flags = XEN_PCPU_FLAGS_ONLINE;
        info->apic_id = m_apicid;
        info->acpi_id = m_acpiid;
        m_uv_vcpu->set_rax(0);
        return true;
    }
    case XENPF_settime64: {
        const struct xenpf_settime64 *time = &xpf->u.settime64;
        if (time->mbz) {
            m_uv_vcpu->set_rax(-EINVAL);
            return false;
        }

        m_xen_dom->update_wallclock(this, time);
        m_uv_vcpu->set_rax(0);
        return true;
    }
    default:
        bfalert_ndec(0, "Unimplemented platform op", xpf->cmd);
        return false;
    }
}

bool xen_vcpu::handle_xsm_op()
{
    expects(m_uv_dom->is_xsvm());
    auto fop = m_uv_vcpu->map_arg<xen_flask_op_t>(m_uv_vcpu->rdi());

    return m_flask->handle(fop.get());
}

struct vcpu_time_info *xen_vcpu::vcpu_time()
{
    /* TODO make sure this is initialized properly since
     * the page is available right after construction */
    expects(m_xen_dom->m_shinfo);
    return &m_xen_dom->m_shinfo->vcpu_info[m_id].time;
}

void xen_vcpu::stop_timer()
{
    m_uv_vcpu->disable_preemption_timer();
    m_pet_enabled = false;
}

int xen_vcpu::set_timer()
{
    auto pet = 0ULL;
    auto vti = this->vcpu_time();
    auto sst = m_uv_vcpu->map_arg<vcpu_set_singleshot_timer_t>(m_uv_vcpu->rdx());

    /* Get the preemption timer ticks corresponding to the deadline */
    if (vti->system_time >= sst->timeout_abs_ns) {
        if (sst->flags & VCPU_SSHOTTMR_future) {
            return -ETIME;
        }
        pet = 0;
    } else {
        auto ns = sst->timeout_abs_ns - vti->system_time;
        auto tsc = ns_to_tsc(ns, vti->tsc_shift, vti->tsc_to_system_mul);
        pet = tsc_to_pet(tsc, m_pet_shift);
    }

    m_uv_vcpu->set_preemption_timer(pet);
    m_uv_vcpu->enable_preemption_timer();
    m_pet_enabled = true;

    return 0;
}

/*
 * Note this is protected by expects(rsi() == m_id), which means
 * the target of the hypercall is *this. Once dom0 starts creating
 * vcpus itself, the target will be different and this check will fail.
 * At that point we need to reimplement these to handle that situation.
 */
bool xen_vcpu::handle_vcpu_op()
{
    expects(m_uv_vcpu->rsi() == m_id);

    switch (m_uv_vcpu->rdi()) {
    case VCPUOP_stop_periodic_timer:
        m_uv_vcpu->set_rax(0);
        return true;
    case VCPUOP_stop_singleshot_timer:
        this->stop_timer();
        m_uv_vcpu->set_rax(0);
        return true;
    case VCPUOP_set_singleshot_timer:
        m_uv_vcpu->set_rax(this->set_timer());
        if (!m_pet_hdlrs_added) {
            m_uv_vcpu->add_preemption_timer_handler({&xen_vcpu::handle_pet, this});
            m_uv_vcpu->add_hlt_handler({&xen_vcpu::handle_hlt, this});
            m_uv_vcpu->add_exit_handler({&xen_vcpu::vmexit_save_tsc, this});
            m_uv_vcpu->emulate_wrmsr(0x6E0, {handle_tsc_deadline});
            m_pet_hdlrs_added = true;
        }
        return true;
    case VCPUOP_register_vcpu_time_memory_area:
        return this->register_vcpu_time();
    case VCPUOP_register_runstate_memory_area:
        return this->register_runstate();
    default:
        return false;
    }
}

bool xen_vcpu::register_vcpu_time()
{
    auto uvv = m_uv_vcpu;
    auto tma = uvv->map_arg<vcpu_register_time_memory_area_t>(uvv->rdx());

    m_user_vti = uvv->map_arg<struct vcpu_time_info>(tma->addr.v);
    memcpy(m_user_vti.get(), this->vcpu_time(), sizeof(*this->vcpu_time()));

    uvv->set_rax(0);
    return true;
}

bool xen_vcpu::register_runstate()
{
    auto uvv = m_uv_vcpu;
    auto rma = uvv->map_arg<vcpu_register_runstate_memory_area_t>(uvv->rdx());

    std::lock_guard lock(m_runstate_mtx);

    m_runstate = uvv->map_arg<struct vcpu_runstate_info>(rma->addr.v);
    m_runstate->state = RUNSTATE_running;
    m_runstate->state_entry_time = this->vcpu_time()->system_time;
    m_runstate->time[RUNSTATE_running] = m_runstate->state_entry_time;

    uvv->set_rax(0);
    return true;
}

bool xen_vcpu::handle_vm_assist()
{
    if (m_uv_vcpu->rdi() != VMASST_CMD_enable) {
        return false;
    }

    switch (m_uv_vcpu->rsi()) {
    case VMASST_TYPE_runstate_update_flag:
        m_runstate_assist = true;
        m_uv_vcpu->set_rax(0);
        return true;
    default:
        return false;
    }
}

bool xen_vcpu::handle_sched_op()
{
    const auto cmd = m_uv_vcpu->rdi();

    switch (cmd) {
    case SCHEDOP_yield: {
        uint64_t usec = 50; /* default yield time ?? */

        if (m_pet_enabled) {
            auto pet = m_uv_vcpu->get_preemption_timer();
            usec = ((pet << m_pet_shift) * 1000) / m_tsc_khz;
        }

        this->update_runstate(RUNSTATE_runnable);

        m_uv_vcpu->set_rax(0);
        m_uv_vcpu->save_xstate();
        m_uv_vcpu->root_vcpu()->load();
        m_uv_vcpu->root_vcpu()->return_yield(usec);

        /* unreachable */
        return false;
    }

    default:
        printv("%s: cmd=%lu unhandled\n", __func__, cmd);
        return false;
    }
}

bool xen_vcpu::is_xenstore()
{
    return m_xen_dom->m_uv_info->is_xenstore();
}

void xen_vcpu::queue_virq(uint32_t virq)
{
    m_xen_dom->m_evtchn->queue_virq(virq);
}

void xen_vcpu::update_runstate(int new_state)
{
    if (GSL_UNLIKELY(!m_xen_dom->m_shinfo)) {
        return;
    }

    /* Update kernel time info */
    auto kvti = this->vcpu_time();
    const uint64_t mult = kvti->tsc_to_system_mul;
    const uint64_t shft = kvti->tsc_shift;
    const uint64_t prev = kvti->tsc_timestamp;

    kvti->version++;
    ::intel_x64::wmb();
    const auto next = ::x64::read_tsc::get();
    kvti->system_time += tsc_to_ns(next - prev, shft, mult);
    kvti->tsc_timestamp = next;
    ::intel_x64::wmb();
    kvti->version++;

    if (GSL_UNLIKELY(!m_user_vti)) {
        return;
    }

    /* Update userspace time info */
    auto uvti = m_user_vti.get();
    uvti->version++;
    ::intel_x64::wmb();
    uvti->system_time = kvti->system_time;
    uvti->tsc_timestamp = next;
    ::intel_x64::wmb();
    uvti->version++;

    if (GSL_UNLIKELY(!m_runstate)) {
        return;
    }

    /* Update runstate info */
    std::lock_guard lock(m_runstate_mtx);

    auto old_state = m_runstate->state;
    auto old_entry = m_runstate->state_entry_time;

    m_runstate->time[old_state] += kvti->system_time - old_entry;
    m_runstate->state = new_state;

    if (GSL_LIKELY(m_runstate_assist)) {
        m_runstate->state_entry_time = XEN_RUNSTATE_UPDATE;
        ::intel_x64::wmb();
        m_runstate->state_entry_time |= kvti->system_time;
        ::intel_x64::wmb();
        m_runstate->state_entry_time &= ~XEN_RUNSTATE_UPDATE;
        ::intel_x64::wmb();
    } else {
        m_runstate->state_entry_time = kvti->system_time;
    }
}

uint64_t xen_vcpu::runstate_time(int state)
{
    expects(state >= 0);
    expects(state <= RUNSTATE_offline);

    std::lock_guard lock(m_runstate_mtx);

    if (!m_runstate) {
        return 0;
    }

    return m_runstate->time[state];
}

/* Steal ticks from the guest's preemption timer */
void xen_vcpu::steal_pet_ticks()
{
    if (GSL_UNLIKELY(m_tsc_at_exit == 0)) {
        return;
    }

    auto pet = m_uv_vcpu->get_preemption_timer();
    auto tsc = this->vcpu_time()->tsc_timestamp;
    auto stolen_tsc = tsc - m_tsc_at_exit;
    auto stolen_pet = stolen_tsc >> m_pet_shift;

    pet = (stolen_pet >= pet) ? 0 : pet - stolen_pet;
    m_uv_vcpu->set_preemption_timer(pet);
}

void xen_vcpu::resume_update(bfobject *obj)
{
    bfignored(obj);

    this->update_runstate(RUNSTATE_running);

    if (m_pet_enabled) {
        steal_pet_ticks();
    }
}

void xen_vcpu::init_shared_info(uintptr_t shinfo_gpfn)
{
    using namespace ::intel_x64::msrs;

    auto tsc = m_xen_dom->init_shared_info(this, shinfo_gpfn);
    if (!tsc) {
        bferror_info(0, "xen_domain::init_shared_info returned 0");
        return;
    }

    auto vti = this->vcpu_time();
    vti->flags |= XEN_PVCLOCK_TSC_STABLE_BIT;
    vti->tsc_shift = m_tsc_shift;
    vti->tsc_to_system_mul = m_tsc_mul;
    vti->tsc_timestamp = tsc;

    m_uv_vcpu->add_resume_delegate({&xen_vcpu::resume_update, this});
}

bool xen_vcpu::vmexit_save_tsc(base_vcpu *vcpu)
{
    bfignored(vcpu);

    if (m_pet_enabled) {
        m_tsc_at_exit = ::x64::read_tsc::get();
    }

    return true;
}

bool xen_vcpu::handle_pet(base_vcpu *vcpu)
{
    this->stop_timer();
    m_xen_dom->m_evtchn->queue_virq(VIRQ_TIMER);

    return true;
}

/*
 * This will be called *anytime* an interrupt arrives while the guest is running.
 * Care must be taken to ensure that all the structures referenced here are
 * valid. For example, any initialization that depends on guest hypercalls must
 * be checked because this handler could run before the guest executes its first
 * instruction.
 *
 * TODO: add different handlers as more and more state comes online as an
 * optmization to save unnecessary branch instructions.
 */
bool xen_vcpu::handle_interrupt(base_vcpu *vcpu, interrupt_handler::info_t &info)
{
    auto root = m_uv_vcpu->root_vcpu();

    /*
     * Note that guests can safely access their root vcpu without synchronization
     * as long as they are guaranteed to be pinned to the same cpu
     */
    auto guest_msi = root->find_guest_msi(info.vector);

    if (guest_msi) {
        auto pdev = guest_msi->dev();
        expects(pdev);

        auto guest = get_vcpu(pdev->m_guest_vcpuid);
        if (!guest) {
            return true;
        }

        if (guest == m_uv_vcpu) {
            guest->queue_external_interrupt(guest_msi->vector());
        } else {
            guest->push_external_interrupt(guest_msi->vector());
        }

        put_vcpu(pdev->m_guest_vcpuid);
    } else {
        m_uv_vcpu->save_xstate();
        this->update_runstate(RUNSTATE_runnable);

        root->load();
        root->queue_external_interrupt(info.vector);
        root->return_interrupted();
    }

    return true;
}

bool xen_vcpu::handle_hlt(
    base_vcpu *vcpu,
    bfvmm::intel_x64::hlt_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    using namespace vmcs_n;

    if (guest_rflags::interrupt_enable_flag::is_disabled()) {
        return false;
    }

    m_uv_vcpu->advance();
    m_xen_dom->m_evtchn->queue_virq(VIRQ_TIMER);
    this->update_runstate(RUNSTATE_blocked);
    guest_interruptibility_state::blocking_by_sti::disable();

    auto pet = m_uv_vcpu->get_preemption_timer();
    auto yield = ((pet << m_pet_shift) * 1000) / m_tsc_khz;

    m_uv_vcpu->save_xstate();
    m_uv_vcpu->root_vcpu()->load();
    m_uv_vcpu->root_vcpu()->return_yield(yield);

    // unreachable
    return true;
}

bool xen_vcpu::debug_hypercall(microv_vcpu *vcpu)
{
    const auto rax = vcpu->rax();
    const auto rdi = vcpu->rdi();

    if (rax == __HYPERVISOR_sched_op && rdi == SCHEDOP_yield) {
        return false;
    }

    if (rax == __HYPERVISOR_event_channel_op && rdi == EVTCHNOP_send) {
        return false;
    }

    if (!this->is_xenstore()) {
        if (rax == __HYPERVISOR_vcpu_op && rdi == VCPUOP_set_singleshot_timer) {
            return false;
        }

        if (rax == __HYPERVISOR_grant_table_op && rdi == GNTTABOP_copy) {
            return false;
        }
        return true;
    }

    if (rax == __HYPERVISOR_console_io) {
        return false;
    }

    if (rax == __HYPERVISOR_vcpu_op && rdi == VCPUOP_set_singleshot_timer) {
        return false;
    }

    if (rax == __HYPERVISOR_event_channel_op && rdi == EVTCHNOP_status) {
        return false;
    }

    if (rax == __HYPERVISOR_memory_op && rdi == XENMEM_populate_physmap) {
        return false;
    }

    if (rax == __HYPERVISOR_memory_op && rdi == XENMEM_decrease_reservation) {
        return false;
    }

    if (rax == __HYPERVISOR_memory_op && rdi == XENMEM_add_to_physmap_batch) {
        return false;
    }

    if (rax == __HYPERVISOR_memory_op && rdi == XENMEM_remove_from_physmap) {
        return false;
    }

    if (rax == __HYPERVISOR_physdev_op && rdi == PHYSDEVOP_pci_device_add) {
        return false;
    }

    return true;
}

bool xen_vcpu::hypercall(microv_vcpu *vcpu)
{
    if (!m_debug_hypercalls) {
        return false;
    }

    if (this->debug_hypercall(vcpu)) {
        debug_xen_hypercall(this);
    }

    switch (vcpu->rax()) {
    case __HYPERVISOR_memory_op:
        return this->handle_memory_op();
    case __HYPERVISOR_xen_version:
        return this->handle_xen_version();
    case __HYPERVISOR_hvm_op:
        return this->handle_hvm_op();
    case __HYPERVISOR_event_channel_op:
        return this->handle_event_channel_op();
    case __HYPERVISOR_grant_table_op:
        return this->handle_grant_table_op();
    case __HYPERVISOR_platform_op:
        return this->handle_platform_op();
    case __HYPERVISOR_console_io:
        return this->handle_console_io();
    case __HYPERVISOR_sysctl:
        return this->handle_sysctl();
    case __HYPERVISOR_domctl:
        return this->handle_domctl();
    case __HYPERVISOR_xsm_op:
        return this->handle_xsm_op();
    case __HYPERVISOR_physdev_op:
        return this->handle_physdev_op();
    case __HYPERVISOR_vcpu_op:
        return this->handle_vcpu_op();
    case __HYPERVISOR_vm_assist:
        return this->handle_vm_assist();
    case __HYPERVISOR_sched_op:
        return this->handle_sched_op();
    default:
        return false;
    }
}

xen_vcpu::xen_vcpu(microv_vcpu *vcpu) :
    m_uv_vcpu{vcpu},
    m_uv_dom{vcpu->dom()},
    m_xen_dom{m_uv_dom->xen_dom()}
{
    m_id = 0;
    m_apicid = 0;
    m_acpiid = 0;

    m_flask = std::make_unique<class xen_flask>(this);
    m_xenver = std::make_unique<class xen_version>(this);
    m_physdev = std::make_unique<class xen_physdev>(this);

    m_tsc_khz = vcpu->m_yield_handler.m_tsc_freq;
    m_tsc_mul = (1000000ULL << 32) / m_tsc_khz;
    m_tsc_shift = 0;
    m_pet_shift = vcpu->m_yield_handler.m_pet_shift;

    vcpu->add_cpuid_emulator(xen_leaf(0), {xen_leaf0});
    vcpu->add_cpuid_emulator(xen_leaf(2), {xen_leaf2});
    vcpu->emulate_wrmsr(hcall_page_msr, {&xen_vcpu::init_hypercall_page, this});
    vcpu->add_vmcall_handler({&xen_vcpu::hypercall, this});
    vcpu->add_cpuid_emulator(xen_leaf(1), {xen_leaf1});
    vcpu->add_cpuid_emulator(xen_leaf(4), {&xen_vcpu::xen_leaf4, this});

    vcpu->add_handler(0, handle_exception);
    vcpu->emulate_wrmsr(self_ipi_msr, {wrmsr_self_ipi});
    vcpu->add_external_interrupt_handler({&xen_vcpu::handle_interrupt, this});

    m_xen_dom->bind_vcpu(this);

    vcpu->emulate_io_instruction(0xA1, {xlboot_io_insn_in}, {xlboot_io_insn_out});
    vcpu->emulate_io_instruction(0x21, {xlboot_io_insn_in}, {xlboot_io_insn_out});
    vcpu->emulate_io_instruction(0x43, {xlboot_io_insn_in}, {xlboot_io_insn_out});
    vcpu->emulate_io_instruction(0x80, {xlboot_io_insn_in}, {xlboot_io_insn_out});
    vcpu->emulate_io_instruction(0x40, {xlboot_io_insn_in}, {xlboot_io_insn_out});

    /* Toolstack cpuid accesses */
    vcpu->add_cpuid_emulator(PSN_LEAF, {cpuid_zeros});
    vcpu->add_cpuid_emulator(MWAIT_LEAF, {cpuid_zeros});
    vcpu->add_cpuid_emulator(0x8, {cpuid_zeros});
    vcpu->add_cpuid_emulator(DCA_LEAF, {cpuid_zeros});
    vcpu->add_cpuid_emulator(0xC, {cpuid_zeros});
    vcpu->add_cpuid_emulator(0x80000005, {cpuid_zeros});
    vcpu->add_cpuid_emulator(CLSIZE_LEAF, {cpuid_passthrough});
    vcpu->add_cpuid_emulator(INVARIANT_TSC_LEAF, {cpuid_passthrough});
    vcpu->add_cpuid_emulator(ADDR_SIZE_LEAF, {cpuid_passthrough});
}
}
