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

#include <bfgpalayout.h>
#include <printv.h>
#include <xen/sysctl.h>
#include <xen/xen.h>

#include <public/domctl.h>
#include <public/errno.h>

#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12

#define TOTAL_PAGES (PVH_MEM_SIZE >> PAGE_SHIFT)

namespace microv {

sysctl::sysctl(xen *xen) : m_xen{xen}, m_vcpu{xen->m_vcpu}
{

}

bool sysctl::getdomaininfolist(xen_sysctl_t *ctl)
{
    auto gdil = &ctl->u.getdomaininfolist;

    expects(m_xen->m_dom->initdom());
    expects(gdil->first_domain == m_xen->domid);
    expects(gdil->max_domains == 1);

    gdil->num_domains = 1;
    auto buf = m_vcpu->map_gva_4k<xen_domctl_getdomaininfo_t>(
                   gdil->buffer.p,
                   gdil->max_domains);

    auto info = buf.get();
    info->domain = m_xen->domid;
    info->flags |= XEN_DOMINF_hvm_guest;
    info->flags |= XEN_DOMINF_running;
    info->flags |= XEN_DOMINF_xs_domain;
    info->flags |= XEN_DOMINF_hap;
    info->tot_pages = TOTAL_PAGES;
    info->max_pages = 0;
    info->outstanding_pages = 0;
    info->shr_pages = 0;
    info->paged_pages = 0;
    info->shared_info_frame = m_xen->m_shinfo_gpfn;
    info->cpu_time = 0;
    info->nr_online_vcpus = 1;
    info->max_vcpu_id = m_xen->vcpuid;
    info->ssidref = 0;
    memcpy(&info->handle, &m_xen->xdh, sizeof(xen_domain_handle_t));
    info->cpupool = -1; /* CPUPOOLID_NONE */
    info->arch_config.emulation_flags = 0;

    m_vcpu->set_rax(0);
    return true;
}

/* Called from xl create in dom 0 */
bool sysctl::physinfo(xen_sysctl_t *ctl)
{
    auto info = &ctl->u.physinfo;

     /* the core counts may need to be massaged for migrating to bfexec */
    info->threads_per_core = 1;
    info->cores_per_socket = 1;
    info->nr_cpus = 1; /* # online cpus */
    info->max_cpu_id = 0;
    info->nr_nodes = 1; /* # numa nodes */
    info->max_node_id = 0;
    info->cpu_khz = m_xen->m_tsc_khz;
    info->capabilities = XEN_SYSCTL_PHYSCAP_hvm;
    info->capabilities |= XEN_SYSCTL_PHYSCAP_directio;
    info->max_mfn = PVH_MAX_MFN;
    info->total_pages = TOTAL_PAGES;
    info->free_pages = TOTAL_PAGES; /* TODO */
    info->scrub_pages = 0; /* TODO */
    info->outstanding_pages = 0; /* TODO */

    m_vcpu->set_rax(0);

    static bool pr_create = true;
    if (pr_create) {
        bfdebug_info(0, "BEGIN XL CREATE");
        pr_create = false;
    }

    return true;
}

bool sysctl::cpupool_op(xen_sysctl_t *ctl)
{
    auto cpo = &ctl->u.cpupool_op;

    printv("sysctl: cpupool op:%u pool_id:0x%x sched_id:0x%x domid:0x%x\n",
            cpo->op,
            cpo->cpupool_id,
            cpo->sched_id,
            cpo->domid);

    m_vcpu->set_rax(0);
    return true;
}

bool sysctl::handle(xen_sysctl_t *ctl)
{
    if (ctl->interface_version != XEN_SYSCTL_INTERFACE_VERSION) {
        m_vcpu->set_rax(-EACCES);
        return true;
    }

    switch (ctl->cmd) {
    case XEN_SYSCTL_getdomaininfolist:
        return this->getdomaininfolist(ctl);

    /* called from xl create */
    case XEN_SYSCTL_physinfo:
        return this->physinfo(ctl);
    case XEN_SYSCTL_cpupool_op:
        return this->cpupool_op(ctl);

    default:
        bfalert_nhex(0, "unhandled sysctl", ctl->cmd);
    }

    return false;
}
}
