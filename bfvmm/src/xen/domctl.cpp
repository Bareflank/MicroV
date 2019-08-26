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

#include <hve/arch/intel_x64/vcpu.h>
#include <bfgpalayout.h>
#include <printv.h>
#include <xen/domctl.h>
#include <xen/xen.h>

#include <public/domctl.h>
#include <public/errno.h>

namespace microv {

domctl::domctl(xen *xen) : m_xen{xen}, m_vcpu{xen->m_vcpu}
{

}

//bool domctl::getdomaininfolist(xen_domctl_t *ctl)
//{
//    auto gdil = &ctl->u.getdomaininfolist;
//
//    expects(m_xen->m_dom->initdom());
//    expects(gdil->first_domain == m_xen->domid);
//    expects(gdil->max_domains == 1);
//
//    gdil->num_domains = 1;
//    auto buf = m_vcpu->map_gva_4k<xen_domctl_getdomaininfo_t>(
//                   gdil->buffer.p,
//                   gdil->max_domains);
//
//    auto info = buf.get();
//    info->domain = m_xen->domid;
//    info->flags |= XEN_DOMINF_hvm_guest;
//    info->flags |= XEN_DOMINF_running;
//    info->flags |= XEN_DOMINF_xs_domain;
//    info->flags |= XEN_DOMINF_hap;
//    info->tot_pages = TOTAL_PAGES;
//    info->max_pages = 0;
//    info->outstanding_pages = 0;
//    info->shr_pages = 0;
//    info->paged_pages = 0;
//    info->shared_info_frame = m_xen->m_shinfo_gpfn;
//    info->cpu_time = 0;
//    info->nr_online_vcpus = 1;
//    info->max_vcpu_id = m_xen->vcpuid;
//    info->ssidref = 0;
//    memcpy(&info->handle, &m_xen->xdh, sizeof(xen_domain_handle_t));
//    info->cpupool = -1; /* CPUPOOLID_NONE */
//    info->arch_config.emulation_flags = 0;
//
//    m_vcpu->set_rax(0);
//    return true;
//}

/* Called from xl create in dom 0 */
//bool domctl::physinfo(xen_domctl_t *ctl)
//{
//}

bool domctl::createdomain(xen_domctl_t *ctl)
{
    auto cd = &ctl->u.createdomain;
    printv("domctl: createdomain 0x%x\n", ctl->domain);
    printv("domctl: ssidref:0x%x flags:0x%x vcpus:%u evtchns:%u grant_frames:%u maptrack_frames:%u arch_flags:0x%x\n",
            cd->ssidref,
            cd->flags,
            cd->max_vcpus,
            cd->max_evtchn_port,
            cd->max_grant_frames,
            cd->max_maptrack_frames,
            cd->arch.emulation_flags);

    if (!ctl->domain) {
        bfalert_info(0, "domctl: need generated domain id");
    }

    m_vcpu->set_rax(0);
    return true;
}

bool domctl::handle(xen_domctl_t *ctl)
{
    if (ctl->interface_version != XEN_DOMCTL_INTERFACE_VERSION) {
        m_vcpu->set_rax(-EACCES);
        return true;
    }

    switch (ctl->cmd) {
    case XEN_DOMCTL_createdomain:
        return this->createdomain(ctl);
    default:
        bfalert_nhex(0, "unhandled domctl", ctl->cmd);
    }

    return false;
}
}
