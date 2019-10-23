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
#include <printv.h>
#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>
#include <xen/domain.h>
#include <xen/evtchn.h>
#include <xen/hvm.h>
#include <xen/vcpu.h>

namespace microv {

bool xen_hvm_set_param(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto param = uvv->map_arg<xen_hvm_param_t>(uvv->rsi());

    if (param->index >= HVM_NR_PARAMS) {
        uvv->set_rax(-EINVAL);
        return true;
    }

    auto domid = param->domid;
    if (domid == DOMID_SELF) {
        domid = vcpu->m_xen_dom->m_id;
    }

    auto dom = get_xen_domain(domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_hvm->set_param(vcpu, param.get());
    put_xen_domain(domid);

    return ret;
}

bool xen_hvm_get_param(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto param = uvv->map_arg<xen_hvm_param_t>(uvv->rsi());

    if (param->index >= HVM_NR_PARAMS) {
        uvv->set_rax(-EINVAL);
        return true;
    }

    auto domid = param->domid;
    if (domid == DOMID_SELF) {
        domid = vcpu->m_xen_dom->m_id;
    }

    auto dom = get_xen_domain(domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_hvm->get_param(vcpu, param.get());
    put_xen_domain(domid);

    return ret;
}

bool xen_hvm_pagetable_dying(xen_vcpu *vcpu)
{
    vcpu->m_uv_vcpu->set_rax(-ENOSYS);
    return true;
}

bool xen_hvm_set_evtchn_upcall_vector(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto arg = uvv->map_arg<xen_hvm_evtchn_upcall_vector_t>(uvv->rsi());
    auto ret = vcpu->m_xen_dom->m_evtchn->set_upcall_vector(vcpu, arg.get());

    uvv->set_rax(ret);
    return true;
}

void xen_hvm::init_root_store_params()
{
    /*
     * Note both the store and console pages are accessed from this guest
     * (i.e. the root domain) and dom0. Right now, the pages are already
     * mapped into the root's EPT which is identity mapped, so no more
     * work is needed for the root to use them. The dom0 guest will map
     * in the xenstore page when the root is xs_introduce_domain()'d to
     * xenstore.
     */
    store_page = std::make_unique<uint8_t[]>(UV_PAGE_SIZE);

    evtchn_alloc_unbound_t store_chan = {
        .dom = DOMID_SELF,
        .remote_dom = 0,
        .port = 0
    };

    if (int rc = xen_dom->m_evtchn->alloc_unbound(&store_chan); rc) {
        printv("winpv: failed to alloc store port, rc=%d\n", rc);
        return;
    }

    const auto gpfn = xen_frame(g_mm->virtptr_to_physint(store_page.get()));
    const auto port = store_chan.port;

    printv("winpv: xenstore pfn=0x%lx, evtchn=%u\n", gpfn, port);

    params[HVM_PARAM_STORE_PFN] = gpfn;
    params[HVM_PARAM_STORE_EVTCHN] = port;
}

void xen_hvm::init_root_console_params()
{
    console_page = std::make_unique<uint8_t[]>(UV_PAGE_SIZE);

    evtchn_alloc_unbound_t console_chan = {
        .dom = DOMID_SELF,
        .remote_dom = 0,
        .port = 0
    };

    if (int rc = xen_dom->m_evtchn->alloc_unbound(&console_chan); rc) {
        printv("winpv: failed to alloc console port, rc=%d\n", rc);
        return;
    }

    const auto gpfn = xen_frame(g_mm->virtptr_to_physint(console_page.get()));
    const auto port = console_chan.port;

    printv("winpv: console pfn=0x%lx, evtchn=%u\n", gpfn, port);

    params[HVM_PARAM_CONSOLE_PFN] = gpfn;
    params[HVM_PARAM_CONSOLE_EVTCHN] = port;
}

xen_hvm::xen_hvm(xen_domain *dom, xen_memory *mem) :
    xen_dom{dom},
    xen_mem{mem}
{
    if (xen_dom->m_uv_info->origin != domain_info::origin_root) {
        return;
    }

    if (xen_dom->m_id == DOMID_WINPV) {
        init_root_store_params();
        init_root_console_params();
    }
}

bool xen_hvm::set_param(xen_vcpu *vcpu, xen_hvm_param_t *p)
{
    int err = 0;

    switch (p->index) {
    case HVM_PARAM_CALLBACK_IRQ:
        err = xen_dom->m_evtchn->set_upcall_vector(vcpu, p);
        break;
    case HVM_PARAM_TIMER_MODE:
        err = xen_dom->set_timer_mode(p->value);
        break;
    case HVM_PARAM_NESTEDHVM:
    case HVM_PARAM_ALTP2M:
        if (p->value != 0) {
            err = -EINVAL;
        }
        break;
    case HVM_PARAM_PAE_ENABLED:
    case HVM_PARAM_IDENT_PT:
        break;
    case HVM_PARAM_STORE_PFN:
    case HVM_PARAM_BUFIOREQ_PFN:
    case HVM_PARAM_IOREQ_PFN:
    case HVM_PARAM_CONSOLE_PFN:
    case HVM_PARAM_PAGING_RING_PFN:
    case HVM_PARAM_MONITOR_RING_PFN:
    case HVM_PARAM_SHARING_RING_PFN:
        if (!xen_mem->find_page(p->value)) {
            xen_mem->add_page(p->value, pg_perm_rw, pg_mtype_wb);
        }
        break;
    case HVM_PARAM_STORE_EVTCHN:
    case HVM_PARAM_CONSOLE_EVTCHN:
        break;
    default:
        bferror_nhex(0, "unhandled hvm set_param", p->index);
        return false;
    }

    if (!err) {
        params[p->index] = p->value;
    }

    vcpu->m_uv_vcpu->set_rax(err);
    return true;
}

uint64_t xen_hvm::get_param(uint32_t index) const
{
    expects(index < params.size());
    return params[index];
}

bool xen_hvm::get_param(xen_vcpu *vcpu, xen_hvm_param_t *p)
{
    int err = 0;
    auto uvv = vcpu->m_uv_vcpu;

    if (uvv->is_guest_vcpu()) {
        switch (p->index) {
        case HVM_PARAM_STORE_PFN:
        case HVM_PARAM_CONSOLE_PFN:
        case HVM_PARAM_PAE_ENABLED:
        case HVM_PARAM_NESTEDHVM:
        case HVM_PARAM_STORE_EVTCHN:
        case HVM_PARAM_CONSOLE_EVTCHN:
            break;
        default:
            bferror_nhex(0, "hvm get_param:", p->index);
            return false;
        }

        p->value = this->get_param(p->index);
        uvv->set_rax(err);

        return true;
    }

    if (uvv->is_root_vcpu()) {
        expects(vcpu->m_xen_dom->m_id == DOMID_WINPV);
        expects(this->xen_dom->m_id == DOMID_WINPV);

        switch (p->index) {
        case HVM_PARAM_STORE_EVTCHN:
        case HVM_PARAM_CONSOLE_EVTCHN:
            p->value = this->get_param(p->index);
            uvv->set_rax(0);
            return true;
        default:
            return false;
        }
    }

    printv("%s: ERROR invalid vcpu type\n", __func__);
    return false;
}

}
