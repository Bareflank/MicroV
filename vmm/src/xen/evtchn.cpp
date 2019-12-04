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

#include <atomic_ops.h>
#include <printv.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <xen/domain.h>
#include <xen/evtchn.h>
#include <xen/virq.h>
#include <xen/vcpu.h>

namespace microv {

using word_t = xen_evtchn::word_t;
using port_t = xen_evtchn::port_t;

/**
 * FIFO event channels
 *
 * This implementation of the Xen event channel interface as defined
 * in deps/xen/xen/include/public/event_channel.h only supports
 * the FIFO ABI (as opposed to the original "2l" ABI) for now.
 *
 * With the FIFO ABI, event words are the primary mechanism for
 * controlling events between the VMM and a guest. Whenever a
 * guest requires event services, it allocates a page of event words
 * (i.e. uint32_t's) with each word's EVTCHN_FIFO_MASKED bit set. This page
 * is then shared with the VMM via the EVTCHNOP_expand_array hypercall.
 * The guest then associates a word with a port by allocating a port from
 * the VMM (a port serves as the "address" of an event channel and is the
 * main currency used throughout the ABI). When an event arrives
 * at a given port, the VMM sets the EVTCHN_FIFO_PENDING bit in the
 * corresponding event word, and adds the word onto the FIFO queue. The queue
 * is defined by another page of shared memory initialized by the
 * EVTCHNOP_init_control hypercall. After linking the word into the queue,
 * the VMM injects an interrupt into the guest vcpu's "callback vector".
 * The handler at this vector consumes each event on the queue, calling
 * any registered callbacks as necessary.
 *
 * TODO: the code assumes that backing pages of words and chans stays valid
 * after acquiring a pointer to one. To fully support suspend/resume a refcount
 * or similar will need to be added to prevent use-after-free.
 */

bool xen_evtchn_init_control(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto eic = uvv->map_arg<evtchn_init_control_t>(uvv->rsi());

    expects(v->m_xen_dom);
    return v->m_xen_dom->m_evtchn->init_control(v, eic.get());
}

bool xen_evtchn_unmask(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto arg = uvv->map_arg<evtchn_unmask_t>(uvv->rsi());

    return v->m_xen_dom->m_evtchn->unmask(v, arg.get());
}

bool xen_evtchn_expand_array(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto eea = uvv->map_arg<evtchn_expand_array_t>(uvv->rsi());

    expects(v->m_xen_dom);
    return v->m_xen_dom->m_evtchn->expand_array(v, eea.get());
}

bool xen_evtchn_set_priority(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto esp = uvv->map_arg<evtchn_set_priority_t>(uvv->rsi());

    expects(v->m_xen_dom);
    return v->m_xen_dom->m_evtchn->set_priority(v, esp.get());
}

bool xen_evtchn_status(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto sts = uvv->map_arg<evtchn_status_t>(uvv->rsi());
    auto domid = sts->dom;

    if (domid == DOMID_SELF || domid == v->m_xen_dom->m_id) {
        return v->m_xen_dom->m_evtchn->status(v, sts.get());
    }

    auto dom = get_xen_domain(domid);
    if (!dom) {
        printv("%s: dom:0x%x not found\n", __func__, domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_evtchn->status(v, sts.get());
    put_xen_domain(domid);
    return ret;
}

bool xen_evtchn_alloc_unbound(xen_vcpu *v)
{
    expects(v->m_xen_dom);

    auto rc = -EINVAL;
    auto uvv = v->m_uv_vcpu;
    auto eau = uvv->map_arg<evtchn_alloc_unbound_t>(uvv->rsi());
    auto domid = eau->dom;

    if (domid == DOMID_SELF || domid == v->m_xen_dom->m_id) {
        rc = v->m_xen_dom->m_evtchn->alloc_unbound(eau.get());
    } else {
        auto dom = get_xen_domain(domid);
        if (!dom) {
            printv("%s: dom:0x%x not found\n", __func__, domid);
            uvv->set_rax(-ESRCH);
            return true;
        }

        try {
            rc = dom->m_evtchn->alloc_unbound(eau.get());
        } catch (...) {
            put_xen_domain(domid);
            throw;
        }

        put_xen_domain(domid);
    }

    uvv->set_rax(rc);
    return true;
}

bool xen_evtchn_bind_interdomain(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto ebi = uvv->map_arg<evtchn_bind_interdomain_t>(uvv->rsi());

    expects(v->m_xen_dom);
    return v->m_xen_dom->m_evtchn->bind_interdomain(v, ebi.get());
}

bool xen_evtchn_bind_vcpu(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto ebv = uvv->map_arg<evtchn_bind_vcpu_t>(uvv->rsi());

    expects(v->m_xen_dom);
    return v->m_xen_dom->m_evtchn->bind_vcpu(v, ebv.get());
}

bool xen_evtchn_bind_virq(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto ebv = uvv->map_arg<evtchn_bind_virq_t>(uvv->rsi());

    expects(v->m_xen_dom);
    return v->m_xen_dom->m_evtchn->bind_virq(v, ebv.get());
}

bool xen_evtchn_close(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto ec = uvv->map_arg<evtchn_close_t>(uvv->rsi());

    expects(v->m_xen_dom);
    return v->m_xen_dom->m_evtchn->close(v, ec.get());
}

bool xen_evtchn_send(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto es = uvv->map_arg<evtchn_send_t>(uvv->rsi());

    expects(v->m_xen_dom);
    return v->m_xen_dom->m_evtchn->send(v, es.get());
}

xen_evtchn::xen_evtchn(xen_domain *dom) : m_xen_dom{dom}
{
    m_nr_ports = dom->m_max_evtchn_port + 1;
    ensures(is_power_of_2(m_nr_ports));

    /* Each port maps one-to-one to a word and a chan */
    const auto total_words = m_nr_ports;
    const auto total_chans = m_nr_ports;

    m_word_pages.reserve(total_words / words_per_page);
    m_chan_pages.reserve(total_chans / chans_per_page);

    ensures(m_word_pages.capacity() > 0);
    ensures(m_chan_pages.capacity() > 0);

    this->setup_ports();
}

/* This signature sets the vector for vcpu0 */
int xen_evtchn::set_upcall_vector(xen_vcpu *v, xen_hvm_param_t *param)
{
    auto type = (param->value & HVM_PARAM_CALLBACK_IRQ_TYPE_MASK) >> 56;
    if (type != HVM_PARAM_CALLBACK_TYPE_VECTOR) {
        printv("%s: unsupported type: 0x%llx\n", __func__, type);
        return -EINVAL;
    }

    auto vector = param->value & 0xFFU;
    if (vector < 0x20U) {
        printv("%s: invalid vector: 0x%lx\n", __func__, vector);
        return -ERANGE;
    }

    expects(m_event_ctl.size() > 0);
    m_event_ctl[0]->upcall_vector = vector;
    printv("evtchn: set global upcall vector: 0x%lx\n", vector);

    return 0;
}

/* This signature sets the vector for the vcpu referenced in arg */
int xen_evtchn::set_upcall_vector(xen_vcpu *v,
                                  xen_hvm_evtchn_upcall_vector_t *arg)
{
    if (arg->vcpu >= m_event_ctl.size()) {
        printv("%s: invalid vcpuid: 0x%x\n", __func__, arg->vcpu);
        return -EINVAL;
    }

    if (arg->vector < 0x20U || arg->vector >= 0xFFU) {
        printv("%s: invalid vector: 0x%x\n", __func__, arg->vector);
        return -ERANGE;
    }

    auto ctl = m_event_ctl[arg->vcpu].get();
    ctl->upcall_vector = arg->vector;

    printv("evtchn: set upcall vector 0x%x on vcpu 0x%x\n",
           arg->vector,
           arg->vcpu);

    return 0;
}

bool xen_evtchn::init_control(xen_vcpu *v, evtchn_init_control_t *ctl)
{
    expects(ctl->offset <= (UV_PAGE_SIZE - sizeof(evtchn_fifo_control_block_t)));
    expects((ctl->offset & 0x7) == 0);

    this->add_event_ctl(v, ctl);
    return true;
}

bool xen_evtchn::expand_array(xen_vcpu *v, evtchn_expand_array_t *eea)
{
    auto uvv = v->m_uv_vcpu;
    this->make_word_page(uvv, eea->array_gfn);

    printv("evtchn: added event word page at 0x%lx\n", xen_addr(eea->array_gfn));
    uvv->set_rax(0);

    return true;
}

bool xen_evtchn::set_priority(xen_vcpu *v, evtchn_set_priority_t *esp)
{
    auto chan = this->port_to_chan(esp->port);
    expects(chan);

    printv("evtchn: set port %u priority: old=%u new=%u\n",
           esp->port, chan->priority, esp->priority);

    chan->priority = esp->priority;
    v->m_uv_vcpu->set_rax(0);

    return true;
}

bool xen_evtchn::status(xen_vcpu *v, evtchn_status_t *sts)
{
    auto uvv = v->m_uv_vcpu;
    auto chan = this->port_to_chan(sts->port);

    expects(chan);

    switch (chan->state) {
    case event_channel::state_free:
        sts->status = EVTCHNSTAT_closed;
        break;
    case event_channel::state_reserved:
        printv("%s: port %u is reserved\n", __func__, sts->port);
        uvv->set_rax(-EINVAL);
        return true;
    case event_channel::state_unbound:
        sts->status = EVTCHNSTAT_unbound;
        sts->u.unbound.dom = chan->rdomid;
        break;
    case event_channel::state_interdomain:
        sts->status = EVTCHNSTAT_interdomain;
        sts->u.interdomain.dom = chan->rdomid;
        sts->u.interdomain.port = chan->rport;
        break;
    case event_channel::state_pirq:
        sts->status = EVTCHNSTAT_pirq;
        sts->u.pirq = chan->pirq;
        break;
    case event_channel::state_virq:
        sts->status = EVTCHNSTAT_virq;
        sts->u.virq = chan->virq;
        break;
    case event_channel::state_ipi:
        sts->status = EVTCHNSTAT_ipi;
        break;
    }

    sts->vcpu = chan->vcpuid;
    uvv->set_rax(0);

    return true;
}

bool xen_evtchn::unmask(xen_vcpu *v, evtchn_unmask_t *unmask)
{
    auto word = this->port_to_word(unmask->port);
    expects(word);

    clear_bit(word, EVTCHN_FIFO_MASKED);

    if (test_bit(word, EVTCHN_FIFO_PENDING)) {
        auto chan = this->port_to_chan(unmask->port);
        expects(chan);
        this->queue_upcall(chan);
    }

    v->m_uv_vcpu->set_rax(0);
    return true;
}

int xen_evtchn::alloc_unbound(evtchn_alloc_unbound_t *eau)
{
    auto port = this->bind(chan_t::state_unbound);
    auto chan = this->port_to_chan(port);

    if (eau->remote_dom == DOMID_SELF) {
        chan->rdomid = m_xen_dom->m_id;
    } else {
        chan->rdomid = eau->remote_dom;
    }

    printv("evtchn: alloc_unbound: lport:%u ldom:0x%x rdom:0x%x\n",
            port,
            m_xen_dom->m_id,
            chan->rdomid);

    eau->port = port;

    return 0;
}

int xen_evtchn::bind_interdomain(evtchn_port_t lport,
                                 evtchn_port_t rport,
                                 xen_domid_t rdomid)
{
    auto chan = this->port_to_chan(lport);

    expects(chan);
    expects(chan->port == lport);

    printv("evtchn: bind_interdom(2): lport:%u ldom:0x%x rport:%u rdom:0x%x\n",
            lport, m_xen_dom->m_id, rport, rdomid);

    if (chan->state != chan_t::state_unbound) {
        return -EINVAL;
    }

    if (chan->rdomid != rdomid) {
        return -EINVAL;
    }

    chan->state = chan_t::state_interdomain;
    chan->rport = rport;

    return 0;
}

bool xen_evtchn::bind_interdomain(xen_vcpu *v, evtchn_bind_interdomain_t *ebi)
{
    auto uvv = v->m_uv_vcpu;
    bool put_remote = false;

    auto ldomid = v->m_xen_dom->m_id;
    auto rport = ebi->remote_port;
    auto rdomid = ebi->remote_dom;

    if (rdomid == DOMID_SELF) {
        rdomid = ldomid;
    }

    xen_domain *remote = nullptr;

    if (rdomid == ldomid) {
        remote = m_xen_dom;
    } else {
        remote = get_xen_domain(rdomid);
        if (!remote) {
            bferror_nhex(0, "remote dom not found:", rdomid);
            uvv->set_rax(-EINVAL);
            return true;
        }
        put_remote = true;
    }

    try {
        auto port = this->bind(chan_t::state_interdomain);

        printv("evtchn: bind_interdom(1): lport:%u ldom:0x%x rport:%u rdom:0x%x\n",
               port, ldomid, rport, rdomid);
        /*
         * Look up the channel at rport and ensure 1) its state
         * is unbound and 2) it's accepting connections from ldomid
         */
        auto err = remote->m_evtchn->bind_interdomain(rport, port, ldomid);

        if (err) {
            bferror_nhex(0, "failed to bind_interdomain on remote", rdomid);
            if (put_remote) {
                put_remote = false;
                put_xen_domain(rdomid);
            }
            uvv->set_rax(-EINVAL);
            return true;
        } else {
            if (put_remote) {
                put_remote = false;
                put_xen_domain(rdomid);
            }
        }

        auto chan = this->port_to_chan(port);

        chan->rdomid = rdomid;
        chan->rport = ebi->remote_port;

        this->queue_upcall(chan);

        ebi->local_port = port;
        uvv->set_rax(0);

        return true;
    } catch (...) {
        if (put_remote) {
            put_xen_domain(rdomid);
        }
        throw;
    }
}

bool xen_evtchn::bind_vcpu(xen_vcpu *v, evtchn_bind_vcpu_t *ebv)
{
    expects(ebv->vcpu == v->m_id);

    auto chan = this->port_to_chan(ebv->port);
    expects(chan);
    expects(chan->vcpuid == v->m_id);

    printv("evtchn: bind_vcpu to port %u\n", ebv->port);
    v->m_uv_vcpu->set_rax(0);

    return true;
}

bool xen_evtchn::bind_virq(xen_vcpu *v, evtchn_bind_virq_t *ebv)
{
    expects(ebv->vcpu < m_xen_dom->m_nr_vcpus);
    expects(ebv->virq < virq_info.size());
    expects(ebv->virq < m_virq_to_port.size());

    auto port = this->bind(chan_t::state_virq);
    auto chan = this->port_to_chan(port);

    chan->vcpuid = ebv->vcpu;
    chan->virq = ebv->virq;

    m_virq_to_port[ebv->virq] = port;
    ebv->port = port;

    printv("evtchn: bind_virq %s to port %u on vcpu 0x%x\n",
           virq_info[ebv->virq].name, port, ebv->vcpu);

    v->m_uv_vcpu->set_rax(0);
    return true;
}

void xen_evtchn::unbind_interdomain(evtchn_port_t port, xen_domid_t rdomid)
{
    auto chan = this->port_to_chan(port);

    expects(chan);
    expects(chan->state == chan_t::state_interdomain);
    expects(chan->rdomid == rdomid);

    chan->state = chan_t::state_unbound;
}

bool xen_evtchn::close(xen_vcpu *v, evtchn_close_t *ec)
{
    auto uvv = v->m_uv_vcpu;
    auto chan = this->port_to_chan(ec->port);

    expects(chan);
    printv("evtchn: close port %u\n", ec->port);

    switch (chan->state) {
    case chan_t::state_free:
    case chan_t::state_reserved:
        printv("evtchn::close: invalid state: port:%u state:%u\n", ec->port,
                chan->state);
        uvv->set_rax(-EINVAL);
        return true;
    case chan_t::state_unbound:
        break;
    case chan_t::state_interdomain: {
        auto rdom = get_xen_domain(chan->rdomid);
        if (!rdom) {
            printv("evtchn::close: remote 0x%x not found\n", chan->rdomid);
            uvv->set_rax(-EINVAL);
            return false;
        }

        try {
            rdom->m_evtchn->unbind_interdomain(chan->rport, m_xen_dom->m_id);
        } catch (...) {
            put_xen_domain(chan->rdomid);
            throw;
        }

        put_xen_domain(chan->rdomid);
        break;
    }
    case chan_t::state_pirq:
        break;
    case chan_t::state_virq:
        expects(chan->virq < m_virq_to_port.size());
        m_virq_to_port[chan->virq] = 0;
        break;
    case chan_t::state_ipi:
        break;
    default:
        printv("evtchn::close: state %u unknown\n", chan->state);
        uvv->set_rax(-EINVAL);
        return false;
    }

    chan->free();
    uvv->set_rax(0);
    return true;
}

void xen_evtchn::notify_remote(chan_t *chan)
{
    const auto ldomid = m_xen_dom->m_id;
    const auto rdomid = chan->rdomid;

    if (ldomid == rdomid) {
        auto rchan = this->port_to_chan(chan->rport);
        expects(rchan);
        this->queue_upcall(rchan);
        return;
    }

    auto rdom = get_xen_domain(rdomid);
    if (!rdom) {
        printv("%s: remote 0x%x not found\n", __func__, rdomid);
        return;
    }

    /*
     * Use push_upcall here so that we don't access the remote's vmcs.
     * Alternatively, we could check the affinity of the remote vcpu
     * and if it is the same as us, we could vmcs->load() then queue_upcall.
     *
     * N.B. this will not queue the callback vector into the remote if it
     * is a guest domain (as opposed to root domain), which means that the
     * remote may not see this event until another comes along. This is fine
     * assuming the guest kernel uses periodic idle because the timer tick will
     * ensure forward progress.
     *
     * N.B. push_upcall acquires a lock of the channel referenced by the port
     * argument. This is to ensure that VMM access to the channel's data and
     * corresponding event word is synchronized. The other upcall variants
     * are NOT locked right now, so dont use them here unless locks are added.
     */

    rdom->m_evtchn->push_upcall(chan->rport);
    put_xen_domain(rdomid);
}

bool xen_evtchn::send(xen_vcpu *v, evtchn_send_t *es)
{
    auto chan = this->port_to_chan(es->port);
    if (GSL_UNLIKELY(!chan)) {
        bfalert_nhex(0, "evtchn::send: chan not found:", es->port);
        return false;
    }

    /* Xen allows interdomain and IPIs to be sent here */
    switch (chan->state) {
    case chan_t::state_interdomain:
        this->notify_remote(chan);
        break;
    case chan_t::state_ipi:
        this->queue_upcall(chan);
        break;
    case chan_t::state_unbound:
        break;
    default:
        v->m_uv_vcpu->set_rax(-EINVAL);
        bfalert_nhex(0, "evtchn::send: unsupported state", chan->state);
        return true;
    }

    v->m_uv_vcpu->set_rax(0);
    return true;
}

void xen_evtchn::queue_virq(uint32_t virq)
{
    auto port = m_virq_to_port[virq];

    /*
     * If the vcpu faults prior to binding the console virq, we
     * will arrive here because of the ^C command to kill the vcpu.
     * In this case we silently return.
     */
    if (!port && virq == VIRQ_CONSOLE) {
        return;
    } else {
        expects(port);
    }

    auto chan = this->port_to_chan(port);
    expects(chan);
    expects(chan->virq == virq);

    this->queue_upcall(chan);
}

void xen_evtchn::inject_virq(uint32_t virq)
{
    auto port = m_virq_to_port[virq];
    expects(port);

    auto chan = this->port_to_chan(port);
    expects(chan);
    expects(chan->virq == virq);

    this->inject_upcall(chan);
}

void xen_evtchn::add_event_ctl(xen_vcpu *v, evtchn_init_control_t *ctl)
{
    auto uvv = v->m_uv_vcpu;
    auto vcpuid = ctl->vcpu;

    if (vcpuid >= m_xen_dom->m_nr_vcpus) {
        printv("%s: invalid vcpuid: %u (dom->nr_vcpus=%lu)\n",
                __func__, vcpuid, m_xen_dom->m_nr_vcpus);
        uvv->set_rax(-EINVAL);
        return;
    }

    if (vcpuid != m_event_ctl.size()) {
        printv("%s: vcpuid %u inserted out of order\n", __func__, vcpuid);
        uvv->set_rax(-EINVAL);
        return;
    }

    m_event_ctl.emplace_back(std::make_unique<struct event_control>(uvv, ctl));
    ctl->link_bits = EVTCHN_FIFO_LINK_BITS;
    uvv->set_rax(0);
}

void xen_evtchn::setup_ports()
{
    expects(m_word_pages.size() == 0);
    expects(m_chan_pages.size() == 0);
    expects(m_allocated_words == 0);
    expects(m_allocated_chans == 0);

    this->make_chan_page(0);
    this->port_to_chan(0)->state = chan_t::state_reserved;
}

xen_evtchn::port_t xen_evtchn::bind(chan_t::state_t state)
{
    auto port = this->make_new_port();
    auto chan = this->port_to_chan(port);

    expects(chan);
    expects(chan->port == port);
    chan->state = state;

    return port;
}

void xen_evtchn::push_upcall(port_t port)
{
    auto chan = this->port_to_chan(port);
    expects(chan);

    this->push_upcall(chan);
}

void xen_evtchn::push_upcall(chan_t *chan)
{
    spin_acquire(&chan->lock);
    auto ___ = gsl::finally([chan](){ spin_release(&chan->lock); });

    if (this->raise(chan)) {
        auto xend = m_xen_dom;
        auto xenv = xend->get_xen_vcpu(chan->vcpuid);

        if (!xenv) {
            bferror_nhex(0, "could not get xen vcpu, dom=", xend->m_id);
            return;
        }

        auto ctl = m_event_ctl[chan->vcpuid].get();
        xenv->push_external_interrupt(ctl->upcall_vector);
        xend->put_xen_vcpu(chan->vcpuid);
    }
}

void xen_evtchn::queue_upcall(chan_t *chan)
{
    if (this->raise(chan)) {
        auto xend = m_xen_dom;
        auto xenv = xend->get_xen_vcpu(chan->vcpuid);

        if (!xenv) {
            bferror_nhex(0, "could not get xen vcpu, dom=", xend->m_id);
            return;
        }

        auto ctl = m_event_ctl[chan->vcpuid].get();
        xenv->queue_external_interrupt(ctl->upcall_vector);
        xend->put_xen_vcpu(chan->vcpuid);
    }
}

void xen_evtchn::inject_upcall(chan_t *chan)
{
    if (this->raise(chan)) {
        auto xend = m_xen_dom;
        auto xenv = xend->get_xen_vcpu(chan->vcpuid);

        if (!xenv) {
            bferror_nhex(0, "could not get xen vcpu, dom=", xend->m_id);
            return;
        }

        auto ctl = m_event_ctl[chan->vcpuid].get();
        xenv->inject_external_interrupt(ctl->upcall_vector);
        xend->put_xen_vcpu(chan->vcpuid);
    }
}

static int attempt_link(word_t *tail, event_word_t *w, port_t port) noexcept
{
    if (!(*w & (1 << EVTCHN_FIFO_LINKED))) {
        return 0;
    }

    event_word_t mask = (1 << EVTCHN_FIFO_BUSY) | EVTCHN_FIFO_LINK_MASK;
    event_word_t &need = *w;
    event_word_t want = (need & ~mask) | port;

    return tail->compare_exchange_strong(need, want) ? 1 : -EAGAIN;
}

/*
 * Atomically set the LINK field iff it is still LINKED.
 *
 * The guest is only permitted to make the following changes to a
 * LINKED event.
 *
 * - set MASKED
 * - clear MASKED
 * - clear PENDING
 * - clear LINKED (and LINK)
 *
 * We block unmasking by the guest by marking the tail word as BUSY,
 * therefore, the cmpxchg() may fail at most 4 times.
 */
static bool set_link(word_t *tail, port_t port) noexcept
{
    event_word_t w = read_atomic(tail);

    int ret = attempt_link(tail, &w, port);
    if (ret >= 0) {
        return ret;
    }

    /* Lock the word to prevent guest unmasking. */
    set_bit(tail, EVTCHN_FIFO_BUSY);

    w = read_atomic(tail);

    for (auto attempt = 0; attempt < 4; attempt++) {
        ret = attempt_link(tail, &w, port);

        if (ret >= 0) {
            if (ret == 0) {
                clear_bit(tail, EVTCHN_FIFO_BUSY);
            }
            return ret;
        }
    }

    bfalert_nhex(0, "evtchn: failed to set link", port);
    clear_bit(tail, EVTCHN_FIFO_BUSY);

    return true;
}

struct event_queue *xen_evtchn::lock_old_queue(chan_t *chan)
{
    struct event_control *ctl;
    struct event_queue *q, *oldq;

    for (auto attempt = 0; attempt < 3; attempt++) {
        ctl = m_event_ctl[chan->prev_vcpuid].get();
        oldq = &ctl->queue[chan->prev_priority];

        spin_acquire(&oldq->lock);

        ctl = m_event_ctl[chan->prev_vcpuid].get();
        q = &ctl->queue[chan->prev_priority];

        if (oldq == q) {
            return oldq;
        }

        spin_release(&oldq->lock);
    }

    printv("%s: ALERT: lost event at port %u (too many queue changes)\n",
           __func__, chan->port);

    return nullptr;
}

/*
 * For further reference on the algorithm used here see:
 *   https://xenbits.xenproject.org/people/dvrabel/event-channels-F.pdf
 *
 * Xen's implementation:
 *   deps/xen/xen/common/events_fifo.c:evtchn_fifo_set_pending
 *
 * Linux guest side:
 *   deps/linux/drivers/xen/events/events_fifo.c:__evtchn_fifo_handle_events
 *
 * Windows guest side:
 *   drivers/winpv/xenbus/src/xenbus/evtchn_fifo.c:EvtchnFifoPoll
 */

bool xen_evtchn::raise(chan_t *chan)
{
    if (chan->vcpuid >= m_event_ctl.size()) {
        printv("%s: OOB vcpuid=%u, event_ctl.size=%lu\n",
                __func__, chan->vcpuid, m_event_ctl.size());
        return false;
    }

    auto port = chan->port;
    auto word = this->port_to_word(port);

    if (!word) {
        bferror_nhex(0, "port doesn't map to word", port);
        return false;
    }

    set_bit(word, EVTCHN_FIFO_PENDING);

    if (test_bit(word, EVTCHN_FIFO_MASKED)) {
        return false;
    }

    if (test_bit(word, EVTCHN_FIFO_LINKED)) {
        return false;
    }

    auto ctl = m_event_ctl[chan->vcpuid].get();
    expects(chan->priority < EVTCHN_FIFO_MAX_QUEUES);

    auto curq = &ctl->queue[chan->priority];
    auto oldq = this->lock_old_queue(chan);

    if (!oldq) {
        return false;
    }

    if (test_and_set_bit(word, EVTCHN_FIFO_LINKED)) {
        spin_release(&oldq->lock);
        return false;
    }

    /*
     * If this event was a tail, the old queue is now empty and
     * its tail must be invalidated to prevent adding an event to
     * the old queue from corrupting the new queue.
     */
    if (oldq->tail == port) {
        oldq->tail = 0;
    }

    if (oldq != curq) {
        chan->prev_vcpuid = chan->vcpuid;
        chan->prev_priority = chan->priority;

        spin_release(&oldq->lock);
        spin_acquire(&curq->lock);
    }

    bool linked = false;

    /*
     * Write port into the link field of the tail word iff
     * the tail word itself is linked.
     */
    if (curq->tail) {
        auto tail_word = this->port_to_word(curq->tail);
        linked = set_link(tail_word, port);
    }

    /*
     * If the tail wasn't linked, the queue is empty. In this
     * case we update head to point to the new event.
     */
    if (!linked) {
        write_atomic(curq->head, port);
    }

    curq->tail = port;
    spin_release(&curq->lock);

    /*
     * Only preform an upcall if the queue was empty and the queue's
     * priority bit in the ready word transitions from 0 to 1.
     */
    if (!linked && !test_and_set_bit(ctl->ready, chan->priority)) {
        m_xen_dom->set_upcall_pending(chan->vcpuid);
        return true;
    }

    return false;
}

xen_evtchn::port_t xen_evtchn::make_new_port()
{
    for (port_t p = m_port_end; p < m_nr_ports; p++) {
        if (this->make_port(p) == -EBUSY) {
            continue;
        }

        m_port_end = p + 1U;
        return p;
    }

    throw std::runtime_error("evtchn ports exhausted");
}

xen_evtchn::chan_t *xen_evtchn::port_to_chan(port_t port) const
{
    auto size = m_chan_pages.size();
    auto page = (port & chan_page_mask) >> chan_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto chan = m_chan_pages[page].get();
    return &chan[port & chan_mask];
}

xen_evtchn::word_t *xen_evtchn::port_to_word(port_t port) const
{
    auto size = m_word_pages.size();
    auto page = (port & word_page_mask) >> word_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto word = m_word_pages[page].get();
    return &word[port & word_mask];
}

int xen_evtchn::make_port(port_t port)
{
    if (port >= m_nr_ports) {
        throw std::invalid_argument("make_port: port out of range: " +
                                    std::to_string(port));
    }

    if (auto chan = this->port_to_chan(port); chan) {
        if (chan->state != chan_t::state_free) {
            return -EBUSY;
        }

        auto word = this->port_to_word(port);
        if (word && test_bit(word, EVTCHN_FIFO_BUSY)) {
            return -EBUSY;
        }

        return 0;
    }

    this->make_chan_page(port);
    return 0;
}

void xen_evtchn::make_chan_page(port_t port)
{
    auto indx = (port & chan_page_mask) >> chan_page_shift;
    auto size = m_chan_pages.size();
    auto cpty = m_chan_pages.capacity();

    expects(size == indx);
    expects(size < cpty);

    auto page = make_page<chan_t>();

    for (auto i = 0U; i < chans_per_page; i++) {
        auto chan = &page.get()[i];
        chan->reset(port + i);
    }

    m_chan_pages.push_back(std::move(page));
    m_allocated_chans += chans_per_page;
}

void xen_evtchn::make_word_page(microv_vcpu *uvv, uintptr_t gfn)
{
    expects(m_word_pages.size() < m_word_pages.capacity());

    m_word_pages.push_back(uvv->map_gpa_4k<word_t>(xen_addr(gfn)));
    m_allocated_words += words_per_page;
}

}
