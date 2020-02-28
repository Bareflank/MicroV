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

using word_t = xen_evtchn::word_t;
using port_t = xen_evtchn::port_t;

bool xen_evtchn_reset(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto arg = uvv->map_arg<evtchn_reset_t>(uvv->rsi());

    expects(v->m_xen_dom);

    if (arg->dom == DOMID_SELF || arg->dom == v->m_xen_dom->m_id) {
        return v->m_xen_dom->m_evtchn->reset(v);
    } else {
        uvv->set_rax(-ESRCH);
        return true;
    }
}

bool xen_evtchn_init_control(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto eic = uvv->map_arg<evtchn_init_control_t>(uvv->rsi());
    auto ret = v->m_xen_dom->m_evtchn->init_control(v, eic.get());

    uvv->set_rax(ret);
    return true;
}

bool xen_evtchn_unmask(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto arg = uvv->map_arg<evtchn_unmask_t>(uvv->rsi());
    auto ret = v->m_xen_dom->m_evtchn->unmask(v, arg.get());

    uvv->set_rax(ret);
    return true;
}

bool xen_evtchn_expand_array(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto eea = uvv->map_arg<evtchn_expand_array_t>(uvv->rsi());
    auto ret = v->m_xen_dom->m_evtchn->expand_array(v, eea.get());

    uvv->set_rax(ret);
    return true;
}

bool xen_evtchn_set_priority(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto esp = uvv->map_arg<evtchn_set_priority_t>(uvv->rsi());
    auto ret = v->m_xen_dom->m_evtchn->set_priority(v, esp.get());

    uvv->set_rax(ret);
    return true;
}

bool xen_evtchn_status(xen_vcpu *v)
{
    auto rc = -EINVAL;
    auto uvv = v->m_uv_vcpu;
    auto sts = uvv->map_arg<evtchn_status_t>(uvv->rsi());
    auto domid = sts->dom;

    if (domid == DOMID_SELF || domid == v->m_xen_dom->m_id) {
        rc = v->m_xen_dom->m_evtchn->status(v, sts.get());
    } else {
        auto dom = get_xen_domain(domid);
        if (!dom) {
            printv("%s: dom:0x%x not found\n", __func__, domid);
            uvv->set_rax(-ESRCH);
            return true;
        }

        auto put_dom = gsl::finally([domid](){ put_xen_domain(domid); });
        rc = dom->m_evtchn->status(v, sts.get());
    }

    uvv->set_rax(rc);
    return true;
}

bool xen_evtchn_alloc_unbound(xen_vcpu *v)
{
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

        auto put_dom = gsl::finally([domid](){ put_xen_domain(domid); });
        rc = dom->m_evtchn->alloc_unbound(eau.get());
    }

    uvv->set_rax(rc);
    return true;
}

bool xen_evtchn_bind_interdomain(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto ebi = uvv->map_arg<evtchn_bind_interdomain_t>(uvv->rsi());
    auto ret = v->m_xen_dom->m_evtchn->bind_interdomain(v, ebi.get());

    uvv->set_rax(ret);
    return true;
}

bool xen_evtchn_bind_vcpu(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto ebv = uvv->map_arg<evtchn_bind_vcpu_t>(uvv->rsi());
    auto ret = v->m_xen_dom->m_evtchn->bind_vcpu(v, ebv.get());

    uvv->set_rax(ret);
    return true;
}

bool xen_evtchn_bind_virq(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto ebv = uvv->map_arg<evtchn_bind_virq_t>(uvv->rsi());
    auto ret = v->m_xen_dom->m_evtchn->bind_virq(v, ebv.get());

    uvv->set_rax(ret);
    return true;
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

    /*
     * Allocate the first page of struct event_channels. Each
     * channel is initialized to a default state == chan_t::state_free.
     * We mark the first channel as chan_t::state_reserved, which in
     * effect makes port 0 reserved, i.e., any port allocated for guest
     * use must have a positive value.
     */
    this->make_chan_page(0);
    this->port_to_chan(0)->state = chan_t::state_reserved;
}

int xen_evtchn::init_control(xen_vcpu *v, evtchn_init_control_t *ctl)
{
    auto vcpuid = ctl->vcpu;
    auto offset = ctl->offset;

    if (vcpuid >= m_xen_dom->m_nr_vcpus) {
        return -ENOENT;
    }

    if (offset > (UV_PAGE_SIZE - sizeof(evtchn_fifo_control_block_t))) {
        return -EINVAL;
    }

    if ((offset & 0x7U) != 0U) {
        return -EINVAL;
    }

    std::lock_guard guard(m_event_lock);

    auto vcpu = m_xen_dom->get_xen_vcpu(vcpuid);
    if (!vcpu) {
        printv("%s: ERROR: unable to get vcpu %u\n", __func__, vcpuid);
        return -ENOENT;
    }

    auto put_vcpu = gsl::finally([this, vcpuid](){
        m_xen_dom->put_xen_vcpu(vcpuid);
    });

    vcpu->init_event_ctl(ctl);
    ctl->link_bits = EVTCHN_FIFO_LINK_BITS;

    return 0;
}

int xen_evtchn::expand_array(xen_vcpu *v, evtchn_expand_array_t *eea)
{
    std::lock_guard guard(m_event_lock);
    return this->make_word_page(v->m_uv_vcpu, eea->array_gfn);
}

int xen_evtchn::set_priority(xen_vcpu *v, const evtchn_set_priority_t *esp)
{
    std::lock_guard guard(m_event_lock);

    if (esp->port >= m_allocated_chans) {
        return -EINVAL;
    }

    if (esp->priority > EVTCHN_FIFO_PRIORITY_MIN) {
        return -EINVAL;
    }

    this->port_to_chan(esp->port)->priority = esp->priority;
    return 0;
}

int xen_evtchn::status(xen_vcpu *v, evtchn_status_t *sts)
{
    std::lock_guard guard(m_event_lock);

    auto uvv = v->m_uv_vcpu;
    auto port = sts->port;

    if (port > m_allocated_chans) {
        return -EINVAL;
    }

    auto chan = this->port_to_chan(port);

    switch (chan->state) {
    case event_channel::state_free:
    case event_channel::state_reserved:
        sts->status = EVTCHNSTAT_closed;
        break;
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
    return 0;
}

int xen_evtchn::unmask(xen_vcpu *v, const evtchn_unmask_t *unmask)
{
    std::lock_guard guard(m_event_lock);

    auto port = unmask->port;
    if (port >= m_allocated_chans) {
        return -EINVAL;
    }

    auto word = this->port_to_word(port);
    if (!word) {
        return 0;
    }

    clear_bit(word, EVTCHN_FIFO_MASKED);

    if (test_bit(word, EVTCHN_FIFO_PENDING)) {
        auto chan = this->port_to_chan(port);
        this->queue_upcall(chan);
    }

    return 0;
}

int xen_evtchn::alloc_unbound(evtchn_alloc_unbound_t *eau)
{
    auto rdomid = eau->remote_dom;
    if (rdomid == DOMID_SELF) {
        rdomid = m_xen_dom->m_id;
    }

    std::lock_guard evt_guard(m_event_lock);
    auto port = this->get_free_port();

    if (port < 0) {
        printv("%s: get_free_port failed, rc = %ld\n", __func__, port);
        return port;
    }

    auto chan = this->port_to_chan(port);
    std::lock_guard chn_guard(chan->lock);

    chan->state = chan_t::state_unbound;
    chan->rdomid = rdomid;

    eau->port = port;
    return 0;
}

static void double_chan_lock(struct event_channel *lchn,
                             struct event_channel *rchn) noexcept
{
    if (lchn < rchn) {
        spin_acquire(&lchn->lock);
        spin_acquire(&rchn->lock);
    } else {
        if (lchn != rchn) {
            spin_acquire(&rchn->lock);
        }
        spin_acquire(&lchn->lock);
    }
}

static void double_chan_unlock(struct event_channel *lchn,
                               struct event_channel *rchn) noexcept
{
    spin_release(&lchn->lock);

    if (lchn != rchn) {
        spin_release(&rchn->lock);
    }
}

void xen_evtchn::double_event_lock(struct xen_domain *ldom,
                                   struct xen_domain *rdom) noexcept
{
    if (ldom < rdom) {
        spin_acquire(&ldom->m_evtchn->m_event_lock);
        spin_acquire(&rdom->m_evtchn->m_event_lock);
    } else {
        if (ldom != rdom) {
            spin_acquire(&rdom->m_evtchn->m_event_lock);
        }
        spin_acquire(&ldom->m_evtchn->m_event_lock);
    }
}

void xen_evtchn::double_event_unlock(struct xen_domain *ldom,
                                     struct xen_domain *rdom) noexcept
{
    spin_release(&ldom->m_evtchn->m_event_lock);
    if (ldom != rdom) {
        spin_release(&rdom->m_evtchn->m_event_lock);
    }
}

int xen_evtchn::bind_interdomain(xen_vcpu *v, evtchn_bind_interdomain_t *ebi)
{
    auto rc = 0;
    auto uvv = v->m_uv_vcpu;
    auto ldomid = v->m_xen_dom->m_id;
    auto rdomid = (ebi->remote_dom == DOMID_SELF) ? ldomid : ebi->remote_dom;
    auto rport = ebi->remote_port;
    xen_domain *ldom = v->m_xen_dom;
    xen_domain *rdom = (rdomid == ldomid) ? ldom : nullptr;

    if (!rdom) {
        rdom = get_xen_domain(rdomid);
        if (!rdom) {
            printv("%s: ERROR: rdom %u not found\n", __func__, rdomid);
            return -ESRCH;
        }
    }

    auto put_rdom = gsl::finally([ldomid, rdomid]() {
        if (rdomid != ldomid) {
            put_xen_domain(rdomid);
        }
    });

    this->double_event_lock(ldom, rdom);

    auto unlock_events = gsl::finally([this, ldom, rdom]() {
        this->double_event_unlock(ldom, rdom);
    });

    if (rport >= rdom->m_evtchn->m_allocated_chans) {
        return -EINVAL;
    }

    auto rchan = rdom->m_evtchn->port_to_chan(rport);
    if (rchan->state != chan_t::state_unbound || rchan->rdomid != ldomid) {
        printv("%s: ERROR: rdom %u is not accepting bindings, state=%d\n",
                __func__, rchan->rdomid, rchan->state);
        return -EINVAL;
    }

    auto lport = this->get_free_port();
    if (lport < 0) {
        printv("%s: ERROR: get_free_port failed, rc = %ld\n", __func__, lport);
        return lport;
    }

    auto lchan = this->port_to_chan(lport);
    double_chan_lock(lchan, rchan);

    auto unlock_chans = gsl::finally([lchan, rchan]() {
        double_chan_unlock(lchan, rchan);
    });

    lchan->state = chan_t::state_interdomain;
    lchan->rport = rport;
    lchan->rdomid = rdomid;

    rchan->state = chan_t::state_interdomain;
    rchan->rport = lport;
    rchan->rdomid = ldomid;

    this->queue_upcall(lchan);
    ebi->local_port = lport;

    return 0;
}

static inline bool virq_is_global(uint32_t virq)
{
    return virq_info[virq].global;
}

int xen_evtchn::bind_vcpu(xen_vcpu *v, const evtchn_bind_vcpu_t *bind)
{
    auto vcpu = bind->vcpu;
    auto port = bind->port;

    if (vcpu >= m_xen_dom->m_nr_vcpus) {
        printv("%s: vcpu %u invalid\n", __func__, vcpu);
        return -ENOENT;
    }

    std::lock_guard guard(m_event_lock);

    if (port >= m_allocated_chans) {
        return -EINVAL;
    }

    auto chan = this->port_to_chan(port);

    switch (chan->state) {
    case chan_t::state_virq:
        if (virq_is_global(chan->virq)) {
            chan->vcpuid = vcpu;
        } else {
            return -EINVAL;
        }
        break;
    case chan_t::state_unbound:
    case chan_t::state_interdomain:
        chan->vcpuid = vcpu;
        break;
    default:
        printv("%s: ERROR: state %d invalid\n", __func__, chan->state);
        return -EINVAL;
    }

    return 0;
}

int xen_evtchn::bind_virq(xen_vcpu *v, evtchn_bind_virq_t *bind)
{
    auto vcpu = bind->vcpu;
    auto virq = bind->virq;

    if (virq >= virq_info.size() || virq >= m_virq_to_port.size()) {
        return -EINVAL;
    }

    if (virq_is_global(virq) && vcpu != 0) {
        return -EINVAL;
    }

    if (vcpu >= m_xen_dom->m_nr_vcpus) {
        return -ENOENT;
    }

    std::lock_guard evt_guard(m_event_lock);

    if (m_virq_to_port[virq] != 0) {
        return -EEXIST;
    }

    auto port = this->get_free_port();
    if (port < 0) {
        return port;
    }

    auto chan = this->port_to_chan(port);
    std::lock_guard chn_guard(chan->lock);

    chan->state = chan_t::state_virq;
    chan->vcpuid = vcpu;
    chan->virq = virq;

    m_virq_to_port[virq] = port;
    bind->port = port;

    printv("%s: bound %s to port %lu on vcpu %u\n",
           __func__, virq_info[virq].name, port, vcpu);

    return 0;
}

bool xen_evtchn::close(xen_vcpu *v, evtchn_close_t *ec)
{
    auto uvv = v->m_uv_vcpu;
    auto chan = this->port_to_chan(ec->port);

    expects(chan);
    printv("evtchn: close port %u\n", ec->port);

    this->close(chan);
    uvv->set_rax(0);

    return true;
}

void xen_evtchn::close(chan_t *chan)
{
    std::lock_guard guard(chan->lock);

    switch (chan->state) {
    case chan_t::state_free:
    case chan_t::state_reserved:
        return;
    case chan_t::state_unbound:
    case chan_t::state_interdomain:
    case chan_t::state_pirq:
    case chan_t::state_ipi:
        break;
    case chan_t::state_virq:
        expects(chan->virq < m_virq_to_port.size());
        m_virq_to_port[chan->virq] = 0;
        break;
    default:
        printv("evtchn::close: state %u unknown\n", chan->state);
        return;
    }

    chan->free();
}

bool xen_evtchn::reset(xen_vcpu *v)
{
    for (auto i = 1; i < m_allocated_chans; i++) {
        auto chan = this->port_to_chan(i);
        this->close(chan);
    }

    v->m_uv_vcpu->set_rax(0);
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

void xen_evtchn::push_upcall(port_t port)
{
    auto chan = this->port_to_chan(port);
    expects(chan);

    this->push_upcall(chan);
}

void xen_evtchn::push_upcall(chan_t *chan)
{
    std::lock_guard guard(chan->lock);

    if (chan->state == chan_t::state_free) {
        return;
    }

    if (this->raise(chan)) {
        auto xend = m_xen_dom;
        auto xenv = xend->get_xen_vcpu(chan->vcpuid);

        if (!xenv) {
            bferror_nhex(0, "could not get xen vcpu, dom=", xend->m_id);
            return;
        }

        if (auto vec = xenv->m_upcall_vector; vec) {
            xenv->push_external_interrupt(vec);
        }

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

        if (auto vec = xenv->m_upcall_vector; vec) {
            xenv->queue_external_interrupt(vec);
        }

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

        if (auto vec = xenv->m_upcall_vector; vec) {
            xenv->inject_external_interrupt(vec);
        }

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

struct event_queue *xen_evtchn::lock_old_queue(const chan_t *chan)
{
    struct event_queue *q{};
    struct event_queue *oldq{};

    for (auto attempt = 0; attempt < 3; attempt++) {
        auto prev_vcpuid = chan->prev_vcpuid;
        auto vcpu = m_xen_dom->get_xen_vcpu(prev_vcpuid);
        if (!vcpu) {
            printv("%s: ERROR: prev_vcpuid %u not found\n",
                    __func__, prev_vcpuid);
            return nullptr;
        }

        auto put_vcpu = gsl::finally([this, prev_vcpuid](){
            m_xen_dom->put_xen_vcpu(prev_vcpuid);
        });

        auto ctl = vcpu->m_event_ctl.get();
        if (!ctl) {
            printv("%s: ERROR: prev_vcpuid %u has invalid event_control\n",
                    __func__, prev_vcpuid);
            return nullptr;
        }

        oldq = &ctl->queue[chan->prev_priority];
        spin_acquire(&oldq->lock);
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
    auto port = chan->port;
    auto word = this->port_to_word(port);

    if (!word) {
        bferror_nhex(0, "port doesn't map to word", port);
        chan->pending = true;
        return false;
    }

    set_bit(word, EVTCHN_FIFO_PENDING);

    if (test_bit(word, EVTCHN_FIFO_MASKED)) {
        return false;
    }

    if (test_bit(word, EVTCHN_FIFO_LINKED)) {
        return false;
    }

    auto vcpu = m_xen_dom->get_xen_vcpu(chan->vcpuid);
    if (!vcpu) {
        printv("%s: vcpuid %u not found\n", __func__, chan->vcpuid);
        return false;
    }

    auto put_vcpu = gsl::finally([this, chan](){
        m_xen_dom->put_xen_vcpu(chan->vcpuid);
    });

    auto ctl = vcpu->m_event_ctl.get();
    if (!ctl) {
        printv("%s: vcpu %u has invalid event_control\n",
                __func__, chan->vcpuid);
        return false;
    }

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

int64_t xen_evtchn::get_free_port()
{
    for (port_t p = 0; p < m_nr_ports; p++) {
        if (this->allocate_port(p) == -EBUSY) {
            continue;
        }

        return p;
    }

    return -ENOSPC;
}

int64_t xen_evtchn::allocate_port(port_t p)
{
    if (p < m_allocated_chans) {
        auto chan = this->port_to_chan(p);
        if (chan->state != chan_t::state_free) {
            return -EBUSY;
        }

        auto word = this->port_to_word(p);
        if (word && test_bit(word, EVTCHN_FIFO_BUSY)) {
            return -EBUSY;
        }
    } else {
        this->make_chan_page(p);
    }

    return 0;
}

xen_evtchn::chan_t *xen_evtchn::port_to_chan(port_t port) const noexcept
{
    auto size = m_chan_pages.size();
    auto page = (port & chan_page_mask) >> chan_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto chan = m_chan_pages[page].get();
    return &chan[port & chan_mask];
}

xen_evtchn::word_t *xen_evtchn::port_to_word(port_t port) const noexcept
{
    auto size = m_word_pages.size();
    auto page = (port & word_page_mask) >> word_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto word = m_word_pages[page].get();
    return &word[port & word_mask];
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

int xen_evtchn::make_word_page(microv_vcpu *uvv, uintptr_t gfn)
{
    if (m_word_pages.size() >= m_word_pages.capacity()) {
        printv("%s: ERROR: word pages maxed out, size=%lu, cap=%lu\n",
               __func__, m_word_pages.size(), m_word_pages.capacity());
        return -ENOSPC;
    }

    auto port = m_allocated_words;
    m_word_pages.push_back(uvv->map_gpa_4k<word_t>(xen_addr(gfn)));
    m_allocated_words += words_per_page;

    for (; port < m_allocated_words; port++) {
        if (port >= m_allocated_chans) {
            break;
        }

        auto chan = this->port_to_chan(port);
        if (chan->pending) {
            this->queue_upcall(chan);
        }
    }

    return 0;
}

}
