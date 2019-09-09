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
#include <xen/domain.h>
#include <xen/evtchn.h>
#include <xen/virq.h>
#include <xen/vcpu.h>

namespace microv {

#define PAGE_SIZE 0x1000UL

bool xen_evtchn_init_control(xen_vcpu *v)
{
    auto uvv = v->m_uv_vcpu;
    auto eic = uvv->map_arg<evtchn_init_control_t>(uvv->rsi());

    expects(v->m_xen_dom);
    return v->m_xen_dom->m_evtchn->init_control(v, eic.get());
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

bool xen_evtchn_alloc_unbound(xen_vcpu *v)
{
    expects(v->m_xen_dom);

    auto uvv = v->m_uv_vcpu;
    auto eau = uvv->map_arg<evtchn_alloc_unbound_t>(uvv->rsi());

    if (eau->dom == DOMID_SELF || eau->dom == v->m_xen_dom->m_id) {
        return v->m_xen_dom->m_evtchn->alloc_unbound(v, eau.get());
    } else {
        auto domid = eau->dom;
        auto dom = get_xen_domain(domid);
        if (!dom) {
            bferror_nhex(0, "eau: couldnt find domid", domid);
            uvv->set_rax(-EINVAL);
            return true;
        }

        bool ret = false;
        try {
            ret = dom->m_evtchn->alloc_unbound(v, eau.get());
        } catch (...) {
            put_xen_domain(domid);
            throw;
        }

        put_xen_domain(domid);
        return ret;
    }
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

bool xen_evtchn::init_control(xen_vcpu *v, evtchn_init_control_t *eic)
{
    expects(eic->offset <= (PAGE_SIZE - sizeof(evtchn_fifo_control_block_t)));
    expects((eic->offset & 0x7) == 0);

    auto uvv = v->m_uv_vcpu;
    this->setup_ctl_blk(uvv, eic->control_gfn, eic->offset);
    eic->link_bits = EVTCHN_FIFO_LINK_BITS;

    printv("evtchn: init_control\n");
    uvv->set_rax(0);
    return true;
}

bool xen_evtchn::expand_array(xen_vcpu *v, evtchn_expand_array_t *eea)
{
    auto uvv = v->m_uv_vcpu;
    this->make_word_page(uvv, eea->array_gfn);

    printv("evtchn: expand_array\n");
    uvv->set_rax(0);
    return true;
}

bool xen_evtchn::set_priority(xen_vcpu *v, evtchn_set_priority_t *esp)
{
    auto chan = this->port_to_chan(esp->port);

    expects(chan);
    chan->priority = esp->priority;

    printv("evtchn: set_priority\n");
    v->m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_evtchn::alloc_unbound(xen_vcpu *v, evtchn_alloc_unbound_t *eau)
{
    auto port = this->make_new_port();
    auto chan = this->port_to_chan(port);

    expects(chan);
    expects(chan->port == port);

    chan->state = chan_t::state_unbound;
    eau->port = port;

    if (eau->remote_dom == DOMID_SELF) {
        chan->rdomid = m_xen_dom->m_id;
    } else {
        chan->rdomid = eau->remote_dom;
    }

    printv("evtchn: alloc_unbound: lport:%u ldom:0x%x rdom:0x%x\n",
            port,
            m_xen_dom->m_id,
            chan->rdomid);

    v->m_uv_vcpu->set_rax(0);
    return true;
}

int xen_evtchn::bind_interdomain(evtchn_port_t local_port,
                                 evtchn_port_t rport,
                                 xen_domid_t rdomid)
{
    auto chan = this->port_to_chan(local_port);

    expects(chan);
    expects(chan->port == local_port);

    printv("evtchn: bind_interdom(2): lport:%u ldom:0x%x rport:%u rdom:0x%x\n",
            local_port, m_xen_dom->m_id, rport, rdomid);

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

    const auto ldomid = v->m_xen_dom->m_id;
    const auto rport = ebi->remote_port;
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
        /*
         * Look up the channel at rport and ensure 1) its state
         * is unbound and 2) it's accepting connections from ldomid
         */
        auto port = this->make_new_port();
        printv("evtchn: bind_interdom(1): lport:%u ldom:0x%x rport:%u rdom:0x%x\n",
                port, ldomid, rport, rdomid);

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
        expects(chan);
        expects(chan->port == port);

        chan->state = chan_t::state_interdomain;
        chan->rdomid = rdomid;
        chan->rport = ebi->remote_port;
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
    expects(ebv->vcpu == v->m_id);
    expects(ebv->virq < virq_info.size());
    expects(ebv->virq < m_virq_to_port.size());

    auto port = this->bind(chan_t::state_virq);
    auto chan = this->port_to_chan(port);

    chan->virq = ebv->virq;
    m_virq_to_port[ebv->virq] = port;
    ebv->port = port;

    const auto name = virq_info[ebv->virq].name;
    printv("evtchn: bind_virq %s to port %u\n", name, port);
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
     * Use upcall here so that we don't access the remote's vmcs.
     * Alternatively, we could check the affinity of the remote vcpu
     * and if it is the same as us, we could vmcs->load() then queue_upcall.
     *
     * N.B. this will not queue the callback vector into the remote,
     * which means that the remote may not see this event until another
     * comes along. This is fine assuming periodic idle; the latency
     * is bounded above by the timer period.
     */

    rdom->m_evtchn->upcall(chan->rport);
    put_xen_domain(rdomid);
}

bool xen_evtchn::send(xen_vcpu *v, evtchn_send_t *es)
{
    auto chan = this->port_to_chan(es->port);
    if (!chan) {
        bfalert_nhex(0, "evtchn::send: chan not found:", es->port);
        return false;
    }

    /* xen allows interdomain and IPIs to be sent here */
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

void xen_evtchn::set_callback_via(uint64_t via)
{
    m_cb_via = via;
}

void xen_evtchn::queue_virq(uint32_t virq)
{
    auto port = m_virq_to_port[virq];
    expects(port);

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

// =============================================================================
// Initialization
// =============================================================================

void xen_evtchn::setup_ctl_blk(microv_vcpu *uvv, uint64_t gfn, uint32_t offset)
{
    const auto gpa = gfn << ::x64::pt::page_shift;
    m_ctl_blk_ump = uvv->map_gpa_4k<uint8_t>(gpa);

    uint8_t *base = m_ctl_blk_ump.get() + offset;
    m_ctl_blk = reinterpret_cast<evtchn_fifo_control_block_t *>(base);

    for (auto i = 0U; i <= EVTCHN_FIFO_PRIORITY_MIN; i++) {
        m_queues[i].priority = gsl::narrow_cast<uint8_t>(i);
        m_queues[i].head = &m_ctl_blk->head[i];
    }
}

void xen_evtchn::setup_ports()
{
    expects(m_word_pages.size() == 0);
    expects(m_chan_pages.size() == 0);
    expects(m_allocated_words == 0);
    expects(m_allocated_chans == 0);

    this->make_chan_page(null_port);
    this->port_to_chan(null_port)->state = chan_t::state_reserved;
}

xen_evtchn::port_t xen_evtchn::bind(chan_t::state_t state)
{
    const auto port = this->make_new_port();
    auto chan = this->port_to_chan(port);

    expects(chan);
    expects(chan->port == port);
    chan->state = state;

    return port;
}

bool xen_evtchn::set_link(word_t *word, event_word_t *val, port_t link)
{
    auto link_bits = (1U << EVTCHN_FIFO_LINKED) | link;
    auto &expect = *val;
    auto desire = (expect & ~((1 << EVTCHN_FIFO_BUSY) | port_mask)) | link_bits;

    return word->compare_exchange_strong(expect, desire);
}

void xen_evtchn::queue_upcall(chan_t *chan)
{
    if (!this->upcall(chan)) {
        auto xend = m_xen_dom;
        auto xenv = xend->get_xen_vcpu();

        if (!xenv) {
            bferror_nhex(0, "could not get xen vcpu, dom=", xend->m_id);
            return;
        }

        xenv->m_uv_vcpu->queue_external_interrupt(m_cb_via);
        xend->put_xen_vcpu();
    }
}

void xen_evtchn::inject_upcall(chan_t *chan)
{
    if (!this->upcall(chan)) {
        auto xend = m_xen_dom;
        auto xenv = xend->get_xen_vcpu();

        if (!xenv) {
            bferror_nhex(0, "could not get xen vcpu, dom=", xend->m_id);
            return;
        }

        xenv->m_uv_vcpu->inject_external_interrupt(m_cb_via);
        xend->put_xen_vcpu();
    }
}

void xen_evtchn::upcall(evtchn_port_t port)
{
    auto chan = this->port_to_chan(port);
    expects(chan);

    if (auto err = this->upcall(chan); err) {
        printv("%s: upcall failed, rc=%d\n", __func__, err);
    }
}

int xen_evtchn::upcall(chan_t *chan)
{
    expects(m_ctl_blk);

    auto port = chan->port;
    auto word = this->port_to_word(port);
    if (!word) {
        bferror_nhex(0, "port doesn't map to word", port);
        chan->is_pending = true;
        return -EADDRNOTAVAIL;
    }

    /* Return if the guest has masked the event */
    if (this->word_is_masked(word)) {
        return -EBUSY;
    }

    auto p = chan->priority;
    auto q = &m_queues.at(p);

    if (*q->head == null_port) {
        *q->head = port;
    } else if (*q->head != port) {
        auto link = *q->head;
        auto tail = *q->head;
        do {
            tail = link;
            auto w = this->port_to_word(tail);
            link = w->load() & EVTCHN_FIFO_LINK_MASK;
        } while (link && link != port);

        if (GSL_LIKELY(!link)) {
            auto w = this->port_to_word(tail);
            auto val = w->load();
            if (!this->set_link(w, &val, port)) {
                bferror_info(0, "evtchn: failed to set_link");
            }
        }
    }

    this->word_set_pending(word);
    m_ctl_blk->ready |= (1UL << p);
    ::intel_x64::wmb();

    return 0;
}

// Ports
//
// A port is an address to two things: a chan_t and a word_t
// Ports use a two-level addressing scheme.
//

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
    const auto size = m_chan_pages.size();
    const auto page = (port & chan_page_mask) >> chan_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto chan = m_chan_pages[page].get();
    return &chan[port & chan_mask];
}

xen_evtchn::word_t *xen_evtchn::port_to_word(port_t port) const
{
    const auto size = m_word_pages.size();
    const auto page = (port & word_page_mask) >> word_page_shift;

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

    if (const auto chan = this->port_to_chan(port); chan) {
        if (chan->state != chan_t::state_free) {
            return -EBUSY;
        }

        auto word = this->port_to_word(port);
        if (word && this->word_is_busy(word)) {
            return -EBUSY;
        }
        return 0;
    }

    this->make_chan_page(port);
    return 0;
}

void xen_evtchn::make_chan_page(port_t port)
{
    const auto indx = (port & chan_page_mask) >> chan_page_shift;
    const auto size = m_chan_pages.size();
    const auto cpty = m_chan_pages.capacity();

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

    m_word_pages.push_back(uvv->map_gpa_4k<word_t>(gfn << 12));
    m_allocated_words += words_per_page;
}

bool xen_evtchn::word_is_masked(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_MASKED);
}

bool xen_evtchn::word_is_busy(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_BUSY);
}

void xen_evtchn::word_set_pending(word_t *word)
{
    word->fetch_or(1U << EVTCHN_FIFO_PENDING);
}

}
