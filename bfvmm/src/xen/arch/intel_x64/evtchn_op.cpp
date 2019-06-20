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

#include <bfvmm/memory_manager/memory_manager.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <xen/arch/intel_x64/evtchn_op.h>

namespace microv::xen::intel_x64 {

evtchn_op::evtchn_op(microv::intel_x64::vcpu *vcpu) : m_vcpu{vcpu}
{
    m_event_words.reserve(max_word_pages);
    m_event_chans.reserve(max_chan_pages);
}

void
evtchn_op::init_control(evtchn_init_control_t *ctl)
{
    //expects(ctl->vcpu == m_vcpu->lapicid());
    expects(ctl->offset <= (0x1000 - sizeof(evtchn_fifo_control_block_t)));
    expects((ctl->offset & 0x7) == 0);

    this->setup_control_block(ctl->control_gfn, ctl->offset);
    this->setup_ports();

    ctl->link_bits = EVTCHN_FIFO_LINK_BITS;
}

void
evtchn_op::set_callback_via(uint64_t via)
{
    //expects(m_xen_op->shared_info());

    // At this point, the guest has initialized the evtchn
    // control structures and has just given us the vector
    // to inject whenever an upcall is pending.
    //
    m_cb_via = via;
}

//void
//evtchn_op::expand_array(gsl::not_null<evtchn_expand_array_t *> arr)
//{ this->make_word_page(arr); }
//
//void
//evtchn_op::alloc_unbound(gsl::not_null<evtchn_alloc_unbound_t *> arg)
//{
//    expects(arg->dom == DOMID_SELF);
//    expects(arg->remote_dom == DOMID_SELF);
//
//    auto port = this->make_new_port();
//    auto chan = this->port_to_chan(port);
//
//    chan->set_port(port);
//    chan->set_state(evtchn::state_unbound);
//
//    arg->port = port;
////    bfdebug_nhex(0, "alloc unbound", port);
//}
//
//void
//evtchn_op::send(gsl::not_null<evtchn_send_t *> arg)
//{
////    bfdebug_nhex(0, "send port", arg->port);
//    this->set_pending(this->port_to_chan(arg->port));
//}
//
//evtchn_op::port_t
//evtchn_op::bind_store()
//{
//    auto port = this->bind(evtchn::state_reserved);
//    bfdebug_nhex(0, "bound store:", port);
//    return port;
//}

evtchn_op::port_t evtchn_op::bind_console()
{
    auto port = this->bind(evtchn::state_reserved);
    bfdebug_nhex(0, "evtchn: bound console:", port);
    return port;
}

//void
//evtchn_op::bind_ipi(gsl::not_null<evtchn_bind_ipi_t *> arg)
//{
//    expects(arg->vcpu == 0);
//
//    const auto port = this->bind(evtchn::state_ipi);
//    arg->port = port;
//    bfdebug_nhex(0, "bound ipi:", port);
//}
//
//void
//evtchn_op::bind_virq(gsl::not_null<evtchn_bind_virq_t *> arg)
//{
//    expects(arg->vcpu == 0);
//
//    const auto port = this->bind(evtchn::state_virq);
//    auto chan = this->port_to_chan(port);
//
//    bfdebug_nhex(0, "bound virq:", arg->virq);
//
//    chan->set_virq(arg->virq);
//    arg->port = port;
//}
//
//void
//evtchn_op::bind_vcpu(gsl::not_null<evtchn_bind_vcpu_t *> arg)
//{
//    expects(arg->vcpu == 0);
//
//    auto chan = this->port_to_chan(arg->port);
//    auto prev = chan->vcpuid();
//
//    bfdebug_nhex(0, "bound vcpu:", arg->vcpu);
//    bfdebug_subnhex(0, "port:", arg->port);
//
//    chan->set_vcpuid(arg->vcpu);
//    chan->set_prev_vcpuid(prev);
//}

// =============================================================================
// Initialization
// =============================================================================

void
evtchn_op::setup_control_block(uint64_t gfn, uint32_t offset)
{
    const auto gpa = gfn << ::x64::pt::page_shift;
    m_ctl_blk_ump = m_vcpu->map_gpa_4k<uint8_t>(gpa);

    uint8_t *base = m_ctl_blk_ump.get() + offset;
    m_ctl_blk = reinterpret_cast<evtchn_fifo_control_block_t *>(base);

    for (auto i = 0U; i <= EVTCHN_FIFO_PRIORITY_MIN; i++) {
        m_queues[i].priority = gsl::narrow_cast<uint8_t>(i);
        m_queues[i].head = &m_ctl_blk->head[i];
    }
}

void
evtchn_op::setup_ports()
{
    expects(m_event_words.size() == 0);
    expects(m_event_chans.size() == 0);
    expects(m_allocated_words == 0);
    expects(m_allocated_chans == 0);

    this->make_chan_page(null_port);
    this->port_to_chan(null_port)->state = evtchn::state_reserved;
}

evtchn_op::port_t evtchn_op::bind(evtchn::state_t state)
{
    const auto port = this->make_new_port();
    auto chan = this->port_to_chan(port);

    chan->port = port;
    chan->state = state;

    return port;
}

//bool
//evtchn_op::set_link(word_t *word, event_word_t *val, port_t link)
//{
//    auto link_bits = (1U << EVTCHN_FIFO_LINKED) | link;
//    auto &expect = *val;
//    auto desire = (expect & ~((1 << EVTCHN_FIFO_BUSY) | port_mask)) | link_bits;
//
//    return word->compare_exchange_strong(expect, desire);
//}
//
//void
//evtchn_op::set_pending(chan_t *chan)
//{
//    expects(m_ctl_blk);
//
//    const auto new_port = chan->port();
//    auto new_word = this->port_to_word(new_port);
//    if (!new_word) {
//
//        // The guest hasn't added the corresponding
//        // event array, so we set pending for later
//        //
//        bfalert_nhex(0, "port doesn't map to word", new_port);
//        chan->set_pending();
//        return;
//    }
//
//    if (this->word_is_masked(new_word) || this->word_is_linked(new_word)) {
//        return;
//    }
//
//    this->word_set_pending(new_word);
//    auto p = chan->priority();
//    auto q = &m_queues.at(p);
//
//    // If the queue is empty, insert the tail and signal ready
//    if (*q->head == 0) {
//        *q->head = new_port;
//        q->tail = new_port;
//
//        m_ctl_blk->ready |= (1UL << p);
//        ::intel_x64::barrier::wmb();
//        m_vcpu->queue_external_interrupt(m_cb_via);
//
//        return;
//    }
//
//    auto tail_word = this->port_to_word(q->tail);
//    auto tail_val = tail_word->load();
//
//    if (!this->set_link(tail_word, &tail_val, new_port)) {
//        bfalert_nhex(0, "Failed to set link:", new_port);
//        throw std::runtime_error("Failed to set link: " +
//                                 std::to_string(new_port));
//    }
//
//    q->tail = new_port;
//    m_ctl_blk->ready |= (1UL << p);
//    ::intel_x64::barrier::wmb();
//    m_vcpu->queue_external_interrupt(m_cb_via);
//}

// Ports
//
// A port is an address to two things: a chan_t and a word_t
// Ports use a two-level addressing scheme.
//

evtchn_op::port_t evtchn_op::make_new_port()
{
    for (port_t p = m_port_end; p < max_channels; p++) {
        if (this->make_port(p) == -EBUSY) {
            continue;
        }

        m_port_end = p + 1U;
        return p;
    }

    return null_port;
}

evtchn_op::chan_t *evtchn_op::port_to_chan(port_t port) const
{
    const auto size = m_event_chans.size();
    const auto page = (port & chan_page_mask) >> chan_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto chan = m_event_chans[page].get();
    return &chan[port & chan_mask];
}

// Note:
//
// Word arrays are shared between the guest and host. The guest adds a new
// word array with the EVTCHNOP_expand_array hypercall, so it is possible
// that a given port doesn't map to an existing event word.
//
evtchn_op::word_t *evtchn_op::port_to_word(port_t port) const
{
    const auto size = m_event_words.size();
    const auto page = (port & word_page_mask) >> word_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto word = m_event_words[page].get();
    return &word[port & word_mask];
}

int evtchn_op::make_port(port_t port)
{
    if (port >= max_channels) {
        throw std::invalid_argument("make_port: port out of range" +
                                    std::to_string(port));
    }

    if (const auto chan = this->port_to_chan(port); chan) {
        if (chan->state != evtchn::state_free) {
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

void evtchn_op::make_chan_page(port_t port)
{
    const auto indx = (port & chan_page_mask) >> chan_page_shift;
    const auto size = m_event_chans.size();
    const auto cpty = m_event_chans.capacity();

    expects(size == indx);
    expects(size < cpty);

    auto page = make_page<chan_t>();

    for (auto i = 0U; i < chans_per_page; i++) {
        auto chan = &page.get()[i];

        chan->state = evtchn::state_free;
        chan->priority = EVTCHN_FIFO_PRIORITY_DEFAULT;
        chan->prev_priority = EVTCHN_FIFO_PRIORITY_DEFAULT;

        //TODO: Need to use ID the guest
        // passes in to bind_virq
        chan->vcpuid = 0;
        chan->prev_vcpuid = 0;
        chan->port = port + i;
        chan->is_pending = false;
    }

    m_event_chans.push_back(std::move(page));
    m_allocated_chans += chans_per_page;
}

//void
//evtchn_op::make_word_page(gsl::not_null<evtchn_expand_array_t *> expand)
//{
//    expects(m_event_words.size() < m_event_words.capacity());
//
//    auto addr = expand->array_gfn << ::x64::pt::page_shift;
//    auto page = m_vcpu->map_gpa_4k<word_t>(addr);
//
//    m_event_words.push_back(std::move(page));
//    m_allocated_words += words_per_page;
//}
//
//bool evtchn_op::word_is_pending(word_t *word) const
//{
//    return is_bit_set(word->load(), EVTCHN_FIFO_PENDING);
//}
//
//bool evtchn_op::word_is_masked(word_t *word) const
//{
//    return is_bit_set(word->load(), EVTCHN_FIFO_MASKED);
//}
//
//bool evtchn_op::word_is_linked(word_t *word) const
//{
//    return is_bit_set(word->load(), EVTCHN_FIFO_LINKED);
//}

bool evtchn_op::word_is_busy(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_BUSY);
}

//void evtchn_op::word_set_pending(word_t *word)
//{
//    word->fetch_or(1U << EVTCHN_FIFO_PENDING);
//}
//
//bool evtchn_op::word_test_and_set_pending(word_t *word)
//{
//    const auto mask = 1U << EVTCHN_FIFO_PENDING;
//    const auto prev = word->fetch_or(mask);
//
//    return is_bit_set(prev, EVTCHN_FIFO_PENDING);
//}
//
//void evtchn_op::word_set_busy(word_t *word)
//{
//    word->fetch_or(1U << EVTCHN_FIFO_BUSY);
//}
//
//bool evtchn_op::word_test_and_set_busy(word_t *word)
//{
//    const auto mask = 1U << EVTCHN_FIFO_BUSY;
//    const auto prev = word->fetch_or(mask);
//
//    return is_bit_set(prev, EVTCHN_FIFO_BUSY);
//}
//
//void evtchn_op::word_set_masked(word_t *word)
//{
//    word->fetch_or(1U << EVTCHN_FIFO_MASKED);
//}
//
//bool evtchn_op::word_test_and_set_masked(word_t *word)
//{
//    const auto mask = 1U << EVTCHN_FIFO_MASKED;
//    const auto prev = word->fetch_or(mask);
//
//    return is_bit_set(prev, EVTCHN_FIFO_MASKED);
//}
//
//void evtchn_op::word_set_linked(word_t *word)
//{
//    word->fetch_or(1U << EVTCHN_FIFO_LINKED);
//}
//
//bool evtchn_op::word_test_and_set_linked(word_t *word)
//{
//    const auto mask = 1U << EVTCHN_FIFO_LINKED;
//    const auto prev = word->fetch_or(mask);
//
//    return is_bit_set(prev, EVTCHN_FIFO_LINKED);
//}
//
//void evtchn_op::word_clear_pending(word_t *word)
//{
//    word->fetch_and(~(1U << EVTCHN_FIFO_PENDING));
//}
//
//bool evtchn_op::word_test_and_clear_pending(word_t *word)
//{
//    const auto mask = ~(1U << EVTCHN_FIFO_PENDING);
//    const auto prev = word->fetch_and(mask);
//
//    return is_bit_cleared(prev, EVTCHN_FIFO_PENDING);
//}
//
//void evtchn_op::word_clear_busy(word_t *word)
//{
//    word->fetch_and(~(1U << EVTCHN_FIFO_BUSY));
//}
//
//bool evtchn_op::word_test_and_clear_busy(word_t *word)
//{
//    const auto mask = ~(1U << EVTCHN_FIFO_BUSY);
//    const auto prev = word->fetch_and(mask);
//
//    return is_bit_cleared(prev, EVTCHN_FIFO_BUSY);
//}
//
//void evtchn_op::word_clear_masked(word_t *word)
//{
//    word->fetch_and(~(1U << EVTCHN_FIFO_MASKED));
//}
//
//bool evtchn_op::word_test_and_clear_masked(word_t *word)
//{
//    const auto mask = ~(1U << EVTCHN_FIFO_MASKED);
//    const auto prev = word->fetch_and(mask);
//
//    return is_bit_cleared(prev, EVTCHN_FIFO_MASKED);
//}
//
//void evtchn_op::word_clear_linked(word_t *word)
//{
//    word->fetch_and(~(1U << EVTCHN_FIFO_LINKED));
//}
//
//bool evtchn_op::word_test_and_clear_linked(word_t *word)
//{
//    const auto mask = ~(1U << EVTCHN_FIFO_LINKED);
//    const auto prev = word->fetch_and(mask);
//
//    return is_bit_cleared(prev, EVTCHN_FIFO_LINKED);
//}

}
