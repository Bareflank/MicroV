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

#ifndef MICROV_XEN_EVTCHN_H
#define MICROV_XEN_EVTCHN_H

#include <vector>

#include "types.h"
#include "../spin_lock.h"
#include <public/event_channel.h>
#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>
#include <xen/page.h>

namespace microv {

bool xen_evtchn_reset(xen_vcpu *v);
bool xen_evtchn_init_control(xen_vcpu *v);
bool xen_evtchn_expand_array(xen_vcpu *v);
bool xen_evtchn_set_priority(xen_vcpu *v);
bool xen_evtchn_alloc_unbound(xen_vcpu *v);
bool xen_evtchn_bind_interdomain(xen_vcpu *v);
bool xen_evtchn_bind_vcpu(xen_vcpu *v);
bool xen_evtchn_bind_virq(xen_vcpu *v);
bool xen_evtchn_close(xen_vcpu *v);
bool xen_evtchn_send(xen_vcpu *v);
bool xen_evtchn_status(xen_vcpu *v);
bool xen_evtchn_unmask(xen_vcpu *v);

/**
 * struct event_channel
 *
 * This structure stores all the information specific to a single event. Pages
 * of struct event_channel's are allocated on a per-domain basis and are
 * associated with guest events via "ports" - numbers starting at 1 that serve
 * as the handle of the event. The VMM binds an event_channel to a port in
 * response to hypercalls invoked by domains. An event_channel is bound to at
 * most one port at any given time.
 */
struct event_channel {
    static constexpr uint32_t invalid_virq = ~0;
    static constexpr uint32_t invalid_pirq = ~0;
    static constexpr xen_domid_t invalid_domid = ~0;

    enum state : uint8_t {
        state_free,
        state_reserved,
        state_unbound,
        state_interdomain,
        state_pirq,
        state_virq,
        state_ipi
    };

    using state_t = enum state;

    state_t state{state_free};
    struct spin_lock lock{};

    /* Defined when state == state_virq */
    uint32_t virq{invalid_virq};

    /* Defined when state == state_pirq */
    uint32_t pirq{invalid_pirq};

    /*
     * These are defined by alloc_unbound and bind_interdomain.
     * One domain does alloc_unbound which defines the local port
     * (i.e. the "port" member defined below) and rdomid. The domain
     * on the other end (with id = rdomid) does bind_interdomain
     * which then sets rport here.
     */
    xen_domid_t rdomid{invalid_domid};
    evtchn_port_t rport{0};

    /* Priority determines what queue the event is on */
    uint8_t priority{EVTCHN_FIFO_PRIORITY_DEFAULT};
    uint8_t prev_priority{EVTCHN_FIFO_PRIORITY_DEFAULT};

    /* The vcpu that gets an upcall when an event is ready */
    xen_vcpuid_t vcpuid{};
    xen_vcpuid_t prev_vcpuid{};

    /* The local port of the event */
    evtchn_port_t port{0};

    /* Used to mark events pending when there is no word to back it yet */
    bool pending{};

    /* Pad to a power of 2 */
    uint8_t pad[1]{};

    /*
     * Note that the current implementation needs more work
     * on reusing freed/closed events.
     */
    void free() noexcept
    {
        state = state_free;
        vcpuid = 0;
        prev_vcpuid = 0;
    }

    void reset(evtchn_port_t p) noexcept
    {
        memset(&lock, 0, sizeof(lock));
        state = state_free;
        virq = invalid_virq;
        pirq = invalid_pirq;
        rdomid = invalid_domid;
        rport = 0;
        priority = EVTCHN_FIFO_PRIORITY_DEFAULT;
        prev_priority = EVTCHN_FIFO_PRIORITY_DEFAULT;
        vcpuid = 0;
        prev_vcpuid = 0;
        port = p;
        pending = false;
    }

    event_channel(event_channel &&) = delete;
    event_channel(const event_channel &) = delete;
    event_channel &operator=(event_channel &&) = delete;
    event_channel &operator=(const event_channel &) = delete;

} __attribute__((packed));

/**
 * struct event_queue
 *
 * Represents a FIFO queue of events. The VMM produces events onto
 * the tail of the queue and the guest vcpu consumes events off of
 * the queue starting with the head.
 *
 * @lock spinlock to protect the queue against concurrent VMM accesses.
 *
 * @head a pointer to the head port of the queue. The pointer
 * points to the queue's corresponding head value in the control block
 * that is shared with the guest vcpu.
 *
 * @tail the port corresponding to the tail of the queue. This value
 * is used by the VMM for internal bookkeeping.
 *
 * @priority the priority of the queue. This value corresponds to a
 * bit in the ready field of the shared control block that is set
 * whenever its corresponding queue is not empty.
 */
struct event_queue {
    struct spin_lock lock{};
    std::atomic<evtchn_port_t> *head{};
    evtchn_port_t tail{};
    uint8_t priority{EVTCHN_FIFO_PRIORITY_DEFAULT};
};

/* Per-vcpu event control structure */
struct event_control {
    unique_map<uint8_t> map{};
    evtchn_fifo_control_block_t *blk{};
    std::atomic<uint32_t> *ready{};
    std::array<struct event_queue, EVTCHN_FIFO_MAX_QUEUES> queue;

    event_control(microv_vcpu *uvv, evtchn_init_control *init)
    {
        auto gpa = xen_addr(init->control_gfn);
        auto off = init->offset;

        map = uvv->map_gpa_4k<uint8_t>(gpa);
        blk = reinterpret_cast<evtchn_fifo_control_block_t *>(map.get() + off);
        ready = reinterpret_cast<std::atomic<uint32_t> *>(&blk->ready);

        for (auto i = 0U; i <= EVTCHN_FIFO_PRIORITY_MIN; i++) {
            queue[i].head = reinterpret_cast<std::atomic<uint32_t> *>(&blk->head[i]);
            queue[i].tail = 0;
            queue[i].priority = gsl::narrow_cast<uint8_t>(i);
        }
    }
};

class xen_evtchn {
public:
    using port_t = evtchn_port_t;
    using word_t = std::atomic<event_word_t>;
    using chan_t = struct event_channel;

    static_assert(is_power_of_2(EVTCHN_FIFO_NR_CHANNELS));
    static_assert(is_power_of_2(sizeof(word_t)));
    static_assert(is_power_of_2(sizeof(chan_t)));
    static_assert(UV_PAGE_SIZE > sizeof(chan_t));
    static_assert(sizeof(chan_t) > sizeof(word_t));
    static_assert(word_t::is_always_lock_free);

    xen_evtchn(xen_domain *dom);

    int init_control(xen_vcpu *v, evtchn_init_control_t *eic);
    int expand_array(xen_vcpu *v, evtchn_expand_array_t *eea);
    int set_priority(xen_vcpu *v, const evtchn_set_priority_t *esp);
    int status(xen_vcpu *v, evtchn_status *sts);
    int unmask(xen_vcpu *v, const evtchn_unmask *unmask);
    int alloc_unbound(xen_vcpu *v, evtchn_alloc_unbound_t *eau);
    int bind_interdomain(xen_vcpu *v, evtchn_bind_interdomain_t *ebi);
    int bind_vcpu(xen_vcpu *v, const evtchn_bind_vcpu_t *ebv);
    int bind_virq(xen_vcpu *v, evtchn_bind_virq_t *ebv);
    bool close(xen_vcpu *v, evtchn_close_t *ec);
    bool send(xen_vcpu *v, evtchn_send_t *es);
    bool reset(xen_vcpu *v);

    void close(chan_t *chan);
    void queue_virq(uint32_t virq);
    void inject_virq(uint32_t virq);
    int alloc_unbound(evtchn_alloc_unbound_t *arg);

    static constexpr auto max_channels = EVTCHN_FIFO_NR_CHANNELS;

private:
    friend class xen_evtchn;

    static constexpr auto bits_per_xen_ulong = sizeof(xen_ulong_t) * 8;
    static constexpr auto words_per_page = ::x64::pt::page_size / sizeof(word_t);
    static constexpr auto chans_per_page = ::x64::pt::page_size / sizeof(chan_t);
    static constexpr auto port_mask = max_channels - 1U;
    static constexpr auto word_mask = words_per_page - 1U;
    static constexpr auto chan_mask = chans_per_page - 1U;
    static constexpr auto word_page_mask = port_mask & ~word_mask;
    static constexpr auto chan_page_mask = port_mask & ~chan_mask;
    static constexpr auto word_page_shift = log2<words_per_page>();
    static constexpr auto chan_page_shift = log2<chans_per_page>();

    void double_event_lock(struct xen_domain *ldom,
                           struct xen_domain *rdom) noexcept;
    void double_event_unlock(struct xen_domain *ldom,
                             struct xen_domain *rdom) noexcept;

    chan_t *port_to_chan(port_t port) const noexcept;
    word_t *port_to_word(port_t port) const noexcept;

    int64_t get_free_port();
    int64_t allocate_port(port_t p);

    void make_chan_page(port_t port);
    int make_word_page(microv_vcpu *uvv, uintptr_t gfn);

    void notify_remote(chan_t *chan);
    void push_upcall(port_t port);
    void push_upcall(chan_t *chan);
    void queue_upcall(chan_t *chan);
    void inject_upcall(chan_t *chan);
    bool raise(chan_t *chan);
    struct event_queue *lock_old_queue(const chan_t *chan);

    struct spin_lock m_event_lock{};
    uint64_t m_allocated_chans{};
    uint64_t m_allocated_words{};

    std::array<port_t, NR_VIRQS> m_virq_to_port{0};
    std::vector<std::unique_ptr<struct event_control>> m_event_ctl{};
    std::vector<unique_map<word_t>> m_word_pages{};
    std::vector<page_ptr<chan_t>> m_chan_pages{};

    xen_domain *m_xen_dom{};
    port_t m_nr_ports{};
    port_t m_port_end{1};

public:

    ~xen_evtchn() = default;
    xen_evtchn(xen_evtchn &&) = delete;
    xen_evtchn(const xen_evtchn &) = delete;
    xen_evtchn &operator=(xen_evtchn &&) = delete;
    xen_evtchn &operator=(const xen_evtchn &) = delete;
};

}
#endif
