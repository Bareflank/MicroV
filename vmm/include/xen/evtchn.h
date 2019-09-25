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

#include "types.h"
#include <public/event_channel.h>
#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>

namespace microv {

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

struct event_channel {
    static constexpr auto invalid_virq = 0xFFFFUL;
    static constexpr auto invalid_pirq = 0xFFFFUL;
    static constexpr auto invalid_domid = 0xFFFFUL;
    static constexpr auto invalid_port = 0x0UL;

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
    uint32_t virq;
    uint32_t pirq;
    xen_domid_t rdomid;
    evtchn_port_t rport;

    bool is_pending{};
    uint8_t priority{EVTCHN_FIFO_PRIORITY_DEFAULT};
    uint8_t prev_priority{EVTCHN_FIFO_PRIORITY_DEFAULT};
    xen_vcpuid_t vcpuid{};
    xen_vcpuid_t prev_vcpuid{};
    evtchn_port_t port{};

    uint8_t pad[34];

    void free() noexcept
    {
        state = state_free;
        vcpuid = 0;
    }

    void reset(evtchn_port_t p) noexcept
    {
        state = state_free;
        virq = invalid_virq;
        pirq = invalid_pirq;
        rdomid = invalid_domid;
        rport = invalid_port;
        is_pending = false;
        priority = EVTCHN_FIFO_PRIORITY_DEFAULT;
        prev_priority = EVTCHN_FIFO_PRIORITY_DEFAULT;
        vcpuid = 0;
        prev_vcpuid = 0;
        port = p;
    }

} __attribute__((packed));

class xen_evtchn {
public:
    using port_t = evtchn_port_t;
    using word_t = std::atomic<event_word_t>;
    using chan_t = struct event_channel;
    using queue_t = struct fifo_queue {
        port_t *head;
        uint8_t priority;
    };

    static_assert(is_power_of_2(EVTCHN_FIFO_NR_CHANNELS));
    static_assert(is_power_of_2(sizeof(word_t)));
    static_assert(is_power_of_2(sizeof(chan_t)));
    static_assert(::x64::pt::page_size > sizeof(chan_t));
    static_assert(sizeof(chan_t) > sizeof(word_t));
    static_assert(word_t::is_always_lock_free);

    xen_evtchn(xen_domain *dom);

    bool init_control(xen_vcpu *v, evtchn_init_control_t *eic);
    bool expand_array(xen_vcpu *v, evtchn_expand_array_t *eea);
    bool set_priority(xen_vcpu *v, evtchn_set_priority_t *esp);
    bool status(xen_vcpu *v, evtchn_status *sts);
    bool unmask(xen_vcpu *v, evtchn_unmask *unmask);
    bool alloc_unbound(xen_vcpu *v, evtchn_alloc_unbound_t *eau);
    bool bind_interdomain(xen_vcpu *v, evtchn_bind_interdomain_t *ebi);
    bool bind_vcpu(xen_vcpu *v, evtchn_bind_vcpu_t *ebv);
    bool bind_virq(xen_vcpu *v, evtchn_bind_virq_t *ebv);
    bool close(xen_vcpu *v, evtchn_close_t *ec);
    bool send(xen_vcpu *v, evtchn_send_t *es);

    int set_upcall_vector(xen_vcpu *v, xen_hvm_param_t *param);
    void queue_virq(uint32_t virq);
    void inject_virq(uint32_t virq);
    void unbind_interdomain(evtchn_port_t port, xen_domid_t remote_domid);
    int bind_interdomain(evtchn_port_t port,
                         evtchn_port_t remote_port,
                         xen_domid_t remote_domid);

    void upcall(evtchn_port_t port);

    static constexpr auto max_channels = EVTCHN_FIFO_NR_CHANNELS;

private:
    friend class xen_evtchn;

    // Static constants
    //
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

    static constexpr auto null_port = 0;

    // Ports
    //
    port_t bind(chan_t::state_t state);
    chan_t *port_to_chan(port_t port) const;
    word_t *port_to_word(port_t port) const;

    uint64_t port_to_chan_page(port_t port) const;
    uint64_t port_to_word_page(port_t port) const;

    port_t make_new_port();
    int make_port(port_t port);
    void setup_ports();
    void setup_ctl_blk(microv_vcpu *uvv, uint64_t gfn, uint32_t offset);

    void make_chan_page(port_t port);
    void make_word_page(microv_vcpu *uvv, uintptr_t gfn);

    void notify_remote(chan_t *chan);
    void queue_upcall(chan_t *chan);
    void inject_upcall(chan_t *chan);
    int upcall(chan_t *chan);

    bool set_link(word_t *word, event_word_t *val, port_t link);

    // Interface for atomic accesses to shared memory
    //
    bool word_is_masked(word_t *word) const;
    bool word_is_busy(word_t *word) const;
    void word_set_pending(word_t *word);
    void word_clr_mask(word_t *word);

    // Data members
    //
    uint64_t m_allocated_chans{};
    uint64_t m_allocated_words{};

    evtchn_fifo_control_block_t *m_ctl_blk{};
    unique_map<uint8_t> m_ctl_blk_ump{};

    std::array<queue_t, EVTCHN_FIFO_MAX_QUEUES> m_queues{0};
    std::array<port_t, NR_VIRQS> m_virq_to_port{0};

    std::vector<unique_map<word_t>> m_word_pages{};
    std::vector<page_ptr<chan_t>> m_chan_pages{};

    xen_domain *m_xen_dom{};
    uint64_t m_upcall_vec{};
    port_t m_nr_ports{};
    port_t m_port_end{1};

public:

    ~xen_evtchn() = default;
    xen_evtchn(xen_evtchn &&) = default;
    xen_evtchn(const xen_evtchn &) = delete;
    xen_evtchn &operator=(xen_evtchn &&) = default;
    xen_evtchn &operator=(const xen_evtchn &) = delete;
};

}
#endif
