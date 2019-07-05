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

#ifndef MICROV_INTEL_X64_EVTCHN_OP_H
#define MICROV_INTEL_X64_EVTCHN_OP_H

#include <atomic>
#include <bfmath.h>
#include <bfvmm/hve/arch/x64/unmapper.h>
#include "../../evtchn.h"

namespace microv::xen::intel_x64 {

class evtchn_op {
public:

    using port_t = evtchn_port_t;
    using word_t = std::atomic<event_word_t>;
    using chan_t = class microv::xen::evtchn;

    using queue_t = struct fifo_queue {
        port_t *head;
        port_t tail;
        uint8_t priority;

        // No locking needed yet
        // std::mutex lock;
    };

    static_assert(is_power_of_2(EVTCHN_FIFO_NR_CHANNELS));
    static_assert(is_power_of_2(sizeof(word_t)));
    static_assert(is_power_of_2(sizeof(chan_t)));
    static_assert(::x64::pt::page_size > sizeof(chan_t));
    static_assert(sizeof(chan_t) > sizeof(word_t));
    static_assert(word_t::is_always_lock_free);

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu of the evtchn_op
    ///
    evtchn_op(microv::intel_x64::vcpu *vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~evtchn_op() = default;

    /// Init control
    ///
    void init_control(evtchn_init_control_t *ctl);

    /// Set callback via
    ///
    /// Set the vector used to inject events into the guest
    ///
    void set_callback_via(uint64_t via);

    /// Alloc unbound
    ///
    void alloc_unbound(evtchn_alloc_unbound_t *unbound);

    /// Expand array
    ///
    void expand_array(evtchn_expand_array_t *arr);

    /// Send
    ///
    void send(evtchn_send_t *arg);

    /// Bind IPI
    ///
    void bind_ipi(gsl::not_null<evtchn_bind_ipi_t *> arg);

    /// Bind VIRQ
    ///
    void bind_virq(evtchn_bind_virq_t *arg);

    /// Bind VCPU
    ///
    void bind_vcpu(gsl::not_null<evtchn_bind_vcpu *> arg);

    /// Bind console
    ///
    port_t bind_console();

    /// Bind store
    ///
    port_t bind_store();

private:

    port_t bind(evtchn::state_t state);

    // Static constants
    //
    static constexpr auto bits_per_xen_ulong = sizeof(xen_ulong_t) * 8;
    static constexpr auto max_channels = EVTCHN_FIFO_NR_CHANNELS;

    static constexpr auto words_per_page = ::x64::pt::page_size / sizeof(word_t);
    static constexpr auto chans_per_page = ::x64::pt::page_size / sizeof(chan_t);
    static constexpr auto max_word_pages = max_channels / words_per_page;
    static constexpr auto max_chan_pages = max_channels / chans_per_page;

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
    chan_t *port_to_chan(port_t port) const;
    word_t *port_to_word(port_t port) const;

    uint64_t port_to_chan_page(port_t port) const;
    uint64_t port_to_word_page(port_t port) const;

    port_t make_new_port();
    int make_port(port_t port);
    void setup_ports();
    void setup_control_block(uint64_t gfn, uint32_t offset);

    void make_chan_page(port_t port);
    void make_word_page(evtchn_expand_array_t *expand);

    // Links
    //
    bool set_link(word_t *word, event_word_t *val, port_t link);
    void set_pending(chan_t *chan);

    // Interface for atomic accesses to shared memory
    //
    bool word_is_busy(word_t *word) const;
    bool word_is_linked(word_t *word) const;
    bool word_is_masked(word_t *word) const;
    bool word_is_pending(word_t *word) const;

    void word_set_pending(word_t *word);
    bool word_test_and_set_pending(word_t *word);

    void word_clear_pending(word_t *word);
    bool word_test_and_clear_pending(word_t *word);

    void word_set_busy(word_t *word);
    bool word_test_and_set_busy(word_t *word);

    void word_clear_busy(word_t *word);
    bool word_test_and_clear_busy(word_t *word);

    void word_set_masked(word_t *word);
    bool word_test_and_set_masked(word_t *word);

    void word_clear_masked(word_t *word);
    bool word_test_and_clear_masked(word_t *word);

    void word_set_linked(word_t *word);
    bool word_test_and_set_linked(word_t *word);

    void word_clear_linked(word_t *word);
    bool word_test_and_clear_linked(word_t *word);

    // Data members
    //
    uint64_t m_allocated_chans{};
    uint64_t m_allocated_words{};

    evtchn_fifo_control_block_t *m_ctl_blk{};
    bfvmm::x64::unique_map<uint8_t> m_ctl_blk_ump{};

    std::array<queue_t, EVTCHN_FIFO_MAX_QUEUES> m_queues{};
    std::array<port_t, NR_VIRQS> m_virq_to_port;

    std::vector<bfvmm::x64::unique_map<word_t>> m_event_words{};
    std::vector<page_ptr<chan_t>> m_event_chans{};

    microv::intel_x64::vcpu *m_vcpu{};
    uint64_t m_cb_via{};
    port_t m_port_end{1};

public:

    /// @cond

    evtchn_op(evtchn_op &&) = default;
    evtchn_op &operator=(evtchn_op &&) = default;

    evtchn_op(const evtchn_op &) = delete;
    evtchn_op &operator=(const evtchn_op &) = delete;

    /// @endcond
};
}
#endif
