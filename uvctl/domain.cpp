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

#include <array>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

#ifdef WIN64
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include "domain.h"
#include "log.h"
#include "vcpu.h"

using namespace std::chrono;
using namespace std::chrono_literals;

static constexpr auto uart_sleep = 100ms;
static constexpr auto hvc_sleep = 100ms;

uvc_domain::uvc_domain(domainid_t id,
                       uvc_domain *parent,
                       bool enable_uart,
                       bool enable_hvc) :
    m_id{id},
    m_parent{parent},
    m_enable_uart{enable_uart},
    m_enable_hvc{enable_hvc}
{}

bool uvc_domain::is_root() const noexcept
{
    return m_parent == nullptr;
}

domainid_t uvc_domain::id() const noexcept
{
    return m_id;
}

void uvc_domain::recv_uart()
{
    uint64_t size{};
    std::array<char, UART_MAX_BUFFER> buf{};

    while (m_enable_uart) {
        size = __domain_op__dump_uart(m_id, buf.data());
        log_raw(buf.data(), (int)size);
        std::this_thread::sleep_for(uart_sleep);
    }
}

void uvc_domain::recv_hvc()
{
    uint64_t size{};
    std::array<char, HVC_TX_SIZE> array{0};

#ifdef WIN64
    /* Lock memory; this may fail the first attempt. */
    if (!VirtualLock(array.data(), HVC_TX_SIZE)) {
        log_msg("%s: Unable to lock HVC recv array (err: 0x%x), trying again\n",
                __func__,
                GetLastError());
        if (!VirtualLock(array.data(), HVC_TX_SIZE)) {
            log_msg("%s: Unable to lock HVC recv array (err: 0x%x)\n",
                    __func__,
                    GetLastError());
            return;
        }
    }
#else
    if (mlock(array.data(), HVC_TX_SIZE) == -1) {
        log_msg(
            "%s: Unable to lock HVC recv array (err: %d)\n", __func__, errno);
        return;
    }
#endif

    while (m_enable_hvc) {
        char *buf = array.data();
        size = __domain_op__hvc_tx_get(m_id, buf, HVC_TX_SIZE);

        log_raw(buf, (int)size);
        std::this_thread::sleep_for(hvc_sleep);
    }
}

#ifdef __CYGWIN__
#define HVC_CTRL_STOP_PROCESS 0x01 /* ^A - stop in-guest process */
#else
#define HVC_CTRL_STOP_PROCESS 0x13 /* ^S - stop in-guest process */
#endif

#define HVC_CTRL_EXIT_CONSOLE 0x1D /* ^] - exit domU console */

void uvc_domain::send_hvc()
{
    std::array<char, HVC_RX_SIZE> array{0};

#ifdef WIN64
    /* Lock memory; this may fail the first attempt. */
    if (!VirtualLock(array.data(), HVC_RX_SIZE)) {
        log_msg("%s: Unable to lock HVC send array (err: 0x%x), trying again\n",
                __func__,
                GetLastError());
        if (!VirtualLock(array.data(), HVC_RX_SIZE)) {
            log_msg("%s: Unable to lock HVC send array (err: 0x%x)\n",
                    __func__,
                    GetLastError());
            return;
        }
    }
#else
    if (mlock(array.data(), HVC_RX_SIZE) == -1) {
        log_msg(
            "%s: Unable to lock HVC recv array (err: %d)\n", __func__, errno);
        return;
    }
#endif

    while (m_enable_hvc) {
        std::cin.getline(array.data(), array.size());
        array.data()[std::cin.gcount() - 1] = '\n';
        auto count = std::cin.gcount();

        if (count == 2) {
            const char ctrl_code = array.data()[0];

            switch (ctrl_code) {
            case HVC_CTRL_STOP_PROCESS:
                /* Remap to ^C */
                array.data()[0] = 0x03;
                break;
            case HVC_CTRL_EXIT_CONSOLE:
                /* Only 1 char must be sent */
                count = 1;
                break;
            default:
                break;
            }
        }

        __domain_op__hvc_rx_put(m_id, array.data(), count);
        std::this_thread::sleep_for(hvc_sleep);
    }
}

void uvc_domain::handle_events()
{
    std::unique_lock lock(m_event_mtx);

    m_event_cond.wait(lock, [&]() {
        switch (m_event_code) {
        case __enum_run_op__create_domain:
            this->create_child(m_event_data);
            break;
        case __enum_run_op__pause_domain:
            this->pause_child(m_event_data);
            break;
        case __enum_run_op__unpause_domain:
            this->unpause_child(m_event_data);
            break;
        case __enum_run_op__destroy_domain:
            this->destroy_child(m_event_data);
            break;
        }

        return !m_enable_events;
    });
}

void uvc_domain::notify_event(uint64_t event_code, uint64_t event_data)
{
    std::lock_guard lock(m_event_mtx);

    m_event_code = event_code;
    m_event_data = event_data;

    /*
     * Since each vcpu is a potential notifier, we need to notify_one()
     * with the lock held. Otherwise events could be dropped since the
     * domain's event thread is essentially a one-element work queue.
     * If this lock becomes a bottleneck, we could use a bonafide
     * queue and/or schedule std::async tasks from the event thread.
     */
    m_event_cond.notify_one();
}

void uvc_domain::create_child(domainid_t domid)
{
    m_child_list.emplace_front(domid, this, false, false);
    m_child_list.front().launch();
}

void uvc_domain::pause_child(domainid_t domid)
{
    for (auto c = m_child_list.begin(); c != m_child_list.end(); c++) {
        if (c->m_id == domid) {
            c->pause();
        }
    }
}

void uvc_domain::unpause_child(domainid_t domid)
{
    for (auto c = m_child_list.begin(); c != m_child_list.end(); c++) {
        if (c->m_id == domid) {
            c->unpause();
        }
    }
}

void uvc_domain::destroy_child(domainid_t domid)
{
    for (auto c = m_child_list.begin(); c != m_child_list.end(); c++) {
        if (c->m_id == domid) {
            c->destroy();
        }
    }
}

void uvc_domain::pause()
{
    std::lock_guard lock(m_vcpu_mtx);

    for (auto &v : m_vcpu_list) {
        v.pause();
    }
}

void uvc_domain::unpause()
{
    std::lock_guard lock(m_vcpu_mtx);

    for (auto &v : m_vcpu_list) {
        v.unpause();
    }
}

void uvc_domain::destroy()
{
    m_enable_uart = false;
    m_enable_hvc = false;

    if (m_event_thread.joinable()) {
        /* Acquire the event lock */
        std::unique_lock lock(m_event_mtx);

        /* Clear the event data */
        m_event_code = 0;
        m_event_data = 0;

        /* Tell the thread to return */
        m_enable_events = false;
        m_event_cond.notify_one();

        /* Release the event lock */
        lock.unlock();
        m_event_thread.join();
    }

    if (m_hvc_recv.joinable()) {
        m_hvc_recv.join();
    }

    if (m_hvc_send.joinable()) {
        m_hvc_send.join();
    }

    if (m_uart_recv.joinable()) {
        m_uart_recv.join();
    }

    /*
     * Note we can safely access the child list here as long as
     * the only other modifications happen in the event thread
     * (which has joined at this point).
     */
    for (auto &c : m_child_list) {
        log_msg("%s: destroying child 0x%x\n", __func__, c.id());
        c.destroy();
    }

    std::lock_guard lock(m_vcpu_mtx);

    for (auto &v : m_vcpu_list) {
        log_msg("%s: halting vcpu 0x%x\n", __func__, v.id);
        v.halt();
    }

    for (auto &v : m_vcpu_list) {
        if (v.run_thread.joinable()) {
            log_msg("%s: joining vcpu 0x%x\n", __func__, v.id);
            v.run_thread.join();
        }
    }

    destroy_vcpus();

    /*
     * Only perform the destroy vmcall on non-root domains. The
     * root domain is destroyed via the ioctl interface.
     */
    if (!this->is_root()) {
        __domain_op__destroy_domain(m_id);
    }
}

void uvc_domain::launch()
{
    if (this->is_root()) {
        if (m_enable_uart) {
            m_uart_recv = std::thread(std::bind(&uvc_domain::recv_uart, this));
        } else if (m_enable_hvc) {
            m_hvc_recv = std::thread(std::bind(&uvc_domain::recv_hvc, this));
            m_hvc_send = std::thread(std::bind(&uvc_domain::send_hvc, this));
        }

        m_enable_events = true;
        m_event_thread =
            std::thread(std::bind(&uvc_domain::handle_events, this));
    }

    std::lock_guard lock(m_vcpu_mtx);

    if (m_vcpu_list.size() == 0) {
        create_vcpu();
    }

    for (auto v = m_vcpu_list.begin(); v != m_vcpu_list.end(); v++) {
        v->launch();
    }
}

void uvc_domain::create_vcpu()
{
    auto newid = __vcpu_op__create_vcpu(m_id);
    if (newid == INVALID_VCPUID) {
        throw std::runtime_error("create_vcpu failed");
    }

    m_vcpu_list.emplace_front(newid, this);
}

void uvc_domain::destroy_vcpus()
{
    for (auto v = m_vcpu_list.begin(); v != m_vcpu_list.end(); v++) {
        __vcpu_op__destroy_vcpu(v->id);
    }

    m_vcpu_list.clear();
}
