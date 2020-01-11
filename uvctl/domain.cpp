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
#include "vcpu.h"

using namespace std::chrono;
using namespace std::chrono_literals;

static constexpr auto uart_sleep = 100ms;
static constexpr auto hvc_sleep = 100ms;

uvc_domain::uvc_domain()
{
    this->id = 0;
    this->parent = nullptr;
}

uvc_domain::uvc_domain(domainid_t id, struct uvc_domain *parent)
{
    this->id = id;
    this->parent = parent;
}

bool uvc_domain::is_root() const noexcept
{
    return parent == nullptr;
}

void uvc_domain::recv_uart()
{
    uint64_t size{};
    std::array<char, UART_MAX_BUFFER> buf{};

    while (enable_uart) {
        size = __domain_op__dump_uart(id, buf.data());
        std::cout.write(buf.data(), (int)size);
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
        std::cout << __func__ << ": Unable to lock HVC recv array " << "(error: "
                  << std::to_string(GetLastError()) << "), will reattempt\n";
        if (!VirtualLock(array.data(), HVC_TX_SIZE)) {
            std::cout << __func__ << ": Second attempt; unable to lock HVC recv array "
                      << "(error: " << std::to_string(GetLastError()) << ")\n";
	      }
#else
    if (mlock(array.data(), HVC_TX_SIZE) == -1) {
        std::cout << __func__ << ": Unable to lock array\n";
#endif
    }

    while (enable_hvc) {
        auto buf = static_cast<volatile char *>(array.data());

        size = __domain_op__hvc_tx_get(id, (char *)buf, HVC_TX_SIZE);

        std::cout.write((const char *)buf, (int)size);
        std::cout.flush();
        std::this_thread::sleep_for(hvc_sleep);
    }
}

#ifdef WIN64
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
        std::cout << __func__ << ": Unable to lock HVC send array " << "(error: "
                  << std::to_string(GetLastError()) << "), will reattempt\n";
        if (!VirtualLock(array.data(), HVC_RX_SIZE)) {
            std::cout << __func__ << ": Second attempt; unable to lock HVC send array "
                      << "(error: " << std::to_string(GetLastError()) << ")\n";
        }
#else
    if (mlock(array.data(), HVC_RX_SIZE) == -1) {
        std::cout << __func__ << ": Unable to lock array\n";
#endif
    }

    while (enable_hvc) {
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

        __domain_op__hvc_rx_put(id, array.data(), count);
        std::this_thread::sleep_for(hvc_sleep);
    }
}

void uvc_domain::handle_events()
{
    std::unique_lock lock(event_mtx);

    event_cond.wait(lock, [&](){
        switch (event_code) {
        case __enum_run_op__create_domain:
            this->create_child(event_data);
            break;
        case __enum_run_op__pause_domain:
            this->pause_child(event_data);
            break;
        case __enum_run_op__unpause_domain:
            this->unpause_child(event_data);
            break;
        case __enum_run_op__destroy_domain:
            this->destroy_child(event_data);
            break;
        }

        return !enable_events;
    });
}

void uvc_domain::create_child(domainid_t domid)
{
    child_list.emplace_front(domid, this);
    child_list.front().launch();
}

void uvc_domain::pause_child(domainid_t domid)
{
    for (auto c = child_list.begin(); c != child_list.end(); c++) {
        if (c->id == domid) {
            c->pause();
        }
    }
}

void uvc_domain::unpause_child(domainid_t domid)
{
    for (auto c = child_list.begin(); c != child_list.end(); c++) {
        if (c->id == domid) {
            c->unpause();
        }
    }
}

void uvc_domain::destroy_child(domainid_t domid)
{
    for (auto c = child_list.begin(); c != child_list.end(); c++) {
        if (c->id == domid) {
            c->destroy();
        }
    }
}

void uvc_domain::pause()
{
    std::lock_guard lock(vcpu_mtx);

    for (auto &v : vcpu_list) {
        v.pause();
    }
}

void uvc_domain::unpause()
{
    std::lock_guard lock(vcpu_mtx);

    for (auto &v : vcpu_list) {
        v.unpause();
    }
}

void uvc_domain::destroy()
{
    enable_uart = false;
    enable_hvc = false;

    if (event_thread.joinable()) {
        /* Acquire the event lock */
        std::unique_lock lock(event_mtx);

        /* Clear the event data */
        event_code = 0;
        event_data = 0;

        /* Tell the thread to return */
        enable_events = false;
        event_cond.notify_one();

        /* Release the event lock */
        lock.unlock();
        event_thread.join();
    }

    if (hvc_recv.joinable()) {
        hvc_recv.join();
    }

    if (hvc_send.joinable()) {
        hvc_send.join();
    }

    if (uart_recv.joinable()) {
        uart_recv.join();
    }

    /*
     * Note we can safely access the child list here as long as
     * the only other modifications happen in the event thread
     * (which has joined at this point).
     */
    for (auto &c : child_list) {
        printf("%s: destroying child 0x%llx\n", __func__, c.id);
        c.destroy();
    }

    std::lock_guard lock(vcpu_mtx);

    for (auto &v : vcpu_list) {
        printf("%s: halting vcpu 0x%llx\n", __func__, v.id);
        v.halt();
    }

    for (auto &v : vcpu_list) {
        if (v.run_thread.joinable()) {
            printf("%s: joining vcpu 0x%llx\n", __func__, v.id);
            v.run_thread.join();
        }
    }

    destroy_vcpus();

    /*
     * Only perform the destroy vmcall on non-root domains. The
     * root domain is destroyed via the ioctl interface.
     */
    if (!this->is_root()) {
        __domain_op__destroy_domain(id);
    }
}

void uvc_domain::launch()
{
    if (this->is_root()) {
        if (enable_uart) {
            uart_recv = std::thread(std::bind(&uvc_domain::recv_uart, this));
        } else if (enable_hvc) {
            hvc_recv = std::thread(std::bind(&uvc_domain::recv_hvc, this));
            hvc_send = std::thread(std::bind(&uvc_domain::send_hvc, this));
        }

        enable_events = true;
        event_thread = std::thread(std::bind(&uvc_domain::handle_events, this));
    }

    std::lock_guard lock(vcpu_mtx);

    if (vcpu_list.size() == 0) {
        create_vcpu();
    }

    for (auto v = vcpu_list.begin(); v != vcpu_list.end(); v++) {
        v->launch();
    }
}

void uvc_domain::create_vcpu()
{
    auto newid = __vcpu_op__create_vcpu(id);
    if (newid == INVALID_VCPUID) {
        throw std::runtime_error("create_vcpu failed");
    }

    vcpu_list.emplace_front(newid, this);
}

void uvc_domain::destroy_vcpus()
{
    for (auto v = vcpu_list.begin(); v != vcpu_list.end(); v++) {
        __vcpu_op__destroy_vcpu(v->id);
    }

    vcpu_list.clear();
}
