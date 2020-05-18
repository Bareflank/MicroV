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

#include <chrono>
#include <functional>
#include <iostream>

#include "domain.h"
#include "vcpu.h"

using namespace std::chrono;
using namespace std::chrono_literals;

static constexpr auto pause_duration = 200us;

uvc_vcpu::uvc_vcpu(vcpuid_t id, struct uvc_domain *dom) noexcept
{
    this->id = id;
    this->state = runstate::halted;
    this->domain = dom;
}

void uvc_vcpu::launch()
{
    state = runstate::running;
    run_thread = std::thread(std::bind(&uvc_vcpu::run, this));
}

void uvc_vcpu::halt() noexcept
{
    state = runstate::halted;
}

void uvc_vcpu::pause() noexcept
{
    state = runstate::paused;
}

void uvc_vcpu::unpause() noexcept
{
    state = runstate::running;
}

void uvc_vcpu::fault(uint64_t err) const noexcept
{
    std::cerr << "[" << std::hex << id << "]: vcpu fault, err="
              << std::hex << err << '\n';
}

void uvc_vcpu::usleep(const microseconds &us) const
{
    std::this_thread::sleep_for(us);
}

void uvc_vcpu::notify(uint64_t event_code, uint64_t event_data) const
{
    std::lock_guard lock(domain->event_mtx);

    domain->event_code = event_code;
    domain->event_data = event_data;

    /*
     * Since each vcpu is a potential notifier, we need to notify_one()
     * with the lock held. Otherwise events could be dropped since the
     * domain's event thread is essentially a one-element work queue.
     * If this lock becomes a bottleneck, we could use a bonafide
     * queue and/or schedule std::async tasks from the event thread.
     */
    domain->event_cond.notify_one();
}

/*
 * This is the primary thread that runs a vcpu. The function is marked const to
 * ensure that it doesn't modify the uvc_vcpu::state; any modification must be
 * done by the vcpu's domain. The domain modifies the state to exert control
 * over the runtime given to the vcpu. This can be in response to some external
 * factor like a kill signal, or a parent domain that wants to modify the
 * runstate (e.g. pause) in some way.
 *
 * Enforcing read-only access to the state member from run() eliminates any
 * possibility of races and thus no locking or atomic access is required.
 */
void uvc_vcpu::run() const
{
    while (true) {
        /* Handle the current runstate */
        switch (state) {
        case runstate::running:
            break;
        case runstate::paused:
            this->usleep(pause_duration);
            continue;
        case runstate::halted:
            return;
        }

        /* Run the vcpu */
        const auto ret = __run_op(id, 0, 0);
        const auto arg = run_op_ret_arg(ret);
        const auto rc = run_op_ret_op(ret);

        /* Handle the return code */
        switch (rc) {
        case __enum_run_op__hlt:
            return;
        case __enum_run_op__fault:
            this->fault(arg);
            return;
        case __enum_run_op__yield:
            this->usleep(microseconds(arg));
            break;
        case __enum_run_op__interrupted:
            break;
        case __enum_run_op__create_domain:
        case __enum_run_op__pause_domain:
        case __enum_run_op__unpause_domain:
        case __enum_run_op__destroy_domain:
            this->notify(rc, arg);
            break;
        }
    }
}
