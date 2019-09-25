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
#include <stdio.h>

#include "vcpu.h"

using namespace std::chrono;
using namespace std::chrono_literals;

/* Each pause iteration is 200 microseconds */
static constexpr auto pause_duration = 200us;

uvc_vcpu::uvc_vcpu(vcpuid_t id, struct uvc_domain *dom) noexcept
{
    this->id = id;
    this->state = runstate::halted;
    this->domain = dom;
}

/* ensures(state <= runstate::runable) */
void uvc_vcpu::launch()
{
    state = runstate::runable;
    run_thread = std::thread(std::bind(&uvc_vcpu::run, this));
}

/* ensures(state == runstate::halted) */
void uvc_vcpu::halt()
{
    state = runstate::halted;
}

/* ensures(state == runstate::halted) */
void uvc_vcpu::fault(uint64_t err)
{
    printf("[0x%x]: vcpu fault: 0x%x\n", id, err);
    this->halt();
}

void uvc_vcpu::usleep(const microseconds &us)
{
    std::this_thread::sleep_for(us);
}

void uvc_vcpu::notify_create_domain(domainid_t domid)
{
}

void uvc_vcpu::run()
{
    while (true) {

        /* Respond to the current runstate */
        switch (state) {
        case runstate::running:
        case runstate::runable:
            break;
        case runstate::paused:
            this->usleep(pause_duration);
            continue;
        case runstate::halted:
            return;
        }

        state = runstate::running;

        auto ret = __run_op(id, 0, 0);
        auto arg = run_op_ret_arg(ret);
        auto rc = run_op_ret_op(ret);

        /* Handle the return code */
        switch (rc) {
        case __enum_run_op__hlt:
            this->halt();
            break;
        case __enum_run_op__fault:
            this->fault(arg);
            break;
        case __enum_run_op__yield:
            this->usleep(microseconds(arg));
            break;
        case __enum_run_op__interrupted:
            break;
        case __enum_run_op__create_domain:
            this->notify_create_domain(arg);
            break;
        }
    }
}
