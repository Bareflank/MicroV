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
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <iostream>

#include "domain.h"
#include "log.h"
#include "vcpu.h"

using namespace std::chrono;
using namespace std::chrono_literals;

static constexpr auto PAUSE_DURATION = 200us;
static constexpr size_t MAX_DOMAINS = 16;

#ifdef WIN64
HANDLE uvctl_ioctl_open(const GUID *guid);
int64_t uvctl_rw_ioctl(HANDLE fd, DWORD request, void *data, DWORD size);

static std::array<HANDLE, MAX_DOMAINS> domain_events{0};
#endif

uvc_vcpu::uvc_vcpu(vcpuid_t id, struct uvc_domain *dom)
{
#ifdef WIN64
    if (dom->id >= domain_events.size()) {
        log_msg("%s: Domain limit of %u reached, throwing\n",
                __func__, domain_events.size());
        throw std::runtime_error("domain limit reached\n");
    }
#endif

    this->id = id;
    this->state = runstate::halted;
    this->domain = dom;
}

#ifdef WIN64

bool uvc_vcpu::init_xenbus_events(HANDLE event)
{
    HANDLE fd = uvctl_ioctl_open(&GUID_DEVINTERFACE_XENBUS);
    if (fd == INVALID_HANDLE_VALUE) {
        log_msg("%s: Domain 0x%x failed to open xenbus fd\n", __func__, domain->id);
        return false;
    }

    XENBUS_ADD_USER_EVENT_IN user_event{0};

    user_event.EventHandle = event;
    user_event.RemoteDomain = domain->id - 1; /* convert our microv ID to xen ID */

    auto rc = uvctl_rw_ioctl(fd,
                             IOCTL_XENBUS_ADD_USER_EVENT,
                             &user_event,
                             sizeof(user_event));
    CloseHandle(fd);

    if (rc < 0) {
        log_msg("%s: failed to add xenbus event for domain 0x%x\n",
                __func__, domain->id);
        return false;
    }

    return true;
}

bool uvc_vcpu::init_visr_events(HANDLE event)
{
    HANDLE fd = uvctl_ioctl_open(&GUID_DEVINTERFACE_visr);
    if (fd == INVALID_HANDLE_VALUE) {
        log_msg("%s: NDVM failed to open visr fd\n", __func__);
        return false;
    }

    struct visr_register_event user_event{0};

    user_event.event = event;

    auto rc = uvctl_rw_ioctl(fd,
                             IOCTL_VISR_REGISTER_EVENT,
                             &user_event,
                             sizeof(user_event));
    CloseHandle(fd);

    if (rc < 0) {
        log_msg("%s: NDVM failed to register visr event\n", __func__);
        return false;
    }

    return true;
}

void uvc_vcpu::init_events()
{
    HANDLE event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!event) {
       log_msg("%s: Failed to create event for domain 0x%x (last error = 0x%x)\n",
               __func__, domain->id, GetLastError());
       return;
    }

    domain_events[domain->id] = event;

    log_msg("%s: Created handle 0x%llx for domain 0x%x\n",
            __func__, event, domain->id);

    bool xenbus_succeeded = this->init_xenbus_events(event);
    if (!xenbus_succeeded && domain->id != 2) {
        goto put_event;
    }

    /*
     * TODO: use a more elegant way of determining if an event
     * should be registered with visr. For now we just assume id == 2
     * implies the NDVM.
     */
    if (domain->id != 2) {
        return;
    }

    if (!this->init_visr_events(event) && !xenbus_succeeded) {
        goto put_event;
    }

    return;

put_event:
    domain_events[domain->id] = 0;
    CloseHandle(event);

    return;
}
#endif

void uvc_vcpu::launch()
{
#ifdef WIN64
    this->init_events();
#endif

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
    log_msg("[0x%x]: vcpu fault, err=0x%x\n", id, err);
}

void uvc_vcpu::usleep(const microseconds &us) const
{
    std::this_thread::sleep_for(us);
}

void uvc_vcpu::notify_mgmt_event(uint64_t event_code, uint64_t event_data) const
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

    std::this_thread::yield();
}

void uvc_vcpu::notify_send_event(domainid_t domid) const
{
    if (!domid) {
        /*
         * domid == 0 in this case is the root domain, which doesn't
         * have an associated uvc_domain nor any uvc_vcpus, so just yield
         * in this case.
         */
        std::this_thread::yield();
        return;
    }

#ifdef WIN64
    SetEvent(domain_events[domid]);
#endif

    std::this_thread::yield();
}

void uvc_vcpu::wait(uint64_t us) const
{
#ifdef WIN64
    HANDLE event = domain_events[domain->id];
    DWORD ms = (DWORD)us / 1000U;
    ms = (ms >= 1U) ? ms : 1U;

    WaitForSingleObject(event, ms);
    ResetEvent(event);
#else
    this->usleep(microseconds(us));
#endif
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
            this->usleep(PAUSE_DURATION);
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
            this->wait(arg);
            break;
        case __enum_run_op__interrupted:
            break;
        case __enum_run_op__create_domain:
        case __enum_run_op__pause_domain:
        case __enum_run_op__unpause_domain:
        case __enum_run_op__destroy_domain:
            this->notify_mgmt_event(rc, arg);
            break;
        case __enum_run_op__notify_domain:
            this->notify_send_event(arg);
            break;
        }
    }
}
