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

#include <mutex>
#include <printv.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vmcall/event_op.h>

#include <pci/cfg.h>
#include <pci/dev.h>
#include <pci/msi.h>

namespace microv::intel_x64
{

static uint64_t xenstore_ready = 0;

vmcall_event_op_handler::vmcall_event_op_handler(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;
    vcpu->add_vmcall_handler({&vmcall_event_op_handler::dispatch, this});
}

bool vmcall_event_op_handler::dispatch(vcpu *vcpu)
{
    if (bfopcode(vcpu->rax()) != __enum_event_op) {
        return false;
    }

    switch (vcpu->rbx()) {
    case __enum_event_op__send_vector:
        this->send_vector(vcpu->rcx());
        return true;
    case __enum_event_op__send_bdf:
        this->send_bdf(vcpu->rcx());
        return true;
    case __enum_event_op__set_xenstore_ready:
        printv("xenstore ready\n");
        xenstore_ready = 1;
        return true;
    case __enum_event_op__is_xenstore_ready:
        vcpu->set_rax(xenstore_ready);
        return true;
    default:
        break;
    };

    throw std::runtime_error("unknown event opcode");
}

void vmcall_event_op_handler::send_bdf(uint64_t bdf)
{
    auto pdev = find_passthru_dev(bdf);
    expects(pdev);

    std::lock_guard msi_lock(pdev->m_msi_mtx);

    auto root_vector = pdev->m_root_msi.vector();
    auto guest_msi = m_vcpu->find_guest_msi(root_vector);
    expects(guest_msi);

    if (!guest_msi->is_enabled()) {
        return;
    }

    auto guest = get_vcpu(pdev->m_guest_vcpuid);
    if (!guest) {
        return;
    }

    auto put_guest = gsl::finally([pdev]{ put_vcpu(pdev->m_guest_vcpuid); });

    if (m_vcpu->pcpuid() == guest->pcpuid()) {
        guest->load();
        guest->queue_external_interrupt(guest_msi->vector());
        m_vcpu->load();
    } else {
        guest->push_external_interrupt(guest_msi->vector());
    }
}

void vmcall_event_op_handler::send_vector(uint64_t root_vector)
{
    auto guest_msi = m_vcpu->find_guest_msi(root_vector);
    expects(guest_msi);

    auto pdev = guest_msi->pdev;
    expects(pdev);

    std::lock_guard msi_lock(pdev->m_msi_mtx);

    if (!guest_msi->is_enabled()) {
        return;
    }

    auto guest = get_vcpu(pdev->m_guest_vcpuid);
    if (!guest) {
        return;
    }

    auto put_guest = gsl::finally([pdev]{ put_vcpu(pdev->m_guest_vcpuid); });

    if (m_vcpu->pcpuid() == guest->pcpuid()) {
        guest->load();
        guest->queue_external_interrupt(guest_msi->vector());
        m_vcpu->load();
    } else {
        guest->push_external_interrupt(guest_msi->vector());
    }
}

}