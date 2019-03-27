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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/virt/virq.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

virq_handler::virq_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    if (vcpu->is_dom0()) {
        return;
    }

    m_vcpu->add_vmcall_handler(
        {&virq_handler::dispatch, this}
    );
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

void
virq_handler::queue_virtual_interrupt(uint64_t vector)
{
    m_interrupt_queue.push(vector);
    m_vcpu->queue_external_interrupt(m_hypervisor_callback_vector);
}

void
virq_handler::inject_virtual_interrupt(uint64_t vector)
{
    m_interrupt_queue.push(vector);
    m_vcpu->inject_external_interrupt(m_hypervisor_callback_vector);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

void
virq_handler::virq_op__set_hypervisor_callback_vector(
    vcpu *vcpu)
{
    try {
        m_hypervisor_callback_vector = vcpu->rbx();
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
virq_handler::virq_op__get_next_virq(vcpu *vcpu)
{
    try {
        if (m_interrupt_queue.empty()) {
            throw std::runtime_error("virq queue empty");
        }

        vcpu->set_rax(m_interrupt_queue.pop());
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

bool
virq_handler::dispatch(vcpu *vcpu)
{
    if (bfopcode(vcpu->rax()) != hypercall_enum_virq_op) {
        return false;
    }

    switch (vcpu->rax()) {
        case hypercall_enum_virq_op__set_hypervisor_callback_vector:
            virq_op__set_hypervisor_callback_vector(vcpu);
            break;

        case hypercall_enum_virq_op__get_next_virq:
            virq_op__get_next_virq(vcpu);
            break;

        default:
            vcpu->halt("unknown virq op");
    };

    return true;
}

}
