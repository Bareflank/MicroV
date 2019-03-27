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

#ifndef VIRT_VIRQ_INTEL_X64_BOXY_H
#define VIRT_VIRQ_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/hve/arch/intel_x64/interrupt_queue.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class virq_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    virq_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~virq_handler() = default;

public:

    /// Queue vIRQ
    ///
    /// Queues a virtual IRQ to be delivered to a guest VM. Note that this
    /// will actually queue the Hypervisor Callback Vector IRQ into the
    /// guest, and then the guest has to VMCall to this class to get the
    /// vIRQ vector. Also note that all vIRQs are essentially vMSIs so once
    /// the vIRQ is dequeued, it is gone.
    ///
    /// @expects
    /// @ensures
    ///
    void queue_virtual_interrupt(uint64_t vector);

    /// Inject vIRQ
    ///
    /// Injects a virtual IRQ to be delivered to a guest VM. Note that this
    /// will actually inject the Hypervisor Callback Vector IRQ into the
    /// guest, and then the guest has to VMCall to this class to get the
    /// vIRQ vector. Also note that all vIRQs are essentially vMSIs so once
    /// the vIRQ is dequeued, it is gone.
    ///
    /// @expects
    /// @ensures
    ///
    void inject_virtual_interrupt(uint64_t vector);

public:

    /// @cond

    void virq_op__set_hypervisor_callback_vector(vcpu *vcpu);
    void virq_op__get_next_virq(vcpu *vcpu);

    bool dispatch(vcpu *vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;

    uint64_t m_hypervisor_callback_vector{};
    bfvmm::intel_x64::interrupt_queue m_interrupt_queue;

public:

    /// @cond

    virq_handler(virq_handler &&) = default;
    virq_handler &operator=(virq_handler &&) = default;

    virq_handler(const virq_handler &) = delete;
    virq_handler &operator=(const virq_handler &) = delete;

    /// @endcond
};

}

#endif
