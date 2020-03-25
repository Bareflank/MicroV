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
#include <hve/arch/intel_x64/vmexit/hlt.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

hlt_handler::hlt_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    if (vcpu->is_dom0()) {
        return;
    }

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::hlt,
        {&hlt_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
hlt_handler::add_hlt_handler(
    const handler_delegate_t &d)
{ m_hlt_handlers.push_back(d); }

void
hlt_handler::add_yield_handler(
    const handler_delegate_t &d)
{ m_yield_handlers.push_back(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

template<typename T> bool
dispatch(vcpu *vcpu, const T &handlers)
{
    for (const auto &d : handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    return false;
}

bool
hlt_handler::handle(vcpu_t *vcpu)
{
    bfignored(vcpu);

    // Notes:
    //
    // - The big difference between a hlt and a yield is that when the
    //   guest attempts to execute a hlt it will first disable interrupts.
    //   This is the guest's way of saying that it has nothing to do. If the
    //   guest attempts to yield it will enable interrupts instead.
    //
    // - We disable blocking_by_sti because if the guest is trying to yield
    //   it will execute an STI right before executing a hlt (to ensure that
    //   interrupts are enabled) which triggers this flag. Since we have a VM
    //   exit, the flag is meaningless but it will trigger a VM entry failure
    //   when we attempt to inject.
    //

    if (vmcs_n::guest_rflags::interrupt_enable_flag::is_disabled()) {
        return dispatch(m_vcpu, m_hlt_handlers);
    }

    vmcs_n::guest_interruptibility_state::blocking_by_sti::disable();
    return dispatch(m_vcpu, m_yield_handlers);
}

}
