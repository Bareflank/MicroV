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
#include <hve/arch/intel_x64/vmcall/run_op.h>

namespace boxy::intel_x64
{

run_op_handler::run_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    if (vcpu->is_domU()) {
        return;
    }

    vcpu->add_vmcall_handler({&run_op_handler::dispatch, this});
}

bool
run_op_handler::dispatch(vcpu *vcpu)
{
    // Note:
    //
    // This code executes a lot. For example, every time an interrupt fires,
    // control is handed back to the parent vCPU, so when it is time to
    // execute the guest again, this code has to execute. As a result, the
    // following should be considered:
    // - Keep the code in this function to a minimum. Every line in this
    //   function has been carefully examined to reduce the total overhead of
    //   executing a guest.
    // - Do no assume that the parent vCPU is always the same. It is possible
    //   for the host to change the parent vCPU the next time this is executed.
    //   If this happens, a VMCS migration must take place.
    // - This handler should be the first handler to be called. This way, we
    //   do no end up looping through the vmcall handlers on every interrupt.

    if (bfopcode(vcpu->rax()) != hypercall_enum_run_op) {
        return false;
    }

    try {
        if (m_child_vcpuid != vcpu->rbx()) {
            m_child_vcpu = get_vcpu(vcpu->rbx());
            m_child_vcpuid = vcpu->rbx();
        }

        m_child_vcpu->set_parent_vcpu(vcpu);

        if (m_child_vcpu->is_alive()) {
            m_child_vcpu->load();

            try {
                m_child_vcpu->prepare_for_world_switch();
                m_child_vcpu->run();
            }
            catch (...) {
                vcpu->prepare_for_world_switch();
                throw;
            }
        }

        vcpu->set_rax(hypercall_enum_run_op__hlt);
    }
    catchall({
        vcpu->set_rax(hypercall_enum_run_op__fault);
    })

    return true;
}

}
