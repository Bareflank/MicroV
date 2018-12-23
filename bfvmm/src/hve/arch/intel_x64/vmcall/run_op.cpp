//
// Copyright (C) 2018 Assured Information Security, Inc.
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

namespace hyperkernel::intel_x64
{

vmcall_run_op_handler::vmcall_run_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_run_op_handler, dispatch)
    );
}

bool
vmcall_run_op_handler::dispatch(
    gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __enum_run_op) {
        return false;
    }

    try {
        if (m_child_vcpu == nullptr ||
            m_child_vcpu->id() != vcpu->rbx()
           ) {
            m_child_vcpu = get_vcpu(vcpu->rbx());
        }

        m_child_vcpu->set_parent_vcpu(vcpu);

        if (m_child_vcpu->is_alive()) {
            m_child_vcpu->load();
            m_child_vcpu->run(&world_switch);
        }

        vcpu->set_rax(__enum_run_op__hlt);
    }
    catchall({
        vcpu->set_rax(__enum_run_op__fault);
    })

    return true;
}

}
