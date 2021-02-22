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

namespace microv::intel_x64 {

vmcall_run_op_handler::vmcall_run_op_handler(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler({&vmcall_run_op_handler::dispatch, this});
}

bool vmcall_run_op_handler::dispatch(vcpu *root)
{
    // Note:
    //
    // This code executes a lot. For example, every time an interrupt fires,
    // control is handed back to the root vCPU, so when it is time to
    // execute the guest again, this code has to execute. As a result, the
    // following should be considered:
    // - Keep the code in this function to a minimum. Every line in this
    //   function has been carefully examined to reduce the total overhead of
    //   executing a guest.
    // - Once VMCS migration is implemented, the root vcpu may change in between
    //   calls to this function.
    // - This handler should be the first handler to be called. This way, we
    //   dont end up looping through the vmcall handlers on every interrupt.

    if (bfopcode(root->rax()) != __enum_run_op) {
        return false;
    }

    try {
        auto child = root->find_child_vcpu(root->rbx());
        if (!child) {
            bfalert_nhex(0, "not child found with id = ", root->rbx());
        }

        expects(child);

        child->set_root_vcpu(root);
        root->save_xstate();

        child->load_xstate();
        child->load();
        child->run(&world_switch);

        /* unreachable */
        root->set_rax(__enum_run_op__hlt);
    }
    catchall({ root->set_rax(__enum_run_op__fault); })

        return true;
}

}
