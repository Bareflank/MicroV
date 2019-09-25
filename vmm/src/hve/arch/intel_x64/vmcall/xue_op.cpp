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
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vmcall/xue_op.h>
#include <xue.h>

extern struct xue g_xue;
extern struct xue_ops g_xue_ops;

void reset_xue()
{
    memset(&g_xue, 0, sizeof(g_xue));
    memset(&g_xue_ops, 0, sizeof(g_xue_ops));

    xue_open(&g_xue, &g_xue_ops, NULL);

    __asm volatile("mfence");

    ensures(g_xue.dbc_reg->ctrl & (1UL << XUE_CTRL_DCR));
}

namespace microv::intel_x64
{

vmcall_xue_op_handler::vmcall_xue_op_handler(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler({&vmcall_xue_op_handler::dispatch, this});
}

bool
vmcall_xue_op_handler::dispatch(vcpu *vcpu)
{
    if (bfopcode(vcpu->rax()) != __enum_xue_op) {
        return false;
    }

    switch (vcpu->rbx()) {
    case __enum_xue_op__reset:
        reset_xue();
        return true;

//        case __enum_vcpu_op__kill_vcpu:
//            this->vcpu_op__kill_vcpu(vcpu);
//            return true;
//
//        case __enum_vcpu_op__destroy_vcpu:
//            this->vcpu_op__destroy_vcpu(vcpu);
//            return true;
//
        default:
            break;
    };

    throw std::runtime_error("unknown xue opcode");
}

}
