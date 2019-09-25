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
#include <hve/arch/intel_x64/vmcall/iommu_op.h>

#include <iommu/iommu.h>

namespace microv::intel_x64
{

vmcall_iommu_op_handler::vmcall_iommu_op_handler(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;
    vcpu->add_vmcall_handler({&vmcall_iommu_op_handler::dispatch, this});
}

bool vmcall_iommu_op_handler::dispatch(vcpu *vcpu)
{
    if (bfopcode(vcpu->rax()) != __enum_iommu_op) {
        return false;
    }

    switch (vcpu->rbx()) {
    case __enum_iommu_op__dump:
        this->dump();
        return true;
    default:
        break;
    };

    throw std::runtime_error("unknown iommu opcode");
}

void vmcall_iommu_op_handler::dump()
{
    ::microv::iommu_dump();
}

}
