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

#ifndef VMCALL_VCPU_INTEL_X64_BOXY_H
#define VMCALL_VCPU_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class vmcall_vcpu_op_handler
{
public:

    vmcall_vcpu_op_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcall_vcpu_op_handler() = default;

private:

    void vcpu_op__create_vcpu(vcpu *vcpu);
    void vcpu_op__kill_vcpu(vcpu *vcpu);
    void vcpu_op__destroy_vcpu(vcpu *vcpu);

    bool dispatch(vcpu *vcpu);

private:

    vcpu *m_vcpu;

public:

    /// @cond

    vmcall_vcpu_op_handler(vmcall_vcpu_op_handler &&) = default;
    vmcall_vcpu_op_handler &operator=(vmcall_vcpu_op_handler &&) = default;

    vmcall_vcpu_op_handler(const vmcall_vcpu_op_handler &) = delete;
    vmcall_vcpu_op_handler &operator=(const vmcall_vcpu_op_handler &) = delete;

    /// @endcond
};

}

#endif
