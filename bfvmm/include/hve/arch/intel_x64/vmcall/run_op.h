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

#ifndef VMCALL_RUN_INTEL_X64_BOXY_H
#define VMCALL_RUN_INTEL_X64_BOXY_H

#include <bfhypercall.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class vmcall_run_op_handler
{
public:

    vmcall_run_op_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcall_run_op_handler() = default;

private:

    bool dispatch(vcpu *vcpu);

private:

    vcpu *m_vcpu;

    vcpu *m_child_vcpu;
    vcpuid_t m_child_vcpuid;

public:

    /// @cond

    vmcall_run_op_handler(vmcall_run_op_handler &&) = default;
    vmcall_run_op_handler &operator=(vmcall_run_op_handler &&) = default;

    vmcall_run_op_handler(const vmcall_run_op_handler &) = delete;
    vmcall_run_op_handler &operator=(const vmcall_run_op_handler &) = delete;

    /// @endcond
};

}

#endif
