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

#ifndef VMCALL_DOMAIN_INTEL_X64_HYPERKERNEL_H
#define VMCALL_DOMAIN_INTEL_X64_HYPERKERNEL_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HYPERKERNEL_HVE
#ifdef SHARED_HYPERKERNEL_HVE
#define EXPORT_HYPERKERNEL_HVE EXPORT_SYM
#else
#define EXPORT_HYPERKERNEL_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HYPERKERNEL_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

class vcpu;

class EXPORT_HYPERKERNEL_HVE vmcall_domain_op_handler
{
public:

    vmcall_domain_op_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcall_domain_op_handler() = default;

private:

    void domain_op__create_domain(gsl::not_null<vcpu *> vcpu);
    void domain_op__destroy_domain(gsl::not_null<vcpu *> vcpu);
    void domain_op__share_page(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_entry(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_uart(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_pt_uart(gsl::not_null<vcpu *> vcpu);
    void domain_op__dump_uart(gsl::not_null<vcpu *> vcpu);

    bool dispatch(gsl::not_null<vcpu *> vcpu);

private:

    vcpu *m_vcpu;

public:

    /// @cond

    vmcall_domain_op_handler(vmcall_domain_op_handler &&) = default;
    vmcall_domain_op_handler &operator=(vmcall_domain_op_handler &&) = default;

    vmcall_domain_op_handler(const vmcall_domain_op_handler &) = delete;
    vmcall_domain_op_handler &operator=(const vmcall_domain_op_handler &) = delete;

    /// @endcond
};

}

#endif
