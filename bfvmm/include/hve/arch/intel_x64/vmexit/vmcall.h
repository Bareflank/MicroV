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

#ifndef VMEXIT_VMCALL_INTEL_X64_BOXY_H
#define VMEXIT_VMCALL_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class vmcall_handler
{
public:

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t = delegate<bool(vcpu *)>;

#define vmcall_handler_delegate(a,b) \
    vmcall_handler::handler_delegate_t::create<a, &a::b>(this)

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this interrupt window handler
    ///
    vmcall_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcall_handler() = default;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(const handler_delegate_t &d);

public:

    /// @cond

    bool handle(vcpu_t *vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;
    std::list<handler_delegate_t> m_handlers;

public:

    /// @cond

    vmcall_handler(vmcall_handler &&) = default;
    vmcall_handler &operator=(vmcall_handler &&) = default;

    vmcall_handler(const vmcall_handler &) = delete;
    vmcall_handler &operator=(const vmcall_handler &) = delete;

    /// @endcond
};

}

#endif
