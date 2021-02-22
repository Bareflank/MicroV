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

#ifndef VMEXIT_HLT_INTEL_X64_H
#define VMEXIT_HLT_INTEL_X64_H

#include <bfgsl.h>
#include <bfdelegate.h>
#include <list>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// HLT instruction
///
/// Provides an interface for registering handlers vmexit handlers
///
class hlt_handler {
public:
    struct info_t {
        bool ignore_advance;
    };

    using handler_delegate_t = delegate<bool(vcpu *, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this hlt handler
    ///
    hlt_handler(gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~hlt_handler() = default;

    /// Add handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param hdlr the delegate to call when a hlt exit occurs
    ///
    void add_handler(const handler_delegate_t &hdlr);
    void enable_exiting();
    void disable_exiting();

private:

    bool handle(vcpu *vcpu);

    vcpu *m_vcpu;
    std::list<handler_delegate_t> m_handlers;

public:

    /// @cond

    hlt_handler(hlt_handler &&) = default;
    hlt_handler &operator=(hlt_handler &&) = default;

    hlt_handler(const hlt_handler &) = delete;
    hlt_handler &operator=(const hlt_handler &) = delete;

    /// @endcond
};

}

#endif
