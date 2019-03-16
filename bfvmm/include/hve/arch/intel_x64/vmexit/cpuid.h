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

#ifndef VMEXIT_CPUID_INTEL_X64_BOXY_H
#define VMEXIT_CPUID_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/cpuid.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class cpuid_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    cpuid_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~cpuid_handler() = default;

public:

    /// @cond

    bool handle_0x00000000(vcpu_t *vcpu);
    bool handle_0x00000001(vcpu_t *vcpu);
    bool handle_0x00000002(vcpu_t *vcpu);
    bool handle_0x00000004(vcpu_t *vcpu);
    bool handle_0x00000006(vcpu_t *vcpu);
    bool handle_0x00000007(vcpu_t *vcpu);
    bool handle_0x0000000A(vcpu_t *vcpu);
    bool handle_0x0000000B(vcpu_t *vcpu);
    bool handle_0x0000000D(vcpu_t *vcpu);
    bool handle_0x0000000F(vcpu_t *vcpu);
    bool handle_0x00000010(vcpu_t *vcpu);
    bool handle_0x00000015(vcpu_t *vcpu);
    bool handle_0x00000016(vcpu_t *vcpu);
    bool handle_0x80000000(vcpu_t *vcpu);
    bool handle_0x80000001(vcpu_t *vcpu);
    bool handle_0x80000002(vcpu_t *vcpu);
    bool handle_0x80000003(vcpu_t *vcpu);
    bool handle_0x80000004(vcpu_t *vcpu);
    bool handle_0x80000007(vcpu_t *vcpu);
    bool handle_0x80000008(vcpu_t *vcpu);

    bool handle_0x40000000(vcpu_t *vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;

public:

    /// @cond

    cpuid_handler(cpuid_handler &&) = default;
    cpuid_handler &operator=(cpuid_handler &&) = default;

    cpuid_handler(const cpuid_handler &) = delete;
    cpuid_handler &operator=(const cpuid_handler &) = delete;

    /// @endcond
};

}

#endif
