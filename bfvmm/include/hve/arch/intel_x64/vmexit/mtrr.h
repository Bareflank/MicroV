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

#ifndef VMEXIT_MTRR_INTEL_X64_BOXY_H
#define VMEXIT_MTRR_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/rdmsr.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/wrmsr.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class mtrr_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    mtrr_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~mtrr_handler() = default;

public:

    /// @cond

    bool handle_rdmsr_0x000000FE(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x000000FE(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0x00000200(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x00000200(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0x00000201(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x00000201(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0x000002FF(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x000002FF(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    /// @endcond

private:

    vcpu *m_vcpu;
    uint64_t m_mtrr_def_type{0xC00};

public:

    /// @cond

    mtrr_handler(mtrr_handler &&) = default;
    mtrr_handler &operator=(mtrr_handler &&) = default;

    mtrr_handler(const mtrr_handler &) = delete;
    mtrr_handler &operator=(const mtrr_handler &) = delete;

    /// @endcond
};

}

#endif
