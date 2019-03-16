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

#ifndef VMEXIT_MSR_INTEL_X64_BOXY_H
#define VMEXIT_MSR_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/rdmsr.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/wrmsr.h>

#include <unordered_map>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class msr_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    msr_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~msr_handler() = default;

public:

    /// @cond

    void isolate_msr(uint32_t msr);

    void isolate_msr__on_run(
        bfobject *obj);
    bool isolate_msr__on_exit(
        vcpu_t *vcpu);
    bool isolate_msr__on_write(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    /// @endcond

public:

    /// @cond

    bool handle_rdmsr_0x00000034(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x00000034(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0x000000CE(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x000000CE(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0x00000140(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x00000140(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0x000001A0(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x000001A0(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0x00000606(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x00000606(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0x0000064E(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x0000064E(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0xC0000103(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0xC0000103(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    /// @endcond

private:

    vcpu *m_vcpu;

    uint64_t m_0xC0000103{0};
    std::unordered_map<uint32_t, uint64_t> m_msrs;

public:

    /// @cond

    msr_handler(msr_handler &&) = default;
    msr_handler &operator=(msr_handler &&) = default;

    msr_handler(const msr_handler &) = delete;
    msr_handler &operator=(const msr_handler &) = delete;

    /// @endcond
};

}

#endif
