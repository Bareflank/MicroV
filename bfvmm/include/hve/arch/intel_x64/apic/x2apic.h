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

#ifndef APIC_X2APIC_INTEL_X64_BOXY_H
#define APIC_X2APIC_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <eapis/hve/arch/intel_x64/vmexit/rdmsr.h>
#include <eapis/hve/arch/intel_x64/vmexit/wrmsr.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_BOXY_HVE
#ifdef SHARED_BOXY_HVE
#define EXPORT_BOXY_HVE EXPORT_SYM
#else
#define EXPORT_BOXY_HVE IMPORT_SYM
#endif
#else
#define EXPORT_BOXY_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class EXPORT_BOXY_HVE x2apic_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    x2apic_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~x2apic_handler() = default;

public:

    /// @cond

    bool handle_rdmsr_0x0000001B(
        gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x0000001B(
        gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::wrmsr_handler::info_t &info);

    bool handle_rdmsr_0x00000802(
        gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x00000802(
        gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::wrmsr_handler::info_t &info);
    bool handle_rdmsr_0x00000803(
        gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::rdmsr_handler::info_t &info);
    bool handle_wrmsr_0x00000803(
        gsl::not_null<vcpu_t *> vcpu, ::eapis::intel_x64::wrmsr_handler::info_t &info);

    /// @endcond

private:

    vcpu *m_vcpu;

    uint64_t m_0x0000001B{0xFEE00D00};

public:

    /// @cond

    x2apic_handler(x2apic_handler &&) = default;
    x2apic_handler &operator=(x2apic_handler &&) = default;

    x2apic_handler(const x2apic_handler &) = delete;
    x2apic_handler &operator=(const x2apic_handler &) = delete;

    /// @endcond
};

}

#endif
