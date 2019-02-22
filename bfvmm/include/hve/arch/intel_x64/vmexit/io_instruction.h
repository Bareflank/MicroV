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

#ifndef VMEXIT_IO_INSTRUCTION_INTEL_X64_BOXY_H
#define VMEXIT_IO_INSTRUCTION_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/io_instruction.h>

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

class EXPORT_BOXY_HVE io_instruction_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    io_instruction_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~io_instruction_handler() = default;

public:

    /// @cond

    bool handle_in_0x0070(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x0070(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_in_0x0071(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x0071(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_in_0x04D0(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x04D0(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_in_0x04D1(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x04D1(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);

    /// @endcond

private:

    vcpu *m_vcpu;

public:

    /// @cond

    io_instruction_handler(io_instruction_handler &&) = default;
    io_instruction_handler &operator=(io_instruction_handler &&) = default;

    io_instruction_handler(const io_instruction_handler &) = delete;
    io_instruction_handler &operator=(const io_instruction_handler &) = delete;

    /// @endcond
};

}

#endif
