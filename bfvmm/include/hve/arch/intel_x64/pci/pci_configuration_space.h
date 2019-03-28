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

#ifndef PCI_PCI_CONFIGURATION_SPACE_INTEL_X64_BOXY_H
#define PCI_PCI_CONFIGURATION_SPACE_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/io_instruction.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class pci_configuration_space_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    pci_configuration_space_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~pci_configuration_space_handler() = default;

public:

    /// @cond

    bool handle_in_0x0CF8(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x0CF8(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_in_0x0CFA(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x0CFA(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_in_0x0CFB(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x0CFB(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_in_0x0CFC(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x0CFC(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_in_0x0CFD(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x0CFD(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_in_0x0CFE(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x0CFE(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_in_0x0CFF(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool handle_out_0x0CFF(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);

    /// @endcond

private:

    vcpu *m_vcpu;

public:

    /// @cond

    pci_configuration_space_handler(pci_configuration_space_handler &&) = default;
    pci_configuration_space_handler &operator=(pci_configuration_space_handler &&) = default;

    pci_configuration_space_handler(const pci_configuration_space_handler &) = delete;
    pci_configuration_space_handler &operator=(const pci_configuration_space_handler &) = delete;

    /// @endcond
};

}

#endif
