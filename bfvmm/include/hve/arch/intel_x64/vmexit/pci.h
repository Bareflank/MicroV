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

#ifndef PCI_HANDLER_MICROV_H
#define PCI_HANDLER_MICROV_H

#include "../vcpu.h"
#include "io_instruction.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace microv::intel_x64
{

class vcpu;

class pci_handler
{
    vcpu *m_vcpu;

public:
    using base_vcpu = bfvmm::intel_x64::vcpu;
    using handler = delegate<bool(base_vcpu *)>;
    using info = bfvmm::intel_x64::io_instruction_handler::info_t;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    pci_handler(vcpu *vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~pci_handler() = default;

    /// Enable the default host handlers
    ///
    void enable_host_defaults();

    /// Handle config access to the device at the given bus/dev/fun
    ///
    void add_handler(uint32_t bus, uint32_t dev, uint32_t fun);

    /// @cond

    pci_handler(pci_handler &&) = default;
    pci_handler &operator=(pci_handler &&) = default;
    pci_handler(const pci_handler &) = delete;
    pci_handler &operator=(const pci_handler &) = delete;

    /// @endcond
};
}
#endif
