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

#ifndef VMCALL_EVENT_INTEL_X64_MICROV_H
#define VMCALL_EVENT_INTEL_X64_MICROV_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace microv::intel_x64 {

class vcpu;

class vmcall_event_op_handler {
private:
    bool dispatch(vcpu *vcpu);
    vcpu *m_vcpu{};

public:
    void send_bdf(uint64_t bdf);
    void send_vector(uint64_t root_vector);

    vmcall_event_op_handler(gsl::not_null<vcpu *> vcpu);
    vmcall_event_op_handler() = default;
    ~vmcall_event_op_handler() = default;
    vmcall_event_op_handler(vmcall_event_op_handler &&) = default;
    vmcall_event_op_handler &operator=(vmcall_event_op_handler &&) = default;
    vmcall_event_op_handler(const vmcall_event_op_handler &) = delete;
    vmcall_event_op_handler &operator=(const vmcall_event_op_handler &) =
        delete;
};

}

#endif
