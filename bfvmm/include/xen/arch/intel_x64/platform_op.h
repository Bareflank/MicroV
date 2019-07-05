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

#ifndef MICROV_INTEL_X64_PLATFORM_OP_H
#define MICROV_INTEL_X64_PLATFORM_OP_H

#include <public/xen.h>
#include <public/platform.h>

namespace microv::intel_x64 { class vcpu; }

namespace microv::xen::intel_x64 {

class platform_op {
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu of the platform_op
    ///
    platform_op(microv::intel_x64::vcpu *vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~platform_op() = default;

    int get_cpuinfo(struct xenpf_pcpuinfo *info);

private:
    microv::intel_x64::vcpu *m_vcpu{};

public:

    /// @cond

    platform_op(platform_op &&) = default;
    platform_op &operator=(platform_op &&) = default;

    platform_op(const platform_op &) = delete;
    platform_op &operator=(const platform_op &) = delete;

    /// @endcond
};
}
#endif
