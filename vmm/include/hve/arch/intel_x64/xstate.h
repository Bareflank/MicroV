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

#ifndef XSTATE_INTEL_X64_MICROV_H
#define XSTATE_INTEL_X64_MICROV_H

#include <bftypes.h>
#include <memory>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>

namespace microv::intel_x64 {

class vcpu;

class xstate {
public:
    using base_vcpu = bfvmm::intel_x64::vcpu;
    using xsetbv_info = bfvmm::intel_x64::xsetbv_handler::info_t;

    void load();
    void save();
    bool handle_xsetbv(base_vcpu *vcpu, xsetbv_info &info);

    xstate(vcpu *v);
    ~xstate() = default;
    xstate(xstate &&) = default;
    xstate &operator=(xstate &&) = default;
    xstate(const xstate &) = delete;
    xstate &operator=(const xstate &) = delete;

private:
    vcpu *m_vcpu{};
    uint64_t m_xcr0{};
    uint64_t m_rfbm{};
    uint64_t m_size{};
    std::unique_ptr<char[]> m_area{};
};

}
#endif
