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

#include <arch/x64/msrs.h>
#include <bfdebug.h>
#include <bfgsl.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/xsave.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace microv::intel_x64 {

xsave::xsave(microv::intel_x64::vcpu *vcpu) :
    m_vcpu{vcpu},
    m_area{make_page<uint8_t>()}
{
    expects(xsave_supported());

    auto sub0 = ::x64::cpuid::get(0xD, 0, 0, 0);
    auto sub1 = ::x64::cpuid::get(0xD, 0, 1, 0);

    m_max_size = xsave_max_size(sub0);
    m_cur_size = xsave_current_size(sub0);

    auto supported_xcr0 = (sub0.rdx << 32) | sub0.rax;
    auto supported_xss = (sub1.rdx << 32) | sub0.rcx;

    static bool print = false;

    if (print) {
        bfdebug_nhex(0, "xsave xcr0", read_xcr0());
        bfdebug_nhex(0, "xsave xinuse", read_xinuse());
        bfdebug_nhex(0, "xsave xcr0 max size", m_max_size);
        bfdebug_nhex(0, "xsave xcr0 current size", m_cur_size);

        bfdebug_nhex(0, "xsave xss", ::x64::msrs::get(0xDA0));
        bfdebug_nhex(0, "xsave xss current size", xsaves_current_size(sub1));

        bfdebug_bool(0, "xsaveopt", xsaveopt_supported(sub1));
        bfdebug_bool(0, "xsavec", xsavec_supported(sub1));
        bfdebug_bool(0, "xinuse", xinuse_supported(sub1));
        bfdebug_bool(0, "xsaves", xsaves_supported(sub1));

        bfdebug_info(0, "XCR0 supported states");
        dump_xsave_bitmap(supported_xcr0);

        bfdebug_info(0, "XSS supported states");
        dump_xsave_bitmap(supported_xss);
        print = 0;
    }

    expects(m_max_size < 4096);
    expects(xsaves_current_size(sub1) < 4096);
    //m_vcpu->state()->guest_xsave_ptr = (uint64_t)m_area.get();
}

}
