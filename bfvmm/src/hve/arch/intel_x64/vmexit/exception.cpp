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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vmexit/exception.h>

namespace boxy::intel_x64
{

exception_handler::exception_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    if (vcpu->is_dom0()) {
        return;
    }

    constexpr uint64_t ac_exception{17U};
    constexpr uint64_t mc_exception{18U};

    m_vcpu->add_exception_handler(
        ac_exception, {&exception_handler::handle, this});
    m_vcpu->add_exception_handler(
        mc_exception, {&exception_handler::handle, this});
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
exception_handler::handle(
    vcpu_t *vcpu, bfvmm::intel_x64::exception_handler::info_t &info)
{
    bfignored(vcpu);
    auto parent_vcpu = m_vcpu->parent_vcpu();

    parent_vcpu->load();
    parent_vcpu->inject_exception(info.vector);
    parent_vcpu->return_continue();

    // Unreachable
    return true;
}

}
