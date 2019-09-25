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

#include <bfcallonce.h>
#include <bfvmm/vcpu/vcpu_factory.h>
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <xen/vcpu.h>

namespace bfvmm
{

static bfn::once_flag dom0_init;
static microv::intel_x64::domain *dom0{};

std::unique_ptr<vcpu>
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    using namespace microv::intel_x64;

    bfn::call_once(dom0_init, [&]() {
        microv::domain_info dom0_info{};
        g_dm->create(0, &dom0_info);
        dom0 = get_domain(0);
    });

    if (vcpuid::is_root_vcpu(vcpuid)) {
        return std::make_unique<microv::intel_x64::vcpu>(
                vcpuid,
                dynamic_cast<domain *>(dom0));
    } else {
        return std::make_unique<microv::intel_x64::vcpu>(
                vcpuid,
                dynamic_cast<domain *>(obj));
    }
}

}
