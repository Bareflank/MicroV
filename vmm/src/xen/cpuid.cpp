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

#include <mutex>
#include <arch/x64/cpuid.h>
#include <bfcallonce.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <public/arch-x86/cpuid.h>
#include <xen/cpuid.h>

namespace microv {

static bfn::once_flag cpufeat_init{};
static uint32_t vmm_features[xen_cpufeat_words]{};
static uint32_t pvh_features[xen_cpufeat_words]{};

static void init_vmm_cpufeatures() noexcept
{
    /* Only Intel features are initialzed right now*/
    auto leaf1 = ::x64::cpuid::get(1);
    auto leaf7 = ::x64::cpuid::get(0x7);

    vmm_features[0] = (uint32_t)leaf1.rdx;
    vmm_features[1] = (uint32_t)leaf1.rcx;
    vmm_features[4] = (uint32_t)(::x64::cpuid::get(0xD, 1).rax);
    vmm_features[5] = (uint32_t)(leaf7.rbx);
    vmm_features[6] = (uint32_t)(leaf7.rcx);
    vmm_features[9] = (uint32_t)(leaf7.rdx);
    vmm_features[10] = (uint32_t)(::x64::cpuid::get(0x7, 1).rax);

    /* AMD */
    vmm_features[2] = 0;
    vmm_features[3] = 0;
    vmm_features[7] = 0;
    vmm_features[8] = 0;
}

static void init_pvh_cpufeatures() noexcept
{
    for (auto i = 0; i < xen_cpufeat_words; i++) {
        pvh_features[i] = vmm_features[i];
    }

    /* See bfvmm/src/hve/arch/intel_x64/vmexit/cpuid.cpp for mask values */
    pvh_features[0] &= 0x1FCBFBFB;

    pvh_features[1] &= 0x21FC3203;
    pvh_features[1] |= (1UL << 26); /* enable xsave */
    pvh_features[1] |= (1UL << 28); /* enable AVX */
    pvh_features[1] |= (1UL << 31); /* tell the guest it's in a VM */

    pvh_features[5] &= 0x019D23F9;
    pvh_features[6] = 0;
    pvh_features[9] = 0;
    pvh_features[10] = 0;
}

void xen_init_cpufeatures() noexcept
{
    bfn::call_once(cpufeat_init, [&]() {
        init_vmm_cpufeatures();
        init_pvh_cpufeatures();
    });
}

void xen_get_pvh_cpufeatures(uint32_t cpufeat[xen_cpufeat_words]) noexcept
{
    for (auto i = 0; i < xen_cpufeat_words; i++) {
        cpufeat[i] = pvh_features[i];
    }
}

/* Generic xen cpuid leaf handling */

bool xen_leaf0(base_vcpu *vcpu)
{
    vcpu->set_rax(xen_leaf(5));
    vcpu->set_rbx(XEN_CPUID_SIGNATURE_EBX);
    vcpu->set_rcx(XEN_CPUID_SIGNATURE_ECX);
    vcpu->set_rdx(XEN_CPUID_SIGNATURE_EDX);

    vcpu->advance();
    return true;
}

bool xen_leaf1(base_vcpu *vcpu)
{
    vcpu->set_rax(0x0004000D);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    vcpu->advance();
    return true;
}

bool xen_leaf2(base_vcpu *vcpu)
{
    vcpu->set_rax(1);
    vcpu->set_rbx(xen_hypercall_page_msr);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    vcpu->advance();
    return true;
}

}
