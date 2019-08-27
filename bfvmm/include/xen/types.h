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

#ifndef MICROV_XEN_TYPES_H
#define MICROV_XEN_TYPES_H

#include <atomic>
#include <bfhypercall.h>
#include <bfmath.h>
#include <bfobject.h>
#include <bftypes.h>
#include <bfvmm/hve/arch/x64/unmapper.h>
#include <bfvmm/memory_manager/memory_manager.h>

/* Base hypervisor vcpu */
namespace bfvmm::intel_x64 {
    class vcpu;
    class hlt_handler;
    class external_interrupt_handler;
    class wrmsr_handler;
}

/* Microv vcpu and domain */
namespace microv::intel_x64 {
    class domain;
    class vcpu;
}

namespace microv {

class xen_vcpu;
class gnttab;
class evtchn;
class xenver;

using xen_vcpu = microv::xen_vcpu;
using microv_vcpu = microv::intel_x64::vcpu;
using microv_domain = microv::intel_x64::domain;

using base_vcpu = bfvmm::intel_x64::vcpu;
using hlt_handler = bfvmm::intel_x64::hlt_handler;
using interrupt_handler = bfvmm::intel_x64::external_interrupt_handler;
using wrmsr_handler = bfvmm::intel_x64::wrmsr_handler;

template<typename T>
using unique_map = bfvmm::x64::unique_map<T>;

}

#endif
