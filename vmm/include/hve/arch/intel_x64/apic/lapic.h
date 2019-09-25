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

#ifndef LAPIC_INTEL_X64_MICROV_H
#define LAPIC_INTEL_X64_MICROV_H

#include <bftypes.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vcpu.h>

namespace microv::intel_x64 {

class vcpu;

class lapic {
private:
    using base_vcpu = ::bfvmm::intel_x64::vcpu;
    using wrmsr_handler = ::bfvmm::intel_x64::wrmsr_handler;

    struct access_ops {
        void (*write)(uintptr_t base, uint32_t reg, uint32_t val);
        void (*write_icr)(uintptr_t base, uint64_t val);
        uint32_t (*read)(uintptr_t base, uint32_t reg);
    };

    vcpu *m_vcpu{};
    uint64_t m_base_msr{};
    uint32_t m_local_id{};
    uint32_t *m_xapic_hva{};
    uintptr_t m_xapic_hpa{};
    uintptr_t m_base_addr{};
    struct access_ops m_ops{};

    void init_xapic();
    void init_x2apic();
    void write(uint32_t reg, uint32_t val);
    void write_icr(uint64_t val);
    uint32_t read(uint32_t reg) const;
    bool emulate_wrmsr_base(base_vcpu *v, wrmsr_handler::info_t &info);

public:

    /* Destination model. Only relevant when dest_mode is logical */
    enum {
        xapic_flat,
        xapic_cluster,
        x2apic_cluster
    };

    /// Constructor
    ///
    /// @expects vcpu->is_dom0()
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    lapic(vcpu *vcpu);

    uint32_t local_id() const;
    uint32_t logical_id() const;
    int dest_model() const;
    bool logical_dest() const;
    bool is_xapic() const;
    bool is_x2apic() const;

    /// @cond

    ~lapic() = default;

    lapic(lapic &&) = default;
    lapic &operator=(lapic &&) = default;

    lapic(const lapic &) = delete;
    lapic &operator=(const lapic &) = delete;

    /// @endcond
};
}

#endif
