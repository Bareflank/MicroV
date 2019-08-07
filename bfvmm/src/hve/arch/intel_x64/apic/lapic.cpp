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

#include <arch/intel_x64/apic/lapic.h>
#include <bfvmm/memory_manager/arch/x64/cr3/mmap.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/apic/lapic.h>

namespace microv::intel_x64 {

using namespace ::intel_x64::msrs;
using namespace ::bfvmm::x64;

static constexpr size_t xapic_bytes{4096};
static constexpr uintptr_t x2apic_base{0x800};

/* Register offsets */
static constexpr uint32_t ID_REG = 0x02;
static constexpr uint32_t LDR_REG = 0x0D;
static constexpr uint32_t DFR_REG = 0x0E;
static constexpr uint32_t ICR_REG = 0x30;

/* x2APIC operations */
static uint32_t x2apic_read(uintptr_t base, uint32_t reg)
{
    return gsl::narrow_cast<uint32_t>(::x64::msrs::get(base | reg));
}

static void x2apic_write(uintptr_t base, uint32_t reg, uint32_t val)
{
    ::x64::msrs::set(base | reg, val);
}

static void x2apic_write_icr(uintptr_t base, uint64_t val)
{
    bfignored(base);
    ia32_x2apic_icr::set(val);
}

/* xAPIC operations */
static uint32_t xapic_read(uintptr_t base, uint32_t reg)
{
    return *reinterpret_cast<volatile uint32_t *>(base | (reg << 4));
}

static void xapic_write(uintptr_t base, uint32_t reg, uint32_t val)
{
    *reinterpret_cast<volatile uint32_t *>(base | (reg << 4)) = val;
}

static void xapic_write_icr(uintptr_t base, uint64_t val)
{
    constexpr uintptr_t icr_hi = 0x310;
    constexpr uintptr_t icr_lo = 0x300;

    auto hi_addr = reinterpret_cast<volatile uint32_t *>(base | icr_hi);
    auto lo_addr = reinterpret_cast<volatile uint32_t *>(base | icr_lo);

    *hi_addr = (uint32_t)(val >> 32);
    ::intel_x64::barrier::wmb();
    *lo_addr = (uint32_t)val;
}

/* class implementation */

lapic::lapic(vcpu *vcpu) : m_vcpu{vcpu}
{
    expects(vcpu->is_dom0());

    m_base_msr = ia32_apic_base::get();
    auto state = ia32_apic_base::state::get(m_base_msr);

    switch (state) {
    case ia32_apic_base::state::xapic:
        init_xapic();
        break;
    case ia32_apic_base::state::x2apic:
        init_x2apic();
        break;
    default:
        bferror_nhex(0, "Unsupported lapic state", state);
        throw std::runtime_error("Unsupported lapic state");
    }

    vcpu->emulate_wrmsr(ia32_apic_base::addr,
                        {&lapic::emulate_wrmsr_base, this});

    const auto id = this->read(ID_REG);
    m_local_id = (m_xapic_hva) ? id >> 24 : id;
}

void lapic::init_xapic()
{
    auto msr_hpa = ia32_apic_base::apic_base::get(m_base_msr);
    auto hpa = m_vcpu->gpa_to_hpa(msr_hpa).first;
    ensures(hpa == msr_hpa);

    m_xapic_hpa = hpa;
    m_xapic_hva = reinterpret_cast<uint32_t *>(g_mm->alloc_map(xapic_bytes));

    g_cr3->map_4k(m_xapic_hva,
                  m_xapic_hpa,
                  cr3::mmap::attr_type::read_write,
                  cr3::mmap::memory_type::uncacheable);

    m_base_addr = reinterpret_cast<uintptr_t>(m_xapic_hva);
    m_ops.write = xapic_write;
    m_ops.write_icr = xapic_write_icr;
    m_ops.read = xapic_read;
}

void lapic::init_x2apic()
{
    m_base_addr = x2apic_base;
    m_ops.write = x2apic_write;
    m_ops.write_icr = x2apic_write_icr;
    m_ops.read = x2apic_read;
}

void lapic::write(uint32_t reg, uint32_t val)
{
    m_ops.write(m_base_addr, reg, val);
}

uint32_t lapic::read(uint32_t reg) const
{
    return m_ops.read(m_base_addr, reg);
}

void lapic::write_icr(uint64_t val)
{
    m_ops.write_icr(m_base_addr, val);
}

/*
 * NOTE: this must *not* do an APIC access. MSI mapping code assumes this
 * function does not touch the actual APIC. Instead the ID value that was
 * cached at construction is returned.
 */
uint32_t lapic::local_id() const
{
    return m_local_id;
}

uint32_t lapic::logical_id() const
{
    const auto reg = this->read(LDR_REG);
    return (m_xapic_hva) ? reg >> 24 : reg;
}

int lapic::dest_model() const
{
    expects(this->is_xapic());
    return this->read(DFR_REG) >> 28;
}

bool lapic::logical_dest() const
{
    return (this->read(ICR_REG) >> 11) & 1;
}

bool lapic::is_xapic() const
{
    namespace state = ia32_apic_base::state;
    return state::get(m_base_msr) == state::xapic;
}

bool lapic::is_x2apic() const
{
    namespace state = ia32_apic_base::state;
    return state::get(m_base_msr) == state::x2apic;
}

bool lapic::emulate_wrmsr_base(base_vcpu *v, wrmsr_handler::info_t &info)
{
    namespace base = ia32_apic_base;

    const auto old_state = base::state::get(m_base_msr);
    const auto new_state = base::state::get(info.val);

    const auto old_hpa = m_xapic_hpa;
    const auto new_hpa = base::apic_base::get(info.val);

    switch (new_state) {
    case base::state::x2apic:
        if (old_state == base::state::xapic) {
            g_cr3->unmap(m_xapic_hva);
            g_mm->free_map(m_xapic_hva);
            m_xapic_hva = 0;
            m_xapic_hpa = 0;
            this->init_x2apic();
            m_base_msr = info.val;
            base::set(info.val);
        }
        break;
    case base::state::xapic:
        expects(old_state == base::state::xapic);
        if (old_hpa != new_hpa) {
            m_xapic_hpa = new_hpa;
            g_cr3->unmap(m_xapic_hva);
            g_cr3->map_4k(m_xapic_hva,
                          m_xapic_hpa,
                          cr3::mmap::attr_type::read_write,
                          cr3::mmap::memory_type::uncacheable);
            ::x64::tlb::invlpg(m_xapic_hva);
            m_base_msr = info.val;
            base::set(info.val);
            ensures(m_vcpu->gpa_to_hpa(new_hpa).first == new_hpa);
        }
        break;
    default:
        bferror_nhex(0, "Invalid lapic state", new_state);
        break;
    }

    return true;
}

}
