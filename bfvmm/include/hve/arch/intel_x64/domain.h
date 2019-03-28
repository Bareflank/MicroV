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

#ifndef DOMAIN_INTEL_X64_BOXY_H
#define DOMAIN_INTEL_X64_BOXY_H

#include <vector>
#include <memory>

#include "uart.h"
#include "../../../domain/domain.h"
#include "../../../domain/domain_manager.h"

#include <bfvmm/hve/arch/intel_x64/vcpu.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

/// Domain
///
class domain : public boxy::domain
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    domain(domainid_type domainid);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~domain() = default;

public:

    /// Map 1g GPA to HPA (Read-Only)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_1g_r(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read-Only)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_2m_r(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read-Only)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_r(uintptr_t gpa, uintptr_t hpa);

    /// Map 1g GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_1g_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_2m_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 1g GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_1g_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_2m_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Unmap GPA
    ///
    /// Unmaps a guest physical address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to unmap
    ///
    void unmap(uintptr_t gpa);

    /// Release Virtual Address
    ///
    /// Returns any unused page tables back to the heap, releasing memory and
    /// providing a means to reconfigure the granularity of a previous mapping.
    ///
    /// @note that unmap must be run for any existing mappings, otherwise this
    ///     function has no effect.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the address to release
    ///
    void release(uintptr_t gpa);

public:

    /// Set UART
    ///
    /// If set, enables the use of an emulated UART that will be created
    /// during the vCPU's construction
    ///
    /// @expects
    /// @ensures
    ///
    /// @param uart the port of the serial device to emulate
    ///
    void set_uart(uart::port_type uart) noexcept;

    /// Set Pass-Through UART
    ///
    /// If set, passes through a UART to the VM during each vCPU's
    /// construction.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param uart the port of the serial device to pass through
    ///
    void set_pt_uart(uart::port_type uart) noexcept;

    /// Setup vCPU UARTs
    ///
    /// Given a vCPU, this function will setup all of the UARTs based
    /// on how the domain have been configured.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vCPU to setup
    ///
    void setup_vcpu_uarts(gsl::not_null<vcpu *> vcpu);

    /// Dump UART
    ///
    /// Dumps the contents of the active UART to a provided buffer. Either
    /// set_uart or set_pt_uart must be executed for this function to
    /// succeed. Once complete, the UART's internal buffer is cleared.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param buffer the buffer to dump the contents of the UART into
    /// @return the number of bytes transferred to the buffer
    ///
    uint64_t dump_uart(const gsl::span<char> &buffer);

public:

    /// Domain Registers
    ///
    /// The domain registers are read/write registers that are used to set
    /// the initial state of a guest vCPU as it is created. Once a vCPU is
    /// created it will use its own internal versions of each of these
    /// registers. Note that dom0 vCPUs do not use these at all.
    ///

    /// @cond

    VIRTUAL uint64_t rax() const noexcept;
    VIRTUAL void set_rax(uint64_t val) noexcept;
    VIRTUAL uint64_t rbx() const noexcept;
    VIRTUAL void set_rbx(uint64_t val) noexcept;
    VIRTUAL uint64_t rcx() const noexcept;
    VIRTUAL void set_rcx(uint64_t val) noexcept;
    VIRTUAL uint64_t rdx() const noexcept;
    VIRTUAL void set_rdx(uint64_t val) noexcept;
    VIRTUAL uint64_t rbp() const noexcept;
    VIRTUAL void set_rbp(uint64_t val) noexcept;
    VIRTUAL uint64_t rsi() const noexcept;
    VIRTUAL void set_rsi(uint64_t val) noexcept;
    VIRTUAL uint64_t rdi() const noexcept;
    VIRTUAL void set_rdi(uint64_t val) noexcept;
    VIRTUAL uint64_t r08() const noexcept;
    VIRTUAL void set_r08(uint64_t val) noexcept;
    VIRTUAL uint64_t r09() const noexcept;
    VIRTUAL void set_r09(uint64_t val) noexcept;
    VIRTUAL uint64_t r10() const noexcept;
    VIRTUAL void set_r10(uint64_t val) noexcept;
    VIRTUAL uint64_t r11() const noexcept;
    VIRTUAL void set_r11(uint64_t val) noexcept;
    VIRTUAL uint64_t r12() const noexcept;
    VIRTUAL void set_r12(uint64_t val) noexcept;
    VIRTUAL uint64_t r13() const noexcept;
    VIRTUAL void set_r13(uint64_t val) noexcept;
    VIRTUAL uint64_t r14() const noexcept;
    VIRTUAL void set_r14(uint64_t val) noexcept;
    VIRTUAL uint64_t r15() const noexcept;
    VIRTUAL void set_r15(uint64_t val) noexcept;
    VIRTUAL uint64_t rip() const noexcept;
    VIRTUAL void set_rip(uint64_t val) noexcept;
    VIRTUAL uint64_t rsp() const noexcept;
    VIRTUAL void set_rsp(uint64_t val) noexcept;
    VIRTUAL uint64_t gdt_base() const noexcept;
    VIRTUAL void set_gdt_base(uint64_t val) noexcept;
    VIRTUAL uint64_t gdt_limit() const noexcept;
    VIRTUAL void set_gdt_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t idt_base() const noexcept;
    VIRTUAL void set_idt_base(uint64_t val) noexcept;
    VIRTUAL uint64_t idt_limit() const noexcept;
    VIRTUAL void set_idt_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t cr0() const noexcept;
    VIRTUAL void set_cr0(uint64_t val) noexcept;
    VIRTUAL uint64_t cr3() const noexcept;
    VIRTUAL void set_cr3(uint64_t val) noexcept;
    VIRTUAL uint64_t cr4() const noexcept;
    VIRTUAL void set_cr4(uint64_t val) noexcept;
    VIRTUAL uint64_t ia32_efer() const noexcept;
    VIRTUAL void set_ia32_efer(uint64_t val) noexcept;
    VIRTUAL uint64_t ia32_pat() const noexcept;
    VIRTUAL void set_ia32_pat(uint64_t val) noexcept;

    VIRTUAL uint64_t es_selector() const noexcept;
    VIRTUAL void set_es_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t es_base() const noexcept;
    VIRTUAL void set_es_base(uint64_t val) noexcept;
    VIRTUAL uint64_t es_limit() const noexcept;
    VIRTUAL void set_es_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t es_access_rights() const noexcept;
    VIRTUAL void set_es_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t cs_selector() const noexcept;
    VIRTUAL void set_cs_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t cs_base() const noexcept;
    VIRTUAL void set_cs_base(uint64_t val) noexcept;
    VIRTUAL uint64_t cs_limit() const noexcept;
    VIRTUAL void set_cs_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t cs_access_rights() const noexcept;
    VIRTUAL void set_cs_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t ss_selector() const noexcept;
    VIRTUAL void set_ss_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t ss_base() const noexcept;
    VIRTUAL void set_ss_base(uint64_t val) noexcept;
    VIRTUAL uint64_t ss_limit() const noexcept;
    VIRTUAL void set_ss_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t ss_access_rights() const noexcept;
    VIRTUAL void set_ss_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t ds_selector() const noexcept;
    VIRTUAL void set_ds_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t ds_base() const noexcept;
    VIRTUAL void set_ds_base(uint64_t val) noexcept;
    VIRTUAL uint64_t ds_limit() const noexcept;
    VIRTUAL void set_ds_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t ds_access_rights() const noexcept;
    VIRTUAL void set_ds_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t fs_selector() const noexcept;
    VIRTUAL void set_fs_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t fs_base() const noexcept;
    VIRTUAL void set_fs_base(uint64_t val) noexcept;
    VIRTUAL uint64_t fs_limit() const noexcept;
    VIRTUAL void set_fs_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t fs_access_rights() const noexcept;
    VIRTUAL void set_fs_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t gs_selector() const noexcept;
    VIRTUAL void set_gs_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t gs_base() const noexcept;
    VIRTUAL void set_gs_base(uint64_t val) noexcept;
    VIRTUAL uint64_t gs_limit() const noexcept;
    VIRTUAL void set_gs_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t gs_access_rights() const noexcept;
    VIRTUAL void set_gs_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t tr_selector() const noexcept;
    VIRTUAL void set_tr_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t tr_base() const noexcept;
    VIRTUAL void set_tr_base(uint64_t val) noexcept;
    VIRTUAL uint64_t tr_limit() const noexcept;
    VIRTUAL void set_tr_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t tr_access_rights() const noexcept;
    VIRTUAL void set_tr_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t ldtr_selector() const noexcept;
    VIRTUAL void set_ldtr_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t ldtr_base() const noexcept;
    VIRTUAL void set_ldtr_base(uint64_t val) noexcept;
    VIRTUAL uint64_t ldtr_limit() const noexcept;
    VIRTUAL void set_ldtr_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t ldtr_access_rights() const noexcept;
    VIRTUAL void set_ldtr_access_rights(uint64_t val) noexcept;

    /// @endcond

public:

    bfvmm::intel_x64::ept::mmap &ept()
    { return m_ept_map; }

    gsl::not_null<bfvmm::intel_x64::vcpu_global_state_t *>
    global_state()
    { return &m_vcpu_global_state; }

private:

    void setup_dom0();
    void setup_domU();

private:

    bfvmm::intel_x64::ept::mmap m_ept_map;
    bfvmm::intel_x64::vcpu_global_state_t m_vcpu_global_state;

    uart::port_type m_uart_port{};
    uart::port_type m_pt_uart_port{};
    uart m_uart_3F8{0x3F8};
    uart m_uart_2F8{0x2F8};
    uart m_uart_3E8{0x3E8};
    uart m_uart_2E8{0x2E8};
    std::unique_ptr<uart> m_pt_uart{};

    uint64_t m_rax{};
    uint64_t m_rbx{};
    uint64_t m_rcx{};
    uint64_t m_rdx{};
    uint64_t m_rbp{};
    uint64_t m_rsi{};
    uint64_t m_rdi{};
    uint64_t m_r08{};
    uint64_t m_r09{};
    uint64_t m_r10{};
    uint64_t m_r11{};
    uint64_t m_r12{};
    uint64_t m_r13{};
    uint64_t m_r14{};
    uint64_t m_r15{};
    uint64_t m_rip{};
    uint64_t m_rsp{};
    uint64_t m_gdt_base{};
    uint64_t m_gdt_limit{};
    uint64_t m_idt_base{};
    uint64_t m_idt_limit{};
    uint64_t m_cr0{};
    uint64_t m_cr3{};
    uint64_t m_cr4{};
    uint64_t m_ia32_efer{};
    uint64_t m_ia32_pat{};

    uint64_t m_es_selector{};
    uint64_t m_es_base{};
    uint64_t m_es_limit{};
    uint64_t m_es_access_rights{};
    uint64_t m_cs_selector{};
    uint64_t m_cs_base{};
    uint64_t m_cs_limit{};
    uint64_t m_cs_access_rights{};
    uint64_t m_ss_selector{};
    uint64_t m_ss_base{};
    uint64_t m_ss_limit{};
    uint64_t m_ss_access_rights{};
    uint64_t m_ds_selector{};
    uint64_t m_ds_base{};
    uint64_t m_ds_limit{};
    uint64_t m_ds_access_rights{};
    uint64_t m_fs_selector{};
    uint64_t m_fs_base{};
    uint64_t m_fs_limit{};
    uint64_t m_fs_access_rights{};
    uint64_t m_gs_selector{};
    uint64_t m_gs_base{};
    uint64_t m_gs_limit{};
    uint64_t m_gs_access_rights{};
    uint64_t m_tr_selector{};
    uint64_t m_tr_base{};
    uint64_t m_tr_limit{};
    uint64_t m_tr_access_rights{};
    uint64_t m_ldtr_selector{};
    uint64_t m_ldtr_base{};
    uint64_t m_ldtr_limit{};
    uint64_t m_ldtr_access_rights{};

public:

    /// @cond

    domain(domain &&) = default;
    domain &operator=(domain &&) = default;

    domain(const domain &) = delete;
    domain &operator=(const domain &) = delete;

    /// @endcond
};

}

/// Get Domain
///
/// Gets a domain from the domain manager given a domain id
///
/// @expects
/// @ensures
///
/// @return returns a pointer to the domain being queried or throws
///     and exception.
///
#define get_domain(a) \
    g_dm->get<boxy::intel_x64::domain *>(a, "invalid domainid: " __FILE__)

#endif
