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

#include <set>
#include <intrinsics.h>

#include <bfgpalayout.h>
#include <hve/arch/intel_x64/vcpu.h>

//------------------------------------------------------------------------------
// Fault Handlers
//------------------------------------------------------------------------------

static bool
rdmsr_handler(vcpu_t *vcpu)
{
    vcpu->halt("rdmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
wrmsr_handler(vcpu_t *vcpu)
{
    vcpu->halt("wrmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
io_instruction_handler(vcpu_t *vcpu)
{
    vcpu->halt("io_instruction_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
ept_violation_handler(vcpu_t *vcpu)
{
    vcpu->halt("ept_violation_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

//------------------------------------------------------------------------------
// Implementation
//------------------------------------------------------------------------------

namespace boxy::intel_x64
{

// TODO:
//
// Remove this and use the bfmanager's foreach and check for domU.
//
std::set<vcpu *> g_domU_vcpus{};

vcpu::vcpu(
    vcpuid::type id,
    gsl::not_null<domain *> domain
) :
    bfvmm::intel_x64::vcpu{id, domain->global_state()},
    m_domain{domain},

    m_external_interrupt_handler{this},
    m_hlt_handler{this},
    m_io_instruction_handler{this},
    m_msr_handler{this},
    m_preemption_timer_handler{this},
    m_vmcall_handler{this},

    m_run_op_handler{this},
    m_domain_op_handler{this},
    m_vcpu_op_handler{this},

    m_cpuid_handler{this},
    m_mtrr_handler{this},
    m_x2apic_handler{this},

    m_vclock_handler{this},
    m_virq_handler{this}
{
    this->set_eptp(domain->ept());

    if (this->is_dom0()) {
        this->write_dom0_guest_state(domain);
    }
    else {
        g_domU_vcpus.insert(this);
        this->write_domU_guest_state(domain);
    }
}

vcpu::~vcpu()
{
    if (this->is_bootstrap_vcpu()) {
        for (const auto &vcpu : g_domU_vcpus) {
            vcpu->clear();
            vcpu->reset_host_wallclock();
        }
    }
}

//------------------------------------------------------------------------------
// Domain Info
//------------------------------------------------------------------------------

bool
vcpu::is_dom0() const noexcept
{ return m_domain->id() == 0; }

bool
vcpu::is_domU() const noexcept
{ return m_domain->id() != 0; }

domain::domainid_type
vcpu::domid() const noexcept
{ return m_domain->id(); }

//------------------------------------------------------------------------------
// VMCall
//------------------------------------------------------------------------------

void
vcpu::add_vmcall_handler(const handler_delegate_t &d)
{ m_vmcall_handler.add_handler(std::move(d)); }

//------------------------------------------------------------------------------
// Hlt
//------------------------------------------------------------------------------

void
vcpu::add_hlt_handler(const handler_delegate_t &d)
{ m_hlt_handler.add_hlt_handler(d); }

void
vcpu::add_yield_handler(const handler_delegate_t &d)
{ m_hlt_handler.add_yield_handler(d); }

//------------------------------------------------------------------------------
// Preemption Timer
//------------------------------------------------------------------------------

void
vcpu::add_preemption_timer_handler(const handler_delegate_t &d)
{ m_preemption_timer_handler.add_handler(d); }

//------------------------------------------------------------------------------
// Parent vCPU
//------------------------------------------------------------------------------

void
vcpu::set_parent_vcpu(gsl::not_null<vcpu *> vcpu)
{ m_parent_vcpu = vcpu; }

vcpu *
vcpu::parent_vcpu() const noexcept
{ return m_parent_vcpu; }

void
vcpu::prepare_for_world_switch()
{ m_msr_handler.isolate_msr__on_world_switch(this); }

void
vcpu::return_fault(uint64_t error)
{
    this->set_rax((error << 4) | hypercall_enum_run_op__fault);
    this->prepare_for_world_switch();
    this->run();
}

void
vcpu::return_continue()
{
    this->set_rax(hypercall_enum_run_op__continue);
    this->prepare_for_world_switch();
    this->run();
}

void
vcpu::return_yield(uint64_t nsec)
{
    this->set_rax((nsec << 4) | hypercall_enum_run_op__yield);
    this->prepare_for_world_switch();
    this->run();
}

void
vcpu::return_set_wallclock()
{
    this->set_rax(hypercall_enum_run_op__set_wallclock);
    this->prepare_for_world_switch();
    this->run();
}

//------------------------------------------------------------------------------
// Control
//------------------------------------------------------------------------------

void
vcpu::kill() noexcept
{ m_killed = true; }

bool
vcpu::is_alive() const noexcept
{ return !m_killed; }

bool
vcpu::is_killed() const noexcept
{ return m_killed; }

//------------------------------------------------------------------------------
// Virtual IRQs
//------------------------------------------------------------------------------

void
vcpu::queue_virtual_interrupt(uint64_t vector)
{ m_virq_handler.queue_virtual_interrupt(vector); }

void
vcpu::inject_virtual_interrupt(uint64_t vector)
{ m_virq_handler.inject_virtual_interrupt(vector); }

//------------------------------------------------------------------------------
// Virtual Clock
//------------------------------------------------------------------------------

void
vcpu::set_host_wallclock_rtc(uint64_t sec, uint64_t nsec) noexcept
{ m_vclock_handler.set_host_wallclock_rtc(sec, nsec); }

void
vcpu::set_host_wallclock_tsc(uint64_t val) noexcept
{ m_vclock_handler.set_host_wallclock_tsc(val); }

void
vcpu::reset_host_wallclock(void) noexcept
{ m_vclock_handler.reset_host_wallclock(); }

std::pair<struct timespec, uint64_t>
vcpu::get_host_wallclock() const
{ return m_vclock_handler.get_host_wallclock(); }

//------------------------------------------------------------------------------
// Fault
//------------------------------------------------------------------------------

void
vcpu::halt(const std::string &str)
{
    this->dump(("halting vcpu: " + str).c_str());

    if (auto parent_vcpu = this->parent_vcpu()) {

        bferror_lnbr(0);
        bferror_info(0, "child vcpu being killed");
        bferror_lnbr(0);

        try {
            parent_vcpu->load();
            parent_vcpu->return_fault();
        }
        catch (...) {
            bferror_info(0, "attempt to kill child failed!!!");
            ::x64::pm::stop();
        }
    }
    else {
        ::x64::pm::stop();
    }
}

//------------------------------------------------------------------------------
// Setup Functions
//------------------------------------------------------------------------------

void
vcpu::write_dom0_guest_state(domain *domain)
{ bfignored(domain); }

void
vcpu::write_domU_guest_state(domain *domain)
{
    this->setup_default_register_state();
    this->setup_default_controls();
    this->setup_default_handlers();

    domain->setup_vcpu_uarts(this);
}

void
vcpu::setup_default_register_state()
{
    using namespace vmcs_n;

    this->set_rax(m_domain->rax());
    this->set_rbx(m_domain->rbx());
    this->set_rcx(m_domain->rcx());
    this->set_rdx(m_domain->rdx());
    this->set_rbp(m_domain->rbp());
    this->set_rsi(m_domain->rsi());
    this->set_rdi(m_domain->rdi());
    this->set_r08(m_domain->r08());
    this->set_r09(m_domain->r09());
    this->set_r10(m_domain->r10());
    this->set_r11(m_domain->r11());
    this->set_r12(m_domain->r12());
    this->set_r13(m_domain->r13());
    this->set_r14(m_domain->r14());
    this->set_r15(m_domain->r15());
    this->set_rip(m_domain->rip());
    this->set_rsp(m_domain->rsp());
    this->set_gdt_base(m_domain->gdt_base());
    this->set_gdt_limit(m_domain->gdt_limit());
    this->set_idt_base(m_domain->idt_base());
    this->set_idt_limit(m_domain->idt_limit());
    this->set_cr0(m_domain->cr0());
    this->set_cr3(m_domain->cr3());
    this->set_cr4(m_domain->cr4());
    this->set_ia32_efer(m_domain->ia32_efer());
    this->set_ia32_pat(m_domain->ia32_pat());

    this->set_es_selector(m_domain->es_selector());
    this->set_es_base(m_domain->es_base());
    this->set_es_limit(m_domain->es_limit());
    this->set_es_access_rights(m_domain->es_access_rights());
    this->set_cs_selector(m_domain->cs_selector());
    this->set_cs_base(m_domain->cs_base());
    this->set_cs_limit(m_domain->cs_limit());
    this->set_cs_access_rights(m_domain->cs_access_rights());
    this->set_ss_selector(m_domain->ss_selector());
    this->set_ss_base(m_domain->ss_base());
    this->set_ss_limit(m_domain->ss_limit());
    this->set_ss_access_rights(m_domain->ss_access_rights());
    this->set_ds_selector(m_domain->ds_selector());
    this->set_ds_base(m_domain->ds_base());
    this->set_ds_limit(m_domain->ds_limit());
    this->set_ds_access_rights(m_domain->ds_access_rights());
    this->set_fs_selector(m_domain->fs_selector());
    this->set_fs_base(m_domain->fs_base());
    this->set_fs_limit(m_domain->fs_limit());
    this->set_fs_access_rights(m_domain->fs_access_rights());
    this->set_gs_selector(m_domain->gs_selector());
    this->set_gs_base(m_domain->gs_base());
    this->set_gs_limit(m_domain->gs_limit());
    this->set_gs_access_rights(m_domain->gs_access_rights());
    this->set_tr_selector(m_domain->tr_selector());
    this->set_tr_base(m_domain->tr_base());
    this->set_tr_limit(m_domain->tr_limit());
    this->set_tr_access_rights(m_domain->tr_access_rights());
    this->set_ldtr_selector(m_domain->ldtr_selector());
    this->set_ldtr_base(m_domain->ldtr_base());
    this->set_ldtr_limit(m_domain->ldtr_limit());
    this->set_ldtr_access_rights(m_domain->ldtr_access_rights());

    guest_rflags::set(2);
    vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFF);
}

void
vcpu::setup_default_controls()
{
    using namespace vmcs_n;
    using namespace vm_entry_controls;

    if (guest_ia32_efer::lme::is_disabled()) {
        ia_32e_mode_guest::disable();
    }

    using namespace primary_processor_based_vm_execution_controls;
    hlt_exiting::enable();
    mwait_exiting::enable();
    rdpmc_exiting::enable();
    monitor_exiting::enable();
    use_tsc_offsetting::enable();

    using namespace secondary_processor_based_vm_execution_controls;
    enable_invpcid::disable();
    enable_xsaves_xrstors::disable();
}

void
vcpu::setup_default_handlers()
{
    this->add_default_wrmsr_handler(::wrmsr_handler);
    this->add_default_rdmsr_handler(::rdmsr_handler);
    this->add_default_io_instruction_handler(::io_instruction_handler);
    this->add_default_ept_read_violation_handler(::ept_violation_handler);
    this->add_default_ept_write_violation_handler(::ept_violation_handler);
    this->add_default_ept_execute_violation_handler(::ept_violation_handler);
}

}
