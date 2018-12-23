//
// Copyright (C) 2018 Assured Information Security, Inc.
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

#include <intrinsics.h>

#include <bfgpalayout.h>
#include <hve/arch/intel_x64/vcpu.h>

//------------------------------------------------------------------------------
// Fault Handlers
//------------------------------------------------------------------------------

static bool
cpuid_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("cpuid_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
rdmsr_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("rdmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("wrmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
io_instruction_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("io_instruction_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
ept_violation_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("ept_violation_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

//------------------------------------------------------------------------------
// Implementation
//------------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

vcpu::vcpu(
    vcpuid::type id,
    gsl::not_null<domain *> domain
) :
    eapis::intel_x64::vcpu{
    id, domain->global_state()
},

    m_domain{domain},

    m_external_interrupt_handler{this},
    m_vmcall_handler{this},

    m_vmcall_domain_op_handler{this},
    m_vmcall_run_op_handler{this},
    m_vmcall_vcpu_op_handler{this}
{
    if (this->is_dom0()) {
        this->write_dom0_guest_state(domain);
    }
    else {
        this->write_domU_guest_state(domain);
    }
}

//------------------------------------------------------------------------------
// Setup
//------------------------------------------------------------------------------

void
vcpu::write_dom0_guest_state(domain *domain)
{
    this->set_eptp(domain->ept());
}

void
vcpu::write_domU_guest_state(domain *domain)
{
    this->set_eptp(domain->ept());

    // using namespace ::intel_x64;
    // using namespace ::intel_x64::vmcs;
    // using namespace ::intel_x64::cpuid;

    // using namespace ::x64::access_rights;
    // using namespace ::x64::segment_register;

    // uint64_t cr0 = guest_cr0::get();
    // cr0 |= cr0::protection_enable::mask;
    // cr0 |= cr0::monitor_coprocessor::mask;
    // cr0 |= cr0::extension_type::mask;
    // cr0 |= cr0::numeric_error::mask;
    // cr0 |= cr0::write_protect::mask;

    // uint64_t cr4 = guest_cr4::get();
    // cr4 |= cr4::vmx_enable_bit::mask;

    // guest_cr0::set(cr0);
    // guest_cr4::set(cr4);

    // vm_entry_controls::ia_32e_mode_guest::disable();

    // unsigned es_index = 3;
    // unsigned cs_index = 2;
    // unsigned ss_index = 3;
    // unsigned ds_index = 3;
    // unsigned fs_index = 3;
    // unsigned gs_index = 3;
    // unsigned tr_index = 4;

    // guest_es_selector::set(es_index << 3);
    // guest_cs_selector::set(cs_index << 3);
    // guest_ss_selector::set(ss_index << 3);
    // guest_ds_selector::set(ds_index << 3);
    // guest_fs_selector::set(fs_index << 3);
    // guest_gs_selector::set(gs_index << 3);
    // guest_tr_selector::set(tr_index << 3);

    // guest_es_limit::set(domain->gdt()->limit(es_index));
    // guest_cs_limit::set(domain->gdt()->limit(cs_index));
    // guest_ss_limit::set(domain->gdt()->limit(ss_index));
    // guest_ds_limit::set(domain->gdt()->limit(ds_index));
    // guest_fs_limit::set(domain->gdt()->limit(fs_index));
    // guest_gs_limit::set(domain->gdt()->limit(gs_index));
    // guest_tr_limit::set(domain->gdt()->limit(tr_index));

    // guest_es_access_rights::set(domain->gdt()->access_rights(es_index));
    // guest_cs_access_rights::set(domain->gdt()->access_rights(cs_index));
    // guest_ss_access_rights::set(domain->gdt()->access_rights(ss_index));
    // guest_ds_access_rights::set(domain->gdt()->access_rights(ds_index));
    // guest_fs_access_rights::set(domain->gdt()->access_rights(fs_index));
    // guest_gs_access_rights::set(domain->gdt()->access_rights(gs_index));
    // guest_tr_access_rights::set(domain->gdt()->access_rights(tr_index));

    // guest_ldtr_access_rights::set(guest_ldtr_access_rights::unusable::mask);

    // guest_es_base::set(domain->gdt()->base(es_index));
    // guest_cs_base::set(domain->gdt()->base(cs_index));
    // guest_ss_base::set(domain->gdt()->base(ss_index));
    // guest_ds_base::set(domain->gdt()->base(ds_index));
    // guest_fs_base::set(domain->gdt()->base(fs_index));
    // guest_gs_base::set(domain->gdt()->base(gs_index));
    // guest_tr_base::set(domain->gdt()->base(tr_index));

    // guest_rflags::set(2);
    // vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFF);

    // // m_lapic.init();
    // // m_ioapic.init();

    // using namespace primary_processor_based_vm_execution_controls;
    // hlt_exiting::enable();
    // rdpmc_exiting::enable();

    // using namespace secondary_processor_based_vm_execution_controls;
    // enable_invpcid::disable();
    // enable_xsaves_xrstors::disable();

    // this->set_rip(domain->entry());
    // this->set_rbx(XEN_START_INFO_PAGE_GPA);

    // this->add_default_cpuid_handler(
    //     ::handler_delegate_t::create<cpuid_handler>()
    // );

    // this->add_default_wrmsr_handler(
    //     ::handler_delegate_t::create<wrmsr_handler>()
    // );

    // this->add_default_rdmsr_handler(
    //     ::handler_delegate_t::create<rdmsr_handler>()
    // );

    // this->add_default_io_instruction_handler(
    //     ::handler_delegate_t::create<io_instruction_handler>()
    // );

    // this->add_default_ept_read_violation_handler(
    //     ::handler_delegate_t::create<ept_violation_handler>()
    // );

    // this->add_default_ept_write_violation_handler(
    //     ::handler_delegate_t::create<ept_violation_handler>()
    // );

    // this->add_default_ept_execute_violation_handler(
    //     ::handler_delegate_t::create<ept_violation_handler>()
    // );
}

//------------------------------------------------------------------------------
// Domain Info
//------------------------------------------------------------------------------

bool
vcpu::is_dom0() const
{ return m_domain->id() == 0; }

bool
vcpu::is_domU() const
{ return m_domain->id() != 0; }

domain::domainid_type
vcpu::domid() const
{ return m_domain->id(); }

//------------------------------------------------------------------------------
// VMCall
//------------------------------------------------------------------------------

gsl::not_null<vmcall_handler *>
vcpu::vmcall()
{ return &m_vmcall_handler; }

void
vcpu::add_vmcall_handler(
    const vmcall_handler::handler_delegate_t &d)
{ m_vmcall_handler.add_handler(std::move(d)); }

//------------------------------------------------------------------------------
// Parent vCPU
//------------------------------------------------------------------------------

void
vcpu::set_parent_vcpu(gsl::not_null<vcpu *> vcpu)
{ m_parent_vcpu = vcpu; }

vcpu *
vcpu::parent_vcpu() const
{ return m_parent_vcpu; }

void
vcpu::return_hlt()
{
    this->set_rax(__enum_run_op__hlt);
    this->run(&world_switch);
}

void
vcpu::return_fault(uint64_t error)
{
    this->set_rax((error << 4) | __enum_run_op__fault);
    this->run(&world_switch);
}

void
vcpu::return_resume_after_interrupt()
{
    this->set_rax(__enum_run_op__resume_after_interrupt);
    this->run(&world_switch);
}

void
vcpu::return_yield(uint64_t usec)
{
    this->set_rax((usec << 4) | __enum_run_op__yield);
    this->run(&world_switch);
}

//------------------------------------------------------------------------------
// Control
//------------------------------------------------------------------------------

bool
vcpu::is_alive() const
{ return !m_killed; }

bool
vcpu::is_killed() const
{ return m_killed; }

void
vcpu::kill()
{ m_killed = true; }


//------------------------------------------------------------------------------
// APIC
//------------------------------------------------------------------------------

// uint32_t
// vcpu::lapicid() const
// { return m_lapic.id(); }

// uint64_t
// vcpu::lapic_base() const
// { return m_lapic.base(); }

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

        parent_vcpu->load();
        parent_vcpu->return_fault();
    }
    else {
        ::x64::pm::stop();
    }
}

}
