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

#include <intrinsics.h>

#include <acpi.h>
#include <bfcallonce.h>
#include <bfexports.h>
#include <microv/gpalayout.h>
#include <microv/builderinterface.h>
#include <clflush.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <iommu/iommu.h>
#include <pci/dev.h>
#include <pci/pci.h>
#include <printv.h>
#include <xen/platform_pci.h>
#include <xen/vcpu.h>
#include <xue.h>

microv::intel_x64::vcpu *vcpu0{nullptr};

extern struct xue g_xue;
extern struct xue_ops g_xue_ops;

void WEAK_SYM vcpu_init_root(bfvmm::intel_x64::vcpu *vcpu);

static bfn::once_flag acpi_ready;
static bfn::once_flag vtd_ready;
static bfn::once_flag pci_ready;

//------------------------------------------------------------------------------
// Default Handlers/Emulators
//------------------------------------------------------------------------------

static bool cpuid_zeros_emulator(vcpu_t *vcpu)
{
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    return vcpu->advance();
}

static bool rdmsr_handler(vcpu_t *vcpu)
{
    vcpu->halt("rdmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool wrmsr_handler(vcpu_t *vcpu)
{
    vcpu->halt("wrmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool io_instruction_handler(vcpu_t *vcpu)
{
    vcpu->halt("io_instruction_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool ept_violation_handler(vcpu_t *vcpu)
{
    vcpu->halt("ept_violation_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static std::mutex root_ept_mtx;

static bool handle_root_ept_violation(
    vcpu_t *vcpu,
    bfvmm::intel_x64::ept_violation_handler::info_t &info)
{

    auto qual = info.exit_qualification;

    switch (qual & 0x7) {
    case 1:
        printv("ALERT: EPT read  qual:0x%lx gva:0x%lx gpa:0x%lx ",
               qual, info.gva, info.gpa);
        break;
    case 2:
        printv("ALERT: EPT write qual:0x%lx gva:0x%lx gpa:0x%lx ",
               qual, info.gva, info.gpa);
        break;
    case 4:
        printv("ALERT: EPT exec  qual:0x%lx gva:0x%lx gpa:0x%lx ",
               qual, info.gva, info.gpa);
        break;
    default:
        printv("ERROR: EPT unexpected qual:0x%lx gva:0x%lx gpa:0x%lx\n",
               qual, info.gva, info.gpa);
        return false;
    }

    auto dom = vcpu_cast(vcpu)->dom();
    auto ept = &dom->ept();

    std::lock_guard lock(root_ept_mtx);

    try {
        auto entry_pair = ept->entry(info.gpa);
        auto entry = &entry_pair.first.get();
        auto from = entry_pair.second;

        printv("(mapped from:%lu) entry:0x%lx\n", from, *entry);

        *entry |= 0x7;
        ::intel_x64::wmb();
        vcpu->invept();
        info.ignore_advance = true;

    } catch (std::runtime_error &e) {
        using namespace ::bfvmm::intel_x64::ept;

        printv("(not mapped, e.what=%s)\n", e.what());

        auto gpa_2m = bfn::upper(info.gpa, 21);

        identity_map(*ept, gpa_2m, gpa_2m + (1 << 21));
        ::intel_x64::wmb();
        vcpu->invept();
        info.ignore_advance = true;

    } catch (std::exception &e) {
        printv("(non-runtime_error caught: e.what=%s)\n", e.what());
        info.ignore_advance = false;
    }

    return true;
}

//------------------------------------------------------------------------------
// Implementation
//------------------------------------------------------------------------------

namespace microv::intel_x64
{

bool vcpu::handle_rdcr8(vcpu_t *vcpu)
{
    vcpu->set_gr1(m_cr8);
    emulate_wrgpr(vcpu);

    return true;
}

bool vcpu::handle_wrcr8(vcpu_t *vcpu)
{
    emulate_rdgpr(vcpu);
    m_cr8 = vcpu->gr1();

    bfalert_nhex(0, "guest wrote to CR8", m_cr8);

    /*
     * Linux doesn't really use CR8. If a guest ever does, then we will need
     * to incorporate the changes to CR8 into the interrupt injection logic to
     * ensure that priorities are being respected. Right now it isn't an issue
     * because the value is one of the two below, which is well below any
     * vector that we will be injecting.
     */

    if (m_cr8 != 0 && m_cr8 != 1) {
        return false;
    }

    return true;
}

vcpu::vcpu(
    vcpuid::type id,
    gsl::not_null<domain *> domain
) :
    bfvmm::intel_x64::vcpu{id, domain->global_state()},
    m_domain{domain},

    m_cpuid_handler{this},
    m_external_interrupt_handler{this},
    m_io_instruction_handler{this},
    m_msr_handler{this},
    m_mtrr_handler{this},
    m_vmcall_handler{this},
    m_yield_handler{this},

    m_vmcall_run_op_handler{this},
    m_vmcall_domain_op_handler{this},
    m_vmcall_event_op_handler{this},
    m_vmcall_iommu_op_handler{this},
    m_vmcall_vcpu_op_handler{this},
    m_vmcall_xue_op_handler{this},
    m_vmcall_xenpfd_op_handler{this},

    m_x2apic_handler{this},
    m_pci_handler{this}
{
    domain->add_vcpu(id);
    this->set_eptp(domain->ept());

    if (this->is_dom0()) {
        nr_root_vcpus++;

        if (vcpu0 == nullptr) {
            vcpu0 = this;
            init_cache_ops();
        }

        this->write_dom0_guest_state(domain);

        this->add_ept_read_violation_handler({handle_root_ept_violation});
        this->add_ept_write_violation_handler({handle_root_ept_violation});
        this->add_ept_execute_violation_handler({handle_root_ept_violation});
    }
    else {
        this->write_domU_guest_state(domain);

        this->init_xstate();
        this->add_rdcr8_handler({&vcpu::handle_rdcr8, this});
        this->add_wrcr8_handler({&vcpu::handle_wrcr8, this});
    }

    this->add_cpuid_emulator(0x4BF00010, {&vcpu::handle_0x4BF00010, this});
    this->add_cpuid_emulator(0x4BF00021, {&vcpu::handle_0x4BF00021, this});
}

//------------------------------------------------------------------------------
// Setup
//------------------------------------------------------------------------------

static inline void trap_exceptions()
{
    /* Only used for guest debugging of invalid opcodes */
    ::intel_x64::vmcs::exception_bitmap::set(1UL << 6);
}

void
vcpu::write_dom0_guest_state(domain *domain)
{
    if (domain->exec_mode() == VM_EXEC_XENPVH) {
        m_xen_vcpu = std::make_unique<class xen_vcpu>(this);

        if (g_enable_winpv) {
            init_xen_platform_pci(m_xen_vcpu.get());
        }
    }
}

void
vcpu::write_domU_guest_state(domain *domain)
{
    this->setup_default_register_state();
    this->setup_default_controls();
    this->setup_default_handlers();

    domain->setup_vcpu_uarts(this);

    if (domain->exec_mode() == VM_EXEC_XENPVH) {
        using namespace vmcs_n::secondary_processor_based_vm_execution_controls;

        enable_rdtscp::enable();
        trap_exceptions();

        bfdebug_bool(0, "domain is_xsvm:", domain->is_xsvm());
        bfdebug_bool(0, "domain is_ndvm:", domain->is_ndvm());

        if (domain->is_xsvm() || domain->is_ndvm()) {
            init_pci_on_vcpu(this);
        }

        m_xen_vcpu = std::make_unique<class xen_vcpu>(this);
    }
}

microv::xen_vcpu *vcpu::xen_vcpu() noexcept
{
    return m_xen_vcpu.get();
}

void vcpu::add_child_vcpu(vcpuid_t child_id)
{
    vcpu *child{};

    try {
        expects(this->is_dom0());
        expects(vcpuid::is_guest_vcpu(child_id));
        expects(m_child_vcpus.count(child_id) == 0);

        child = get_vcpu(child_id);
        expects(child);

        m_child_vcpus[child_id] = child;
        ensures(m_child_vcpus.count(child_id) == 1);
    } catch (...) {
        if (child) {
            put_vcpu(child_id);
        }
        throw;
    }
}

vcpu *vcpu::find_child_vcpu(vcpuid_t child_id)
{
    auto itr = m_child_vcpus.find(child_id);
    if (itr != m_child_vcpus.end()) {
        return itr->second;
    } else {
        return nullptr;
    }
}

void vcpu::remove_child_vcpu(vcpuid_t child_id)
{
    if (m_child_vcpus.count(child_id) == 1) {
        put_vcpu(child_id);
        m_child_vcpus.erase(child_id);
    }
}

void vcpu::add_child_domain(domainid_t child_id)
{
    domain *child{};

    try {
        expects(this->is_dom0());
        expects(m_child_doms.count(child_id) == 0);

        child = get_domain(child_id);
        expects(child);

        m_child_doms[child_id] = child;
        ensures(m_child_doms.count(child_id) == 1);
    } catch (...) {
        if (child) {
            put_domain(child_id);
        }
        throw;
    }
}

domain *vcpu::find_child_domain(domainid_t child_id)
{
    auto itr = m_child_doms.find(child_id);
    if (itr != m_child_doms.end()) {
        return itr->second;
    } else {
        return nullptr;
    }
}

void vcpu::remove_child_domain(domainid_t child_id)
{
    if (m_child_doms.count(child_id) == 1) {
        put_domain(child_id);
        m_child_doms.erase(child_id);
    }
}

bool vcpu::handle_0x4BF00010(bfvmm::intel_x64::vcpu *vcpu)
{
#ifdef USE_XUE
    if (g_enable_xue) {
        if (vcpu->id() == 0 && g_xue.sysid == xue_sysid_windows) {
            xue_open(&g_xue, &g_xue_ops, NULL);
        }
    }
#endif

    m_lapic = std::make_unique<lapic>(this);

    if (g_uefi_boot) {
        /* Order matters with these init functions */
        bfn::call_once(acpi_ready, []{ init_acpi(); });
        bfn::call_once(pci_ready, []{ init_pci(); });

        if (pci_passthru) {
            bfn::call_once(vtd_ready, []{ init_vtd(); });
            m_pci_handler.enable();
            init_pci_on_vcpu(this);
        }
    }

    vcpu_init_root(vcpu);
    return vcpu->advance();
}

bool vcpu::handle_0x4BF00021(bfvmm::intel_x64::vcpu *vcpu)
{
    bfdebug_info(0, "host os is" bfcolor_red " not " bfcolor_end "in a vm");

#ifdef USE_XUE
    if (g_enable_xue) {
        if (vcpu->id() == 0 && g_xue.sysid == xue_sysid_windows) {
            xue_close(&g_xue);
        }
    }
#endif

    vcpu->promote();
    throw std::runtime_error("promote failed");
}

void vcpu::write_ipi(uint64_t vector)
{
    m_lapic->write_ipi(vector, this->id());
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

domain::id_t
vcpu::domid() const
{ return m_domain->id(); }

//------------------------------------------------------------------------------
// VMCall
//------------------------------------------------------------------------------

void
vcpu::add_vmcall_handler(
    const vmcall_handler::handler_delegate_t &d)
{ m_vmcall_handler.add_handler(std::move(d)); }

//------------------------------------------------------------------------------
// root vCPU
//------------------------------------------------------------------------------

void
vcpu::set_root_vcpu(gsl::not_null<vcpu *> vcpu)
{ m_root_vcpu = vcpu; }

vcpu *
vcpu::root_vcpu() const
{ return m_root_vcpu; }

void
vcpu::return_hlt()
{
    this->load_xstate();
    this->set_rax(__enum_run_op__hlt);
    this->run(&world_switch);
}

void
vcpu::return_create_domain(uint64_t newdomid)
{
    this->add_child_domain(newdomid);
    this->load_xstate();
    this->set_rax((newdomid << 4) | __enum_run_op__create_domain);
    this->run(&world_switch);
}

void
vcpu::return_pause_domain(uint64_t domid)
{
    this->load_xstate();
    this->set_rax((domid << 4) | __enum_run_op__pause_domain);
    this->run(&world_switch);
}

void
vcpu::return_unpause_domain(uint64_t domid)
{
    this->load_xstate();
    this->set_rax((domid << 4) | __enum_run_op__unpause_domain);
    this->run(&world_switch);
}

void
vcpu::return_destroy_domain(uint64_t domid)
{
    this->load_xstate();
    this->set_rax((domid << 4) | __enum_run_op__destroy_domain);
    this->run(&world_switch);
}

void
vcpu::return_fault(uint64_t error)
{
    this->load_xstate();
    this->set_rax((error << 4) | __enum_run_op__fault);
    this->run(&world_switch);
}

void
vcpu::return_interrupted()
{
    this->load_xstate();
    this->set_rax(__enum_run_op__interrupted);
    this->run(&world_switch);
}

void
vcpu::return_yield(uint64_t usec)
{
    this->load_xstate();
    this->set_rax((usec << 4) | __enum_run_op__yield);
    this->run(&world_switch);
}

//------------------------------------------------------------------------------
// Halt
//------------------------------------------------------------------------------

void
vcpu::halt(const std::string &str)
{
    this->dump(("halting vcpu: " + str).c_str());

    if (auto root_vcpu = this->root_vcpu()) {

        bferror_lnbr(0);
        bferror_info(0, "child vcpu being killed");
        bferror_lnbr(0);

        this->save_xstate();

        root_vcpu->load();
        root_vcpu->return_fault();
    }
    else {
        ::x64::pm::stop();
    }
}

//------------------------------------------------------------------------------
// APIC
//------------------------------------------------------------------------------

uint8_t
vcpu::apic_timer_vector()
{ return m_x2apic_handler.timer_vector(); }

//------------------------------------------------------------------------------
// Setup Functions
//------------------------------------------------------------------------------
void vcpu::set_xenstore_ready() noexcept
{
    m_domain->m_xenstore_ready = 1;
}

uint64_t vcpu::is_xenstore_ready() noexcept
{
    return m_domain->m_xenstore_ready;
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

    using namespace secondary_processor_based_vm_execution_controls;
    enable_invpcid::disable();
    enable_xsaves_xrstors::enable();
    rdrand_exiting::disable();
    rdseed_exiting::disable();
}

void
vcpu::setup_default_handlers()
{
    this->add_default_cpuid_emulator(::cpuid_zeros_emulator);
    this->add_default_wrmsr_handler(::wrmsr_handler);
    this->add_default_rdmsr_handler(::rdmsr_handler);
    this->add_default_io_instruction_handler(::io_instruction_handler);
    this->add_default_ept_read_violation_handler(::ept_violation_handler);
    this->add_default_ept_write_violation_handler(::ept_violation_handler);
    this->add_default_ept_execute_violation_handler(::ept_violation_handler);
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

    guest_dr7::set(0x400);
    guest_ia32_debugctl::set(0);
    guest_ia32_sysenter_cs::set(0);
    guest_ia32_sysenter_esp::set(0);
    guest_ia32_sysenter_eip::set(0);
}

void vcpu::init_xstate()
{
    m_xstate = std::make_unique<xstate>(this);
}

void vcpu::save_xstate()
{
    m_xstate->save();
}

void vcpu::load_xstate()
{
    m_xstate->load();
}

void vcpu::add_pci_cfg_handler(uint64_t cfg_addr,
                               const pci_cfg_handler::delegate_t &d,
                               int direction)
{
    if (direction == pci_dir_in) {
        m_pci_handler.add_in_handler(cfg_addr, d);
        return;
    }

    m_pci_handler.add_out_handler(cfg_addr, d);
}

void vcpu::add_pci_cfg_handler(uint32_t bus,
                               uint32_t dev,
                               uint32_t fun,
                               const pci_cfg_handler::delegate_t &d,
                               int direction)
{
    auto addr = pci_cfg_bdf_to_addr(bus, dev, fun);
    this->add_pci_cfg_handler(addr, d, direction);
}

uint64_t vcpu::pcpuid()
{
    if (this->is_dom0()) {
        return this->id();
    } else {
        expects(m_root_vcpu);
        expects(m_root_vcpu->is_dom0());
        return m_root_vcpu->id();
    }
}

/* Caller must hold lock on pdev->m_msi_mtx */
void vcpu::map_msi(const struct msi_desc *root_msi,
                   const struct msi_desc *guest_msi)
{
    if (this->is_domU()) {
        expects(this->m_root_vcpu);
        expects(this->m_root_vcpu->is_root_vcpu());
        m_root_vcpu->map_msi(root_msi, guest_msi);
        return;
    }

    validate_msi(root_msi);
    validate_msi(guest_msi);

    /*
     * Ensure that the physical APIC is in xAPIC mode.
     * If it is in x2APIC, all the MSI code needs to be
     * revisited as that will change the way the MSI fields
     * are interpreted.
     */
    expects(m_lapic);
    expects(m_lapic->is_xapic());

    const auto root_destid = root_msi->destid();
    const auto root_vector = root_msi->vector();

    for (uint64_t i = 0; i < nr_root_vcpus; i++) {
        auto root_vcpu = get_vcpu(i);
        if (!root_vcpu) {
            printv("%s: failed to get_vcpu %lu", __func__, i);
            continue;
        }

        try {
            auto msi_map = &root_vcpu->m_msi_map;
            msi_map->try_emplace(root_vector, root_msi, guest_msi);
        } catch (...) {
            bferror_info(0, "exception mapping msi");
            put_vcpu(i);
            throw;
        }

        put_vcpu(i);
    }
}

const struct msi_desc *vcpu::find_guest_msi(msi_key_t root_vector) const
{
    const auto itr = m_msi_map.find(root_vector);
    if (itr == m_msi_map.cend()) {
        return nullptr;
    }

    const auto msi_pair = itr->second;
    return msi_pair.second;
}

}
