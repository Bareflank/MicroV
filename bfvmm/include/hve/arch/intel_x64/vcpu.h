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

#ifndef VCPU_INTEL_X64_MICROV_H
#define VCPU_INTEL_X64_MICROV_H

#include "apic/lapic.h"
#include "apic/x2apic.h"
#include "../../../pci/msi.h"

#include "vmexit/cpuid.h"
#include "vmexit/external_interrupt.h"
#include "vmexit/io_instruction.h"
#include "vmexit/msr.h"
#include "vmexit/mtrr.h"
#include "vmexit/pci_cfg.h"
#include "vmexit/vmcall.h"
#include "vmexit/yield.h"

#include "vmcall/domain_op.h"
#include "vmcall/event_op.h"
#include "vmcall/iommu_op.h"
#include "vmcall/run_op.h"
#include "vmcall/vcpu_op.h"
#include "vmcall/xue_op.h"

#include "domain.h"
#include "xstate.h"

#include <bfvmm/vcpu/vcpu_manager.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

inline vcpuid_t nr_root_vcpus = 0;

namespace microv {
    class xen_vcpu;
    struct msi_desc;
}

namespace microv::intel_x64
{

class vcpu : public bfvmm::intel_x64::vcpu
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    ///
    explicit vcpu(
        vcpuid::type id,
        gsl::not_null<domain *> domain);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

    /// Physical CPU ID
    ///
    /// @expects
    /// @ensures
    ///
    uint64_t pcpuid();

    /// Write Dom0 Guest State
    ///
    /// @expects
    /// @ensures
    ///
    void write_dom0_guest_state(domain *domain);

    /// Write DomU Guest State
    ///
    /// @expects
    /// @ensures
    ///
    void write_domU_guest_state(domain *domain);

public:

    microv::xen_vcpu *xen_vcpu() noexcept;

    void add_child_vcpu(vcpuid_t id);
    vcpu *find_child_vcpu(vcpuid_t id);
    void remove_child_vcpu(vcpuid_t id);

    void add_child_domain(domainid_t id);
    domain *find_child_domain(domainid_t id);
    void remove_child_domain(domainid_t id);

    //--------------------------------------------------------------------------
    // Domain Info
    //--------------------------------------------------------------------------

    /// Is Dom0
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if this is dom0, false otherwise
    ///
    bool is_dom0() const;

    /// Is DomU
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if this is a domU, false otherwise
    ///
    bool is_domU() const;

    /// Domain ID
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the vCPU's domid
    ///
    domain::id_t domid() const;

    /// Domain pointer
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the vCPU's domain
    ///
    domain *dom() { return m_domain; }

    //--------------------------------------------------------------------------
    // VMCall
    //--------------------------------------------------------------------------

    /// Add VMCall Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a vmcall exit occurs
    ///
    VIRTUAL void add_vmcall_handler(
        const vmcall_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Root
    //--------------------------------------------------------------------------

    /// Set root vcpu
    ///
    /// Each guest vcpu must have a parent. If a guest vcpu can no longer
    /// execute (e.g., from a crash, interrupt, hlt, etc...), the parent
    /// vcpu is the vcpu that will be resumed. Note that only one level of
    /// descendants is supported, so for every guest vcpu, its parent is
    /// a root vcpu.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void set_root_vcpu(gsl::not_null<vcpu *> vcpu);

    /// Get root vcpu
    ///
    /// Returns the id for this vcpus parent. Note that this ID could
    /// change on every exit once VMCS migration is supported.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL vcpu *root_vcpu() const;

    /// Return (Hlt)
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to stop the guest vCPU.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void return_hlt();

    /// Return (Fault)
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to stop the guest vCPU and report a fault.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param error the error code to return to the parent
    ///
    VIRTUAL void return_fault(uint64_t error = 0);

    /// Return (Resume After Interrupt)
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to resume the guest as fast as possible. This is used to hand control
    /// back to the parent, even though the guest is not finished yet due to
    /// an interrupt
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void return_resume_after_interrupt();

    /// Return (Yield)
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to put the child vCPU asleep for the specified number of microseconds
    ///
    /// @expects
    /// @ensures
    ///
    /// @param usec the number of microseconds to sleep
    ///
    VIRTUAL void return_yield(uint64_t usec);

    //--------------------------------------------------------------------------
    // Control
    //--------------------------------------------------------------------------

    /// Kill
    ///
    /// Tells the vCPU to stop execution.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void kill();

    /// Is Alive
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if the vCPU has not been killed, false otherwise
    ///
    VIRTUAL bool is_alive() const;

    /// Is Killed
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if the vCPU has been killed, false otherwise
    ///
    VIRTUAL bool is_killed() const;

    //--------------------------------------------------------------------------
    // Fault
    //--------------------------------------------------------------------------

    /// Halt the vCPU
    ///
    /// Halts the vCPU. The default action is to freeze the physical core
    /// resulting in a hang, but this function can be overrided to provide
    /// a safer action if possible.
    ///
    /// @param str the reason for the halt
    ///
    void halt(const std::string &str = {}) override;

    //--------------------------------------------------------------------------
    // Interrupts
    //--------------------------------------------------------------------------

    /// APIC Timer Vector (guest vcpu only)
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the vector number associated with the APIC timer
    ///
    uint8_t apic_timer_vector();

    /// Map msi
    ///
    /// Create a root->guest msi mapping
    ///
    /// @param root_msi the msi info programmed by the root
    /// @param guest_msi the msi info programmed by the guest
    ///
    void map_msi(const struct msi_desc *root_msi,
                 const struct msi_desc *guest_msi);

    /// Find guest msi
    ///
    /// @param key the root vector to look for
    /// @return the guest msi_desc if found, nullptr otherwise
    ///
    const struct msi_desc *find_guest_msi(msi_key_t key) const;

    /// Queue virq into this vcpu
    void queue_virq(uint32_t virq);

    /// Start-of-day base cpuid handler overrides
    bool handle_0x4BF00010(bfvmm::intel_x64::vcpu *vcpu);
    bool handle_0x4BF00021(bfvmm::intel_x64::vcpu *vcpu);

    /// xstate management
    void init_xstate();
    void save_xstate();
    void load_xstate();

    /// Add a config space handler for the PCI device given by cfg_addr
    void add_pci_cfg_handler(uint64_t cfg_addr,
                             const pci_cfg_handler::delegate_t &d,
                             int direction);

    /// Add a config space handler for the PCI device given by bus/dev/fun
    void add_pci_cfg_handler(uint32_t bus,
                             uint32_t dev,
                             uint32_t fun,
                             const pci_cfg_handler::delegate_t &d,
                             int direction);

private:
    friend class microv::xen_vcpu;
    friend class microv::intel_x64::vcpu;

    void setup_default_controls();
    void setup_default_handlers();
    void setup_default_register_state();

    domain *m_domain{};

    cpuid_handler m_cpuid_handler;
    external_interrupt_handler m_external_interrupt_handler;
    io_instruction_handler m_io_instruction_handler;
    msr_handler m_msr_handler;
    mtrr_handler m_mtrr_handler;
    vmcall_handler m_vmcall_handler;
    yield_handler m_yield_handler;

    vmcall_run_op_handler m_vmcall_run_op_handler;
    vmcall_domain_op_handler m_vmcall_domain_op_handler;
    vmcall_event_op_handler m_vmcall_event_op_handler;
    vmcall_iommu_op_handler m_vmcall_iommu_op_handler;
    vmcall_vcpu_op_handler m_vmcall_vcpu_op_handler;
    vmcall_xue_op_handler m_vmcall_xue_op_handler;

    x2apic_handler m_x2apic_handler;
    pci_cfg_handler m_pci_handler;

    bool m_killed{};
    vcpu *m_root_vcpu{};

    std::unique_ptr<microv::xen_vcpu> m_xen_vcpu{};
    std::unique_ptr<microv::intel_x64::lapic> m_lapic{};
    std::unique_ptr<microv::intel_x64::xstate> m_xstate{};

    msi_map_t m_msi_map{};
    std::unordered_map<vcpuid_t, vcpu *> m_child_vcpus{};
    std::unordered_map<domainid_t, domain *> m_child_doms{};
};
}

/**
 *  get_vcpu - acquires a reference to a microv vcpu
 *
 *  A non-null return value is guaranteed to point to a valid object until a
 *  matching put_vcpu is called. Caller must ensure that they release the
 *  reference after they are done with put_vcpu.
 *
 *  @expects
 *  @ensures
 *
 *  @param id the id of the vcpu to acquire
 *  @return ptr to valid vcpu on success, nullptr otherwise
*/
inline microv::intel_x64::vcpu *get_vcpu(vcpuid::type id) noexcept
{
    return g_vcm->acquire<microv::intel_x64::vcpu>(id);
}

/**
 *  put_vcpu - releases a reference to a microv vcpu
 *
 *  Release a previously acquired reference to vcpu. This must
 *  be called after a successful call to get_vcpu.
 *
 *  @expects
 *  @ensures
 *
 *  @param id the id of the vcpu to release
*/
inline void put_vcpu(vcpuid::type id) noexcept
{
    return g_vcm->release(id);
}

/**
 * Note:
 *
 * Undefine previously defined helper macros. Note that these are used by
 * each extension to provide quick access to the vcpu in the extension. If
 * include files are not handled properly, you could end up with the wrong
 * vcpu, resulting in compilation errors
*/

#ifdef vcpu_cast
#undef vcpu_cast
#endif

#define vcpu_cast(p) static_cast<microv::intel_x64::vcpu *>(p)

inline bfobject world_switch;

#endif
