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

#ifndef VCPU_INTEL_X64_BOXY_H
#define VCPU_INTEL_X64_BOXY_H

#include "apic/x2apic.h"
#include "pci/pci_configuration_space.h"

#include "vmexit/cpuid.h"
#include "vmexit/external_interrupt.h"
#include "vmexit/io_instruction.h"
#include "vmexit/msr.h"
#include "vmexit/mtrr.h"
#include "vmexit/vmcall.h"
#include "vmexit/yield.h"

#include "vmcall/domain_op.h"
#include "vmcall/run_op.h"
#include "vmcall/vcpu_op.h"

#include "domain.h"

#include <bfvmm/vcpu/vcpu_manager.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

namespace boxy::intel_x64
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
    /// @cond
    ///
    explicit vcpu(
        vcpuid::type id,
        gsl::not_null<domain *> domain);

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

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
    domain::domainid_type domid() const;

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
    // Parent
    //--------------------------------------------------------------------------

    /// Set Parent vCPU
    ///
    /// Each vCPU that is executing (not created) must have a parent. The
    /// only exception to this is the host vCPUs. If a vCPU can no longer
    /// execute (e.g., from a crash, interrupt, hlt, etc...), the parent
    /// vCPU is the parent that will be resumed.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of the vCPU to resume
    ///
    VIRTUAL void set_parent_vcpu(gsl::not_null<vcpu *> vcpu);

    /// Get Parent vCPU ID
    ///
    /// Returns the vCPU ID for this vCPU's parent. Note that this ID could
    /// change on every exit. Specifically when the Host OS moves the
    /// userspace application associated with a guest vCPU. For this reason,
    /// don't cache this value. It always needs to be looked up.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the vcpuid for this vCPU's parent vCPU.
    ///
    VIRTUAL vcpu *parent_vcpu() const;

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
    // APIC
    //--------------------------------------------------------------------------

    /// APIC Timer Vector
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the vector number associated with the APIC timer
    ///
    uint8_t apic_timer_vector();

private:

    void setup_default_controls();
    void setup_default_handlers();
    void setup_default_register_state();

private:

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
    vmcall_vcpu_op_handler m_vmcall_vcpu_op_handler;

    x2apic_handler m_x2apic_handler;
    pci_configuration_space_handler m_pci_configuration_space_handler;


    bool m_killed{};
    vcpu *m_parent_vcpu{};
};

}

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

// Note:
//
// Undefine previously defined helper macros. Note that these are used by
// each extension to provide quick access to the vcpu in the extension. If
// include files are not handled properly, you could end up with the wrong
// vcpu, resulting in compilation errors
//

#ifdef get_vcpu
#undef get_vcpu
#endif

#ifdef vcpu_cast
#undef vcpu_cast
#endif

/// Get Guest vCPU
///
/// Gets a guest vCPU from the vCPU manager given a vcpuid
///
/// @expects
/// @ensures
///
/// @return returns a pointer to the vCPU being queried or throws
///     and exception.
///
#define get_vcpu(a) \
    g_vcm->get<boxy::intel_x64::vcpu *>(a, __FILE__ ": invalid boxy vcpuid")

#define vcpu_cast(a) \
    static_cast<boxy::intel_x64::vcpu *>(a.get())

inline bfobject world_switch;

#endif
