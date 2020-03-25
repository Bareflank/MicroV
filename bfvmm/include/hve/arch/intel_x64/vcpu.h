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

#include <time.h>
#include <bfvmm/vcpu/vcpu_manager.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>

#include "domain.h"

#include "vmexit/external_interrupt.h"
#include "vmexit/hlt.h"
#include "vmexit/io_instruction.h"
#include "vmexit/msr.h"
#include "vmexit/preemption_timer.h"
#include "vmexit/vmcall.h"

#include "vmcall/domain_op.h"
#include "vmcall/run_op.h"
#include "vmcall/vcpu_op.h"

#include "emulation/cpuid.h"
#include "emulation/mtrr.h"
#include "emulation/x2apic.h"

#include "virt/vclock.h"
#include "virt/virq.h"

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
    ~vcpu() override;

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
    VIRTUAL bool is_dom0() const noexcept;

    /// Is DomU
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if this is a domU, false otherwise
    ///
    VIRTUAL bool is_domU() const noexcept;

    /// Domain ID
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the vCPU's domid
    ///
    VIRTUAL domain::domainid_type domid() const noexcept;

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
    VIRTUAL void add_vmcall_handler(const handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Hlt
    //--------------------------------------------------------------------------

    /// Add Hlt Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    VIRTUAL void add_hlt_handler(const handler_delegate_t &d);

    /// Add Yield Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    VIRTUAL void add_yield_handler(const handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Preemption Timer
    //--------------------------------------------------------------------------

    /// Add Preemption Timer Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    VIRTUAL void add_preemption_timer_handler(const handler_delegate_t &d);

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
    VIRTUAL vcpu *parent_vcpu() const noexcept;

    /// Prepare For World Switch
    ///
    /// Prepares the vCPU for a world switch. This ensures that portions of
    /// the vCPU's state is properly restored.
    ///
    VIRTUAL void prepare_for_world_switch();

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

    /// Return (Continue)
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to resume the guest as fast as possible. This is used to hand control
    /// back to the parent, even though the guest is not finished yet
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void return_continue();

    /// Return (Yield)
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to put the child vCPU asleep for the specified number of nanoseconds
    ///
    /// @expects
    /// @ensures
    ///
    /// @param nsec the number of nanoseconds to sleep
    ///
    VIRTUAL void return_yield(uint64_t nsec);

    /// Return (Set Wall Clock)
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to set the wallclock and then resume back to the guest
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void return_set_wallclock();

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
    VIRTUAL void kill() noexcept;

    /// Is Alive
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if the vCPU has not been killed, false otherwise
    ///
    VIRTUAL bool is_alive() const noexcept;

    /// Is Killed
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if the vCPU has been killed, false otherwise
    ///
    VIRTUAL bool is_killed() const noexcept;

    //--------------------------------------------------------------------------
    // Virtual IRQs
    //--------------------------------------------------------------------------

    /// Queue vIRQ
    ///
    /// Queues a virtual IRQ to be delivered to a guest VM. Note that this
    /// will actually queue the Hypervisor Callback Vector IRQ into the
    /// guest, and then the guest has to VMCall to this class to get the
    /// vIRQ vector. Also note that all vIRQs are essentially vMSIs so once
    /// the vIRQ is dequeued, it is gone.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void queue_virtual_interrupt(uint64_t vector);

    /// Inject vIRQ
    ///
    /// Injects a virtual IRQ to be delivered to a guest VM. Note that this
    /// will actually inject the Hypervisor Callback Vector IRQ into the
    /// guest, and then the guest has to VMCall to this class to get the
    /// vIRQ vector. Also note that all vIRQs are essentially vMSIs so once
    /// the vIRQ is dequeued, it is gone.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void inject_virtual_interrupt(uint64_t vector);

    //--------------------------------------------------------------------------
    // Virtual Clock
    //--------------------------------------------------------------------------

    /// Set Host Wall Clock Real Time Clock
    ///
    /// Records the provided wall clock RTC
    ///
    /// @expects
    /// @ensures
    ///
    /// @param val the wall clock RTC
    ///
    VIRTUAL void set_host_wallclock_rtc(uint64_t sec, uint64_t nsec) noexcept;

    /// Set Host Wall Clock TSC
    ///
    /// Records the wall clock TSC
    ///
    /// @expects
    /// @ensures
    ///
    /// @param val the wall clock TSC
    ///
    VIRTUAL void set_host_wallclock_tsc(uint64_t val) noexcept;

    /// Reset Host Wall Clock
    ///
    /// Resets the host Wall Clock. Once this is executed, any attempt to
    /// launch a vCPU (i.e. a vCPU that has never been run, or has been
    /// cleared) will cause the lanuch to return back to bfexec so that the
    /// host wall clock can be reread.
    ///
    /// Note:
    ///
    /// This does not work the same way as the reset_host_wallclock hypercall.
    /// That hypercall performs the return on-behalf of the guest. This
    /// performs the return on-behalf of the host.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void reset_host_wallclock(void) noexcept;

    /// Get the Host Wall Clock
    ///
    /// Returns the host's Wall Clock from epoch. This function will throw
    /// if the set_host_wallclock_rtc and set_host_wallclock_tsc functions
    /// have not yet been called.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the host's Wall Clock from epoch
    ///
    VIRTUAL std::pair<struct timespec, uint64_t> get_host_wallclock() const;

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

private:

    void write_dom0_guest_state(domain *domain);
    void write_domU_guest_state(domain *domain);

    void setup_default_register_state();
    void setup_default_controls();
    void setup_default_handlers();

private:

    domain *m_domain{};

    bool m_killed{};
    vcpu *m_parent_vcpu{};

private:

    external_interrupt_handler m_external_interrupt_handler;
    hlt_handler m_hlt_handler;
    io_instruction_handler m_io_instruction_handler;
    msr_handler m_msr_handler;
    preemption_timer_handler m_preemption_timer_handler;
    vmcall_handler m_vmcall_handler;

    run_op_handler m_run_op_handler;
    domain_op_handler m_domain_op_handler;
    vcpu_op_handler m_vcpu_op_handler;

    cpuid_handler m_cpuid_handler;
    mtrr_handler m_mtrr_handler;
    x2apic_handler m_x2apic_handler;

    vclock_handler m_vclock_handler;
    virq_handler m_virq_handler;
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

/// Boxy vCPU Cast
///
/// To keeps things simple, this is a Boxy specific vCPU cast so that we can
/// take any vCPU and cast it to a Boxy vCPU. Note that this is a static
/// cast since we know that if we are in this code, we are sure we have the
/// right vCPU so no dynamic cast is needed.
///
#define _v(a) static_cast<boxy::intel_x64::vcpu *>(a)

#endif
