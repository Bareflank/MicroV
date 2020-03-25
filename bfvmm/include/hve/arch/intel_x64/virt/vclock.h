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

#ifndef VIRT_VCLOCK_INTEL_X64_BOXY_H
#define VIRT_VCLOCK_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class vclock_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    vclock_handler(
        gsl::not_null<vcpu *> vcpu);

    //--------------------------------------------------------------------------
    // Host Time
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
    // Guest Time
    //--------------------------------------------------------------------------

    /// Set Guest Wall Clock Real Time Clock
    ///
    /// Records the guest wall clock RTC as the guest wall clock RTC
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void set_guest_wallclock_rtc(void) noexcept;

    /// Set Guest Wall Clock TSC
    ///
    /// Records the guest wall clock TSC as the guest wall clock TSC
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void set_guest_wallclock_tsc(void) noexcept;

    /// Get the Guest Wall Clock
    ///
    /// Returns the guest's Wall Clock from epoch. This function will throw
    /// if the set_guest_wallclock_rtc and set_guest_wallclock_tsc functions
    /// have not yet been called.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the guest's Wall Clock from epoch
    ///
    VIRTUAL std::pair<struct timespec, uint64_t> get_guest_wallclock() const;

    //--------------------------------------------------------------------------
    // Time Helpers
    //--------------------------------------------------------------------------

    /// TSC Frequency (kHz)
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the TSC's frequency (kHz).
    ///
    VIRTUAL uint64_t tsc_freq_khz() const noexcept;

    /// Convert a TSC to Nanoseconds
    ///
    /// Note:
    ///
    /// This function will perform the conversions without fear of overflow.
    /// For this reason, if large number conversions are needed, this is
    /// the function that you should use.
    ///
    /// @expects
    /// @ensures
    ///
    /// @parma tsc the TSC value to convert
    /// @return returns the TSC in nanoseconds
    ///
    VIRTUAL uint64_t tsc_to_nsec(uint64_t tsc) const noexcept;

    /// Convert Nanoseconds to a TSC
    ///
    /// Note:
    ///
    /// This function will perform the conversions without fear of overflow.
    /// For this reason, if large number conversions are needed, this is
    /// the function that you should use.
    ///
    /// @expects
    /// @ensures
    ///
    /// @parma nsec the nanoseconds to convert
    /// @return returns the nanoseconds as a TSC
    ///
    VIRTUAL uint64_t nsec_to_tsc(uint64_t nsec) const noexcept;

public:

    /// @cond

    bool handle_yield(vcpu *vcpu);
    bool handle_preemption_timer(vcpu *vcpu);

    void vclock_op__get_tsc_freq_khz(vcpu *vcpu);
    void vclock_op__set_next_event(vcpu *vcpu);
    void vclock_op__reset_host_wallclock(vcpu *vcpu);
    void vclock_op__set_host_wallclock_rtc(vcpu *vcpu);
    void vclock_op__set_host_wallclock_tsc(vcpu *vcpu);
    void vclock_op__set_guest_wallclock_rtc(vcpu *vcpu);
    void vclock_op__set_guest_wallclock_tsc(vcpu *vcpu);
    void vclock_op__get_guest_wallclock(vcpu *vcpu);

    bool dispatch_dom0(vcpu *vcpu);
    bool dispatch_domU(vcpu *vcpu);

    void resume_delegate(vcpu_t *vcpu);

    /// @endcond

private:

    void setup_dom0();
    void setup_domU();

    void queue_vclock_event();
    void inject_vclock_event();

private:

    vcpu *m_vcpu;

    uint64_t m_tsc_freq_khz{};
    uint64_t m_pet_decrement{};
    uint64_t m_next_event_tsc{};

    uint64_t m_host_wc_tsc{};
    struct timespec m_host_wc_rtc{};
    uint64_t m_guest_wc_tsc{};
    struct timespec m_guest_wc_rtc{};

public:

    /// @cond

    vclock_handler(vclock_handler &&) = default;
    vclock_handler &operator=(vclock_handler &&) = default;

    vclock_handler(const vclock_handler &) = delete;
    vclock_handler &operator=(const vclock_handler &) = delete;

    /// @endcond
};

}

#endif
