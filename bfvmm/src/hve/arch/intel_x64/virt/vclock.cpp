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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/virt/vclock.h>

#define NSEC_PER_SEC 1000000000L

// -----------------------------------------------------------------------------
// Notes about Event Timer Injection
// -----------------------------------------------------------------------------

// The vclock provides the following:
// - wallclock (the data and time)
// - per vcpu clock event device (like the APIC TSC deadline)
//
// The wallclock is handled by the guest asking for the wallclock which causes
// the guest to return to bfexec so that it can report the wallclock to the
// VMM. Once the VMM has the wallclock, it can then provide the wallclock to
// the guest whenever it asks as it can update the wallclock using the TSC.
//
// The clock event device is emulated using the preemption timer. There are
// two modes that the preemption timer can use. One is it can count down
// whenever the vCPU is executing. The problem with this is stolen time adds
// up with this approach causing drift. The other mode is the preemption timer
// can be set on each VMResume. When this occurs, we simply need to know at
// what absolute TSC value the guest would like a clock event. Once that TSC
// is reached we inject the event. This TSC can be reached while the guest is
// running or when the host or another guest is executing, in which case we
// inject the moment we resume. This method is what we do, as it is really
// simple, and it ensures the guest is getting events as it needs. The only
// issue with this approach is whatever userspace application that was executing
// in the guest when a world switch occurs loses time, but that is up to the
// guest OS to sort out.
//

// -----------------------------------------------------------------------------
// Notes about TSC <-> Nanonsecond Conversions
// -----------------------------------------------------------------------------

// - The following APIs are used to set, get and convert the Wall Clock time
//   and Clock Events. Boxy requires an invariant TSC, which means
//   that once the VMM is given a Wall Clock time and a TSC that was
//   captured at the same time the Wall Clock was captured (or at least as
//   close as possible), Boxy, from that point on you can use rdtsc() to get the
//   current Wall Clock time whenever it is needed with a little math.
//
// - The TSC frequency is in kHz and we want to create a set of formulas that
//   will let us convert between TSC and a timespec. To start, it is helpful
//   to remember the following:
//
//   tsc_freq_hz = ticks / seconds
//   tsc_freq_hz = tsc_freq_khz * 1,000
//   seconds = nanoseconds / 1,000,000,000
//
//   A timespec stores the following:
//
//   timespec.tv_sec
//   timespec.tv_nsec
//
//   The values store the total number of seconds from epoch with nanosecond
//   resolution (which we want to maintain). There are three formulas that we
//   will need to ensure that we can manage time properly in the hypervisor:
//
//   1. TSC ticks -> nanoseconds
//   2. nanoseconds -> TSC ticks
//   3. get current wallclock time
//
//   Formula #1:
//
//   - tsc_freq_hz = tsc ticks / seconds
//   - tsc_freq_khz * 1,000 = tsc ticks / seconds
//   - tsc_freq_khz * 1,000 = tsc ticks / (nanoseconds / 1,000,000,000)
//   - tsc_freq_khz * 1,000 = (tsc ticks * 1,000,000,000) / nanoseconds
//   - tsc_freq_khz = (tsc ticks * 1,000,000) / nanoseconds
//   - nanoseconds = (tsc ticks * 1,000,000) / tsc_freq_khz
//
//   The issue with this equation is that it will overflow if we just
//   perform the math as stated above. To deal with this, there are a couple
//   of solutions:
//
//   - We could use nothing but scaling math to deal with this issue. The
//     problem with scaling math is that it will produce error which will
//     produce drift. The larger the scaling factor, the smaller the drift
//     so the you have to dynamically calculate the scaling factor to
//     figure out what scaling factor produces the smallest possible drift
//     without overflowing, and then readjust over time. When this
//     is paired with a hypervisor that is attempting to maintain the same
//     time as the guest, you have a problem because the hypervisor doesn't
//     know how this is being calculated which means that the guest will
//     drift from the hypervisor if they are not calculating this math
//     the same. In the Linux Kernel, you can see where they perform their
//     scaling math for the TSC here:
//     https://elixir.bootlin.com/linux/v4.19.32/source/arch/x86/kernel/tsc.c#L83
//
//   - We could use a BigInt library. Specifically, if we use a uint128_t
//     instead of 64bit integers, we wouldn't see any overflow. The biggest
//     issue with this approach is the hardware normally doesn't support
//     BigInt natively so you have to provide library facilities that
//     emulate BitInt math which is slow.
//
//   - We could use the Quotient Remainder therom. Specifically, this therom
//     allows us to construct the following formula:
//
//     ((x / d) * n) + (((x % d) * n) / d)
//
//     The Quotient Remainder therom basically states any number can be
//     broken up into the following
//
//     A = Q * B + R   e.g. 9 = 4*2 + 1
//
//     Q in this case is the quotient and R is the remainder. We can also
//     state that following based on these definitions:
//
//     Q = A / B
//     R = A % B
//
//     Note that the above is specific to integer math. With this, we can
//     do some substitution and get:
//
//     A = (A/B)*B + A%B
//
//     Now this might seem like a strange equation because doesn't B just
//     cancel B? And if it does, do you get A = A + A%B? No. The reason
//     once again is we are working with integers. A/B*B with integers is
//     not that same thing as A. This is because the act of dividing removes
//     the remainder which is why the mod has to be added to the equation.
//     We will use this fact later.
//
//     So, now with that, we can get back to the original problem. We want to
//     calculate the following:
//
//     nanoseconds = (tsc ticks * 1,000,000) / tsc_freq_khz
//
//     And we want to do this without the overflow issue. To do this, let us
//     write the TSC in terms of the Quotient Remainder Therom as follows:
//
//     TSC = Q * f + R    where f == tsc_freq_khz
//
//     The therom states that we can write any number as the multiple of any
//     other number that we want + a remainder. So in this case, we choose to
//     use the above relationship. Now the next step is we want to calculate
//     nanoseconds and not the TSC so we need to change the equation in such
//     a way where we are calculating nsecs. To do this, we do the following:
//
//     nsecs = TSC*(n/f) = (Q * f + R)*(n/f)     where n == 1000000
//
//     The (n/f) or (10000000/tsc_freq_khz) comes straight from the math above
//     and since we multiplied this on both sides, we have equivlance. Finally,
//     we need to deal with the Q and the R. In the beginning we defined what
//     Q (i.e. TSC/tsc_freq_khz) and R (i.e. TSC%tsc_freq_khz) are so we can
//     do the substitution here:
//
//     nsecs = TSC*(n/f) = (TSC/f*f + TCS%f)*(n/f)
//
//     All we have to do is simplify this. Remember that TSC/f*f != TSC. We
//     can however do this:
//
//     nsecs = (TSC/f*f)*(n/f) + (TCS%f)*(n/f)
//     nsecs = (TSC/f)*(n) + (TCS%f)*(n/f)
//     nsecs = ((TSC/f)*n) + ((TCS%f)*n)/f
//
//     Which is the formula we stated above:
//
//     ((x / d) * n) + (((x % d) * n) / d)
//
//     If the remainder portion of this overflows, the result would not be
//     able to fit in a 64bit int anyways so we don't need to worry about
//     that. So the only disadvantage to this approach is that we have to
//     calculate the additional (((x % d) * n) / d) which includes both a
//     divide and a modulo which are both slow. In the grand scheme of things
//     we are willing to deal with this to prevent the loss of precision.
//     Also note that at one point the Linux kernel was doing this same
//     math in the kernel, but they were using the scaling factor so that
//     they could reduce the performance hit of this, but at least there
//     wasn't an issue with overflow (at the cost of some drift due to the use
//     of the scaling factor).
//     https://elixir.bootlin.com/linux/v3.10.56/source/arch/x86/include/asm/timer.h#L44
//
//     There is one more issue here. There are three things that are tracking
//     time: the host OS, the guest OS and the hypervisor. If we provide the
//     guest OS with a custom clock source and both the hypervisor and the
//     guest OS use the same equations for calculating time, we can ensure that
//     the guest OS never drifts from the hypervisor. This gives us:
//
//     host OS time ~= guest OS time == hypervisor time
//
//     The obvious problem here is that the host OS can still drift from the
//     guest OS and hypervisor. There really is no way to deal with this
//     without also modifying the host OS (which we do not plan to do). No
//     matter what approach we take, we have no way of knowing how the host OS
//     will attempt to perform this math, so we don't know how accurate the
//     host OS is with respect to the actual time. The best we can do is attempt
//     to calculate the guest OS and hypervisor times as accurate as possible.
//     This way, whatever drift that does occur is due to the host OS drifting
//     and not our software. If this drift gets bad enough, we will have to add
//     software to the guest OS to recalculate the time (like a sync driver or
//     something like NTP) to ensure that drift is handled.
//
//   Formula #2:
//
//   - nanoseconds = (tsc ticks * 1,000,000) / tsc_freq_khz
//   - nanoseconds * tsc_freq_khz = tsc ticks * 1,000,000
//   - tsc ticks * 1,000,000 = nanoseconds * tsc_freq_khz
//   - tsc ticks = (nanoseconds * tsc_freq_khz) / 1,000,000
//
//   The same issue above holds true with this equation. So we will use the
//   same mul_div function to handle this math.
//
//   Formula #3:
//
//   - current timespec = cached timespec + tsc_to_nsec(current tsc - cached tsc)
//
//   To get the current wallclock time, we need to calculate the number of
//   ticks that have expired since we cached the wallclock time and then
//   calculate how many nanoseconds have passed. Once we have that we can
//   determine the current time.
//

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

static uint64_t
mul_div(uint64_t x, uint64_t n, uint64_t d)
{ return ((x / d) * n) + (((x % d) * n) / d); }

static uint64_t
calibrate_tsc_freq_khz()
{
    using namespace ::intel_x64::cpuid;
	auto [eax, ebx, ecx, edx] = ::x64::cpuid::get(0x15, 0, 0, 0);

    // Notes:
    //
    // For now we only support systems that provide the TSC frequency
    // through CPUID leaf 0x15. Please see the following:
    // - https://lore.kernel.org/patchwork/patch/689875/
    //
    // We could also get the information from the Plafrom Info MSR, but from
    // testing, this value doesn't seem to be as accurate as CPUID leaf 0x15.
    //
    // One issue is that for some CPUs, the frequency is reported as 0
    // even though the numerator and denominator are provided. The manual
    // states that this means the core crystal clock is not enumerated.
    // The Linux kernel maintains a whitelist to deal with this to ensure the
    // TSC frequency is accurate. This can be seen by the following links:
    // - https://lore.kernel.org/patchwork/patch/715512/
    // - https://elixir.bootlin.com/linux/v4.19.32/source/arch/x86/kernel/tsc.c#L610
    //
    // Where the Linux Kernel got this information is still a mystery as I
    // was not able to track down where the original 24MHz and 25MHz numbers
    // came from as it appears that it originated from this patch, which was
    // written by an Intel engineer, and already contained these values:
    // - https://lore.kernel.org/patchwork/patch/696814/
    //

    if (ecx == 0) {
        switch(feature_information::eax::get() & 0x000F00F0) {
            case 0x400E0:
            case 0x500E0:
            case 0x800E0:
            case 0x900E0:
                ecx = 24000;
                break;

            case 0x50050:
                ecx = 25000;
                break;

            case 0x500C0:
                ecx = 19200;
                break;

            default:
                break;
        };
    }
    else {
        ecx /= 1000;
    }

	if (eax == 0 || ebx == 0 || ecx == 0) {
        throw std::runtime_error("missing tsc info. system not supported");
    }

    return (ecx * ebx) / eax;
}

static struct timespec
inc_timespec(const struct timespec &ts, uint64_t nsec)
{
    nsec += static_cast<uint64_t>(ts.tv_nsec);

    return {
        ts.tv_sec + gsl::narrow_cast<int64_t>(nsec / NSEC_PER_SEC),
        gsl::narrow_cast<long>(nsec % NSEC_PER_SEC)
    };
}

static struct timespec
sub_timespec(const struct timespec &ts1, const struct timespec &ts2)
{
    auto sec = ts1.tv_sec - ts2.tv_sec;
    auto nsec = ts1.tv_nsec - ts2.tv_nsec;

    if (nsec < 0) {
        sec--;
        nsec += NSEC_PER_SEC;
    }

    return {sec, nsec};
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

vclock_handler::vclock_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_tsc_freq_khz{calibrate_tsc_freq_khz()}
{
    if (vcpu->is_dom0()) {
        this->setup_dom0();
    }
    else {
        this->setup_domU();
    }
}

//------------------------------------------------------------------------------
// Host Time
//------------------------------------------------------------------------------

void
vclock_handler::set_host_wallclock_rtc(
    uint64_t sec, uint64_t nsec) noexcept
{
    m_host_wc_rtc.tv_sec = gsl::narrow_cast<int64_t>(sec);
    m_host_wc_rtc.tv_nsec = gsl::narrow_cast<long>(nsec);
}

void
vclock_handler::set_host_wallclock_tsc(uint64_t val) noexcept
{ m_host_wc_tsc = val; }

void
vclock_handler::reset_host_wallclock(void) noexcept
{
    m_host_wc_rtc = {};
    m_host_wc_tsc = {};
}

std::pair<struct timespec, uint64_t>
vclock_handler::get_host_wallclock() const
{
    auto tsc = ::x64::tsc::get();
    auto elapsed_nsec = this->tsc_to_nsec(tsc - m_host_wc_tsc);

    return {inc_timespec(m_host_wc_rtc, elapsed_nsec), tsc};
}

//------------------------------------------------------------------------------
// Guest Time
//------------------------------------------------------------------------------

void
vclock_handler::set_guest_wallclock_rtc(void) noexcept
{ m_guest_wc_rtc = m_host_wc_rtc; }

void
vclock_handler::set_guest_wallclock_tsc(void) noexcept
{ m_guest_wc_tsc = m_host_wc_tsc; }

std::pair<struct timespec, uint64_t>
vclock_handler::get_guest_wallclock() const
{
    auto tsc = ::x64::tsc::get();
    auto elapsed_nsec = this->tsc_to_nsec(tsc - m_guest_wc_tsc);

    return {inc_timespec(m_guest_wc_rtc, elapsed_nsec), tsc};
}

//------------------------------------------------------------------------------
// Time Helpers
//------------------------------------------------------------------------------

uint64_t
vclock_handler::tsc_freq_khz() const noexcept
{ return m_tsc_freq_khz; }

uint64_t
vclock_handler::tsc_to_nsec(uint64_t tsc) const noexcept
{ return mul_div(tsc, 1000000, m_tsc_freq_khz); }

uint64_t
vclock_handler::nsec_to_tsc(uint64_t nsec) const noexcept
{ return mul_div(nsec, m_tsc_freq_khz, 1000000); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
vclock_handler::handle_yield(vcpu *vcpu)
{
    auto next_event = m_next_event_tsc;

    vcpu->advance();
    this->inject_vclock_event();

    if (auto tsc = ::x64::tsc::get(); tsc < next_event) {
        auto nsec = this->tsc_to_nsec(next_event - tsc);

        vcpu->parent_vcpu()->load();
        vcpu->parent_vcpu()->return_yield(nsec);
    }

    return true;
}

bool
vclock_handler::handle_preemption_timer(vcpu *vcpu)
{
    bfignored(vcpu);

    this->queue_vclock_event();
    return true;
}

void
vclock_handler::vclock_op__get_tsc_freq_khz(vcpu *vcpu)
{
    try {
        vcpu->set_rax(this->tsc_freq_khz());
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vclock_handler::vclock_op__set_next_event(vcpu *vcpu)
{
    try {
        m_next_event_tsc = ::x64::tsc::get() + vcpu->rbx();
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vclock_handler::vclock_op__reset_host_wallclock(vcpu *vcpu)
{
    try {
        vcpu->set_rax(SUCCESS);

        vcpu->parent_vcpu()->load();
        vcpu->parent_vcpu()->return_set_wallclock();
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vclock_handler::vclock_op__set_host_wallclock_rtc(vcpu *vcpu)
{
    try {
        auto child_vcpu = get_vcpu(vcpu->rbx());
        child_vcpu->set_host_wallclock_rtc(vcpu->rcx(), vcpu->rdx());

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vclock_handler::vclock_op__set_host_wallclock_tsc(vcpu *vcpu)
{
    try {
        auto child_vcpu = get_vcpu(vcpu->rbx());
        child_vcpu->set_host_wallclock_tsc(vcpu->rcx());

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vclock_handler::vclock_op__set_guest_wallclock_rtc(vcpu *vcpu)
{
    try {
        this->set_guest_wallclock_rtc();
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vclock_handler::vclock_op__set_guest_wallclock_tsc(vcpu *vcpu)
{
    try {
        this->set_guest_wallclock_tsc();
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vclock_handler::vclock_op__get_guest_wallclock(vcpu *vcpu)
{
    try {
        auto wallclock = this->get_guest_wallclock();

        vcpu->set_rbx(static_cast<uint64_t>(wallclock.first.tv_sec));
        vcpu->set_rcx(static_cast<uint64_t>(wallclock.first.tv_nsec));
        vcpu->set_rdx(wallclock.second);

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

bool
vclock_handler::dispatch_dom0(vcpu *vcpu)
{
    if (bfopcode(vcpu->rax()) != hypercall_enum_vclock_op) {
        return false;
    }

    switch (vcpu->rax()) {
        case hypercall_enum_vclock_op__get_tsc_freq_khz:
            vclock_op__get_tsc_freq_khz(vcpu);
            break;

        case hypercall_enum_vclock_op__set_host_wallclock_rtc:
            vclock_op__set_host_wallclock_rtc(vcpu);
            break;

        case hypercall_enum_vclock_op__set_host_wallclock_tsc:
            vclock_op__set_host_wallclock_tsc(vcpu);
            break;

        default:
            vcpu->halt("unknown dom0 vclock op");
    };

    return true;
}

bool
vclock_handler::dispatch_domU(vcpu *vcpu)
{
    if (bfopcode(vcpu->rax()) != hypercall_enum_vclock_op) {
        return false;
    }

    switch (vcpu->rax()) {
        case hypercall_enum_vclock_op__get_tsc_freq_khz:
            vclock_op__get_tsc_freq_khz(vcpu);
            break;

        case hypercall_enum_vclock_op__set_next_event:
            vclock_op__set_next_event(vcpu);
            break;

        case hypercall_enum_vclock_op__reset_host_wallclock:
            vclock_op__reset_host_wallclock(vcpu);
            break;

        case hypercall_enum_vclock_op__set_guest_wallclock_rtc:
            vclock_op__set_guest_wallclock_rtc(vcpu);
            break;

        case hypercall_enum_vclock_op__set_guest_wallclock_tsc:
            vclock_op__set_guest_wallclock_tsc(vcpu);
            break;

        case hypercall_enum_vclock_op__get_guest_wallclock:
            vclock_op__get_guest_wallclock(vcpu);
            break;

        default:
            vcpu->halt("unknown domU vclock op");
    };

    return true;
}

void
vclock_handler::resume_delegate(vcpu_t *vcpu)
{
    if (m_next_event_tsc == 0 || m_guest_wc_tsc == 0) {
        return;
    }

    if (auto tsc = ::x64::tsc::get(); tsc < m_next_event_tsc) {
        vcpu->set_preemption_timer(
            ((m_next_event_tsc - tsc) >> m_pet_decrement) + 1
        );

        return;
    }

    this->queue_vclock_event();
}

// -----------------------------------------------------------------------------
// Private Helpers
// -----------------------------------------------------------------------------

void
vclock_handler::setup_dom0()
{
    m_vcpu->add_vmcall_handler(
        {&vclock_handler::dispatch_dom0, this}
    );
}

void
vclock_handler::setup_domU()
{
    using namespace ::intel_x64::msrs;

    m_pet_decrement = ia32_vmx_misc::preemption_timer_decrement::get();
    if (m_pet_decrement == 0) {
        throw std::runtime_error("missing PET info. system not supported");
    }

    m_vcpu->add_vmcall_handler(
        {&vclock_handler::dispatch_domU, this}
    );

    m_vcpu->add_resume_delegate(
        {&vclock_handler::resume_delegate, this}
    );

    m_vcpu->add_yield_handler(
        {&vclock_handler::handle_yield, this}
    );

    m_vcpu->add_preemption_timer_handler(
        {&vclock_handler::handle_preemption_timer, this}
    );
}

void
vclock_handler::queue_vclock_event()
{
    m_vcpu->disable_preemption_timer();
    m_vcpu->queue_virtual_interrupt(boxy_virq__vclock_event_handler);

    m_next_event_tsc = 0;
}

void
vclock_handler::inject_vclock_event()
{
    m_vcpu->disable_preemption_timer();
    m_vcpu->inject_virtual_interrupt(boxy_virq__vclock_event_handler);

    m_next_event_tsc = 0;
}

}









// void
// vclock_handler::launch_delegate(vcpu *vcpu)
// {
//     if (m_guest_wc_tsc == 0) {
//         return;
//     }

//     if (m_host_wc_tsc == 0) {
//         m_vcpu->parent_vcpu()->load();
//         m_vcpu->parent_vcpu()->return_set_wallclock();
//     }

//     auto elapsed_rtc = sub_timespec(m_host_wc_rtc, m_guest_wc_rtc);
//     auto sec = static_cast<uint64_t>(elapsed_rtc.tv_sec);
//     auto nsec = static_cast<uint64_t>(elapsed_rtc.tv_nsec);

//     // Note
//     //
//     // When we resume we need to calculate a TSC offset because it is possible
//     // that the host reset it's TSC on resume, which means that the host TSC
//     // and the guest TSC are no longer the same as we maintain an constant,
//     // reliable TSC in the guest. To accomplish this, we calculate how many
//     // TSC ticks should have occurred and then remove the current TSC to get
//     // the TSC offset
//     //

//     auto tsc = this->nsec_to_tsc((sec * NSEC_PER_SEC) + nsec);
//     auto tsc_offset = (m_guest_wc_tsc - m_host_wc_tsc) + tsc;

//     vmcs_n::tsc_offset::set(tsc_offset);

//     if (m_next_event_tsc != 0) {
//         if (m_next_event_tsc > tsc_offset) {
//             m_next_event_tsc -= tsc_offset;
//         }
//         else {
//             this->queue_vclock_event();
//         }
//     }
// }
