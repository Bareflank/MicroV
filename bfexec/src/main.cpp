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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfstring.h>
#include <bfaffinity.h>
#include <bfbuilderinterface.h>

#include <list>
#include <memory>
#include <chrono>
#include <thread>
#include <fstream>
#include <iostream>

#include <args.h>
#include <cmdl.h>
#include <file.h>
#include <ioctl.h>
#include <verbose.h>

using namespace std::chrono;

vcpuid_t g_vcpuid;
domainid_t g_domainid;

auto ctl = std::make_unique<ioctl>();

// -----------------------------------------------------------------------------
// VMCall
// -----------------------------------------------------------------------------

uint64_t
_vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4) noexcept
{ return ctl->call_ioctl_vmcall(r1, r2, r3, r4); }

// -----------------------------------------------------------------------------
// RDTSC
// -----------------------------------------------------------------------------

#ifdef WIN32
#include <intrin.h>
#endif

#ifdef __CYGWIN__
#define TIME_UTC 1
#define timespec_get __timespec_get

typedef int (* p_timespec_get)(void*, int);
static p_timespec_get __timespec_get;

void
dl_timespec_get()
{
    timespec_get = (p_timespec_get) GetProcAddress(LoadLibrary(TEXT("ucrtbase.dll")), "_timespec64_get");
    if (!timespec_get) {
        std::cerr << "win32 error: " << GetLastError() << "\n";
        throw std::runtime_error("Failed to load timespec_get dynamically.");
    }
}
#endif

inline uint64_t
rdtsc()
{
#ifdef WIN32
    _mm_lfence();
    return static_cast<uint64_t>(__rdtsc());
#else
    uint64_t hi, lo;
    __asm__ __volatile__ ("lfence;rdtsc" : "=a"(lo), "=d"(hi));
    return (hi << 32) | lo;
#endif
}

// -----------------------------------------------------------------------------
// Wall Clock
// -----------------------------------------------------------------------------

bool
set_wallclock()
{
    struct timespec ts;
    uint64_t initial_tsc = 0;
    uint64_t current_tsc = 0;

#ifdef __CYGWIN__
    dl_timespec_get();
#endif

    // Note:
    //
    // We need to ensure that no interrupts fire between when we get the
    // wallclock time and when we read TSC. Since we do not have control of
    // interrupts, we will use a similar approach to how the CMOS wallclock
    // time is read. Basically, you get the TSC twice, once before you get
    // the time, and once after. This not only gives you the TSC value, but
    // it also allows you to measure how long it took to get wallclock time.
    // Once you have that you loop until the difference between these
    // measurements is under a threshold, ensuring that you tighten up the
    // measurements between the TSC and the wallclock. The actual TSC value
    // that we give the the VMM is the average between the two.
    //
    // Also note that as stated in the VMM's notes, we require an invariant
    // TSC which is why this is even possible. If the TSC is not invariant,
    // the creation of the vCPU would have failed.
    //

    int diff1 = 0;
    int diff2 = 0;

    do {
        diff2 = diff1;

        initial_tsc = rdtsc();
        timespec_get(&ts, TIME_UTC);
        current_tsc = rdtsc();

        diff1 = static_cast<int>(current_tsc - initial_tsc);
    }
    while(std::abs(diff1 - diff2) > 100);

    // Note
    //
    // Now that we have the wallclock and the TSC associated with this
    // wallclock, we need to give this information to the VMM so that it can
    // use this information to calculate the current time.
    //

    status_t ret = 0;

    ret |= hypercall_vclock_op__set_host_wallclock_rtc(
        g_vcpuid, ts.tv_sec, ts.tv_nsec);
    ret |= hypercall_vclock_op__set_host_wallclock_tsc(
        g_vcpuid, initial_tsc + static_cast<uint64_t>(diff1 / 2));

    return ret == SUCCESS;
}

// -----------------------------------------------------------------------------
// vCPU Thread
// -----------------------------------------------------------------------------

void
vcpu_thread(vcpuid_t vcpuid)
{
    while (true) {
        auto ret = hypercall_run_op(vcpuid, 0, 0);

        switch (run_op_ret_op(ret)) {
            case hypercall_enum_run_op__continue:
                continue;

            case hypercall_enum_run_op__yield:
                if (auto nsec = run_op_ret_arg(ret); nsec > 0) {
                    std::this_thread::sleep_for(nanoseconds(nsec));
                }
                else {
                    std::this_thread::yield();
                }
                continue;

            case hypercall_enum_run_op__set_wallclock:
                if (!set_wallclock()) {
                    std::cerr << "[0x" << std::hex << vcpuid << std::dec << "] ";
                    std::cerr << "set_wallclock failed\n";
                    return;
                }
                continue;

            case hypercall_enum_run_op__hlt:
                return;

            case hypercall_enum_run_op__fault:
                std::cerr << "[0x" << std::hex << vcpuid << std::dec << "] ";
                std::cerr << "vcpu fault: " << run_op_ret_arg(ret) << '\n';
                return;

            default:

                if (ret == SUSPEND) {
                    std::this_thread::sleep_for(milliseconds(250));
                    continue;
                }

                std::cerr << "[0x" << std::hex << vcpuid << std::dec << "] ";
                std::cerr << "unknown vcpu ret: " << run_op_ret_op(ret) << '\n';
                return;
        }
    }
}

// -----------------------------------------------------------------------------
// UART Thread
// -----------------------------------------------------------------------------

bool g_process_uart = true;

bool
update_output()
{
    std::array<char, UART_MAX_BUFFER> buffer{};
    auto size = hypercall_domain_op__dump_uart(g_domainid, buffer.data());

    if (size == FAILURE) {
        std::cerr << "[ERROR]: dump uart failure!!!\n";
        return false;
    }

    if (size == SUSPEND) {
        return true;
    }

    std::cout.write(buffer.data(), gsl::narrow_cast<int>(size));
    return true;
}

void
uart_thread()
{
    while (g_process_uart && update_output()) {
        std::this_thread::sleep_for(milliseconds(100));
    }

    update_output();
}

// -----------------------------------------------------------------------------
// Signal Handling
// -----------------------------------------------------------------------------

#include <signal.h>

void
kill_signal_handler(void)
{
    status_t ret;

    std::cout << '\n';
    std::cout << '\n';
    std::cout << "killing VM: " << g_domainid << '\n';

    ret = hypercall_vcpu_op__kill_vcpu(g_vcpuid);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__kill_vcpu failed\n");
        return;
    }

    return;
}

void
sig_handler(int sig)
{
    bfignored(sig);
    return kill_signal_handler();
}

void
setup_kill_signal_handler(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

#ifdef SIGQUIT
    signal(SIGQUIT, sig_handler);
#endif
}

// -----------------------------------------------------------------------------
// Attach to VM
// -----------------------------------------------------------------------------

static int
attach_to_vm(const args_type &args)
{
    bfignored(args);

    g_vcpuid = hypercall_vcpu_op__create_vcpu(g_domainid);
    if (g_vcpuid == INVALID_VCPUID) {
        throw std::runtime_error("__vcpu_op__create_vcpu failed");
    }

    std::thread t(vcpu_thread, g_vcpuid);
    std::thread u;

    output_vm_uart_verbose();

    t.join();

    if (verbose) {
        g_process_uart = false;
        u.join();
    }

    if (hypercall_vcpu_op__destroy_vcpu(g_vcpuid) != SUCCESS) {
        std::cerr << "__vcpu_op__destroy_vcpu failed\n";
    }

    return EXIT_SUCCESS;
}

// -----------------------------------------------------------------------------
// Create VM
// -----------------------------------------------------------------------------

static void
create_vm_from_bzimage(const args_type &args)
{
    create_vm_from_bzimage_args ioctl_args {};

    if (!args.count("path")) {
        throw cxxopts::OptionException("must specify --path");
    }

    if (!args.count("initrd")) {
        throw cxxopts::OptionException("must specify --initrd");
    }

    bfn::cmdl cmdl;
    bfn::file bzimage(args["path"].as<std::string>());
    bfn::file initrd(args["initrd"].as<std::string>());

    uint64_t size = bzimage.size() * 2;
    if (args.count("size")) {
        size = args["size"].as<uint64_t>();
    }

    if (size < 0x2000000) {
        size = 0x2000000;
    }

    uint64_t uart = 0;
    if (args.count("uart")) {
        uart = args["uart"].as<uint64_t>();
        cmdl.add(
            "console=uart,io," + bfn::to_string(uart, 16) + ",115200n8"
        );
    }

    uint64_t pt_uart = 0;
    if (args.count("pt_uart")) {
        pt_uart = args["pt_uart"].as<uint64_t>();
        cmdl.add(
            "console=uart,io," + bfn::to_string(pt_uart, 16) + ",115200n8,keep"
        );
    }

    if (args.count("cmdline")) {
        cmdl.add(args["cmdline"].as<std::string>());
    }

    ioctl_args.bzimage = bzimage.data();
    ioctl_args.bzimage_size = bzimage.size();
    ioctl_args.initrd = initrd.data();
    ioctl_args.initrd_size = initrd.size();
    ioctl_args.cmdl = cmdl.data();
    ioctl_args.cmdl_size = cmdl.size();
    ioctl_args.uart = uart;
    ioctl_args.pt_uart = pt_uart;
    ioctl_args.size = size;

    ctl->call_ioctl_create_vm_from_bzimage(ioctl_args);
    create_vm_from_bzimage_verbose();

    g_domainid = ioctl_args.domainid;
}

// -----------------------------------------------------------------------------
// Main Functions
// -----------------------------------------------------------------------------

static int
protected_main(const args_type &args)
{
    if (args.count("affinity")) {
        set_affinity(args["affinity"].as<uint64_t>());
    }
    else {

        // TODO:
        //
        // We need to remove the need for affinity. Right now if you don't
        // state affinity, we default to 0 because we don't support VMCS
        // migration, which needs to be fixed.
        //

        set_affinity(0);
    }

    create_vm_from_bzimage(args);

    auto __ = gsl::finally([&] {
        ctl->call_ioctl_destroy(g_domainid);
    });

    return attach_to_vm(args);
}

int
main(int argc, char *argv[])
{
    setup_kill_signal_handler();

    try {
        args_type args = parse_args(argc, argv);
        return protected_main(args);
    }
    catch (const cxxopts::OptionException &e) {
        std::cerr << "invalid arguments: " << e.what() << '\n';
    }
    catch (const std::exception &e) {
        std::cerr << "Caught unhandled exception:" << '\n';
        std::cerr << "    - what(): " << e.what() << '\n';
    }
    catch (...) {
        std::cerr << "Caught unknown exception" << '\n';
    }

    return EXIT_FAILURE;
}
