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

#include <bfack.h>
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
#include <bootparams.h>

vcpuid_t g_vcpuid;
domainid_t g_domainid;

auto ctl = std::make_unique<ioctl>();

// -----------------------------------------------------------------------------
// vCPU Thread
// -----------------------------------------------------------------------------

void
vcpu_thread(vcpuid_t vcpuid)
{
    using namespace std::chrono;

    while (true) {
        auto ret = __run_op(vcpuid, 0, 0);
        switch (run_op_ret_op(ret)) {
            case __enum_run_op__hlt:
                return;

            case __enum_run_op__fault:
                std::cerr << "[0x" << std::hex << vcpuid << std::dec << "] ";
                std::cerr << "vcpu fault: " << run_op_ret_arg(ret) << '\n';
                return;

            case __enum_run_op__resume_after_interrupt:
                continue;

            case __enum_run_op__yield:
                std::this_thread::sleep_for(microseconds(run_op_ret_arg(ret)));
                continue;

            default:
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

void
uart_thread()
{
    using namespace std::chrono;
    std::array<char, UART_MAX_BUFFER> buffer{};

    while (g_process_uart) {
        auto size = __domain_op__dump_uart(g_domainid, buffer.data());
        std::cout.write(buffer.data(), gsl::narrow_cast<int>(size));
        std::this_thread::sleep_for(milliseconds(100));
    }

    auto size = __domain_op__dump_uart(g_domainid, buffer.data());
    std::cout.write(buffer.data(), gsl::narrow_cast<int>(size));
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

    ret = __vcpu_op__kill_vcpu(g_vcpuid);
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

    if (bfack() == 0) {
        throw std::runtime_error("hypervisor not running");
    }

    g_vcpuid = __vcpu_op__create_vcpu(g_domainid);
    if (g_vcpuid == INVALID_VCPUID) {
        throw std::runtime_error("__vcpu_op__create_vcpu failed");
    }

    std::thread t(vcpu_thread, g_vcpuid);
    std::thread u;

//    output_vm_uart_verbose();

    t.join();

    if (verbose) {
        g_process_uart = false;
        u.join();
    }

    if (__vcpu_op__destroy_vcpu(g_vcpuid) != SUCCESS) {
        std::cerr << "__vcpu_op__destroy_vcpu failed\n";
    }

    return EXIT_SUCCESS;
}

// -----------------------------------------------------------------------------
// VM creation
// -----------------------------------------------------------------------------

static uint64_t
vm_file_type(const char *data, uint64_t size)
{
    /**
     * We support ELF (vmlinux) or bzImage. The latter
     * is identified by parsing some fields in the
     * setup_header, so we make sure size is big enough.
     */
    expects(size > 0x1f1 + sizeof(struct setup_header));

    const char elf_magic[4] = { 0x7F, 'E', 'L', 'F'};
    if (std::memcmp(data, elf_magic, 4) == 0) {
        return VM_FILE_VMLINUX;
    }

    const struct setup_header *hdr = (struct setup_header *)(data + 0x1f1);
    if (hdr->header == 0x53726448) {
        return VM_FILE_BZIMAGE;
    }

    throw std::invalid_argument("Unknown VM file type");
}

static uint64_t
vm_exec_mode(uint64_t file_type)
{
    switch (file_type) {
        case VM_FILE_VMLINUX: return VM_EXEC_XENPVH;
        case VM_FILE_BZIMAGE: return VM_EXEC_NATIVE;
        default: throw std::invalid_argument("Unknown VM exec mode");
    }
}

static void
create_vm(const args_type &args)
{
    create_vm_args ioctl_args {};

    bfn::cmdl cmdl;
    bfn::file kernel(args["kernel"].as<std::string>());
    bfn::file initrd(args["initrd"].as<std::string>());

    uint64_t ram = kernel.size() * 2;
    if (args.count("ram")) {
        ram = args["ram"].as<uint64_t>();
    }

    if (ram < 0x2000000) {
        ram = 0x2000000;
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

    ioctl_args.file_type = vm_file_type(kernel.data(), kernel.size());
    ioctl_args.exec_mode = vm_exec_mode(ioctl_args.file_type);
    ioctl_args.image = kernel.data();
    ioctl_args.image_size = kernel.size();
    ioctl_args.initrd = initrd.data();
    ioctl_args.initrd_size = initrd.size();
    ioctl_args.cmdl = cmdl.data();
    ioctl_args.cmdl_size = cmdl.size();
    ioctl_args.uart = uart;
    ioctl_args.pt_uart = pt_uart;
    ioctl_args.ram = ram;

    ctl->call_ioctl_create_vm(ioctl_args);
//    create_vm_from_bzimage_verbose();

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

    create_vm(args);

    auto ___ = gsl::finally([&] {
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
