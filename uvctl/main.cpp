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

#include <list>
#include <memory>
#include <chrono>
#include <thread>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <unistd.h>

#include <bfack.h>
#include <bfgsl.h>
#include <bfdebug.h>
#include <bfstring.h>
#include <bfaffinity.h>

#include <microv/bootparams.h>
#include <microv/builderinterface.h>
#include <microv/hypercall.h>

#include "args.h"
#include "cmdl.h"
#include "file.h"
#include "ioctl.h"
#include "verbose.h"

struct vcpu {
    vcpuid_t id{INVALID_VCPUID};
    std::thread run{};
    bool paused{};
    bool halt{};
    bool child{};
};

struct vm {
    domainid_t id{INVALID_DOMAINID};

    bool enable_uart{};
    bool enable_hvc{};

    std::thread uart_recv{};
    std::thread hvc_recv{};
    std::thread hvc_send{};

    struct vcpu vcpu{};
    std::list<struct vm> children{};
};

struct vm root_vm{};
std::unique_ptr<ioctl> ctl{};

static void run_vcpu(struct vcpu *vcpu)
{
    using namespace std::chrono;

    std::cout << "[0x" << std::hex << vcpu->id << std::dec << "] running\n";

    while (true) {
        if (vcpu->halt) {
            return;
        }

        if (vcpu->paused) {
            std::this_thread::sleep_for(microseconds(200));
            continue;
        }

        auto ret = __run_op(vcpu->id, 0, 0);

        switch (run_op_ret_op(ret)) {
        case __enum_run_op__hlt:
            return;

        case __enum_run_op__fault:
            std::cerr << "[0x" << std::hex << vcpu->id << std::dec << "] ";
            std::cerr << "vcpu fault: " << run_op_ret_arg(ret) << '\n';
            return;

        case __enum_run_op__interrupted:
            continue;

        case __enum_run_op__yield:
            std::this_thread::sleep_for(microseconds(run_op_ret_arg(ret)));
            continue;

        case __enum_run_op__create_domain:
            if (vcpu->child) {
                std::cerr << "[0x" << std::hex << vcpu->id << "] "
                          << "vcpu fault: returned with new domain 0x"
                          << run_op_ret_arg(ret) << std::dec << '\n';
                return;
            } else {
                std::cout << "[0x" << std::hex << vcpu->id << "] "
                          << "created child domain 0x" << run_op_ret_arg(ret)
                          << std::dec << '\n';

                struct vm vm{};
                vm.id = run_op_ret_arg(ret);
                vm.vcpu.child = true;
                vm.vcpu.id = __vcpu_op__create_vcpu(vm.id);

                if (vm.vcpu.id == INVALID_VCPUID) {
                    std::cerr << "[0x" << std::hex << vcpu->id << "] "
                              << " failed to create vcpu for child domain 0x"
                              << vm.id << std::dec << '\n';
                    continue;
                }

                root_vm.children.push_front(std::move(vm));
                auto &child = root_vm.children.front();
                child.vcpu.run = std::thread(run_vcpu, &child.vcpu);
                continue;
            }
        case __enum_run_op__pause_domain:
            if (vcpu->child) {
                std::cerr << "[0x" << std::hex << vcpu->id << std::dec << "] "
                          << " returned pause; returning\n";
                return;
            } else {
                auto domid = run_op_ret_arg(ret);
                for (auto &child : root_vm.children) {
                    if (child.id == domid) {
                        child.vcpu.paused = true;
                        std::cout << "[0x" << std::hex << vcpu->id << "] "
                                  << "pausing child 0x"
                                  << child.id << std::dec << "\n";
                    }
                }

                break;
            }
        case __enum_run_op__unpause_domain:
            if (vcpu->child) {
                std::cerr << "[0x" << std::hex << vcpu->id << std::dec << "] "
                          << " returned unpause; returning\n";
                return;
            } else {
                auto domid = run_op_ret_arg(ret);
                for (auto &child : root_vm.children) {
                    if (child.id == domid) {
                        child.vcpu.paused = false;
                        std::cout << "[0x" << std::hex << vcpu->id << "] "
                                  << "unpausing child 0x"
                                  << child.id << std::dec << "\n";
                    }
                }

                break;
            }
        case __enum_run_op__destroy_domain:
            if (vcpu->child) {
                std::cerr << "[0x" << std::hex << vcpu->id << std::dec << "] "
                          << " returned destroy; returning\n";
                return;
            } else {
                auto domid = run_op_ret_arg(ret);
                for (auto &child : root_vm.children) {
                    if (child.id == domid) {
                        std::cout << "[0x" << std::hex << vcpu->id << "] "
                                  << "destroying child 0x"
                                  << child.id << std::dec << ": ";

                        child.vcpu.halt = true;
                        child.vcpu.run.join();

                        if (__vcpu_op__destroy_vcpu(child.vcpu.id) != SUCCESS) {
                            std::cerr << " destroy vcpu failed\n";
                        } else if (__domain_op__destroy_domain(child.id) != SUCCESS) {
                            std::cerr << " destroy domain failed\n";
                        } else {
                            std::cout << "done\n";
                        }
                    }
                }

                root_vm.children.remove_if([domid](const struct vm &child) {
                    return child.id == domid;
                });

                break;
            }
        default:
            std::cerr << "[0x" << std::hex << vcpu->id << std::dec << "] ";
            std::cerr << "unknown vcpu ret: " << run_op_ret_op(ret) << '\n';
            return;
        }
    }
}

static void recv_from_uart(struct vm *vm)
{
    using namespace std::chrono;
    std::array<char, UART_MAX_BUFFER> buffer{};

    while (vm->enable_uart) {
        auto size = __domain_op__dump_uart(vm->id, buffer.data());
        std::cout.write(buffer.data(), gsl::narrow_cast<int>(size));
        std::this_thread::sleep_for(milliseconds(100));
    }

    auto size = __domain_op__dump_uart(vm->id, buffer.data());
    std::cout.write(buffer.data(), gsl::narrow_cast<int>(size));
}

static void recv_from_hvc(struct vm *vm)
{
    using namespace std::chrono;
    std::array<char, HVC_TX_SIZE> buf{};

    while (vm->enable_hvc) {
        auto size = __domain_op__hvc_tx_get(vm->id,
                                            buf.data(),
                                            HVC_TX_SIZE);
        std::cout.write(buf.data(), gsl::narrow_cast<int>(size));
        std::cout.flush();
        std::this_thread::sleep_for(milliseconds(100));
    }

    auto size = __domain_op__hvc_tx_get(vm->id,
                                        buf.data(),
                                        HVC_TX_SIZE);
    std::cout.write(buf.data(), gsl::narrow_cast<int>(size));
    std::cout.flush();
}

static void send_to_hvc(struct vm *vm)
{
    using namespace std::chrono;
    std::array<char, HVC_RX_SIZE> buf{};

    while (vm->enable_hvc) {
        std::cin.getline(buf.data(), buf.size());
        buf.data()[std::cin.gcount() - 1] = '\n';
        auto rc = __domain_op__hvc_rx_put(vm->id,
                                          buf.data(),
                                          std::cin.gcount());
        std::this_thread::sleep_for(milliseconds(100));
    }
}

/*
 * NB.1: this can't do anything fancy
 * NB.2: using this is technically undefined on Linux (see man signal)
 */
static void kill_vm(int sig)
{
    root_vm.vcpu.halt = true;
}

static void setup_kill_signal_handler(void)
{
    signal(SIGINT, kill_vm);
    signal(SIGTERM, kill_vm);

#ifdef SIGQUIT
    signal(SIGQUIT, kill_vm);
#endif
}

static int start_vm(struct vm *vm)
{
    if (bfack() == 0) {
        throw std::runtime_error("hypervisor not running");
    }

    /* Create a new vcpu */
    vm->vcpu.id = __vcpu_op__create_vcpu(vm->id);
    if (vm->vcpu.id == INVALID_VCPUID) {
        throw std::runtime_error("__vcpu_op__create_vcpu failed");
    }

    /* Run it */
    vm->vcpu.run = std::thread(run_vcpu, &vm->vcpu);

    /* Start up console IO if any */
    if (vm->enable_hvc) {
        vm->hvc_recv = std::thread(recv_from_hvc, vm);
        vm->hvc_send = std::thread(send_to_hvc, vm);
    } else if (vm->enable_uart) {
        vm->uart_recv = std::thread(recv_from_uart, vm);
    }

    /*
     * Now put this thread to sleep while the vcpu thread runs. Whenever
     * run_vcpu returns, join() returns, and we disable any console IO and
     * destroy any child vms that may have spawned from the root_vm.
     */
    vm->vcpu.run.join();

    if (vm->enable_hvc) {
        vm->enable_hvc = false;
        vm->hvc_recv.join();
        vm->hvc_send.join();
    } else if (vm->enable_uart) {
        vm->enable_uart = false;
        vm->uart_recv.join();
    }

    auto &children = vm->children;

    /* We halt each vm starting with the most-recently created first */
    for (auto cvm = children.begin(); cvm != children.end(); cvm++) {
        cvm->vcpu.halt = true;
        cvm->vcpu.run.join();
    }

    for (auto cvm = children.begin(); cvm != children.end(); cvm++) {
        if (__vcpu_op__destroy_vcpu(cvm->vcpu.id) != SUCCESS) {
            std::cerr << "failed to destroy child vcpu 0x"
                      << std::hex << cvm->vcpu.id << std::dec << " \n";
        }

        if (__domain_op__destroy_domain(cvm->id) != SUCCESS) {
            std::cerr << "failed to destroy child domain 0x"
                      << std::hex << cvm->id << std::dec << " \n";
        }
    }

    /* Now the children are destroyed, we destroy the root and return */
    if (__vcpu_op__destroy_vcpu(vm->vcpu.id) != SUCCESS) {
        std::cerr << "failed to destroy root_vm vcpu\n";
    }

    return EXIT_SUCCESS;
}

static uint64_t vm_file_type(const char *data, uint64_t size)
{
    /**
     * We support ELF (vmlinux) or bzImage. The latter
     * is identified by parsing the magic field in the
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

static void create_vm(const args_type &args, struct vm *vm)
{
    using namespace std::chrono;

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

    if (args.count("hvc")) {
        ioctl_args.hvc = 1;
        cmdl.add("console=hvc0");
    }

    if (args.count("ndvm")) {
        ioctl_args.ndvm = 1;
        cmdl.add("pci=nocrs,lastbus=0xff");
    }

    if (args.count("cmdline")) {
        cmdl.add(args["cmdline"].as<std::string>());
    }

    cmdl.add("idle=halt");

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
    ioctl_args.initdom = args.count("initdom");

    auto now = system_clock::now();
    auto tsc = __domain_op__read_tsc();
    ioctl_args.wc_sec = duration_cast<seconds>(now.time_since_epoch()).count();
    ioctl_args.wc_nsec = duration_cast<nanoseconds>(now.time_since_epoch()).count();
    ioctl_args.tsc = tsc;

    ctl->call_ioctl_create_vm(ioctl_args);
    dump_vm_create_verbose();

    vm->id = ioctl_args.domainid;
    vm->enable_uart = args.count("uart");
    vm->enable_hvc = args.count("hvc");
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

    create_vm(args, &root_vm);

    auto ___ = gsl::finally([&] {
        ctl->call_ioctl_destroy(root_vm.id);
    });

    return start_vm(&root_vm);
}

int
main(int argc, char *argv[])
{
    ctl = std::make_unique<ioctl>();
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
