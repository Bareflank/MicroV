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
#include "domain.h"
#include "vcpu.h"

using namespace std::chrono;
using namespace std::chrono_literals;

std::unique_ptr<ioctl> ctl{};
uint64_t nuke_vm = 0;

/*
 * TODO: man 2 signal states that using signal() for registering
 * a custom handler in a multithreaded program is undefined. We could
 * use sigaction but that is not available on Windows.
 */
static void drop_nuke(int sig)
{
    nuke_vm = 1;
}

static inline void setup_kill_signal_handler(void)
{
    signal(SIGINT, drop_nuke);
    signal(SIGTERM, drop_nuke);

#ifdef SIGQUIT
    signal(SIGQUIT, drop_nuke);
#endif
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

    const int bz_magic = 0x53726448;
    const struct setup_header *hdr = (struct setup_header *)(data + 0x1f1);
    if (hdr->header == bz_magic) {
        return VM_FILE_BZIMAGE;
    }

    throw std::invalid_argument("Unknown VM file type");
}

static uint64_t vm_exec_mode(uint64_t file_type)
{
    switch (file_type) {
        case VM_FILE_VMLINUX: return VM_EXEC_XENPVH;
        case VM_FILE_BZIMAGE: return VM_EXEC_NATIVE;
        default: throw std::invalid_argument("Unknown VM exec mode");
    }
}

static void create_vm(const args_type &args, struct uvc_domain *dom)
{
    using namespace std::chrono;

    create_vm_args ioctl_args{};

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

    dom->id = ioctl_args.domainid;
    dom->parent = nullptr;
    dom->enable_uart = args.count("uart");
    dom->enable_hvc = args.count("hvc");
}

static int protected_main(const args_type &args)
{
    if (bfack() == 0) {
        throw std::runtime_error("vmm not running");
    }

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

    struct uvc_domain root_domain;
    create_vm(args, &root_domain);
    root_domain.launch();

    while (!nuke_vm) {
        std::this_thread::sleep_for(200ms);
    }

    try {
        root_domain.destroy();
    } catch (const std::exception &e) {
        printf("root_domain.destroy threw: what = %s\n", e.what());
    }

    ctl->call_ioctl_destroy(root_domain.id);
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
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
