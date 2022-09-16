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
#include <stdlib.h>

#include <bfack.h>
#include <bfgsl.h>
#include <bfdebug.h>
#include <bfstring.h>
#include <bfaffinity.h>

#include <microv/bootparams.h>
#include <microv/builderinterface.h>
#include <microv/hypercall.h>
#include <microv/xenbusinterface.h>

#include "args.h"
#include "cmdl.h"
#include "file.h"
#include "ioctl.h"
#include "log.h"
#include "verbose.h"
#include "domain.h"
#include "vcpu.h"

#ifdef _WIN64
#include "service.h"
#endif

using namespace std::chrono;
using namespace std::chrono_literals;

std::unique_ptr<ioctl> ctl{};
uint64_t nuke_vm = 0;

#ifdef _WIN64
HANDLE uvctl_ioctl_open(const GUID *guid);
int64_t uvctl_rw_ioctl(HANDLE fd, DWORD request, void *data, DWORD size);
#endif

#ifdef XEN_READCONSOLE_ROOTVM
extern "C" uint64_t _xen_hypercall(uint64_t r1,
                                   uint64_t r2,
                                   uint64_t r3,
                                   uint64_t r4,
                                   uint64_t r5,
                                   uint64_t r6);

/* defined in "../deps/xen/xen/include/public/sysctl.h" */
#define XEN_SYSCTL_INTERFACE_VERSION 0x00000012
#define __HYPERVISOR_sysctl 35
/*
 * Read console content from Xen buffer ring.
 */
/* XEN_SYSCTL_readconsole */
struct xen_sysctl_readconsole {
    /* IN: Non-zero -> clear after reading. */
    uint8_t clear;
    /* IN: Non-zero -> start index specified by @index field. */
    uint8_t incremental;
    uint8_t pad0, pad1;
    /*
     * IN:  Start index for consuming from ring buffer (if @incremental);
     * OUT: End index after consuming from ring buffer.
     */
    uint32_t index;
    /* IN: Virtual address to write console data. */
    char *buffer;
    /* IN: Size of buffer; OUT: Bytes written to buffer. */
    uint32_t count;
};
struct xen_sysctl {
    uint32_t cmd;
#define XEN_SYSCTL_readconsole 1
    uint32_t interface_version; /* XEN_SYSCTL_INTERFACE_VERSION */
    union
    {
        struct xen_sysctl_readconsole readconsole;
        uint8_t pad[128];
    } u;
};
typedef struct xen_sysctl xen_sysctl_t;

void do_dmesg()
{
    status_t ret;
    xen_sysctl_t sysctl{};
    sysctl.cmd = XEN_SYSCTL_readconsole;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;

    auto &cr = sysctl.u.readconsole;

    const unsigned int size = 16384;

#ifdef _MSC_VER
    cr.buffer = (char *)_aligned_malloc(size, BAREFLANK_PAGE_SIZE);
#else
    cr.buffer = (char *)aligned_alloc(BAREFLANK_PAGE_SIZE, size);
#endif
    cr.count = size;
    cr.clear = 0;
    cr.incremental = 1;

    memset(cr.buffer, 0, size);

    while ((ret = _xen_hypercall(
                __HYPERVISOR_sysctl, (uint64_t)&sysctl, 0, 0, 0, 0)) == 0 &&
           cr.count != 0) {
        // printf("%s: ret %lld idx %x count %x buffer %p\n", __func__, ret, cr.index, cr.count, cr.buffer);
        printf("%s", cr.buffer);
    }

    if (ret < 0) {
        log_msg(
            "%s: reading console ring buffer failed (%lld)\n", __func__, ret);
    }

    free(cr.buffer);
}
#endif

/*
 * TODO: man 2 signal states that using signal() for registering
 * a custom handler in a multithreaded program is undefined. We could
 * use sigaction but that is not available on Windows.
 */
static void drop_nuke(int sig)
{
    nuke_vm = 1;
}

static inline void wait_for_stop_signal(bool windows_svc)
{
#ifdef _WIN64
    if (windows_svc) {
        service_wait_for_stop_signal();
    } else {
        while (!nuke_vm) {
            std::this_thread::sleep_for(1s);
        }
    }
#else
    while (!nuke_vm) {
        std::this_thread::sleep_for(1s);
    }
#endif
}

static inline void setup_kill_signal_handler(void)
{
    signal(SIGINT, drop_nuke);
    signal(SIGTERM, drop_nuke);

#ifdef SIGQUIT
    signal(SIGQUIT, drop_nuke);
#endif
}

static uint32_t vm_file_type(const char *data, uint64_t size)
{
    /**
     * We support ELF (vmlinux) or bzImage. The latter
     * is identified by parsing the magic field in the
     * setup_header, so we make sure size is big enough.
     */
    expects(size > 0x1f1 + sizeof(struct setup_header));

    const char elf_magic[4] = {0x7F, 'E', 'L', 'F'};
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

static uint32_t vm_exec_mode(uint64_t file_type)
{
    switch (file_type) {
    case VM_FILE_VMLINUX:
        return VM_EXEC_XENPVH;
    case VM_FILE_BZIMAGE:
        return VM_EXEC_NATIVE;
    default:
        throw std::invalid_argument("Unknown VM exec mode");
    }
}

static uvc_domain create_vm(const args_type &args)
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
        cmdl.add("console=uart,io," + bfn::to_string(uart, 16) + ",115200n8");
    }

    uint64_t pt_uart = 0;
    if (args.count("pt_uart")) {
        pt_uart = args["pt_uart"].as<uint64_t>();
        cmdl.add("console=uart,io," + bfn::to_string(pt_uart, 16) +
                 ",115200n8,keep");
    }

    if (args.count("hvc")) {
        ioctl_args.hvc = 1;
        cmdl.add("console=hvc0");
    }

    if (args.count("ndvm")) {
        ioctl_args.has_passthrough_dev = 1;
        cmdl.add("pci=nocrs,lastbus=0xff");
    }

    if (args.count("xsvm")) {
        ioctl_args.xsvm = 1;
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

    auto now = system_clock::now();
    auto tsc = __domain_op__read_tsc();
    ioctl_args.wc_sec = duration_cast<seconds>(now.time_since_epoch()).count();
    ioctl_args.wc_nsec =
        duration_cast<nanoseconds>(now.time_since_epoch()).count();
    ioctl_args.tsc = tsc;

    ctl->call_ioctl_create_vm(ioctl_args);
    dump_vm_create_verbose();

    return uvc_domain(
        ioctl_args.domainid, nullptr, args.count("uart"), args.count("hvc"));
}

int protected_main(const args_type &args)
{
    if (bfack() == 0) {
        throw std::runtime_error("vmm not running");
    }

    if (!args.count("kernel")) {
        throw std::runtime_error("must specify 'kernel'");
    }

    if (!args.count("initrd")) {
        throw std::runtime_error("must specify 'initrd'");
    }

    if (args.count("affinity")) {
        set_affinity(args["affinity"].as<uint64_t>());
    } else {

        // TODO:
        //
        // We need to remove the need for affinity. Right now if you don't
        // state affinity, we default to 0 because we don't support VMCS
        // migration, which needs to be fixed.
        //

        set_affinity(0);
    }

    if (args.count("high-priority")) {
#ifdef _WIN64
        if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
            log_msg("%s: SetPriorityClass failed (err=0x%x)\n",
                    __func__,
                    GetLastError());
        }
#endif
    }

    bool windows_svc = args.count("windows-svc") != 0;

    auto &&root_domain = create_vm(args);
    root_domain.launch();

    wait_for_stop_signal(windows_svc);

    if (!windows_svc) {
        try {
            root_domain.destroy();
        }
        catch (const std::exception &e) {
            log_msg("root_domain.destroy threw: what = %s\n", e.what());
        }

        ctl->call_ioctl_destroy(root_domain.id());
    } else {
        root_domain.pause();
        std::this_thread::sleep_for(2s);

        if (__domain_op__reclaim_root_pages(root_domain.id()) != SUCCESS) {
            log_msg("%s: failed to reclaim root pages\n", __func__);
        }

#ifdef _WIN64
        // TODO: consolidate the various ioctls
        HANDLE xenbus_fd = uvctl_ioctl_open(&GUID_DEVINTERFACE_XENBUS);
        if (xenbus_fd == INVALID_HANDLE_VALUE) {
            log_msg("%s: failed to open xenbus handle (err=0x%x)\n",
                    __func__,
                    GetLastError());
        } else {
            XENBUS_SET_BACKEND_STATE_IN state{};
            state.BackendState = XENBUS_BACKEND_STATE_DYING;

            auto rc = uvctl_rw_ioctl(xenbus_fd,
                                     IOCTL_XENBUS_SET_BACKEND_STATE,
                                     &state,
                                     sizeof(state));
            if (rc < 0) {
                log_msg("%s: failed to set backend state for xenbus\n",
                        __func__);
            }

            CloseHandle(xenbus_fd);
        }
        service_post_tasks();
#endif
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    try {
        log_set_mode(UVCTL_LOG_STDOUT);
        args_type args = parse_args(argc, argv);
#ifndef _WIN64
        setup_kill_signal_handler();
        ctl = std::make_unique<ioctl>();
        return protected_main(args);
#else
#ifdef XEN_READCONSOLE_ROOTVM
        if (args.count("dmesg")) {
            do_dmesg();
            return EXIT_SUCCESS;
        }
#endif
        if (args.count("windows-svc")) {
            log_set_mode(UVCTL_LOG_WINDOWS_SVC);

            if (copy_args(argc, argv)) {
                log_msg("uvctl: unable to copy args for Windows service\n");
                return EXIT_FAILURE;
            }

            service_start();
            free_args();

            return EXIT_SUCCESS;
        } else {
            setup_kill_signal_handler();
            ctl = std::make_unique<ioctl>();
            return protected_main(args);
        }
#endif
    }
    catch (const cxxopts::OptionException &e) {
        log_msg("invalid arguments: %s\n", e.what());
    }
    catch (const std::exception &e) {
        log_msg("Caught unhandled exception: what = %s\n", e.what());
    }
    catch (...) {
        log_msg("Caught unknown exception\n");
    }

    return EXIT_FAILURE;
}
