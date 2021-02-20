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

#ifndef UVCTL_ARGS_H
#define UVCTL_ARGS_H

#ifdef _WIN64
#pragma warning(push)
#pragma warning(disable : 4267)
#include <malloc.h>
#endif

#include "cxxopts.hpp"
#include "log.h"

#ifdef _WIN64
#pragma warning(pop)
#endif

#include <microv/hypercall.h>

#include <cstdlib>
#include <mutex>

using args_type = cxxopts::ParseResult;

inline bool verbose = false;

inline std::mutex orig_arg_mutex;
inline int orig_argc = 0;
inline char **orig_argv = nullptr;

inline args_type parse_args(int argc, char *argv[])
{
    using namespace cxxopts;
    cxxopts::Options options("uvctl", "control a microv virtual machine");

    // clang-format off
    options.add_options()
    ("h,help", "Print this help menu")
    ("v,verbose", "Enable verbose output")
    ("affinity", "The host CPU to execute the VM on", value<uint64_t>(), "[core #]")
    ("kernel", "The VM's kernel", value<std::string>(), "[path]")
    ("initrd", "The VM's initrd", value<std::string>(), "[path]")
    ("ram", "The VM's total RAM", value<uint64_t>(), "[bytes]")
    ("cmdline", "Additional Linux command line arguments", value<std::string>(), "[text]")
    ("uart", "Give the VM an emulated UART", value<uint64_t>(), "[port #]")
    ("pt_uart", "Pass-through a host UART to the VM", value<uint64_t>(), "[port #]")
    ("xsvm", "The VM is a xenstore VM")
    ("ndvm", "The VM is a network device VM")
    ("hvc", "Use the hvc console")
#ifdef _WIN64
    ("windows-svc", "Run uvctl as a Windows service")
#endif
    ("high-priority", "Run VM threads at high priority");
    // clang-format on

    auto args = options.parse(argc, argv);

    if (args.count("help")) {
        log_msg("%s\n", options.help().c_str());
        exit(EXIT_SUCCESS);
    }

    if (args.count("verbose")) {
        verbose = true;
    }

    return args;
}

inline args_type parse_orig_args()
{
    std::lock_guard lock(orig_arg_mutex);

    return parse_args(orig_argc, orig_argv);
}

inline int copy_args(int argc, char **argv)
{
    if (argc == 0) {
        return -1;
    }

    std::lock_guard lock(orig_arg_mutex);

    orig_argc = argc;
    orig_argv = (char **)malloc(sizeof(char *) * argc);

    if (!orig_argv) {
        log_msg("%s: failed to malloc orig_argv\n", __func__);
        return -1;
    }

    for (int i = 0; i < argc; i++) {
        orig_argv[i] = (char *)malloc(strlen(argv[i]) + 1);

        if (!orig_argv[i]) {
            log_msg("%s: failed to malloc orig_argv[%d]\n", __func__, i);

            for (int j = i - 1; j >= 0; j--) {
                free(orig_argv[j]);
            }

            goto free_argv;
        }

        memcpy(orig_argv[i], argv[i], strlen(argv[i]) + 1);
    }

    return 0;

free_argv:
    free(orig_argv);
    orig_argv = nullptr;

    return -1;
}

inline void free_args()
{
    std::lock_guard lock(orig_arg_mutex);

    if (!orig_argv) {
        return;
    }

    for (int i = 0; i < orig_argc; i++) {
        free(orig_argv[i]);
    }

    free(orig_argv);
    orig_argv = nullptr;
}

#endif
