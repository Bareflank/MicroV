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

#ifndef UVCTL_VERBOSE_H
#define UVCTL_VERBOSE_H

#include "log.h"

#define dump_vm_create_verbose()                                               \
    do {                                                                       \
        if (verbose) {                                                         \
            log_msg("Created VM:\n");                                          \
            log_msg("    kernel | %s\n", kernel.path().c_str());               \
            log_msg("    initrd | %s\n", initrd.path().c_str());               \
            log_msg(" domain id | 0x%x\n", ioctl_args.domainid);               \
            log_msg("  ram size | %luMB\n", (ram / 0x100000U));                \
            log_msg("   cmdline | %s\n", cmdl.data());                         \
            log_msg(" file type | %s\n",                                       \
                    (ioctl_args.file_type == VM_FILE_VMLINUX) ? "vmlinux"      \
                                                              : "bzImage");    \
            log_msg(" exec mode | %s\n",                                       \
                    (ioctl_args.exec_mode == VM_EXEC_XENPVH) ? "xenpvh"        \
                                                             : "native");      \
        }                                                                      \
    } while (0)

#endif
