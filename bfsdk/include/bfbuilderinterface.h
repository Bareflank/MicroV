/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef BUILDERINTERFACE_H
#define BUILDERINTERFACE_H

#include <bftypes.h>
#include "bfhypercall.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Common                                                                     */
/* -------------------------------------------------------------------------- */

#ifndef BUILDER_NAME
#define BUILDER_NAME "bareflank_builder"
#endif

#ifndef BUILDER_MAJOR
#define BUILDER_MAJOR 151
#endif

#ifndef BUILDER_DEVICETYPE
#define BUILDER_DEVICETYPE 0xF00D
#endif

#define IOCTL_CREATE_VM_FROM_BZIMAGE_CMD 0x901
#define IOCTL_DESTROY_CMD 0x902

/**
 * Virtual machine types
 */
enum {
    VM_LINUX_BZIMAGE,
    VM_LINUX_VMLINUX
};

/**
 * @struct create_vm_args
 *
 * This structure is used to create a VM from a Linux image. The image may
 * either be a bzImage or vmlinux. This is the information the builder needs to
 * create a domain and load its resources prior to execution.
 *
 * @var img
 *     the image to load
 * @var type
 *     the type of of the image
 * @var initrd
 *     the initrd to load
 * @var initrd_size
 *     the length of the initrd to load
 * @var cmdl
 *     the command line arguments to pass to the Linux kernel on boot
 * @var cmdl_size
 *     the length of the command line arguments
 * @var uart
 *     defaults to 0 (optional). If non zero, the hypervisor will be told to
 *     emulate the provided uart.
 * @var pt_uart
 *     defaults to 0 (optional). If non zero, the hypervisor will be told to
 *     pass-through the provided uart.
 * @var ram
 *     the amount of RAM to give to the domain (in MB)
 * @var domainid
 *     (out) the domain ID of the VM that was created
 */

struct create_vm_args {
    uint64_t type;

    const char *kernel;
    uint64_t kernel_size;

    const char *initrd;
    uint64_t initrd_size;

    const char *cmdl;
    uint64_t cmdl_size;

    uint64_t uart;
    uint64_t pt_uart;

    uint64_t ram;
    uint64_t domainid;
};

/* -------------------------------------------------------------------------- */
/* Linux Interfaces                                                           */
/* -------------------------------------------------------------------------- */

#ifdef __linux__

#define IOCTL_CREATE_VM_FROM_BZIMAGE _IOWR(BUILDER_MAJOR, IOCTL_CREATE_VM_FROM_BZIMAGE_CMD, struct create_vm_args *)
#define IOCTL_DESTROY _IOW(BUILDER_MAJOR, IOCTL_DESTROY_CMD, domainid_t *)

#endif

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)

#include <initguid.h>

DEFINE_GUID(GUID_DEVINTERFACE_builder,
    0x0156f59a, 0xdf90, 0x4ac6, 0x85, 0x3d, 0xcf, 0xd9, 0x3e, 0x25, 0x65, 0xc2);

#define IOCTL_CREATE_VM_FROM_BZIMAGE CTL_CODE(BUILDER_DEVICETYPE, IOCTL_CREATE_VM_FROM_BZIMAGE_CMD, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_DESTROY CTL_CODE(BUILDER_DEVICETYPE, IOCTL_DESTROY_CMD, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

#endif

#ifdef __cplusplus
}
#endif

#endif
