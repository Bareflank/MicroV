/*
 * Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef COMMON_H
#define COMMON_H

#include <bftypes.h>
#include <bferrorcodes.h>
#include <bfelf_loader.h>
#include <bfbuilderinterface.h>

#define HYPERVISOR_NOT_LOADED bfscast(status_t, 0x8000000000000001)
#define CREATE_FROM_ELF_FAILED bfscast(status_t, 0x8000000000000002)
#define DESTROY_FAILED bfscast(status_t, 0x8000000000000003)

struct vm_t {
    struct bfelf_loader_t bfelf_loader;
    struct bfelf_binary_t bfelf_binary;

    uint32_t entry;
    uint64_t domainid;

    void *bios_ram;
    void *zero_page;

    struct hvm_start_info *xen_start_info;
    char *xen_cmdl;
    void *xen_console;

    int used;
};

/**
 * Create VM from ELF
 *
 * The following function builds a guest VM based on a provided ELF file.
 * To accomplish this, the following function will allocate RAM, load RAM
 * with the contents of the provided ELF file, and then set up the guest's
 * memory map.
 *
 * @param vm the vm_t object associated with the vm
 * @param args the create_from_elf_args arguments needed to create the VM
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_create_from_elf(struct vm_t *vm, struct create_from_elf_args *args);

/**
 * Destroy VM
 *
 * This function will destory a VM by telling the hypervisor to remove all
 * internal resources associated with the VM.
 *
 * @param vm the vm_t object associated with the vm
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_destroy(struct vm_t *vm);

#endif
