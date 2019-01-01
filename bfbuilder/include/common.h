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
#include <bfbuilderinterface.h>

/* -------------------------------------------------------------------------- */
/* Error Codes                                                                */
/* -------------------------------------------------------------------------- */

#define COMMON_NO_HYPERVISOR bfscast(status_t, 0x8000000000000001)
#define COMMON_CREATE_VM_FROM_BZIMAGE_FAILED bfscast(status_t, 0x8000000000000002)

/* -------------------------------------------------------------------------- */
/* Functions                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Create VM from bzImage
 *
 * The following function builds a guest VM based on a provided bzImage.
 * To accomplish this, the following function will allocate RAM, load RAM
 * with the contents of the provided file, and then set up the guest's
 * memory map.
 *
 * @param args the create_vm_from_bzimage_args arguments needed to create the VM
 * @return SUCCESS on success, negative error code on failure
 */
int64_t
common_create_vm_from_bzimage(struct create_vm_from_bzimage_args *args);

/**
 * Destroy VM
 *
 * This function will destory a VM by telling the hypervisor to remove all
 * internal resources associated with the VM.
 *
 * @param domainid the domain to destroy
 * @return SUCCESS on success, negative error code on failure
 */
int64_t
common_destroy(uint64_t domainid);

#endif
