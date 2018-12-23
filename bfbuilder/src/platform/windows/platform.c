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

#include <ntddk.h>

#include <bfdebug.h>
#include <bfplatform.h>
#include <common.h>

#define BD_TAG 'BDLK'
#define BD_NX_TAG 'BDNX'

int64_t
platform_init(void)
{ return BF_SUCCESS; }

void *
platform_alloc_rw(uint64_t len)
{
    void *addr = nullptr;

    if (len == 0) {
        BFALERT("platform_alloc: invalid length\n");
        return addr;
    }

    addr = ExAllocatePoolWithTag(NonPagedPool, len, BD_TAG);

    if (addr == nullptr) {
        BFALERT("platform_alloc_rw: failed to ExAllocatePoolWithTag mem: %lld\n", len);
    }

    return addr;
}

void *
platform_alloc_rwe(uint64_t len)
{ return platform_alloc_rw(len); }

void
platform_free_rw(void *addr, uint64_t len)
{
    (void) len;

    if (addr == nullptr) {
        BFALERT("platform_free_rw: invalid address %p\n", addr);
        return;
    }

    ExFreePoolWithTag(addr, BD_TAG);
}

void
platform_free_rwe(void *addr, uint64_t len)
{ platform_free_rw(addr, len); }

void *
platform_virt_to_phys(void *virt)
{
    PHYSICAL_ADDRESS addr = MmGetPhysicalAddress(virt);
    return (void *)addr.QuadPart;
}

void *
platform_memset(void *ptr, char value, uint64_t num)
{
    if (ptr == nullptr) {
        return nullptr;
    }

    RtlFillMemory(ptr, num, value);
    return ptr;
}

void *
platform_memcpy(void *dst, const void *src, uint64_t num)
{
    if (dst == nullptr || src == nullptr) {
        return nullptr;
    }

    RtlCopyMemory(dst, src, num);
    return dst;
}
