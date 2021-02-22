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

#include <ntddk.h>

#include <bfdebug.h>
#include <bfplatform.h>
#include <common.h>

#define BUILDER_TAG 'RDLB'

FAST_MUTEX g_mutex;

int64_t
platform_init(void)
{
    ExInitializeFastMutex(&g_mutex);
    return BF_SUCCESS;
}

void *
platform_alloc_rw(uint64_t len)
{
    void *addr = nullptr;

    if (len == 0) {
        BFALERT("platform_alloc: invalid length\n");
        return addr;
    }

    addr = ExAllocatePoolWithTag(NonPagedPoolNx, len, BUILDER_TAG);

    if (addr == nullptr) {
        BFALERT("platform_alloc_rw: failed to ExAllocatePoolWithTag mem: %lld\n", len);
    }

    return addr;
}

void
platform_free_rw(void *addr, uint64_t len)
{
    (void) len;

    if (addr == nullptr) {
        BFALERT("platform_free_rw: invalid address %p\n", addr);
        return;
    }

    ExFreePoolWithTag(addr, BUILDER_TAG);
}

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

int64_t
platform_memcpy(
    void *dst, uint64_t dst_size, const void *src, uint64_t src_size, uint64_t num)
{
    if (dst == 0 || src == 0) {
        BFALERT("platform_memcpy: invalid dst or src\n");
        return FAILURE;
    }

    if (num > dst_size || num > src_size) {
        BFALERT("platform_memcpy: num out of range\n");
        return FAILURE;
    }

    RtlCopyMemory(dst, src, num);
    return SUCCESS;
}

_IRQL_raises_(APC_LEVEL)
_IRQL_saves_global_(OldIrql, ignored)
void
platform_acquire_mutex(void *ignored)
{
    (void)ignored;
    ExAcquireFastMutex(&g_mutex);
}

_IRQL_requires_(APC_LEVEL)
_IRQL_restores_global_(OldIrql, ignored)
void
platform_release_mutex(void *ignored)
{
    (void)ignored;
    ExReleaseFastMutex(&g_mutex);
}

#define TIME_US(us) ((us) * 10)
#define TIME_RELATIVE(t) (-(t))

void
platform_usleep(int64_t usec)
{
    LARGE_INTEGER Timeout;

    Timeout.QuadPart = TIME_RELATIVE(TIME_US(usec));
    KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
}
