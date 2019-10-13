/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

#undef  XEN_API
#define XEN_API __declspec(dllexport)

#include <ntddk.h>
#include <xen.h>

#include "hypercall.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define MAXIMUM_HYPERCALL_PAGE_COUNT 2

#pragma code_seg("hypercall")
__declspec(allocate("hypercall"))
static UCHAR        __Section[(MAXIMUM_HYPERCALL_PAGE_COUNT + 1) * PAGE_SIZE];

static ULONG        XenBaseLeaf = 0x40000000;

static PHYSICAL_ADDRESS HypercallPage[MAXIMUM_HYPERCALL_PAGE_COUNT];
static ULONG            HypercallPageCount;
static BOOLEAN          HypercallPageInitialized;

typedef UCHAR           HYPERCALL_GATE[32];
typedef HYPERCALL_GATE  *PHYPERCALL_GATE;

PHYPERCALL_GATE     Hypercall;
ULONG               HypercallMsr;

XEN_API
VOID
HypercallPopulate(
    VOID
    )
{
    ULONG       Index;

    for (Index = 0; Index < HypercallPageCount; Index++) {
        LogPrintf(LOG_LEVEL_INFO,
                  "XEN: HYPERCALL PAGE %d @ %08x.%08x\n",
                  Index,
                  HypercallPage[Index].HighPart,
                  HypercallPage[Index].LowPart);

        __writemsr(HypercallMsr, HypercallPage[Index].QuadPart);
    }

    HypercallPageInitialized = TRUE;
}

VOID
HypercallInitialize(
    VOID
    )
{
    ULONG       EAX = 'DEAD';
    ULONG       EBX = 'DEAD';
    ULONG       ECX = 'DEAD';
    ULONG       EDX = 'DEAD';
    ULONG_PTR   Index;

    for (;;) {
        CHAR    Signature[13] = {0};

        __CpuId(XenBaseLeaf, &EAX, &EBX, &ECX, &EDX);
        *((PULONG)(Signature + 0)) = EBX;
        *((PULONG)(Signature + 4)) = ECX;
        *((PULONG)(Signature + 8)) = EDX;

        if (strcmp(Signature, "XenVMMXenVMM") == 0 &&
            EAX >= XenBaseLeaf + 2)
            break;
            
        XenBaseLeaf += 0x100;
        
        if (XenBaseLeaf > 0x40000100) {
            LogPrintf(LOG_LEVEL_INFO,
                      "XEN: BASE CPUID LEAF NOT FOUND\n");
            return;
        }
    }

    LogPrintf(LOG_LEVEL_INFO,
              "XEN: BASE CPUID LEAF @ %08x\n",
              XenBaseLeaf);

    if ((ULONG_PTR)__Section & (PAGE_SIZE - 1))
        Hypercall = (PVOID)(((ULONG_PTR)__Section + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    else
        Hypercall = (PVOID)__Section;

    ASSERT3U(((ULONG_PTR)Hypercall & (PAGE_SIZE - 1)), ==, 0);

    for (Index = 0; Index < MAXIMUM_HYPERCALL_PAGE_COUNT; Index++)
        HypercallPage[Index] = MmGetPhysicalAddress((PUCHAR)Hypercall +
                                                    (Index << PAGE_SHIFT));

    __CpuId(XenBaseLeaf + 2, &EAX, &EBX, NULL, NULL);
    HypercallPageCount = EAX;
    ASSERT(HypercallPageCount <= MAXIMUM_HYPERCALL_PAGE_COUNT);
    HypercallMsr = EBX;

    HypercallPopulate();
}

extern uintptr_t __stdcall hypercall2(uint32_t ord, uintptr_t arg1, uintptr_t arg2);
extern uintptr_t __stdcall hypercall3(uint32_t ord, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

LONG_PTR
__Hypercall(
    ULONG       Ordinal,
    ULONG       Count,
    ...
    )
{
    va_list     Arguments;
    ULONG_PTR   Value;

    if (!HypercallPageInitialized)
        return -ENOSYS;

    va_start(Arguments, Count);
    switch (Count) {
    case 2: {
        uint32_t   ord = Ordinal;
        uintptr_t  arg1 = va_arg(Arguments, ULONG_PTR);
        uintptr_t  arg2 = va_arg(Arguments, ULONG_PTR);

        Value = hypercall2(ord, arg1, arg2);
        break;
    }
    case 3: {
        uint32_t   ord = Ordinal;
        uintptr_t  arg1 = va_arg(Arguments, ULONG_PTR);
        uintptr_t  arg2 = va_arg(Arguments, ULONG_PTR);
        uintptr_t  arg3 = va_arg(Arguments, ULONG_PTR);

        Value = hypercall3(ord, arg1, arg2, arg3);
        break;
    }
    default:
        ASSERT(FALSE);
        Value = 0;
    }
    va_end(Arguments);

    return Value;
}

VOID
HypercallTeardown(
    VOID
    )
{
    ULONG   Index;

    Hypercall = NULL;

    for (Index = 0; Index < MAXIMUM_HYPERCALL_PAGE_COUNT; Index++)
        HypercallPage[Index].QuadPart = 0;

    HypercallPageCount = 0;
}
