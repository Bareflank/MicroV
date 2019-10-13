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

#include <ntddk.h>
#include <stdlib.h>
#include <xen.h>

#include "mutex.h"
#include "balloon.h"
#include "range_set.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define MDL_SIZE_MAX        ((1 << (RTL_FIELD_SIZE(MDL, Size) * 8)) - 1)
#define MAX_PAGES_PER_MDL   ((MDL_SIZE_MAX - sizeof(MDL)) / sizeof(PFN_NUMBER))

#define XENBUS_BALLOON_PFN_ARRAY_SIZE  (MAX_PAGES_PER_MDL)

typedef struct _XENBUS_BALLOON_FIST {
    BOOLEAN Inflation;
    BOOLEAN Deflation;
} XENBUS_BALLOON_FIST, *PXENBUS_BALLOON_FIST;

struct _XENBUS_BALLOON_CONTEXT {
    PXENBUS_FDO                 Fdo;
    KSPIN_LOCK                  Lock;
    LONG                        References;
    PKEVENT                     LowMemoryEvent;
    HANDLE                      LowMemoryHandle;
    ULONGLONG                   Size;
    MDL                         Mdl;
    PFN_NUMBER                  PfnArray[XENBUS_BALLOON_PFN_ARRAY_SIZE];
    XENBUS_RANGE_SET_INTERFACE  RangeSetInterface;
    PXENBUS_RANGE_SET           RangeSet;
    XENBUS_STORE_INTERFACE      StoreInterface;
    XENBUS_BALLOON_FIST         FIST;
};

#define XENBUS_BALLOON_TAG   'LLAB'

static FORCEINLINE PVOID
__BalloonAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_BALLOON_TAG);
}

static FORCEINLINE VOID
__BalloonFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_BALLOON_TAG);
}

#define SWAP_NODES(_PfnArray, _X, _Y)       \
    do {                                    \
        PFN_NUMBER  _Pfn = _PfnArray[(_Y)]; \
                                            \
        _PfnArray[_Y] = _PfnArray[_X];      \
        _PfnArray[_X] = _Pfn;               \
    } while (FALSE)

static VOID
BalloonHeapPushDown(
    IN  PPFN_NUMBER Heap,
    IN  ULONG       Start,
    IN  ULONG       Count
    )
{
    ULONG           LeftChild;
    ULONG           RightChild;

again:
    LeftChild = Start * 2 + 1;
    RightChild = Start * 2 + 2;

    if (RightChild < Count) {
        ASSERT(Heap[LeftChild] != Heap[Start]);
        ASSERT(Heap[RightChild] != Heap[Start]);
        ASSERT(Heap[LeftChild] != Heap[RightChild]);

        if (Heap[LeftChild] < Heap[Start] &&
            Heap[RightChild] < Heap[Start])
            return;

        if (Heap[LeftChild] < Heap[Start] &&
            Heap[RightChild] > Heap[Start]) {
            SWAP_NODES(Heap, RightChild, Start);
            ASSERT(Heap[RightChild] < Heap[Start]);
            Start = RightChild;
            goto again;
        }

        if (Heap[RightChild] < Heap[Start] &&
            Heap[LeftChild] > Heap[Start]) {
            SWAP_NODES(Heap, LeftChild, Start);
            ASSERT(Heap[LeftChild] < Heap[Start]);
            Start = LeftChild;
            goto again;
        }

        // Heap[LeftChild] > Heap[Start] && Heap[RightChild] > Heap[Start]
        if (Heap[LeftChild] > Heap[RightChild]) {
            SWAP_NODES(Heap, LeftChild, Start);
            ASSERT(Heap[LeftChild] < Heap[Start]);
            Start = LeftChild;
        } else {
            SWAP_NODES(Heap, RightChild, Start);
            ASSERT(Heap[RightChild] < Heap[Start]);
            Start = RightChild;
        }

        goto again;
    }

    if (LeftChild < Count) {    // Only one child
        ASSERT(Heap[LeftChild] != Heap[Start]);
        if (Heap[LeftChild] < Heap[Start])
            return;

        SWAP_NODES(Heap, LeftChild, Start);
        ASSERT(Heap[LeftChild] < Heap[Start]);
        Start = LeftChild;
        goto again;
    }
}

// Turn an array of PFNs into a max heap (largest node at root)
static VOID
BalloonCreateHeap(
    IN  PPFN_NUMBER PfnArray,
    IN  ULONG       Count
    )
{
    LONG            Index = (LONG)Count;

    while (--Index >= 0)
        BalloonHeapPushDown(PfnArray, (ULONG)Index, Count);
}

static VOID
BalloonSort(
    IN  PXENBUS_BALLOON_CONTEXT Context,
    IN  ULONG                   Count
    )
{
    PPFN_NUMBER                 PfnArray;
    ULONG                       Unsorted;
    ULONG                       Index;

    PfnArray = Context->PfnArray;

    // Heap sort to keep stack usage down
    BalloonCreateHeap(PfnArray, Count);

    for (Unsorted = Count; Unsorted != 0; --Unsorted) {
        SWAP_NODES(PfnArray, 0, Unsorted - 1);
        BalloonHeapPushDown(PfnArray, 0, Unsorted - 1);
    }

    for (Index = 0; Index < Count - 1; Index++)
        ASSERT3U(PfnArray[Index], <, PfnArray[Index + 1]);
}

static PMDL
BalloonAllocatePagesForMdl(
    IN  ULONG       Count
    )
{
    LARGE_INTEGER   LowAddress;
    LARGE_INTEGER   HighAddress;
    LARGE_INTEGER   SkipBytes;
    SIZE_T          TotalBytes;
    PMDL            Mdl;

    LowAddress.QuadPart = 0ull;
    HighAddress.QuadPart = ~0ull;
    SkipBytes.QuadPart = 0ull;
    TotalBytes = (SIZE_T)Count << PAGE_SHIFT;
    
    Mdl = MmAllocatePagesForMdlEx(LowAddress,
                                  HighAddress,
                                  SkipBytes,
                                  TotalBytes,
                                  MmCached,
                                  MM_DONT_ZERO_ALLOCATION);
    if (Mdl == NULL)
        goto done;

    ASSERT((Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA |
                             MDL_PARTIAL_HAS_BEEN_MAPPED |
                             MDL_PARTIAL |
                             MDL_PARENT_MAPPED_SYSTEM_VA |
                             MDL_SOURCE_IS_NONPAGED_POOL |
                             MDL_IO_SPACE)) == 0);

done:
    return Mdl;
}

static VOID
BalloonFreePagesFromMdl(
    IN  PMDL        Mdl,
    IN  BOOLEAN     Check
    )
{
    volatile UCHAR  *Mapping;
    ULONG           Index;

    if (!Check)
        goto done;

    // Sanity check:
    //
    // Make sure that things written to the page really do stick. 
    // If the page is still ballooned out at the hypervisor level
    // then writes will be discarded and reads will give back
    // all 1s.

    Mapping = MmMapLockedPagesSpecifyCache(Mdl,
                                           KernelMode,
                                           MmCached,
                                           NULL,
                                           FALSE,
                                           LowPagePriority);
    if (Mapping == NULL)
        // Windows couldn't map the memory. That's kind of sad, but not
        // really an error: it might be that we're very low on kernel
        // virtual address space.
        goto done;

    // Write and read the first byte in each page to make sure it's backed
    // by RAM.
    ASSERT((Mdl->ByteCount & (PAGE_SIZE - 1)) == 0);

    for (Index = 0; Index < (Mdl->ByteCount >> PAGE_SHIFT); Index++) {
        UCHAR   Byte;

        ASSERT3U(Index << PAGE_SHIFT, <, Mdl->ByteCount);
        Mapping[Index << PAGE_SHIFT] = (UCHAR)Index;

        KeMemoryBarrier();
        Byte = Mapping[Index << PAGE_SHIFT];

        ASSERT3U(Byte, ==, (UCHAR)Index);
    }

    MmUnmapLockedPages((PVOID)Mapping, Mdl);

done:
    MmFreePagesFromMdl(Mdl);
}

#define XENBUS_BALLOON_MIN_PAGES_PER_S 1000ull

static ULONG
BalloonAllocatePfnArray(
    IN      PXENBUS_BALLOON_CONTEXT Context,
    IN      ULONG                   Requested,
    IN OUT  PBOOLEAN                Slow
    )
{
    LARGE_INTEGER                   Start;
    LARGE_INTEGER                   End;
    ULONGLONG                       TimeDelta;
    ULONGLONG                       Rate;
    PMDL                            Mdl;
    PPFN_NUMBER                     PfnArray;
    ULONG                           Count;

    ASSERT(Requested != 0);
    ASSERT3U(Requested, <=, XENBUS_BALLOON_PFN_ARRAY_SIZE);
    ASSERT(IsZeroMemory(Context->PfnArray, Requested * sizeof (PFN_NUMBER)));

    KeQuerySystemTime(&Start);
    Count = 0;

    Mdl = BalloonAllocatePagesForMdl(Requested);
    if (Mdl == NULL)
        goto done;

    ASSERT(Mdl->ByteOffset == 0);
    ASSERT((Mdl->ByteCount & (PAGE_SIZE - 1)) == 0);
    ASSERT(Mdl->MdlFlags & MDL_PAGES_LOCKED);

    Count = Mdl->ByteCount >> PAGE_SHIFT;

    PfnArray = MmGetMdlPfnArray(Mdl);
    RtlCopyMemory(Context->PfnArray, PfnArray, Count * sizeof (PFN_NUMBER));

    BalloonSort(Context, Count);

    ExFreePool(Mdl);

done:
    KeQuerySystemTime(&End);
    TimeDelta = __max(((End.QuadPart - Start.QuadPart) / 10000ull), 1);

    Rate = (ULONGLONG)(Count * 1000) / TimeDelta;
    *Slow = (Rate < XENBUS_BALLOON_MIN_PAGES_PER_S) ? TRUE : FALSE;

    Info("%u page(s) at %llu pages/s\n", Count, Rate);
    return Count;
}

static ULONG
BalloonPopulatePhysmap(
    IN  ULONG       Requested,
    IN  PPFN_NUMBER PfnArray
    )
{
    LARGE_INTEGER   Start;
    LARGE_INTEGER   End;
    ULONGLONG       TimeDelta;
    ULONGLONG       Rate;
    ULONG           Count;

    ASSERT(Requested != 0);

    KeQuerySystemTime(&Start);

    Count = MemoryPopulatePhysmap(PAGE_ORDER_4K, Requested, PfnArray);

    KeQuerySystemTime(&End);
    TimeDelta = __max(((End.QuadPart - Start.QuadPart) / 10000ull), 1);

    Rate = (ULONGLONG)(Count * 1000) / TimeDelta;

    Info("%u page(s) at %llu pages/s\n", Count, Rate);
    return Count;
}

static ULONG
BalloonPopulatePfnArray(
    IN      PXENBUS_BALLOON_CONTEXT Context,
    IN      ULONG                   Requested
    )
{
    LARGE_INTEGER                   Start;
    LARGE_INTEGER                   End;
    ULONGLONG                       TimeDelta;
    ULONGLONG                       Rate;
    ULONG                           Index;
    ULONG                           Count;

    ASSERT(Requested != 0);
    ASSERT3U(Requested, <=, XENBUS_BALLOON_PFN_ARRAY_SIZE);
    ASSERT(IsZeroMemory(Context->PfnArray, Requested * sizeof (PFN_NUMBER)));

    KeQuerySystemTime(&Start);

    for (Index = 0; Index < Requested; Index++) {
        LONGLONG    Pfn;
        NTSTATUS    status;

        status = XENBUS_RANGE_SET(Pop,
                                  &Context->RangeSetInterface,
                                  Context->RangeSet,
                                  1,
                                  &Pfn);
        ASSERT(NT_SUCCESS(status));

        Context->PfnArray[Index] = (PFN_NUMBER)Pfn;
    }

    Count = BalloonPopulatePhysmap(Requested, Context->PfnArray);

    Index = Count;
    while (Index < Requested) {
        NTSTATUS    status;

        status = XENBUS_RANGE_SET(Put,
                                  &Context->RangeSetInterface,
                                  Context->RangeSet,
                                  (LONGLONG)Context->PfnArray[Index],
                                  1);

        ASSERT(NT_SUCCESS(status));

        Context->PfnArray[Index] = 0;
        Index++;
    }

    KeQuerySystemTime(&End);
    TimeDelta = __max(((End.QuadPart - Start.QuadPart) / 10000ull), 1);

    Rate = (ULONGLONG)(Count * 1000) / TimeDelta;

    Info("%u page(s) at %llu pages/s\n", Count, Rate);
    return Count;
}

static ULONG
BalloonDecreaseReservation(
    IN  ULONG       Requested,
    IN  PPFN_NUMBER PfnArray
    )
{
    LARGE_INTEGER   Start;
    LARGE_INTEGER   End;
    ULONGLONG       TimeDelta;
    ULONGLONG       Rate;
    ULONG           Count;

    ASSERT(Requested != 0);

    KeQuerySystemTime(&Start);

    Count = MemoryDecreaseReservation(PAGE_ORDER_4K, Requested, PfnArray);

    KeQuerySystemTime(&End);
    TimeDelta = __max(((End.QuadPart - Start.QuadPart) / 10000ull), 1);

    Rate = (ULONGLONG)(Count * 1000) / TimeDelta;

    Info("%u page(s) at %llu pages/s\n", Count, Rate);
    return Count;
}

static ULONG
BalloonReleasePfnArray(
    IN      PXENBUS_BALLOON_CONTEXT Context,
    IN      ULONG                   Requested
    )
{
    LARGE_INTEGER                   Start;
    LARGE_INTEGER                   End;
    ULONGLONG                       TimeDelta;
    ULONGLONG                       Rate;
    ULONG                           Index;
    ULONG                           Count;

    ASSERT3U(Requested, <=, XENBUS_BALLOON_PFN_ARRAY_SIZE);

    KeQuerySystemTime(&Start);
    Count = 0;

    if (Requested == 0)
        goto done;

    Index = 0;
    while (Index < Requested) {
        NTSTATUS    status;

        status = XENBUS_RANGE_SET(Put,
                                  &Context->RangeSetInterface,
                                  Context->RangeSet,
                                  (LONGLONG)Context->PfnArray[Index],
                                  1);
        if (!NT_SUCCESS(status))
            break;

        Index++;
    }
    Requested = Index;

    Count = BalloonDecreaseReservation(Requested, Context->PfnArray);

    RtlZeroMemory(Context->PfnArray, Count * sizeof (PFN_NUMBER));

    for (Index = Count; Index < Requested; Index++) {
        NTSTATUS    status;

        status = XENBUS_RANGE_SET(Get,
                                  &Context->RangeSetInterface,
                                  Context->RangeSet,
                                  (LONGLONG)Context->PfnArray[Index],
                                  1);
        ASSERT(NT_SUCCESS(status));
    }

done:
    ASSERT(IsZeroMemory(Context->PfnArray, Count * sizeof (PFN_NUMBER)));

    KeQuerySystemTime(&End);
    TimeDelta = __max(((End.QuadPart - Start.QuadPart) / 10000ull), 1);

    Rate = (ULONGLONG)(Count * 1000) / TimeDelta;

    Info("%u page(s) at %llu pages/s\n", Count, Rate);
    return Count;
}

static ULONG
BalloonFreePfnArray(
    IN      PXENBUS_BALLOON_CONTEXT Context,
    IN      ULONG                   Requested,
    IN      BOOLEAN                 Check
    )
{
    LARGE_INTEGER                   Start;
    LARGE_INTEGER                   End;
    ULONGLONG                       TimeDelta;
    ULONGLONG                       Rate;
    ULONG                           Index;
    ULONG                           Count;
    PMDL                            Mdl;

    ASSERT3U(Requested, <=, XENBUS_BALLOON_PFN_ARRAY_SIZE);

    KeQuerySystemTime(&Start);
    Count = 0;

    if (Requested == 0)
        goto done;

    ASSERT(IsZeroMemory(&Context->Mdl, sizeof (MDL)));

    for (Index = 0; Index < Requested; Index++)
        ASSERT(Context->PfnArray[Index] != 0);

    Mdl = &Context->Mdl;

#pragma warning(push)
#pragma warning(disable:28145)  // The opaque MDL structure should not be modified by a driver

    Mdl->Next = NULL;
    Mdl->Size = (SHORT)(sizeof(MDL) + (sizeof(PFN_NUMBER) * Requested));
    Mdl->MdlFlags = MDL_PAGES_LOCKED;
    Mdl->Process = NULL;
    Mdl->MappedSystemVa = NULL;
    Mdl->StartVa = NULL;
    Mdl->ByteCount = Requested << PAGE_SHIFT;
    Mdl->ByteOffset = 0;

#pragma warning(pop)

    BalloonFreePagesFromMdl(Mdl, Check);
    Count = Requested;

    RtlZeroMemory(&Context->Mdl, sizeof (MDL));

    RtlZeroMemory(Context->PfnArray, Count * sizeof (PFN_NUMBER));

done:
    ASSERT(IsZeroMemory(Context->PfnArray, Requested * sizeof (PFN_NUMBER)));

    KeQuerySystemTime(&End);
    TimeDelta = __max(((End.QuadPart - Start.QuadPart) / 10000ull), 1);

    Rate = (ULONGLONG)(Count * 1000) / TimeDelta;

    Info("%u page(s) at %llu pages/s\n", Count, Rate);
    return Count;
}

static BOOLEAN
BalloonLowMemory(
    IN  PXENBUS_BALLOON_CONTEXT Context
    )
{
    LARGE_INTEGER               Timeout;
    NTSTATUS                    status;

    Timeout.QuadPart = 0;

    status = KeWaitForSingleObject(Context->LowMemoryEvent,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   &Timeout);

    return (status == STATUS_SUCCESS) ? TRUE : FALSE;
}

static NTSTATUS
BalloonDeflate(
    IN  PXENBUS_BALLOON_CONTEXT Context,
    IN  ULONGLONG               Requested
    )
{
    LARGE_INTEGER               Start;
    LARGE_INTEGER               End;
    ULONGLONG                   Count;
    ULONGLONG                   TimeDelta;
    NTSTATUS                    status;

    status = STATUS_UNSUCCESSFUL;
    if (Context->FIST.Deflation)
        goto done;

    Info("====> %llu page(s)\n", Requested);

    KeQuerySystemTime(&Start);

    Count = 0;
    status = STATUS_SUCCESS;

    while (Count < Requested && NT_SUCCESS(status)) {
        ULONG   ThisTime = (ULONG)__min(Requested - Count, XENBUS_BALLOON_PFN_ARRAY_SIZE);
        ULONG   Populated;
        ULONG   Freed;

        Populated = BalloonPopulatePfnArray(Context, ThisTime);
        if (Populated < ThisTime)
            status = STATUS_RETRY;

        Freed = BalloonFreePfnArray(Context, Populated, TRUE);
        ASSERT(Freed == Populated);

        Count += Freed;
    }

    KeQuerySystemTime(&End);

    TimeDelta = (End.QuadPart - Start.QuadPart) / 10000ull;

    Info("<==== %llu page(s) in %llums\n", Count, TimeDelta);
    Context->Size -= Count;

done:
    return status;
}

static NTSTATUS
BalloonInflate(
    IN  PXENBUS_BALLOON_CONTEXT Context,
    IN  ULONGLONG               Requested
    )
{
    LARGE_INTEGER               Start;
    LARGE_INTEGER               End;
    ULONGLONG                   Count;
    ULONGLONG                   TimeDelta;
    NTSTATUS                    status;

    status = STATUS_UNSUCCESSFUL;
    if (Context->FIST.Inflation)
        goto done;

    status = STATUS_NO_MEMORY;
    if (BalloonLowMemory(Context))
        goto done;

    Info("====> %llu page(s)\n", Requested);

    KeQuerySystemTime(&Start);

    Count = 0;
    status = STATUS_SUCCESS;

    while (Count < Requested && NT_SUCCESS(status)) {
        ULONG   ThisTime = (ULONG)__min(Requested - Count, XENBUS_BALLOON_PFN_ARRAY_SIZE);
        ULONG   Allocated;
        BOOLEAN Slow;
        ULONG   Released;

        Allocated = BalloonAllocatePfnArray(Context, ThisTime, &Slow);
        if (Allocated < ThisTime || Slow)
            status = STATUS_RETRY;

        Released = BalloonReleasePfnArray(Context, Allocated);

        if (Released < Allocated) {
            ULONG   Freed;

            RtlMoveMemory(&(Context->PfnArray[0]),
                          &(Context->PfnArray[Released]),
                          (Allocated - Released) * sizeof (PFN_NUMBER));

            Freed = BalloonFreePfnArray(Context, Allocated - Released, FALSE);
            ASSERT3U(Freed, ==, Allocated - Released);
        }

        if (Released == 0)
            status = STATUS_RETRY;

        Count += Released;
    }

    KeQuerySystemTime(&End);

    TimeDelta = (End.QuadPart - Start.QuadPart) / 10000ull;

    Info("<==== %llu page(s) in %llums\n", Count, TimeDelta);
    Context->Size += Count;

done:
    return status;
}

static VOID
BalloonGetFISTEntries(
    IN  PXENBUS_BALLOON_CONTEXT Context
    )
{
    PCHAR                       Buffer;
    NTSTATUS                    status;

    status = XENBUS_STORE(Read,
                          &Context->StoreInterface,
                          NULL,
                          "FIST/balloon",
                          "inflation",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Context->FIST.Inflation = FALSE;
    } else {
        Context->FIST.Inflation = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Context->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Context->StoreInterface,
                          NULL,
                          "FIST/balloon",
                          "deflation",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Context->FIST.Deflation = FALSE;
    } else {
        Context->FIST.Deflation = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Context->StoreInterface,
                     Buffer);
    }

    if (Context->FIST.Inflation)
        Warning("inflation disallowed\n");
        
    if (Context->FIST.Deflation)
        Warning("deflation disallowed\n");
}

static FORCEINLINE PCHAR
__BalloonStatus(
    IN  NTSTATUS    status
    )
{
    switch (status) {
    case STATUS_SUCCESS:
        return "";
    case STATUS_UNSUCCESSFUL:
        return " [FIST]";
    case STATUS_RETRY:
        return " [RETRY]";
    case STATUS_NO_MEMORY:
        return " [LOW_MEM]";
    default:
        break;
    }

    return " [UNKNOWN]";
}

NTSTATUS
BalloonAdjust(
    IN  PINTERFACE          Interface,
    IN  ULONGLONG           Size
    )
{
    PXENBUS_BALLOON_CONTEXT Context = Interface->Context;
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), <, DISPATCH_LEVEL);

    Info("====> (%llu page(s))\n", Context->Size);

    status = STATUS_SUCCESS;

    BalloonGetFISTEntries(Context);

    while (Context->Size != Size && NT_SUCCESS(status)) {
        if (Size > Context->Size)
            status = BalloonInflate(Context, Size - Context->Size);
        else if (Size < Context->Size)
            status = BalloonDeflate(Context, Context->Size - Size);
    }

    Info("<==== (%llu page(s))%s\n",
         Context->Size,
         __BalloonStatus(status));

    return status;
}

ULONGLONG
BalloonGetSize(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_BALLOON_CONTEXT Context = Interface->Context;

    return Context->Size;
}

static NTSTATUS
BalloonAcquire(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_BALLOON_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;
    NTSTATUS                status;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    status = XENBUS_RANGE_SET(Acquire, &Context->RangeSetInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_RANGE_SET(Create,
                              &Context->RangeSetInterface,
                              "balloon",
                              &Context->RangeSet);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_STORE(Acquire, &Context->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    XENBUS_RANGE_SET(Destroy,
                     &Context->RangeSetInterface,
                     Context->RangeSet);
    Context->RangeSet = NULL;

fail2:
    Error("fail2\n");

    XENBUS_RANGE_SET(Release, &Context->RangeSetInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    --Context->References;
    ASSERT3U(Context->References, ==, 0);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return status;
}

static VOID
BalloonRelease(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_BALLOON_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    if (Context->Size != 0)
        BUG("STILL INFLATED");

    RtlZeroMemory(&Context->FIST, sizeof (XENBUS_BALLOON_FIST));

    XENBUS_STORE(Release, &Context->StoreInterface);

    XENBUS_RANGE_SET(Destroy,
                     &Context->RangeSetInterface,
                     Context->RangeSet);
    Context->RangeSet = NULL;

    XENBUS_RANGE_SET(Release, &Context->RangeSetInterface);

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);
}

static struct _XENBUS_BALLOON_INTERFACE_V1 BalloonInterfaceVersion1 = {
    { sizeof (struct _XENBUS_BALLOON_INTERFACE_V1), 1, NULL, NULL, NULL },
    BalloonAcquire,
    BalloonRelease,
    BalloonAdjust,
    BalloonGetSize
};
                     
NTSTATUS
BalloonInitialize(
    IN  PXENBUS_FDO             Fdo,
    OUT PXENBUS_BALLOON_CONTEXT *Context
    )
{
    UNICODE_STRING              Unicode;
    NTSTATUS                    status;

    Trace("====>\n");

    *Context = __BalloonAllocate(sizeof (XENBUS_BALLOON_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (*Context == NULL)
        goto fail1;

    status = RangeSetGetInterface(FdoGetRangeSetContext(Fdo),
                                  XENBUS_RANGE_SET_INTERFACE_VERSION_MAX,
                                  (PINTERFACE)&(*Context)->RangeSetInterface,
                                  sizeof ((*Context)->RangeSetInterface));
    ASSERT(NT_SUCCESS(status));

    status = StoreGetInterface(FdoGetStoreContext(Fdo),
                               XENBUS_STORE_INTERFACE_VERSION_MAX,
                               (PINTERFACE)&(*Context)->StoreInterface,
                               sizeof ((*Context)->StoreInterface));
    ASSERT(NT_SUCCESS(status));

    RtlInitUnicodeString(&Unicode, L"\\KernelObjects\\LowMemoryCondition");

    (*Context)->LowMemoryEvent = IoCreateNotificationEvent(&Unicode,
                                                           &(*Context)->LowMemoryHandle);

    status = STATUS_UNSUCCESSFUL;
    if ((*Context)->LowMemoryEvent == NULL)
        goto fail2;

    (*Context)->Fdo = Fdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RtlZeroMemory(&(*Context)->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&(*Context)->RangeSetInterface,
                  sizeof (XENBUS_RANGE_SET_INTERFACE));

    ASSERT(IsZeroMemory(*Context, sizeof (XENBUS_BALLOON_CONTEXT)));
    __BalloonFree(*Context);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
BalloonGetInterface(
    IN      PXENBUS_BALLOON_CONTEXT Context,
    IN      ULONG                   Version,
    IN OUT  PINTERFACE              Interface,
    IN      ULONG                   Size
    )
{
    NTSTATUS                        status;

    ASSERT(Context != NULL);

    switch (Version) {
    case 1: {
        struct _XENBUS_BALLOON_INTERFACE_V1  *BalloonInterface;

        BalloonInterface = (struct _XENBUS_BALLOON_INTERFACE_V1 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENBUS_BALLOON_INTERFACE_V1))
            break;

        *BalloonInterface = BalloonInterfaceVersion1;

        ASSERT3U(Interface->Version, ==, Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    return status;
}   

ULONG
BalloonGetReferences(
    IN  PXENBUS_BALLOON_CONTEXT Context
    )
{
    return Context->References;
}

VOID
BalloonTeardown(
    IN  PXENBUS_BALLOON_CONTEXT Context
    )
{
    Trace("====>\n");

    Context->Fdo = NULL;

    ZwClose(Context->LowMemoryHandle);
    Context->LowMemoryHandle = NULL;
    Context->LowMemoryEvent = NULL;

    RtlZeroMemory(&Context->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Context->RangeSetInterface,
                  sizeof (XENBUS_RANGE_SET_INTERFACE));

    ASSERT(IsZeroMemory(Context, sizeof (XENBUS_BALLOON_CONTEXT)));
    __BalloonFree(Context);

    Trace("<====\n");
}
