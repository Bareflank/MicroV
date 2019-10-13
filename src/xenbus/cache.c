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
#include <procgrp.h>
#include <ntstrsafe.h>
#include <stdlib.h>

#include "thread.h"
#include "cache.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

extern ULONG
NTAPI
RtlRandomEx (
    __inout PULONG Seed
    );

#define XENBUS_CACHE_MAGAZINE_SLOTS   6

typedef struct _XENBUS_CACHE_MAGAZINE {
    PVOID   Slot[XENBUS_CACHE_MAGAZINE_SLOTS];
} XENBUS_CACHE_MAGAZINE, *PXENBUS_CACHE_MAGAZINE;


#define XENBUS_CACHE_SLAB_MAGIC 'BALS'

typedef struct _XENBUS_CACHE_SLAB {
    ULONG           Magic;
    PXENBUS_CACHE   Cache;
    LIST_ENTRY      ListEntry;
    USHORT          MaximumOccupancy;
    USHORT          CurrentOccupancy;
    ULONG           *Mask;
    UCHAR           Buffer[1];
} XENBUS_CACHE_SLAB, *PXENBUS_CACHE_SLAB;

#define BITS_PER_ULONG (sizeof (ULONG) * 8)
#define MINIMUM_OBJECT_SIZE (PAGE_SIZE / BITS_PER_ULONG)

C_ASSERT(sizeof (XENBUS_CACHE_SLAB) <= MINIMUM_OBJECT_SIZE);

#define MAXNAMELEN  128

struct _XENBUS_CACHE {
    LIST_ENTRY              ListEntry;
    CHAR                    Name[MAXNAMELEN];
    ULONG                   Size;
    ULONG                   Reservation;
    ULONG                   Cap;
    NTSTATUS                (*Ctor)(PVOID, PVOID);
    VOID                    (*Dtor)(PVOID, PVOID);
    VOID                    (*AcquireLock)(PVOID);
    VOID                    (*ReleaseLock)(PVOID);
    PVOID                   Argument;
    LIST_ENTRY              SlabList;
    PLIST_ENTRY             Cursor;
    ULONG                   Count;
    PXENBUS_CACHE_MAGAZINE  Magazine;
    ULONG                   MagazineCount;
};

struct _XENBUS_CACHE_CONTEXT {
    PXENBUS_FDO             Fdo;
    KSPIN_LOCK              Lock;
    LONG                    References;
    XENBUS_DEBUG_INTERFACE  DebugInterface;
    PXENBUS_DEBUG_CALLBACK  DebugCallback;
    PXENBUS_THREAD          MonitorThread;
    LIST_ENTRY              List;
};

#define CACHE_TAG   'HCAC'

static FORCEINLINE PVOID
__CacheAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, CACHE_TAG);
}

static FORCEINLINE VOID
__CacheFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, CACHE_TAG);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__CacheAcquireLock(
    IN  PXENBUS_CACHE   Cache
    )
{
    Cache->AcquireLock(Cache->Argument);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__CacheReleaseLock(
    IN  PXENBUS_CACHE   Cache
    )
{
    Cache->ReleaseLock(Cache->Argument);
}

static FORCEINLINE NTSTATUS
__drv_requiresIRQL(DISPATCH_LEVEL)
__CacheCtor(
    IN  PXENBUS_CACHE   Cache,
    IN  PVOID           Object
    )
{
    return Cache->Ctor(Cache->Argument, Object);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__CacheDtor(
    IN  PXENBUS_CACHE   Cache,
    IN  PVOID           Object
    )
{
    Cache->Dtor(Cache->Argument, Object);
}

static PVOID
CacheGetObjectFromMagazine(
    IN  PXENBUS_CACHE_MAGAZINE  Magazine
    )
{
    ULONG                       Index;

    for (Index = 0; Index < XENBUS_CACHE_MAGAZINE_SLOTS; Index++) {
        PVOID   Object;

        if (Magazine->Slot[Index] != NULL) {
            Object = Magazine->Slot[Index];
            Magazine->Slot[Index] = NULL;

            return Object;
        }
    }

    return NULL;
}

static NTSTATUS
CachePutObjectToMagazine(
    IN  PXENBUS_CACHE_MAGAZINE  Magazine,
    IN  PVOID                   Object
    )
{
    ULONG                       Index;

    for (Index = 0; Index < XENBUS_CACHE_MAGAZINE_SLOTS; Index++) {
        if (Magazine->Slot[Index] == NULL) {
            Magazine->Slot[Index] = Object;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_UNSUCCESSFUL;
}

static VOID
CacheInsertSlab(
    IN  PXENBUS_CACHE       Cache,
    IN  PXENBUS_CACHE_SLAB  New
    )
{
#define INSERT_BEFORE(_ListEntry, _New)             \
        do {                                        \
            (_New)->Blink = (_ListEntry)->Blink;    \
            (_ListEntry)->Blink->Flink = (_New);    \
                                                    \
            (_ListEntry)->Blink = (_New);           \
            (_New)->Flink = (_ListEntry);           \
        } while (FALSE)

    PLIST_ENTRY             ListEntry;

    ASSERT(New->CurrentOccupancy < New->MaximumOccupancy);

    Cache->Cursor = NULL;

    for (ListEntry = Cache->SlabList.Flink;
         ListEntry != &Cache->SlabList;
         ListEntry = ListEntry->Flink) {
        PXENBUS_CACHE_SLAB  Slab;

        Slab = CONTAINING_RECORD(ListEntry, XENBUS_CACHE_SLAB, ListEntry);

        if (Slab->CurrentOccupancy < New->CurrentOccupancy) {
            INSERT_BEFORE(ListEntry, &New->ListEntry);
            goto done;
        }

        if (Slab->CurrentOccupancy < Slab->MaximumOccupancy &&
            Cache->Cursor == NULL)
            Cache->Cursor = ListEntry;
    }

    InsertTailList(&Cache->SlabList, &New->ListEntry);

done:
    if (Cache->Cursor == NULL)
        Cache->Cursor = &New->ListEntry;

#undef  INSERT_BEFORE
}

#if DBG
static VOID
CacheAudit(
    IN  PXENBUS_CACHE   Cache
    )
{
    ULONG               CurrentOccupancy = ULONG_MAX;
    PLIST_ENTRY         ListEntry;

    //
    // The cursror should point at the first slab that is not fully
    // occupied.
    //
    for (ListEntry = Cache->SlabList.Flink;
         ListEntry != &Cache->SlabList;
         ListEntry = ListEntry->Flink) {
        PXENBUS_CACHE_SLAB  Slab;

        Slab = CONTAINING_RECORD(ListEntry, XENBUS_CACHE_SLAB, ListEntry);

        if (Slab->CurrentOccupancy < Slab->MaximumOccupancy) {
            ASSERT3P(Cache->Cursor, ==, ListEntry);
            break;
        }
    }

    // Slabs should be kept in order of maximum to minimum occupancy
    for (ListEntry = Cache->SlabList.Flink;
         ListEntry != &Cache->SlabList;
         ListEntry = ListEntry->Flink) {
        PXENBUS_CACHE_SLAB  Slab;

        Slab = CONTAINING_RECORD(ListEntry, XENBUS_CACHE_SLAB, ListEntry);

        ASSERT3U(Slab->CurrentOccupancy, <=, CurrentOccupancy);

        CurrentOccupancy = Slab->CurrentOccupancy;
    }
}
#else
#define CacheAudit(_Cache) ((VOID)(_Cache))
#endif

// Must be called with lock held
static NTSTATUS
CacheCreateSlab(
    IN  PXENBUS_CACHE   Cache
    )
{
    PXENBUS_CACHE_SLAB  Slab;
    ULONG               NumberOfBytes;
    ULONG               Count;
    ULONG               Size;
    LONG                Index;
    NTSTATUS            status;

    NumberOfBytes = P2ROUNDUP(FIELD_OFFSET(XENBUS_CACHE_SLAB, Buffer) +
                              Cache->Size,
                              PAGE_SIZE);
    Count = (NumberOfBytes - FIELD_OFFSET(XENBUS_CACHE_SLAB, Buffer)) /
            Cache->Size;
    ASSERT(Count != 0);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (Cache->Count + Count > Cache->Cap)
        goto fail1;

    Slab = __CacheAllocate(NumberOfBytes);
    ASSERT3P(Slab, ==, PAGE_ALIGN(Slab));

    status = STATUS_NO_MEMORY;
    if (Slab == NULL)
        goto fail2;

    RtlZeroMemory(Slab, NumberOfBytes);

    Slab->Magic = XENBUS_CACHE_SLAB_MAGIC;
    Slab->Cache = Cache;
    Slab->MaximumOccupancy = (USHORT)Count;

    Size = P2ROUNDUP(Count, BITS_PER_ULONG);
    Size /= 8;

    Slab->Mask = __CacheAllocate(Size);
    if (Slab->Mask == NULL)
        goto fail3;

    for (Index = 0; Index < (LONG)Slab->MaximumOccupancy; Index++) {
        PVOID Object = (PVOID)&Slab->Buffer[Index * Cache->Size];

        status = __CacheCtor(Cache, Object);
        if (!NT_SUCCESS(status))
            goto fail4;
    }

    CacheInsertSlab(Cache, Slab);
    Cache->Count += Count;

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    while (--Index >= 0) {
        PVOID Object = (PVOID)&Slab->Buffer[Index * Cache->Size];

        __CacheDtor(Cache, Object);
    }

    __CacheFree(Slab->Mask);

fail3:
    Error("fail3\n");

    __CacheFree(Slab);

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

// Must be called with lock held
static VOID
CacheDestroySlab(
    IN  PXENBUS_CACHE       Cache,
    IN  PXENBUS_CACHE_SLAB  Slab
    )
{
    LONG                    Index;

    ASSERT3U(Slab->CurrentOccupancy, ==, 0);

    ASSERT3U(Cache->Count, >=, Slab->MaximumOccupancy);
    Cache->Count -= Slab->MaximumOccupancy;

    //
    // The only reason the cursor should be pointing at this slab is
    // if it is the only one in the list.
    //
    if (Cache->Cursor == &Slab->ListEntry) {
        ASSERT(Slab->ListEntry.Flink == &Cache->SlabList);
        ASSERT(Slab->ListEntry.Blink == &Cache->SlabList);
        Cache->Cursor = &Cache->SlabList;
    }

    RemoveEntryList(&Slab->ListEntry);

    Index = Slab->MaximumOccupancy;
    while (--Index >= 0) {
        PVOID Object = (PVOID)&Slab->Buffer[Index * Cache->Size];

        __CacheDtor(Cache, Object);
    }

    __CacheFree(Slab->Mask);
    __CacheFree(Slab);
}

static FORCEINLINE ULONG
__CacheMaskScan(
    IN  ULONG   *Mask,
    IN  ULONG   Maximum
    )
{
    ULONG       Size;
    ULONG       Index;

    Size = P2ROUNDUP(Maximum, BITS_PER_ULONG);
    Size /= sizeof (ULONG);
    ASSERT(Size != 0);

    for (Index = 0; Index < Size; Index++) {
        ULONG   Free = ~Mask[Index];
        ULONG   Bit;

        if (!_BitScanForward(&Bit, Free))
            continue;

        Bit += Index * BITS_PER_ULONG;
        if (Bit < Maximum)
            return Bit;
    }

    return Maximum;
}

static FORCEINLINE VOID
__CacheMaskSet(
    IN  ULONG   *Mask,
    IN  ULONG   Bit
    )
{
    ULONG       Index = Bit / BITS_PER_ULONG;

    Mask[Index] |= 1u << (Bit % BITS_PER_ULONG);
}

static FORCEINLINE BOOLEAN
__CacheMaskTest(
    IN  ULONG   *Mask,
    IN  ULONG   Bit
    )
{
    ULONG       Index = Bit / BITS_PER_ULONG;

    return (Mask[Index] & (1u << (Bit % BITS_PER_ULONG))) ? TRUE : FALSE;
}

static FORCEINLINE VOID
__CacheMaskClear(
    IN  ULONG   *Mask,
    IN  ULONG   Bit
    )
{
    ULONG       Index = Bit / BITS_PER_ULONG;

    Mask[Index] &= ~(1u << (Bit % BITS_PER_ULONG));
}

// Must be called with lock held
static PVOID
CacheGetObjectFromSlab(
    IN  PXENBUS_CACHE_SLAB  Slab
    )
{
    PXENBUS_CACHE           Cache;
    ULONG                   Index;
    PVOID                   Object;

    Cache = Slab->Cache;

    ASSERT3U(Slab->CurrentOccupancy, <=, Slab->MaximumOccupancy);
    if (Slab->CurrentOccupancy == Slab->MaximumOccupancy)
        return NULL;

    Index = __CacheMaskScan(Slab->Mask, Slab->MaximumOccupancy);
    BUG_ON(Index >= Slab->MaximumOccupancy);

    __CacheMaskSet(Slab->Mask, Index);
    Slab->CurrentOccupancy++;

    Object = (PVOID)&Slab->Buffer[Index * Cache->Size];
    ASSERT3U(Index, ==, (ULONG)((PUCHAR)Object - &Slab->Buffer[0]) /
             Cache->Size);

    return Object;
}

// Must be called with lock held
static VOID
CachePutObjectToSlab(
    IN  PXENBUS_CACHE_SLAB  Slab,
    IN  PVOID               Object
    )
{
    PXENBUS_CACHE           Cache;
    ULONG                   Index;

    Cache = Slab->Cache;

    Index = (ULONG)((PUCHAR)Object - &Slab->Buffer[0]) / Cache->Size;
    BUG_ON(Index >= Slab->MaximumOccupancy);

    ASSERT(Slab->CurrentOccupancy != 0);
    --Slab->CurrentOccupancy;

    ASSERT(__CacheMaskTest(Slab->Mask, Index));
    __CacheMaskClear(Slab->Mask, Index);
}

static PVOID
CacheGet(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_CACHE       Cache,
    IN  BOOLEAN             Locked
    )
{
    KIRQL                   Irql;
    ULONG                   Index;
    PXENBUS_CACHE_MAGAZINE  Magazine;
    PVOID                   Object;

    UNREFERENCED_PARAMETER(Interface);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    Index = KeGetCurrentProcessorNumberEx(NULL);

    ASSERT3U(Index, <, Cache->MagazineCount);
    Magazine = &Cache->Magazine[Index];

    Object = CacheGetObjectFromMagazine(Magazine);
    if (Object != NULL)
        goto done;

    if (!Locked)
        __CacheAcquireLock(Cache);

again:
    if (Cache->Cursor != &Cache->SlabList) {
        PLIST_ENTRY ListEntry = Cache->Cursor;
        PXENBUS_CACHE_SLAB  Slab;

        Slab = CONTAINING_RECORD(ListEntry, XENBUS_CACHE_SLAB, ListEntry);

        Object = CacheGetObjectFromSlab(Slab);
        ASSERT(Object != NULL);

        if (Slab->CurrentOccupancy == Slab->MaximumOccupancy)
            Cache->Cursor = Slab->ListEntry.Flink;
    }

    if (Object == NULL) {
        NTSTATUS status;

        ASSERT3P(Cache->Cursor, ==, &Cache->SlabList);

        status = CacheCreateSlab(Cache);
        if (NT_SUCCESS(status)) {
            ASSERT(Cache->Cursor != &Cache->SlabList);
            goto again;
        }
    }

    CacheAudit(Cache);

    if (!Locked)
        __CacheReleaseLock(Cache);

done:
    KeLowerIrql(Irql);

    return Object;
}

static VOID
CachePut(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_CACHE       Cache,
    IN  PVOID               Object,
    IN  BOOLEAN             Locked
    )
{
    KIRQL                   Irql;
    ULONG                   Index;
    PXENBUS_CACHE_MAGAZINE  Magazine;
    PXENBUS_CACHE_SLAB      Slab;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Interface);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    Index = KeGetCurrentProcessorNumberEx(NULL);

    ASSERT3U(Index, <, Cache->MagazineCount);
    Magazine = &Cache->Magazine[Index];

    status = CachePutObjectToMagazine(Magazine, Object);

    if (NT_SUCCESS(status))
        goto done;

    Slab = (PXENBUS_CACHE_SLAB)PAGE_ALIGN(Object);
    ASSERT3U(Slab->Magic, ==, XENBUS_CACHE_SLAB_MAGIC);

    if (!Locked)
        __CacheAcquireLock(Cache);

    CachePutObjectToSlab(Slab, Object);

    /* Re-insert to keep slab list ordered */
    RemoveEntryList(&Slab->ListEntry);
    CacheInsertSlab(Cache, Slab);

    CacheAudit(Cache);

    if (!Locked)
        __CacheReleaseLock(Cache);

done:
    KeLowerIrql(Irql);
}

static NTSTATUS
CacheFill(
    IN  PXENBUS_CACHE   Cache,
    IN  ULONG           Count
    )
{
    KIRQL               Irql;
    NTSTATUS            status;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __CacheAcquireLock(Cache);

    status = STATUS_SUCCESS;
    while (Cache->Count < Count) {
        status = CacheCreateSlab(Cache);
        if (!NT_SUCCESS(status))
            break;
    }

    CacheAudit(Cache);

    __CacheReleaseLock(Cache);
    KeLowerIrql(Irql);

    return status;
}

static VOID
CacheSpill(
    IN  PXENBUS_CACHE   Cache,
    IN  ULONG           Count
    )
{
    KIRQL               Irql;
    PLIST_ENTRY         ListEntry;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __CacheAcquireLock(Cache);

    if (Cache->Count <= Count)
        goto done;

    ListEntry = Cache->SlabList.Blink;
    while (ListEntry != &Cache->SlabList) {
        PLIST_ENTRY         Prev = ListEntry->Blink;
        PXENBUS_CACHE_SLAB  Slab;

        ASSERT(!IsListEmpty(&Cache->SlabList));

        Slab = CONTAINING_RECORD(ListEntry, XENBUS_CACHE_SLAB, ListEntry);

        if (Slab->CurrentOccupancy != 0)
            break;

        ASSERT(Cache->Count >= Slab->MaximumOccupancy);
        if (Cache->Count - Slab->MaximumOccupancy < Count)
            break;

        CacheDestroySlab(Cache, Slab);

        ListEntry = Prev;
    }

    CacheAudit(Cache);

done:
    __CacheReleaseLock(Cache);
    KeLowerIrql(Irql);
}

static FORCEINLINE VOID
__CacheFlushMagazines(
    IN  PXENBUS_CACHE   Cache
    )
{
    KIRQL               Irql;
    ULONG               Index;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __CacheAcquireLock(Cache);

    for (Index = 0; Index < Cache->MagazineCount; Index++) {
        PXENBUS_CACHE_MAGAZINE  Magazine = &Cache->Magazine[Index];
        PVOID                   Object;

        while ((Object = CacheGetObjectFromMagazine(Magazine)) != NULL) {
            PXENBUS_CACHE_SLAB  Slab;

            Slab = (PXENBUS_CACHE_SLAB)PAGE_ALIGN(Object);
            ASSERT3U(Slab->Magic, ==, XENBUS_CACHE_SLAB_MAGIC);

            CachePutObjectToSlab(Slab, Object);
        }
    }

    __CacheReleaseLock(Cache);
    KeLowerIrql(Irql);
}

static NTSTATUS
CacheCreate(
    IN  PINTERFACE          Interface,
    IN  const CHAR          *Name,
    IN  ULONG               Size,
    IN  ULONG               Reservation,
    IN  ULONG               Cap,
    IN  NTSTATUS            (*Ctor)(PVOID, PVOID),
    IN  VOID                (*Dtor)(PVOID, PVOID),
    IN  VOID                (*AcquireLock)(PVOID),
    IN  VOID                (*ReleaseLock)(PVOID),
    IN  PVOID               Argument,
    OUT PXENBUS_CACHE       *Cache
    )
{
    PXENBUS_CACHE_CONTEXT   Context = Interface->Context;
    KIRQL                   Irql;
    NTSTATUS                status;

    Trace("====> (%s)\n", Name);

    *Cache = __CacheAllocate(sizeof (XENBUS_CACHE));

    status = STATUS_NO_MEMORY;
    if (*Cache == NULL)
        goto fail1;

    status = RtlStringCbPrintfA((*Cache)->Name,
                                sizeof ((*Cache)->Name),
                                "%s",
                                Name);
    if (!NT_SUCCESS(status))
        goto fail2;

    Size = __max(Size, MINIMUM_OBJECT_SIZE);
    Size = P2ROUNDUP(Size, sizeof (ULONG_PTR));

    if (Cap == 0)
        Cap = ULONG_MAX;

    (*Cache)->Size = Size;
    (*Cache)->Reservation = Reservation;
    (*Cache)->Cap = Cap;
    (*Cache)->Ctor = Ctor;
    (*Cache)->Dtor = Dtor;
    (*Cache)->AcquireLock = AcquireLock;
    (*Cache)->ReleaseLock = ReleaseLock;
    (*Cache)->Argument = Argument;

    InitializeListHead(&(*Cache)->SlabList);
    (*Cache)->Cursor = &(*Cache)->SlabList;

    status = STATUS_INVALID_PARAMETER;
    if ((*Cache)->Reservation > (*Cache)->Cap)
        goto fail3;

    status = CacheFill(*Cache, (*Cache)->Reservation);
    if (!NT_SUCCESS(status))
        goto fail4;

    (*Cache)->MagazineCount = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    (*Cache)->Magazine = __CacheAllocate(sizeof (XENBUS_CACHE_MAGAZINE) * (*Cache)->MagazineCount);

    status = STATUS_NO_MEMORY;
    if ((*Cache)->Magazine == NULL)
        goto fail5;

    KeAcquireSpinLock(&Context->Lock, &Irql);
    InsertTailList(&Context->List, &(*Cache)->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    (*Cache)->MagazineCount = 0;

    CacheSpill(*Cache, 0);

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    (*Cache)->Cursor = NULL;
    ASSERT(IsListEmpty(&(*Cache)->SlabList));
    RtlZeroMemory(&(*Cache)->SlabList, sizeof (LIST_ENTRY));

    (*Cache)->Argument = NULL;
    (*Cache)->ReleaseLock = NULL;
    (*Cache)->AcquireLock = NULL;
    (*Cache)->Dtor = NULL;
    (*Cache)->Ctor = NULL;
    (*Cache)->Cap = 0;
    (*Cache)->Reservation = 0;
    (*Cache)->Size = 0;

fail2:
    Error("fail2\n");

    RtlZeroMemory((*Cache)->Name, sizeof ((*Cache)->Name));
    
    ASSERT(IsZeroMemory(*Cache, sizeof (XENBUS_CACHE)));
    __CacheFree(*Cache);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;    
}

static NTSTATUS
CacheCreateVersion1(
    IN  PINTERFACE          Interface,
    IN  const CHAR          *Name,
    IN  ULONG               Size,
    IN  ULONG               Reservation,
    IN  NTSTATUS            (*Ctor)(PVOID, PVOID),
    IN  VOID                (*Dtor)(PVOID, PVOID),
    IN  VOID                (*AcquireLock)(PVOID),
    IN  VOID                (*ReleaseLock)(PVOID),
    IN  PVOID               Argument,
    OUT PXENBUS_CACHE       *Cache
    )
{
    return CacheCreate(Interface,
                       Name,
                       Size,
                       Reservation,
                       0,
                       Ctor,
                       Dtor,
                       AcquireLock,
                       ReleaseLock,
                       Argument,
                       Cache);
}

static VOID
CacheDestroy(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_CACHE       Cache
    )
{
    PXENBUS_CACHE_CONTEXT   Context = Interface->Context;
    KIRQL                   Irql;

    Trace("====> (%s)\n", Cache->Name);

    KeAcquireSpinLock(&Context->Lock, &Irql);
    RemoveEntryList(&Cache->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    RtlZeroMemory(&Cache->ListEntry, sizeof (LIST_ENTRY));

    __CacheFlushMagazines(Cache);

    ASSERT(IsZeroMemory(Cache->Magazine, sizeof (XENBUS_CACHE_MAGAZINE) * Cache->MagazineCount));
    __CacheFree(Cache->Magazine);
    Cache->Magazine = NULL;
    Cache->MagazineCount = 0;

    CacheSpill(Cache, 0);

    Cache->Cursor = NULL;
    ASSERT(IsListEmpty(&Cache->SlabList));
    RtlZeroMemory(&Cache->SlabList, sizeof (LIST_ENTRY));

    Cache->Argument = NULL;
    Cache->ReleaseLock = NULL;
    Cache->AcquireLock = NULL;
    Cache->Dtor = NULL;
    Cache->Ctor = NULL;
    Cache->Cap = 0;
    Cache->Reservation = 0;
    Cache->Size = 0;

    RtlZeroMemory(Cache->Name, sizeof (Cache->Name));

    ASSERT(IsZeroMemory(Cache, sizeof (XENBUS_CACHE)));
    __CacheFree(Cache);

    Trace("<====\n");
}

static VOID
CacheDebugCallback(
    IN  PVOID               Argument,
    IN  BOOLEAN             Crashing
    )
{
    PXENBUS_CACHE_CONTEXT   Context = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    if (!IsListEmpty(&Context->List)) {
        PLIST_ENTRY ListEntry;

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "CACHES:\n");

        for (ListEntry = Context->List.Flink;
             ListEntry != &Context->List;
             ListEntry = ListEntry->Flink) {
            PXENBUS_CACHE   Cache;

            Cache = CONTAINING_RECORD(ListEntry, XENBUS_CACHE, ListEntry);

            XENBUS_DEBUG(Printf,
                         &Context->DebugInterface,
                         "- %s: Count = %d (Reservation = %d)\n",
                         Cache->Name,
                         Cache->Count,
                         Cache->Reservation);
        }
    }
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define XENBUS_CACHE_MONITOR_PERIOD 5

static NTSTATUS
CacheMonitor(
    IN  PXENBUS_THREAD      Self,
    IN  PVOID               _Context
    )
{
    PXENBUS_CACHE_CONTEXT   Context = _Context;
    PKEVENT                 Event;
    LARGE_INTEGER           Timeout;
    PLIST_ENTRY             ListEntry;

    Trace("====>\n");

    Event = ThreadGetEvent(Self);

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(XENBUS_CACHE_MONITOR_PERIOD));

    for (;;) {
        KIRQL   Irql;

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     &Timeout);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        KeAcquireSpinLock(&Context->Lock, &Irql);

        if (Context->References == 0)
            goto loop;

        for (ListEntry = Context->List.Flink;
             ListEntry != &Context->List;
             ListEntry = ListEntry->Flink) {
            PXENBUS_CACHE   Cache;

            Cache = CONTAINING_RECORD(ListEntry, XENBUS_CACHE, ListEntry);

            if (Cache->Count < Cache->Reservation)
                CacheFill(Cache, Cache->Reservation);
            else if (Cache->Count > Cache->Reservation)
                CacheSpill(Cache,
                           __max(Cache->Reservation, (Cache->Count / 2)));
        }

loop:
        KeReleaseSpinLock(&Context->Lock, Irql);
    }

    Trace("====>\n");

    return STATUS_SUCCESS;
}

static NTSTATUS
CacheAcquire(
    PINTERFACE              Interface
    )
{
    PXENBUS_CACHE_CONTEXT   Context = Interface->Context;
    KIRQL                   Irql;
    NTSTATUS                status;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    status = XENBUS_DEBUG(Acquire, &Context->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Register,
                          &Context->DebugInterface,
                          __MODULE__ "|CACHE",
                          CacheDebugCallback,
                          Context,
                          &Context->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail2;

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Context->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    --Context->References;
    ASSERT3U(Context->References, ==, 0);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return status;
}

VOID
CacheRelease(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_CACHE_CONTEXT   Context = Interface->Context;
    KIRQL                   Irql;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    if (!IsListEmpty(&Context->List))
        BUG("OUTSTANDING CACHES");

    XENBUS_DEBUG(Deregister,
                 &Context->DebugInterface,
                 Context->DebugCallback);
    Context->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Context->DebugInterface);

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);
}

static struct _XENBUS_CACHE_INTERFACE_V1 CacheInterfaceVersion1 = {
    { sizeof (struct _XENBUS_CACHE_INTERFACE_V1), 1, NULL, NULL, NULL },
    CacheAcquire,
    CacheRelease,
    CacheCreateVersion1,
    CacheGet,
    CachePut,
    CacheDestroy
};

static struct _XENBUS_CACHE_INTERFACE_V2 CacheInterfaceVersion2 = {
    { sizeof (struct _XENBUS_CACHE_INTERFACE_V2), 2, NULL, NULL, NULL },
    CacheAcquire,
    CacheRelease,
    CacheCreate,
    CacheGet,
    CachePut,
    CacheDestroy
};
                     
NTSTATUS
CacheInitialize(
    IN  PXENBUS_FDO             Fdo,
    OUT PXENBUS_CACHE_CONTEXT   *Context
    )
{
    NTSTATUS                    status;

    Trace("====>\n");

    *Context = __CacheAllocate(sizeof (XENBUS_CACHE_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (*Context == NULL)
        goto fail1;

    status = DebugGetInterface(FdoGetDebugContext(Fdo),
                               XENBUS_DEBUG_INTERFACE_VERSION_MAX,
                               (PINTERFACE)&(*Context)->DebugInterface,
                               sizeof ((*Context)->DebugInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT((*Context)->DebugInterface.Interface.Context != NULL);

    InitializeListHead(&(*Context)->List);
    KeInitializeSpinLock(&(*Context)->Lock);

    status = ThreadCreate(CacheMonitor, *Context, &(*Context)->MonitorThread);
    if (!NT_SUCCESS(status))
        goto fail2;

    (*Context)->Fdo = Fdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RtlZeroMemory(&(*Context)->Lock, sizeof (KSPIN_LOCK));
    RtlZeroMemory(&(*Context)->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&(*Context)->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
CacheGetInterface(
    IN      PXENBUS_CACHE_CONTEXT   Context,
    IN      ULONG                   Version,
    IN OUT  PINTERFACE              Interface,
    IN      ULONG                   Size
    )
{
    NTSTATUS                        status;

    ASSERT(Context != NULL);

    switch (Version) {
    case 1: {
        struct _XENBUS_CACHE_INTERFACE_V1   *CacheInterface;

        CacheInterface = (struct _XENBUS_CACHE_INTERFACE_V1 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENBUS_CACHE_INTERFACE_V1))
            break;

        *CacheInterface = CacheInterfaceVersion1;

        ASSERT3U(Interface->Version, ==, Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    case 2: {
        struct _XENBUS_CACHE_INTERFACE_V2   *CacheInterface;

        CacheInterface = (struct _XENBUS_CACHE_INTERFACE_V2 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENBUS_CACHE_INTERFACE_V2))
            break;

        *CacheInterface = CacheInterfaceVersion2;

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
CacheGetReferences(
    IN  PXENBUS_CACHE_CONTEXT   Context
    )
{
    return Context->References;
}

VOID
CacheTeardown(
    IN  PXENBUS_CACHE_CONTEXT   Context
    )
{
    Trace("====>\n");

    Context->Fdo = NULL;

    ThreadAlert(Context->MonitorThread);
    ThreadJoin(Context->MonitorThread);
    Context->MonitorThread = NULL;

    RtlZeroMemory(&Context->Lock, sizeof (KSPIN_LOCK));
    RtlZeroMemory(&Context->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&Context->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    ASSERT(IsZeroMemory(Context, sizeof (XENBUS_CACHE_CONTEXT)));
    __CacheFree(Context);

    Trace("<====\n");
}
