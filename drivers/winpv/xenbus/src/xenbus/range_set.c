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
#include <ntstrsafe.h>
#include <xen.h>

#include "range_set.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define RANGE_SET_TAG   'GNAR'

typedef struct _RANGE {
    LIST_ENTRY  ListEntry;
    LONGLONG    Start;
    LONGLONG    End;
} RANGE, *PRANGE;

#define MAXNAMELEN  128

struct _XENBUS_RANGE_SET {
    LIST_ENTRY      ListEntry;
    CHAR            Name[MAXNAMELEN];
    KSPIN_LOCK      Lock;
    LIST_ENTRY      List;
    PLIST_ENTRY     Cursor;
    ULONG           RangeCount;
    ULONGLONG       ItemCount;
    PRANGE          Spare;
};

struct _XENBUS_RANGE_SET_CONTEXT {
    PXENBUS_FDO             Fdo;
    KSPIN_LOCK              Lock;
    LONG                    References;
    XENBUS_DEBUG_INTERFACE  DebugInterface;
    PXENBUS_DEBUG_CALLBACK  DebugCallback;
    LIST_ENTRY              List;
};

static FORCEINLINE PVOID
__RangeSetAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, RANGE_SET_TAG);
}

static FORCEINLINE VOID
__RangeSetFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, RANGE_SET_TAG);
}

static FORCEINLINE BOOLEAN
__RangeSetIsEmpty(
    IN  PXENBUS_RANGE_SET   RangeSet
    )
{
    return IsListEmpty(&RangeSet->List);
}

static VOID
RangeSetRemove(
    IN  PXENBUS_RANGE_SET   RangeSet,
    IN  BOOLEAN             After
    )
{
    PLIST_ENTRY             Cursor;
    PRANGE                  Range;

    ASSERT(!__RangeSetIsEmpty(RangeSet));

    Cursor = RangeSet->Cursor;
    ASSERT(Cursor != &RangeSet->List);

    RangeSet->Cursor = (After) ? Cursor->Flink : Cursor->Blink;

    RemoveEntryList(Cursor);

    ASSERT(RangeSet->RangeCount != 0);
    --RangeSet->RangeCount;

    if (RangeSet->Cursor == &RangeSet->List)
        RangeSet->Cursor = (After) ? RangeSet->List.Flink : RangeSet->List.Blink;

    Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);
    ASSERT3S(Range->End, <, Range->Start);

    if (RangeSet->Spare == NULL) {
        RtlZeroMemory(Range, sizeof (RANGE));
        RangeSet->Spare = Range;
    } else {
        __RangeSetFree(Range);
    }
}

static VOID
RangeSetMergeBackwards(
    IN  PXENBUS_RANGE_SET   RangeSet
    )
{
    PLIST_ENTRY             Cursor;
    PRANGE                  Range;
    PRANGE                  Previous;

    Cursor = RangeSet->Cursor;
    ASSERT(Cursor != &RangeSet->List);

    if (Cursor->Blink == &RangeSet->List)
        return;

    Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);
    Previous = CONTAINING_RECORD(Cursor->Blink, RANGE, ListEntry);

    if (Previous->End != Range->Start - 1)  // Not touching
        return;

    Previous->End = Range->End;
    Range->Start = Range->End + 1; // Invalidate
    RangeSetRemove(RangeSet, FALSE);
}

static VOID
RangeSetMergeForwards(
    IN  PXENBUS_RANGE_SET   RangeSet
    )
{
    PLIST_ENTRY             Cursor;
    PRANGE                  Range;
    PRANGE                  Next;

    Cursor = RangeSet->Cursor;
    ASSERT(Cursor != &RangeSet->List);

    if (Cursor->Flink == &RangeSet->List)
        return;

    Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);
    Next = CONTAINING_RECORD(Cursor->Flink, RANGE, ListEntry);

    if (Next->Start != Range->End + 1)  // Not touching
        return;

    Next->Start = Range->Start;
    Range->End = Range->Start - 1;  // Invalidate
    RangeSetRemove(RangeSet, TRUE);
}

static NTSTATUS
RangeSetPop(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_RANGE_SET   RangeSet,
    IN  ULONGLONG           Count,
    OUT PLONGLONG           Start
    )
{
    PLIST_ENTRY             Cursor;
    PRANGE                  Range;
    KIRQL                   Irql;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Interface);

    status = STATUS_INVALID_PARAMETER;

    if (Count == 0)
        goto fail1;

    KeAcquireSpinLock(&RangeSet->Lock, &Irql);

    status = STATUS_INSUFFICIENT_RESOURCES;

    if (__RangeSetIsEmpty(RangeSet))
        goto fail2;

    Cursor = RangeSet->List.Flink;

    while (Cursor != &RangeSet->List) {
        Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);

        if ((ULONGLONG)(Range->End + 1 - Range->Start) >= Count)
            goto found;

        Cursor = Cursor->Flink;
    }

    goto fail3;

found:
    RangeSet->Cursor = Cursor;

    *Start = Range->Start;
    Range->Start += Count;

    ASSERT3U(RangeSet->ItemCount, >=, Count);
    RangeSet->ItemCount -= Count;

    if (Range->Start > Range->End)    // Invalid
        RangeSetRemove(RangeSet, TRUE);

    KeReleaseSpinLock(&RangeSet->Lock, Irql);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    KeReleaseSpinLock(&RangeSet->Lock, Irql);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
RangeSetAdd(
    IN  PXENBUS_RANGE_SET   RangeSet,
    IN  LONGLONG            Start,
    IN  LONGLONG            End,
    IN  BOOLEAN             After
    )
{
#define INSERT_AFTER(_Cursor, _New)             \
        do {                                    \
            (_New)->Flink = (_Cursor)->Flink;   \
            (_Cursor)->Flink->Blink = (_New);   \
                                                \
            (_Cursor)->Flink = (_New);          \
            (_New)->Blink = (_Cursor);          \
        } while (FALSE)

#define INSERT_BEFORE(_Cursor, _New)            \
        do {                                    \
            (_New)->Blink = (_Cursor)->Blink;   \
            (_Cursor)->Blink->Flink = (_New);   \
                                                \
            (_Cursor)->Blink = (_New);          \
            (_New)->Flink = (_Cursor);          \
        } while (FALSE)

    PRANGE                  Range;
    PLIST_ENTRY             Cursor;
    NTSTATUS                status;

    if (RangeSet->Spare != NULL) {
        Range = RangeSet->Spare;
        RangeSet->Spare = NULL;
    } else {
        Range = __RangeSetAllocate(sizeof (RANGE));

        status = STATUS_NO_MEMORY;
        if (Range == NULL)
            goto fail1;
    }

    ASSERT(IsZeroMemory(Range, sizeof (RANGE)));

    Range->Start = Start;
    Range->End = End;

    Cursor = RangeSet->Cursor;

    if (After)
        INSERT_AFTER(Cursor, &Range->ListEntry);
    else
        INSERT_BEFORE(Cursor, &Range->ListEntry);

    RangeSet->RangeCount++;

    RangeSet->Cursor = &Range->ListEntry;

    RangeSetMergeBackwards(RangeSet);
    RangeSetMergeForwards(RangeSet);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;

#undef  INSERT_AFTER
#undef  INSERT_BEFORE
}

static NTSTATUS
RangeSetGet(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_RANGE_SET   RangeSet,
    IN  LONGLONG            Start,
    IN  ULONGLONG           Count
    )
{
    LONGLONG                End = Start + Count - 1;
    PLIST_ENTRY             Cursor;
    PRANGE                  Range;
    KIRQL                   Irql;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Interface);

    status = STATUS_INVALID_PARAMETER;

    if (Count == 0)
        goto fail1;

    KeAcquireSpinLock(&RangeSet->Lock, &Irql);

    Cursor = RangeSet->Cursor;
    ASSERT(Cursor != &RangeSet->List);

    Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);

    if (Start < Range->Start) {
        do {
            Cursor = Cursor->Blink;
            ASSERT(Cursor != &RangeSet->List);

            Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);
        } while (Start < Range->Start);

        RangeSet->Cursor = Cursor;
    } else if (Start > Range->End) {
        do {
            Cursor = Cursor->Flink;
            ASSERT(Cursor != &RangeSet->List);

            Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);
        } while (Start > Range->End);

        RangeSet->Cursor = Cursor;
    }

    ASSERT3S(Start, >=, Range->Start);
    ASSERT3S(Start, <=, Range->End);

    if (Start == Range->Start && End == Range->End) {
        Range->Start = End + 1;    // Invalidate
        RangeSetRemove(RangeSet, TRUE);
        goto done;
    }

    ASSERT3S(Range->End, >, Range->Start);

    if (Start == Range->Start) {
        Range->Start = End + 1;
        goto done;
    }

    ASSERT3S(Range->Start, <, Start);

    if (End == Range->End) {
        Range->End = Start - 1;
        goto done;
    }

    ASSERT3S(End, <, Range->End);

    // We need to split a range
    status = RangeSetAdd(RangeSet, End + 1, Range->End, TRUE);
    if (!NT_SUCCESS(status))
        goto fail2;

    Range->End = Start - 1;

done:
    ASSERT3U(RangeSet->ItemCount, >=, Count);
    RangeSet->ItemCount -= Count;

    KeReleaseSpinLock(&RangeSet->Lock, Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    KeReleaseSpinLock(&RangeSet->Lock, Irql);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;    
}

static NTSTATUS
RangeSetAddAfter(
    IN  PXENBUS_RANGE_SET   RangeSet,
    IN  LONGLONG            Start,
    IN  LONGLONG            End
    )
{
    PLIST_ENTRY             Cursor;
    PRANGE                  Range;
    NTSTATUS                status;

    Cursor = RangeSet->Cursor;
    ASSERT(Cursor != &RangeSet->List);

    Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);
    ASSERT3S(Start, >, Range->End);

    Cursor = Cursor->Flink;
    while (Cursor != &RangeSet->List) {
        Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);

        if (Start < Range->Start) {
            ASSERT(End < Range->Start);
            break;
        }

        Cursor = Cursor->Flink;
    }

    RangeSet->Cursor = Cursor;
    status = RangeSetAdd(RangeSet, Start, End, FALSE);    
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;    
}

static NTSTATUS
RangeSetAddBefore(
    IN  PXENBUS_RANGE_SET   RangeSet,
    IN  LONGLONG            Start,
    IN  LONGLONG            End
    )
{
    PLIST_ENTRY             Cursor;
    PRANGE                  Range;
    NTSTATUS                status;

    Cursor = RangeSet->Cursor;
    ASSERT(Cursor != &RangeSet->List);

    Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);
    ASSERT3S(End, <, Range->Start);

    Cursor = Cursor->Blink;
    while (Cursor != &RangeSet->List) {
        Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);

        if (End > Range->End) {
            ASSERT(Start > Range->End);
            break;
        }

        Cursor = Cursor->Blink;
    }

    RangeSet->Cursor = Cursor;
    status = RangeSetAdd(RangeSet, Start, End, TRUE);    
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;    
}

static NTSTATUS
RangeSetPut(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_RANGE_SET       RangeSet,
    IN  LONGLONG                Start,
    IN  ULONGLONG               Count
    )
{
    LONGLONG                    End = Start + Count - 1;
    PLIST_ENTRY                 Cursor;
    KIRQL                       Irql;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(Interface);

    status = STATUS_INVALID_PARAMETER;

    if (Count == 0)
        goto fail1;

    ASSERT3S(End, >=, Start);

    KeAcquireSpinLock(&RangeSet->Lock, &Irql);

    Cursor = RangeSet->Cursor;

    if (__RangeSetIsEmpty(RangeSet)) {
        status = RangeSetAdd(RangeSet, Start, End, TRUE);
    } else {
        PRANGE  Range;

        Range = CONTAINING_RECORD(Cursor, RANGE, ListEntry);

        if (Start > Range->End) {
            status = RangeSetAddAfter(RangeSet, Start, End);
        } else {
            ASSERT3S(End, <, Range->Start);
            status = RangeSetAddBefore(RangeSet, Start, End);
        }
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    RangeSet->ItemCount += Count;

    KeReleaseSpinLock(&RangeSet->Lock, Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    KeReleaseSpinLock(&RangeSet->Lock, Irql);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
RangeSetCreate(
    IN  PINTERFACE              Interface,
    IN  const CHAR              *Name,
    OUT PXENBUS_RANGE_SET       *RangeSet
    )
{
    PXENBUS_RANGE_SET_CONTEXT   Context = Interface->Context;
    KIRQL                       Irql;
    NTSTATUS                    status;

    Trace("====> (%s)\n", Name);

    *RangeSet = __RangeSetAllocate(sizeof (XENBUS_RANGE_SET));

    status = STATUS_NO_MEMORY;
    if (*RangeSet == NULL)
        goto fail1;

    status = RtlStringCbPrintfA((*RangeSet)->Name,
                                sizeof ((*RangeSet)->Name),
                                "%s",
                                Name);
    if (!NT_SUCCESS(status))
        goto fail2;

    KeInitializeSpinLock(&(*RangeSet)->Lock);
    InitializeListHead(&(*RangeSet)->List);
    (*RangeSet)->Cursor = &(*RangeSet)->List;

    KeAcquireSpinLock(&Context->Lock, &Irql);
    InsertTailList(&Context->List, &(*RangeSet)->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RtlZeroMemory((*RangeSet)->Name, sizeof ((*RangeSet)->Name));

    ASSERT(IsZeroMemory(*RangeSet, sizeof (XENBUS_RANGE_SET)));
    __RangeSetFree(*RangeSet);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
RangeSetDestroy(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_RANGE_SET       RangeSet
    )
{
    PXENBUS_RANGE_SET_CONTEXT   Context = Interface->Context;
    KIRQL                       Irql;

    Trace("====> (%s)\n", RangeSet->Name);

    KeAcquireSpinLock(&Context->Lock, &Irql);
    RemoveEntryList(&RangeSet->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    RtlZeroMemory(&RangeSet->ListEntry, sizeof (LIST_ENTRY));

    if (RangeSet->Spare != NULL) {
        __RangeSetFree(RangeSet->Spare);
        RangeSet->Spare = NULL;
    }
        
    ASSERT(__RangeSetIsEmpty(RangeSet));
    RtlZeroMemory(&RangeSet->List, sizeof (LIST_ENTRY));
    RtlZeroMemory(&RangeSet->Lock, sizeof (KSPIN_LOCK));

    RangeSet->Cursor = NULL;

    RtlZeroMemory(RangeSet->Name, sizeof (RangeSet->Name));

    ASSERT(IsZeroMemory(RangeSet, sizeof (XENBUS_RANGE_SET)));
    __RangeSetFree(RangeSet);

    Trace("<====\n");
}

static VOID
RangeSetDump(
    IN  PXENBUS_RANGE_SET_CONTEXT   Context,
    IN  PXENBUS_RANGE_SET           RangeSet
    )
{
    XENBUS_DEBUG(Printf,
                 &Context->DebugInterface,
                 " - %s:\n",
                 RangeSet->Name);

    if (IsListEmpty(&RangeSet->List)) {
        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "   EMPTY\n");
    } else {
        PLIST_ENTRY ListEntry;
        ULONG       Count;

        Count = 0;

        for (ListEntry = RangeSet->List.Flink;
             ListEntry != &RangeSet->List;
             ListEntry = ListEntry->Flink) {
            PRANGE Range;

            Range = CONTAINING_RECORD(ListEntry, RANGE, ListEntry);

            XENBUS_DEBUG(Printf,
                         &Context->DebugInterface,
                         "   {%llx - %llx}%s\n",
                         Range->Start,
                         Range->End,
                         (ListEntry == RangeSet->Cursor) ? "*" : "");

            if (++Count > 8) {
                XENBUS_DEBUG(Printf,
                             &Context->DebugInterface,
                             "   ...\n");
                break;
            }
        }
    }
}

static VOID
RangeSetDebugCallback(
    IN  PVOID                   Argument,
    IN  BOOLEAN                 Crashing
    )
{
    PXENBUS_RANGE_SET_CONTEXT   Context = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    if (!IsListEmpty(&Context->List)) {
        PLIST_ENTRY ListEntry;

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "RANGE SETS:\n");

        for (ListEntry = Context->List.Flink;
             ListEntry != &Context->List;
             ListEntry = ListEntry->Flink) {
            PXENBUS_RANGE_SET   RangeSet;

            RangeSet = CONTAINING_RECORD(ListEntry, XENBUS_RANGE_SET, ListEntry);

            RangeSetDump(Context, RangeSet);
        }
    }
}

static NTSTATUS
RangeSetAcquire(
    IN  PINTERFACE              Interface
    )
{
    PXENBUS_RANGE_SET_CONTEXT   Context = Interface->Context;
    KIRQL                       Irql;
    NTSTATUS                    status;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    status = XENBUS_DEBUG(Acquire, &Context->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Register,
                          &Context->DebugInterface,
                          __MODULE__ "|RANGE_SET",
                          RangeSetDebugCallback,
                          Context,
                          &Context->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail2;

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail3\n");

    XENBUS_DEBUG(Release, &Context->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    --Context->References;
    ASSERT3U(Context->References, ==, 0);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return status;
}

static VOID
RangeSetRelease(
    IN  PINTERFACE              Interface
    )
{
    PXENBUS_RANGE_SET_CONTEXT   Context = Interface->Context;
    KIRQL                       Irql;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    if (!IsListEmpty(&Context->List))
        BUG("OUTSTANDING RANGE SETS");

    XENBUS_DEBUG(Deregister,
                 &Context->DebugInterface,
                 Context->DebugCallback);
    Context->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Context->DebugInterface);

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);
}

static struct _XENBUS_RANGE_SET_INTERFACE_V1 RangeSetInterfaceVersion1 = {
    { sizeof (struct _XENBUS_RANGE_SET_INTERFACE_V1), 1, NULL, NULL, NULL },
    RangeSetAcquire,
    RangeSetRelease,
    RangeSetCreate,
    RangeSetPut,
    RangeSetPop,
    RangeSetGet,
    RangeSetDestroy
};
                     
NTSTATUS
RangeSetInitialize(
    IN  PXENBUS_FDO                 Fdo,
    OUT PXENBUS_RANGE_SET_CONTEXT   *Context
    )
{
    NTSTATUS                        status;

    Trace("====>\n");

    *Context = __RangeSetAllocate(sizeof (XENBUS_RANGE_SET_CONTEXT));

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

    (*Context)->Fdo = Fdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
RangeSetGetInterface(
    IN      PXENBUS_RANGE_SET_CONTEXT   Context,
    IN      ULONG                       Version,
    IN OUT  PINTERFACE                  Interface,
    IN      ULONG                       Size
    )
{
    NTSTATUS                            status;

    ASSERT(Context != NULL);

    switch (Version) {
    case 1: {
        struct _XENBUS_RANGE_SET_INTERFACE_V1  *RangeSetInterface;

        RangeSetInterface = (struct _XENBUS_RANGE_SET_INTERFACE_V1 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENBUS_RANGE_SET_INTERFACE_V1))
            break;

        *RangeSetInterface = RangeSetInterfaceVersion1;

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
RangeSetGetReferences(
    IN  PXENBUS_RANGE_SET_CONTEXT   Context
    )
{
    return Context->References;
}

VOID
RangeSetTeardown(
    IN  PXENBUS_RANGE_SET_CONTEXT   Context
    )
{
    Trace("====>\n");

    Context->Fdo = NULL;

    RtlZeroMemory(&Context->Lock, sizeof (KSPIN_LOCK));
    RtlZeroMemory(&Context->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&Context->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    ASSERT(IsZeroMemory(Context, sizeof (XENBUS_RANGE_SET_CONTEXT)));
    __RangeSetFree(Context);

    Trace("<====\n");
}
