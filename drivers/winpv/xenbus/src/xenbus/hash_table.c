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
#include <stdarg.h>
#include <xen.h>

#include "hash_table.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

typedef struct _XENBUS_HASH_TABLE_NODE {
    LIST_ENTRY  ListEntry;
    ULONG_PTR   Key;
    ULONG_PTR   Value;
} XENBUS_HASH_TABLE_NODE, *PXENBUS_HASH_TABLE_NODE;

typedef struct _XENBUS_HASH_TABLE_BUCKET {
    LONG        Lock;
    LIST_ENTRY  List;
} XENBUS_HASH_TABLE_BUCKET, *PXENBUS_HASH_TABLE_BUCKET;

#define XENBUS_HASH_TABLE_NR_BUCKETS \
    (1 << (sizeof (UCHAR) * 8))

struct _XENBUS_HASH_TABLE {
    XENBUS_HASH_TABLE_BUCKET    Bucket[XENBUS_HASH_TABLE_NR_BUCKETS];
    XENBUS_HASH_TABLE_BUCKET    Hidden;
    KDPC                        Dpc;
};

#define XENBUS_HASH_TABLE_TAG   'HSAH'

static FORCEINLINE PVOID
__HashTableAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_HASH_TABLE_TAG);
}

static FORCEINLINE VOID
__HashTableFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_HASH_TABLE_TAG);
}

static ULONG
HashTableHash(
    IN  ULONG_PTR   Key
    )
{
    PUCHAR          Array = (PUCHAR)&Key;
    ULONG           Accumulator;
    ULONG           Index;

    Accumulator = 0;

    for (Index = 0; Index < sizeof (ULONG_PTR); Index++) {
        ULONG   Overflow;

        Accumulator = (Accumulator << 4) + Array[Index];

        Overflow = Accumulator & 0x0000ff00;
        if (Overflow != 0) {
            Accumulator ^= Overflow >> 8;
            Accumulator ^= Overflow;
        }
    }

    ASSERT3U(Accumulator, <, XENBUS_HASH_TABLE_NR_BUCKETS);

    return Accumulator;
}

static
_IRQL_requires_max_(HIGH_LEVEL)
_IRQL_saves_
_IRQL_raises_(HIGH_LEVEL)
KIRQL
__HashTableBucketLock(
    IN  PXENBUS_HASH_TABLE_BUCKET   Bucket,
    IN  BOOLEAN                     Writer
    )
{
    KIRQL                           Irql;

    KeRaiseIrql(HIGH_LEVEL, &Irql);

    for (;;) {
        LONG    Lock;
        LONG    Readers;
        LONG    Writers;
        LONG    Old;
        LONG    New;

        KeMemoryBarrier();

        Lock = Bucket->Lock;
        Readers = Lock >> 1;
        Writers = Lock & 1;

        // There must be no existing writer
        Old = Readers << 1;

        if (Writer) 
            Writers++;
        else
            Readers++;

        New = (Readers << 1) | (Writers & 1);

        if (InterlockedCompareExchange(&Bucket->Lock, New, Old) != Old)
            continue;

        //
        // We are done if we're not a writer, or there are no readers
        // left.
        //
        if (!Writer || Readers == 0)
            break;
    }

    return Irql;
}

#define HashTableBucketLock(_Bucket, _Writer, _Irql)            \
    do {                                                        \
        *(_Irql) = __HashTableBucketLock((_Bucket), (_Writer)); \
    } while (FALSE)

static
__drv_requiresIRQL(HIGH_LEVEL)
VOID
HashTableBucketUnlock(
    IN  PXENBUS_HASH_TABLE_BUCKET   Bucket,
    IN  BOOLEAN                     Writer,
    IN  __drv_restoresIRQL KIRQL    Irql
    )
{
    for (;;) {
        LONG    Lock;
        LONG    Readers;
        LONG    Writers;
        LONG    Old;
        LONG    New;

        KeMemoryBarrier();

        Lock = Bucket->Lock;
        Readers = Lock >> 1;
        Writers = Lock & 1;

        Old = (Readers << 1) | (Writers & 1);

        if (Writer) {
            ASSERT(Writers != 0);
            --Writers;
        } else {
            --Readers;
        }

        New = (Readers << 1) | (Writers & 1);

        if (InterlockedCompareExchange(&Bucket->Lock, New, Old) == Old)
            break;
    }

    KeLowerIrql(Irql);
}

NTSTATUS
HashTableAdd(
    IN  PXENBUS_HASH_TABLE      Table,
    IN  ULONG_PTR               Key,
    IN  ULONG_PTR               Value
    )
{
    PXENBUS_HASH_TABLE_NODE     Node;
    PXENBUS_HASH_TABLE_BUCKET   Bucket;
    KIRQL                       Irql;
    NTSTATUS                    status;

    Node = __HashTableAllocate(sizeof (XENBUS_HASH_TABLE_NODE));

    status = STATUS_NO_MEMORY;
    if (Node == NULL)
        goto fail1;

    Node->Key = Key;
    Node->Value = Value;

    Bucket = &Table->Bucket[HashTableHash(Key)];
    
    HashTableBucketLock(Bucket, TRUE, &Irql);
    InsertTailList(&Bucket->List, &Node->ListEntry);
    HashTableBucketUnlock(Bucket, TRUE, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
HashTableRemove(
    IN  PXENBUS_HASH_TABLE      Table,
    IN  ULONG_PTR               Key
    )
{
    PXENBUS_HASH_TABLE_BUCKET   Bucket;
    PXENBUS_HASH_TABLE_BUCKET   Hidden;
    PLIST_ENTRY                 ListEntry;
    PXENBUS_HASH_TABLE_NODE     Node;
    KIRQL                       Irql;
    NTSTATUS                    status;

    Bucket = &Table->Bucket[HashTableHash(Key)];
    Hidden = &Table->Hidden;
    
    HashTableBucketLock(Bucket, TRUE, &Irql);

    for (ListEntry = Bucket->List.Flink;
         ListEntry != &Bucket->List;
         ListEntry = ListEntry->Flink) {
        Node = CONTAINING_RECORD(ListEntry, XENBUS_HASH_TABLE_NODE, ListEntry);

        if (Node->Key == Key)
            goto found;
    }

    HashTableBucketUnlock(Bucket, TRUE, Irql);

    status = STATUS_OBJECT_NAME_NOT_FOUND;
    goto fail1;

found:
    RemoveEntryList(ListEntry);

    HashTableBucketUnlock(Bucket, TRUE, Irql);

    HashTableBucketLock(Hidden, TRUE, &Irql);
    InsertTailList(&Hidden->List, &Node->ListEntry);
    HashTableBucketUnlock(Hidden, TRUE, Irql);

    KeInsertQueueDpc(&Table->Dpc, NULL, NULL);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
HashTableLookup(
    IN  PXENBUS_HASH_TABLE      Table,
    IN  ULONG_PTR               Key,
    OUT PULONG_PTR              Value
    )
{
    PXENBUS_HASH_TABLE_BUCKET   Bucket;
    PLIST_ENTRY                 ListEntry;
    PXENBUS_HASH_TABLE_NODE     Node;
    KIRQL                       Irql;
    NTSTATUS                    status;

    Bucket = &Table->Bucket[HashTableHash(Key)];
    
    HashTableBucketLock(Bucket, FALSE, &Irql);

    for (ListEntry = Bucket->List.Flink;
         ListEntry != &Bucket->List;
         ListEntry = ListEntry->Flink) {
        Node = CONTAINING_RECORD(ListEntry, XENBUS_HASH_TABLE_NODE, ListEntry);

        if (Node->Key == Key)
            goto found;
    }

    HashTableBucketUnlock(Bucket, FALSE, Irql);

    status = STATUS_OBJECT_NAME_NOT_FOUND;
    goto fail1;

found:
    *Value = Node->Value;

    HashTableBucketUnlock(Bucket, FALSE, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static
_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
HashTableDpc(
    IN  PKDPC                   Dpc,
    IN  PVOID                   Context,
    IN  PVOID                   Argument1,
    IN  PVOID                   Argument2
    )
{
    PXENBUS_HASH_TABLE          Table = Context;
    LIST_ENTRY                  List;
    PXENBUS_HASH_TABLE_BUCKET   Hidden;
    KIRQL                       Irql;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    InitializeListHead(&List);

    Hidden = &Table->Hidden;

    HashTableBucketLock(Hidden, TRUE, &Irql);

    while (!IsListEmpty(&Hidden->List)) {
        PLIST_ENTRY ListEntry;

        ListEntry = RemoveHeadList(&Hidden->List);

        InsertTailList(&List, ListEntry);
    }

    HashTableBucketUnlock(Hidden, TRUE, Irql);

    while (!IsListEmpty(&List)) {
        PLIST_ENTRY             ListEntry;
        PXENBUS_HASH_TABLE_NODE Node;

        ListEntry = RemoveHeadList(&List);

        Node = CONTAINING_RECORD(ListEntry, XENBUS_HASH_TABLE_NODE, ListEntry);
        __HashTableFree(Node);
    }
}

NTSTATUS
HashTableCreate(
    OUT PXENBUS_HASH_TABLE      *Table
    )
{
    ULONG                       Index;
    PXENBUS_HASH_TABLE_BUCKET   Hidden;
    NTSTATUS                    status;

    *Table = __HashTableAllocate(sizeof (XENBUS_HASH_TABLE));

    status = STATUS_NO_MEMORY;
    if (*Table == NULL)
        goto fail1;

    for (Index = 0; Index < XENBUS_HASH_TABLE_NR_BUCKETS; Index++) {
        PXENBUS_HASH_TABLE_BUCKET   Bucket = &(*Table)->Bucket[Index];

        InitializeListHead(&Bucket->List);
    }

    Hidden = &(*Table)->Hidden;

    InitializeListHead(&Hidden->List);

    KeInitializeDpc(&(*Table)->Dpc, HashTableDpc, *Table);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
HashTableDestroy(
    IN  PXENBUS_HASH_TABLE      Table
    )
{
    ULONG                       Index;
    PXENBUS_HASH_TABLE_BUCKET   Hidden;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    KeFlushQueuedDpcs();

    RtlZeroMemory(&Table->Dpc, sizeof (KDPC));

    Hidden = &Table->Hidden;

    ASSERT(IsListEmpty(&Hidden->List));
    RtlZeroMemory(&Hidden->List, sizeof (LIST_ENTRY));

    for (Index = 0; Index < XENBUS_HASH_TABLE_NR_BUCKETS; Index++) {
        PXENBUS_HASH_TABLE_BUCKET   Bucket = &Table->Bucket[Index];

        ASSERT(IsListEmpty(&Bucket->List));
        RtlZeroMemory(&Bucket->List, sizeof (LIST_ENTRY));
    }

    ASSERT(IsZeroMemory(Table, sizeof (XENBUS_HASH_TABLE)));
    __HashTableFree(Table);
}

