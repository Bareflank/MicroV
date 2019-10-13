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
#include <stdarg.h>
#include <stdlib.h>
#include <xen.h>

#include "console.h"
#include "evtchn.h"
#include "fdo.h"
#include "high.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define CONSOLE_WAKEUP_MAGIC 'EKAW'

struct _XENBUS_CONSOLE_WAKEUP {
    LIST_ENTRY  ListEntry;
    ULONG       Magic;
    PVOID       Caller;
    PKEVENT     Event;
};

struct _XENBUS_CONSOLE_CONTEXT {
    PXENBUS_FDO                 Fdo;
    KSPIN_LOCK                  Lock;
    LONG                        References;
    struct xencons_interface    *Shared;
    HIGH_LOCK                   RingLock;
    PHYSICAL_ADDRESS            Address;
    LIST_ENTRY                  WakeupList;
    KDPC                        Dpc;
    PXENBUS_EVTCHN_CHANNEL      Channel;
    ULONG                       Events;
    ULONG                       Dpcs;
    XENBUS_GNTTAB_INTERFACE     GnttabInterface;
    XENBUS_EVTCHN_INTERFACE     EvtchnInterface;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    BOOLEAN                     Enabled;
};

C_ASSERT(sizeof (struct xencons_interface) <= PAGE_SIZE);

#define XENBUS_CONSOLE_TAG  'SNOC'

static FORCEINLINE PVOID
__ConsoleAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_CONSOLE_TAG);
}

static FORCEINLINE VOID
__ConsoleFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_CONSOLE_TAG);
}

static ULONG
ConsoleOutAvailable(
    IN  PXENBUS_CONSOLE_CONTEXT Context
    )
{
    struct xencons_interface    *Shared;
    XENCONS_RING_IDX            cons;
    XENCONS_RING_IDX            prod;

    Shared = Context->Shared;

    KeMemoryBarrier();

    prod = Shared->out_prod;
    cons = Shared->out_cons;

    KeMemoryBarrier();

    return cons + sizeof (Shared->out) - prod;
}

static ULONG
ConsoleCopyToOut(
    IN  PXENBUS_CONSOLE_CONTEXT Context,
    IN  PCHAR                   Data,
    IN  ULONG                   Length
    )
{
    struct xencons_interface    *Shared;
    XENCONS_RING_IDX            cons;
    XENCONS_RING_IDX            prod;
    ULONG                       Offset;

    Shared = Context->Shared;

    KeMemoryBarrier();

    prod = Shared->out_prod;
    cons = Shared->out_cons;

    KeMemoryBarrier();

    Offset = 0;
    while (Length != 0) {
        ULONG   Available;
        ULONG   Index;
        ULONG   CopyLength;

        Available = cons + sizeof (Shared->out) - prod;

        if (Available == 0)
            break;

        Index = MASK_XENCONS_IDX(prod, Shared->out);

        CopyLength = __min(Length, Available);
        CopyLength = __min(CopyLength, sizeof (Shared->out) - Index);

        RtlCopyMemory(&Shared->out[Index], Data + Offset, CopyLength);

        Offset += CopyLength;
        Length -= CopyLength;

        prod += CopyLength;
    }

    KeMemoryBarrier();

    Shared->out_prod = prod;

    KeMemoryBarrier();

    return Offset;
}

static ULONG
ConsoleInAvailable(
    IN  PXENBUS_CONSOLE_CONTEXT Context
    )
{
    struct xencons_interface    *Shared;
    XENCONS_RING_IDX            cons;
    XENCONS_RING_IDX            prod;

    Shared = Context->Shared;

    KeMemoryBarrier();

    cons = Shared->in_cons;
    prod = Shared->in_prod;

    KeMemoryBarrier();

    return prod - cons;
}

static ULONG
ConsoleCopyFromIn(
    IN  PXENBUS_CONSOLE_CONTEXT Context,
    IN  PCHAR                   Data,
    IN  ULONG                   Length
    )
{
    struct xencons_interface    *Shared;
    XENCONS_RING_IDX            cons;
    XENCONS_RING_IDX            prod;
    ULONG                       Offset;

    Shared = Context->Shared;

    KeMemoryBarrier();

    cons = Shared->in_cons;
    prod = Shared->in_prod;

    KeMemoryBarrier();

    Offset = 0;
    while (Length != 0) {
        ULONG   Available;
        ULONG   Index;
        ULONG   CopyLength;

        Available = prod - cons;

        if (Available == 0)
            break;

        Index = MASK_XENCONS_IDX(cons, Shared->in);

        CopyLength = __min(Length, Available);
        CopyLength = __min(CopyLength, sizeof (Shared->in) - Index);

        RtlCopyMemory(Data + Offset, &Shared->in[Index], CopyLength);

        Offset += CopyLength;
        Length -= CopyLength;

        cons += CopyLength;
    }

    KeMemoryBarrier();

    Shared->in_cons = cons;

    KeMemoryBarrier();

    return Offset;
}

static VOID
ConsolePoll(
    IN  PXENBUS_CONSOLE_CONTEXT Context
    )
{
    PLIST_ENTRY                 ListEntry;

    for (ListEntry = Context->WakeupList.Flink;
         ListEntry != &Context->WakeupList;
         ListEntry = ListEntry->Flink) {
        PXENBUS_CONSOLE_WAKEUP  Wakeup;

        Wakeup = CONTAINING_RECORD(ListEntry,
                                   XENBUS_CONSOLE_WAKEUP,
                                   ListEntry);

        KeSetEvent(Wakeup->Event, IO_NO_INCREMENT, FALSE);
    }
}

static
_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
ConsoleDpc(
    IN  PKDPC               Dpc,
    IN  PVOID               _Context,
    IN  PVOID               Argument1,
    IN  PVOID               Argument2
    )
{
    PXENBUS_CONSOLE_CONTEXT Context = _Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Context != NULL);

    KeAcquireSpinLockAtDpcLevel(&Context->Lock);
    if (Context->References != 0)
        ConsolePoll(Context);
    KeReleaseSpinLockFromDpcLevel(&Context->Lock);
}

static
_Function_class_(KSERVICE_ROUTINE)
_IRQL_requires_(HIGH_LEVEL)
_IRQL_requires_same_
BOOLEAN
ConsoleEvtchnCallback(
    IN  PKINTERRUPT         InterruptObject,
    IN  PVOID               Argument
    )
{
    PXENBUS_CONSOLE_CONTEXT Context = Argument;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Context != NULL);

    Context->Events++;

    if (KeInsertQueueDpc(&Context->Dpc, NULL, NULL))
        Context->Dpcs++;

    return TRUE;
}

static VOID
ConsoleDisable(
    IN PXENBUS_CONSOLE_CONTEXT  Context
    )
{
    LogPrintf(LOG_LEVEL_INFO,
              "CONSOLE: DISABLE\n");

    Context->Enabled = FALSE;

    XENBUS_EVTCHN(Close,
                  &Context->EvtchnInterface,
                  Context->Channel);
    Context->Channel = NULL;
}

static VOID
ConsoleEnable(
    IN PXENBUS_CONSOLE_CONTEXT  Context
    )
{
    ULONGLONG                   Value;
    ULONG                       Port;
    NTSTATUS                    status;

    status = HvmGetParam(HVM_PARAM_CONSOLE_EVTCHN, &Value);
    ASSERT(NT_SUCCESS(status));

    Port = (ULONG)Value;

    Context->Channel = XENBUS_EVTCHN(Open,
                                     &Context->EvtchnInterface,
                                     XENBUS_EVTCHN_TYPE_FIXED,
                                     ConsoleEvtchnCallback,
                                     Context,
                                     Port,
                                     FALSE);
    ASSERT(Context->Channel != NULL);

    (VOID) XENBUS_EVTCHN(Unmask,
                         &Context->EvtchnInterface,
                         Context->Channel,
                         FALSE,
                         TRUE);

    Context->Enabled = TRUE;

    LogPrintf(LOG_LEVEL_INFO,
              "CONSOLE: ENABLE (%u)\n",
              Port);

    // Trigger an initial poll
    if (KeInsertQueueDpc(&Context->Dpc, NULL, NULL))
        Context->Dpcs++;
}

static
ConsoleGetAddress(
    IN  PXENBUS_CONSOLE_CONTEXT Context,
    OUT PPHYSICAL_ADDRESS       Address
    )
{
    PFN_NUMBER                  Pfn;
    NTSTATUS                    status;

    status = XENBUS_GNTTAB(QueryReference,
                           &Context->GnttabInterface,
                           XENBUS_GNTTAB_CONSOLE_REFERENCE,
                           &Pfn,
                           NULL);
    if (!NT_SUCCESS(status))
        goto fail1;

    Address->QuadPart = Pfn << PAGE_SHIFT;

    LogPrintf(LOG_LEVEL_INFO,
              "CONSOLE: PAGE @ %08x.%08x\n",
              Address->HighPart,
              Address->LowPart);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
ConsoleSuspendCallbackLate(
    IN  PVOID                   Argument
    )
{
    PXENBUS_CONSOLE_CONTEXT     Context = Argument;
    struct xencons_interface    *Shared;
    KIRQL                       Irql;
    PHYSICAL_ADDRESS            Address;
    NTSTATUS                    status;

    status = ConsoleGetAddress(Context, &Address);
    ASSERT3U(Address.QuadPart, ==, Context->Address.QuadPart);

    Shared = Context->Shared;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    ConsoleDisable(Context);
    ConsoleEnable(Context);

    KeReleaseSpinLock(&Context->Lock, Irql);
}

static VOID
ConsoleDebugCallback(
    IN  PVOID               Argument,
    IN  BOOLEAN             Crashing
    )
{
    PXENBUS_CONSOLE_CONTEXT Context = Argument;

    XENBUS_DEBUG(Printf,
                 &Context->DebugInterface,
                 "Address = %08x.%08x\n",
                 Context->Address.HighPart,
                 Context->Address.LowPart);

    if (!Crashing) {
        struct xencons_interface    *Shared;

        Shared = Context->Shared;

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "out_cons = %08x out_prod = %08x\n",
                     Shared->out_cons,
                     Shared->out_prod);

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "in_cons = %08x in_prod = %08x\n",
                     Shared->in_cons,
                     Shared->in_prod);
    }

    XENBUS_DEBUG(Printf,
                 &Context->DebugInterface,
                 "Events = %lu Dpcs = %lu\n",
                 Context->Events,
                 Context->Dpcs);

    if (!IsListEmpty(&Context->WakeupList)) {
        PLIST_ENTRY ListEntry;

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "WAKEUPS:\n");

        for (ListEntry = Context->WakeupList.Flink;
             ListEntry != &(Context->WakeupList);
             ListEntry = ListEntry->Flink) {
            PXENBUS_CONSOLE_WAKEUP  Wakeup;
            PCHAR                   Name;
            ULONG_PTR               Offset;

            Wakeup = CONTAINING_RECORD(ListEntry,
                                       XENBUS_CONSOLE_WAKEUP,
                                       ListEntry);

            ModuleLookup((ULONG_PTR)Wakeup->Caller, &Name, &Offset);

            if (Name != NULL) {
                XENBUS_DEBUG(Printf,
                             &Context->DebugInterface,
                             "- %s + %p\n",
                             Name,
                             (PVOID)Offset);
            } else {
                XENBUS_DEBUG(Printf,
                             &Context->DebugInterface,
                             "- %p\n",
                             (PVOID)Wakeup->Caller);
            }
        }
    }
}

static BOOLEAN
ConsoleCanRead(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_CONSOLE_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;
    ULONG                   Available;

    AcquireHighLock(&Context->RingLock, &Irql);
    Available = ConsoleInAvailable(Context);
    ReleaseHighLock(&Context->RingLock, Irql);

    return (Available != 0) ? TRUE : FALSE;
}

static ULONG
ConsoleRead(
    IN  PINTERFACE          Interface,
    IN  PCHAR               Data,
    IN  ULONG               Length
    )
{
    PXENBUS_CONSOLE_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;
    ULONG                   Read;
    NTSTATUS                status;

    AcquireHighLock(&Context->RingLock, &Irql);

    Read = 0;

    status = STATUS_UNSUCCESSFUL;
    if (!Context->Enabled)
        goto done;

    Read += ConsoleCopyFromIn(Context, Data, Length);

    if (Read != 0)
        XENBUS_EVTCHN(Send,
                      &Context->EvtchnInterface,
                      Context->Channel);

done:
    ReleaseHighLock(&Context->RingLock, Irql);

    return Read;
}

static BOOLEAN
ConsoleCanWrite(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_CONSOLE_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;
    ULONG                   Available;

    AcquireHighLock(&Context->RingLock, &Irql);
    Available = ConsoleOutAvailable(Context);
    ReleaseHighLock(&Context->RingLock, Irql);

    return (Available != 0) ? TRUE : FALSE;
}

static ULONG
ConsoleWrite(
    IN  PINTERFACE          Interface,
    IN  PCHAR               Data,
    IN  ULONG               Length
    )
{
    PXENBUS_CONSOLE_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;
    ULONG                   Written;
    NTSTATUS                status;

    AcquireHighLock(&Context->RingLock, &Irql);

    Written = 0;

    status = STATUS_UNSUCCESSFUL;
    if (!Context->Enabled)
        goto done;

    Written += ConsoleCopyToOut(Context, Data, Length);

    if (Written != 0)
        XENBUS_EVTCHN(Send,
                      &Context->EvtchnInterface,
                      Context->Channel);

done:
    ReleaseHighLock(&Context->RingLock, Irql);

    return Written;
}

extern USHORT
RtlCaptureStackBackTrace(
    __in        ULONG   FramesToSkip,
    __in        ULONG   FramesToCapture,
    __out       PVOID   *BackTrace,
    __out_opt   PULONG  BackTraceHash
    );

static NTSTATUS
ConsoleWakeupAdd(
    IN  PINTERFACE          	Interface,
    IN  PKEVENT             	Event,
    OUT PXENBUS_CONSOLE_WAKEUP	*Wakeup
    )
{
    PXENBUS_CONSOLE_CONTEXT     Context = Interface->Context;
    KIRQL                       Irql;
    NTSTATUS                    status;

    *Wakeup = __ConsoleAllocate(sizeof (XENBUS_CONSOLE_WAKEUP));

    status = STATUS_NO_MEMORY;
    if (*Wakeup == NULL)
        goto fail1;

    (*Wakeup)->Magic = CONSOLE_WAKEUP_MAGIC;
    (VOID) RtlCaptureStackBackTrace(1, 1, &(*Wakeup)->Caller, NULL);

    (*Wakeup)->Event = Event;

    KeAcquireSpinLock(&Context->Lock, &Irql);
    InsertTailList(&Context->WakeupList, &(*Wakeup)->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
ConsoleWakeupRemove(
    IN  PINTERFACE          	Interface,
    IN  PXENBUS_CONSOLE_WAKEUP	Wakeup
    )
{
    PXENBUS_CONSOLE_CONTEXT     Context = Interface->Context;
    KIRQL                       Irql;

    KeAcquireSpinLock(&Context->Lock, &Irql);
    RemoveEntryList(&Wakeup->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    RtlZeroMemory(&Wakeup->ListEntry, sizeof (LIST_ENTRY));

    Wakeup->Event = NULL;

    Wakeup->Caller = NULL;
    Wakeup->Magic = 0;

    ASSERT(IsZeroMemory(Wakeup, sizeof (XENBUS_CONSOLE_WAKEUP)));
    __ConsoleFree(Wakeup);
}

static NTSTATUS
ConsoleAcquire(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_CONSOLE_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;
    PHYSICAL_ADDRESS        Address;
    NTSTATUS                status;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    status = XENBUS_GNTTAB(Acquire, &Context->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = ConsoleGetAddress(Context, &Address);
    if (!NT_SUCCESS(status))
        goto fail2;

    Context->Address = Address;
    Context->Shared = (struct xencons_interface *)MmMapIoSpace(Context->Address,
                                                               PAGE_SIZE,
                                                               MmCached);
    status = STATUS_UNSUCCESSFUL;
    if (Context->Shared == NULL)
        goto fail3;

    status = XENBUS_EVTCHN(Acquire, &Context->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    ConsoleEnable(Context);

    status = XENBUS_SUSPEND(Acquire, &Context->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_SUSPEND(Register,
                            &Context->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            ConsoleSuspendCallbackLate,
                            Context,
                            &Context->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = XENBUS_DEBUG(Acquire, &Context->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = XENBUS_DEBUG(Register,
                          &Context->DebugInterface,
                          __MODULE__ "|CONSOLE",
                          ConsoleDebugCallback,
                          Context,
                          &Context->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail8;

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail8:
    Error("fail8\n");

    XENBUS_DEBUG(Release, &Context->DebugInterface);

fail7:
    Error("fail7\n");

    XENBUS_SUSPEND(Deregister,
                   &Context->SuspendInterface,
                   Context->SuspendCallbackLate);
    Context->SuspendCallbackLate = NULL;

fail6:
    Error("fail6\n");

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

fail5:
    Error("fail5\n");

    ConsoleDisable(Context);

    XENBUS_EVTCHN(Release, &Context->EvtchnInterface);

fail4:
    Error("fail4\n");

    MmUnmapIoSpace(Context->Shared, PAGE_SIZE);
    Context->Shared = NULL;

fail3:
    Error("fail3\n");

    Context->Address.QuadPart = 0;

fail2:
    Error("fail2\n");

    XENBUS_GNTTAB(Release, &Context->GnttabInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    Context->Address.QuadPart = 0;

    --Context->References;
    ASSERT3U(Context->References, ==, 0);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return status;
}

static VOID
ConsoleRelease(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_CONSOLE_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    if (!IsListEmpty(&Context->WakeupList))
        BUG("OUTSTANDING WAKEUPS");

    XENBUS_DEBUG(Deregister,
                 &Context->DebugInterface,
                 Context->DebugCallback);
    Context->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Context->DebugInterface);

    XENBUS_SUSPEND(Deregister,
                   &Context->SuspendInterface,
                   Context->SuspendCallbackLate);
    Context->SuspendCallbackLate = NULL;

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

    ConsoleDisable(Context);

    XENBUS_EVTCHN(Release, &Context->EvtchnInterface);

    MmUnmapIoSpace(Context->Shared, PAGE_SIZE);
    Context->Shared = NULL;

    Context->Address.QuadPart = 0;

    XENBUS_GNTTAB(Release, &Context->GnttabInterface);

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);
}

static struct _XENBUS_CONSOLE_INTERFACE_V1 ConsoleInterfaceVersion1 = {
    { sizeof (struct _XENBUS_CONSOLE_INTERFACE_V1), 1, NULL, NULL, NULL },
    ConsoleAcquire,
    ConsoleRelease,
    ConsoleCanRead,
    ConsoleRead,
    ConsoleCanWrite,
    ConsoleWrite,
    ConsoleWakeupAdd,
    ConsoleWakeupRemove
};

NTSTATUS
ConsoleInitialize(
    IN  PXENBUS_FDO             Fdo,
    OUT PXENBUS_CONSOLE_CONTEXT *Context
    )
{
    NTSTATUS                    status;

    Trace("====>\n");

    *Context = __ConsoleAllocate(sizeof (XENBUS_CONSOLE_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (*Context == NULL)
        goto fail1;

    status = GnttabGetInterface(FdoGetGnttabContext(Fdo),
                                XENBUS_GNTTAB_INTERFACE_VERSION_MAX,
                                (PINTERFACE)&(*Context)->GnttabInterface,
                                sizeof ((*Context)->GnttabInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT((*Context)->GnttabInterface.Interface.Context != NULL);

    status = EvtchnGetInterface(FdoGetEvtchnContext(Fdo),
                                XENBUS_EVTCHN_INTERFACE_VERSION_MAX,
                                (PINTERFACE)&(*Context)->EvtchnInterface,
                                sizeof ((*Context)->EvtchnInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT((*Context)->EvtchnInterface.Interface.Context != NULL);

    status = SuspendGetInterface(FdoGetSuspendContext(Fdo),
                                 XENBUS_SUSPEND_INTERFACE_VERSION_MAX,
                                 (PINTERFACE)&(*Context)->SuspendInterface,
                                 sizeof ((*Context)->SuspendInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT((*Context)->SuspendInterface.Interface.Context != NULL);

    status = DebugGetInterface(FdoGetDebugContext(Fdo),
                               XENBUS_DEBUG_INTERFACE_VERSION_MAX,
                               (PINTERFACE)&(*Context)->DebugInterface,
                               sizeof ((*Context)->DebugInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT((*Context)->DebugInterface.Interface.Context != NULL);

    KeInitializeSpinLock(&(*Context)->Lock);
    InitializeHighLock(&(*Context)->RingLock);

    InitializeListHead(&(*Context)->WakeupList);

    KeInitializeDpc(&(*Context)->Dpc, ConsoleDpc, *Context);

    (*Context)->Fdo = Fdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ConsoleGetInterface(
    IN      PXENBUS_CONSOLE_CONTEXT   Context,
    IN      ULONG                   Version,
    IN OUT  PINTERFACE              Interface,
    IN      ULONG                   Size
    )
{
    NTSTATUS                        status;

    ASSERT(Context != NULL);

    switch (Version) {
    case 1: {
        struct _XENBUS_CONSOLE_INTERFACE_V1  *ConsoleInterface;

        ConsoleInterface = (struct _XENBUS_CONSOLE_INTERFACE_V1 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENBUS_CONSOLE_INTERFACE_V1))
            break;

        *ConsoleInterface = ConsoleInterfaceVersion1;

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
ConsoleGetReferences(
    IN  PXENBUS_CONSOLE_CONTEXT   Context
    )
{
    return Context->References;
}

VOID
ConsoleTeardown(
    IN  PXENBUS_CONSOLE_CONTEXT   Context
    )
{
    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    KeFlushQueuedDpcs();

    Context->Dpcs = 0;
    Context->Events = 0;

    Context->Fdo = NULL;

    RtlZeroMemory(&Context->Dpc, sizeof (KDPC));

    RtlZeroMemory(&Context->WakeupList, sizeof (LIST_ENTRY));

    RtlZeroMemory(&Context->RingLock, sizeof (HIGH_LOCK));
    RtlZeroMemory(&Context->Lock, sizeof (KSPIN_LOCK));

    RtlZeroMemory(&Context->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Context->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&Context->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&Context->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    ASSERT(IsZeroMemory(Context, sizeof (XENBUS_CONSOLE_CONTEXT)));
    __ConsoleFree(Context);

    Trace("<====\n");
}
