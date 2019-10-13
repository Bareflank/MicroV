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

#include "suspend.h"
#include "thread.h"
#include "fdo.h"
#include "sync.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

struct _XENBUS_SUSPEND_CALLBACK {
    LIST_ENTRY  ListEntry;
    VOID        (*Function)(PVOID);
    PVOID       Argument;
};

struct _XENBUS_SUSPEND_CONTEXT {
    PXENBUS_FDO                 Fdo;
    KSPIN_LOCK                  Lock;
    LONG                        References;
    ULONG                       Count;
    LIST_ENTRY                  EarlyList;
    LIST_ENTRY                  LateList;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
};

#define XENBUS_SUSPEND_TAG  'PSUS'

static FORCEINLINE PVOID
__SuspendAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_SUSPEND_TAG);
}

static FORCEINLINE VOID
__SuspendFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_SUSPEND_TAG);
}

static NTSTATUS
SuspendRegister(
    IN  PINTERFACE                      Interface,
    IN  XENBUS_SUSPEND_CALLBACK_TYPE    Type,
    IN  VOID                            (*Function)(PVOID),
    IN  PVOID                           Argument OPTIONAL,
    OUT PXENBUS_SUSPEND_CALLBACK        *Callback
    )
{
    PXENBUS_SUSPEND_CONTEXT             Context = Interface->Context;
    KIRQL                               Irql;
    NTSTATUS                            status;

    *Callback = __SuspendAllocate(sizeof (XENBUS_SUSPEND_CALLBACK));

    status = STATUS_NO_MEMORY;
    if (*Callback == NULL)
        goto fail1;

    (*Callback)->Function = Function;
    (*Callback)->Argument = Argument;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    switch (Type) {
    case SUSPEND_CALLBACK_EARLY:
        InsertTailList(&Context->EarlyList, &(*Callback)->ListEntry);
        break;

    case SUSPEND_CALLBACK_LATE:
        InsertTailList(&Context->LateList, &(*Callback)->ListEntry);
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
SuspendDeregister(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_SUSPEND_CALLBACK    Callback
    )
{
    PXENBUS_SUSPEND_CONTEXT         Context = Interface->Context;
    KIRQL                           Irql;

    KeAcquireSpinLock(&Context->Lock, &Irql);
    RemoveEntryList(&Callback->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    __SuspendFree(Callback);
}

static FORCEINLINE VOID
__SuspendLogTimers(
    IN  const CHAR  *Prefix
    )
{
    LARGE_INTEGER   SystemTime;
    LARGE_INTEGER   TickCount;
    ULONG           TimeIncrement;
    LARGE_INTEGER   PerformanceCounter;
    LARGE_INTEGER   PerformanceFrequency;

    KeQuerySystemTime(&SystemTime);

    TimeIncrement = KeQueryTimeIncrement();
    KeQueryTickCount(&TickCount);

    PerformanceCounter = KeQueryPerformanceCounter(&PerformanceFrequency);

    LogPrintf(LOG_LEVEL_INFO,
              "%s: SystemTime = %08x.%08x\n",
              Prefix,
              SystemTime.HighPart,
              SystemTime.LowPart);

    LogPrintf(LOG_LEVEL_INFO,
              "%s: TickCount = %08x.%08x (TimeIncrement = %08x)\n",
              Prefix,
              TickCount.HighPart,
              TickCount.LowPart,
              TimeIncrement);

    LogPrintf(LOG_LEVEL_INFO,
              "%s: PerformanceCounter = %08x.%08x (Frequency = %08x.%08x)\n",
              Prefix,
              PerformanceCounter.HighPart,
              PerformanceCounter.LowPart,
              PerformanceFrequency.HighPart,
              PerformanceFrequency.LowPart);
}

NTSTATUS
#pragma prefast(suppress:28167) // Function changes IRQL
SuspendTrigger(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_SUSPEND_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;
    NTSTATUS                status;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    LogPrintf(LOG_LEVEL_INFO,
              "SUSPEND: ====>\n");

    SyncCapture();
    SyncDisableInterrupts();

    __SuspendLogTimers("PRE-SUSPEND");

    LogPrintf(LOG_LEVEL_INFO,
              "SUSPEND: SCHEDOP_shutdown:SHUTDOWN_suspend ====>\n");
    status = SchedShutdown(SHUTDOWN_suspend);
    LogPrintf(LOG_LEVEL_INFO,
              "SUSPEND: SCHEDOP_shutdown:SHUTDOWN_suspend <==== (%08x)\n",
              status);

    __SuspendLogTimers("POST-SUSPEND");

    if (NT_SUCCESS(status)) {
        PLIST_ENTRY ListEntry;

        Context->Count++;

        HypercallPopulate();

        UnplugDevices();

        for (ListEntry = Context->EarlyList.Flink;
             ListEntry != &Context->EarlyList;
             ListEntry = ListEntry->Flink) {
            PXENBUS_SUSPEND_CALLBACK  Callback;

            Callback = CONTAINING_RECORD(ListEntry, XENBUS_SUSPEND_CALLBACK, ListEntry);
            Callback->Function(Callback->Argument);
        }
    }

    SyncEnableInterrupts();

    // No lock is required here as the VM is single-threaded until
    // SyncRelease() is called.

    if (NT_SUCCESS(status)) {
        PLIST_ENTRY ListEntry;

        for (ListEntry = Context->LateList.Flink;
             ListEntry != &Context->LateList;
             ListEntry = ListEntry->Flink) {
            PXENBUS_SUSPEND_CALLBACK  Callback;

            Callback = CONTAINING_RECORD(ListEntry, XENBUS_SUSPEND_CALLBACK, ListEntry);
            Callback->Function(Callback->Argument);
        }
    }

    SyncRelease();

    LogPrintf(LOG_LEVEL_INFO, "SUSPEND: <====\n");

    KeLowerIrql(Irql);

    return STATUS_SUCCESS;
}

static ULONG
SuspendGetCount(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_SUSPEND_CONTEXT Context = Interface->Context;

    //
    // No locking is required here since the system will be
    // single-threaded with interrupts disabled when the
    // value is incremented.
    //
    return Context->Count;
}

static VOID
SuspendDebugCallback(
    IN  PVOID               Argument,
    IN  BOOLEAN             Crashing
    )
{
    PXENBUS_SUSPEND_CONTEXT Context = Argument;
    PLIST_ENTRY             ListEntry;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Context->DebugInterface,
                 "Count = %u\n",
                 Context->Count);

    for (ListEntry = Context->EarlyList.Flink;
         ListEntry != &Context->EarlyList;
         ListEntry = ListEntry->Flink) {
        PXENBUS_SUSPEND_CALLBACK    Callback;
        PCHAR                       Name;
        ULONG_PTR                   Offset;

        Callback = CONTAINING_RECORD(ListEntry, XENBUS_SUSPEND_CALLBACK, ListEntry);

        ModuleLookup((ULONG_PTR)Callback->Function, &Name, &Offset);

        if (Name == NULL) {
            XENBUS_DEBUG(Printf,
                         &Context->DebugInterface,
                         "EARLY: %p (%p)\n",
                         Callback->Function,
                         Callback->Argument);
        } else {
            XENBUS_DEBUG(Printf,
                         &Context->DebugInterface,
                         "EARLY: %s + %p (%p)\n",
                         Name,
                         (PVOID)Offset,
                         Callback->Argument);
        }
    }

    for (ListEntry = Context->LateList.Flink;
         ListEntry != &Context->LateList;
         ListEntry = ListEntry->Flink) {
        PXENBUS_SUSPEND_CALLBACK    Callback;
        PCHAR                       Name;
        ULONG_PTR                   Offset;

        Callback = CONTAINING_RECORD(ListEntry, XENBUS_SUSPEND_CALLBACK, ListEntry);

        ModuleLookup((ULONG_PTR)Callback->Function, &Name, &Offset);

        if (Name == NULL) {
            XENBUS_DEBUG(Printf,
                         &Context->DebugInterface,
                         "LATE: %p (%p)\n",
                         Callback->Function,
                         Callback->Argument);
        } else {
            XENBUS_DEBUG(Printf,
                         &Context->DebugInterface,
                         "LATE: %s + %p (%p)\n",
                         Name,
                         (PVOID)Offset,
                         Callback->Argument);
        }
    }
}

static NTSTATUS
SuspendAcquire(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_SUSPEND_CONTEXT Context = Interface->Context;
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
                          __MODULE__ "|SUSPEND",
                          SuspendDebugCallback,
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

static VOID
SuspendRelease(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_SUSPEND_CONTEXT Context = Interface->Context;
    KIRQL                   Irql;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    if (!IsListEmpty(&Context->LateList) ||
        !IsListEmpty(&Context->EarlyList))
        BUG("OUTSTANDING CALLBACKS");

    Context->Count = 0;

    XENBUS_DEBUG(Deregister,
                 &Context->DebugInterface,
                 Context->DebugCallback);
    Context->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Context->DebugInterface);

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);
}

static struct _XENBUS_SUSPEND_INTERFACE_V1 SuspendInterfaceVersion1 = {
    { sizeof (struct _XENBUS_SUSPEND_INTERFACE_V1), 1, NULL, NULL, NULL },
    SuspendAcquire,
    SuspendRelease,
    SuspendRegister,
    SuspendDeregister,
    SuspendTrigger,
    SuspendGetCount
};
                     
NTSTATUS
SuspendInitialize(
    IN  PXENBUS_FDO             Fdo,
    OUT PXENBUS_SUSPEND_CONTEXT *Context
    )
{
    NTSTATUS                    status;

    Trace("====>\n");

    *Context = __SuspendAllocate(sizeof (XENBUS_SUSPEND_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (*Context == NULL)
        goto fail1;

    status = DebugGetInterface(FdoGetDebugContext(Fdo),
                               XENBUS_DEBUG_INTERFACE_VERSION_MAX,
                               (PINTERFACE)&(*Context)->DebugInterface,
                               sizeof ((*Context)->DebugInterface));
    ASSERT(NT_SUCCESS(status));

    InitializeListHead(&(*Context)->EarlyList);
    InitializeListHead(&(*Context)->LateList);
    KeInitializeSpinLock(&(*Context)->Lock);

    (*Context)->Fdo = Fdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
SuspendGetInterface(
    IN      PXENBUS_SUSPEND_CONTEXT Context,
    IN      ULONG                   Version,
    IN OUT  PINTERFACE              Interface,
    IN      ULONG                   Size
    )
{
    NTSTATUS                        status;

    ASSERT(Context != NULL);

    switch (Version) {
    case 1: {
        struct _XENBUS_SUSPEND_INTERFACE_V1  *SuspendInterface;

        SuspendInterface = (struct _XENBUS_SUSPEND_INTERFACE_V1 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENBUS_SUSPEND_INTERFACE_V1))
            break;

        *SuspendInterface = SuspendInterfaceVersion1;

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
SuspendGetReferences(
    IN  PXENBUS_SUSPEND_CONTEXT Context
    )
{
    return Context->References;
}

VOID
SuspendTeardown(
    IN  PXENBUS_SUSPEND_CONTEXT Context
    )
{
    Trace("====>\n");

    Context->Fdo = NULL;

    RtlZeroMemory(&Context->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Context->Lock, sizeof (KSPIN_LOCK));
    RtlZeroMemory(&Context->LateList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Context->EarlyList, sizeof (LIST_ENTRY));

    ASSERT(IsZeroMemory(Context, sizeof (XENBUS_SUSPEND_CONTEXT)));
    __SuspendFree(Context);

    Trace("<====\n");
}
