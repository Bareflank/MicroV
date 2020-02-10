/* Copyright (c) Rafal Wojdyla <omeg@invisiblethingslab.com>
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

#include <ntifs.h>
#include <procgrp.h>
#include "driver.h"
#include "ioctls.h"
#include "xeniface_ioctls.h"
#include "log.h"

_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
EvtchnNotificationDpc(
    __in      PKDPC Dpc,
    __in_opt  PVOID _Context,
    __in_opt  PVOID Argument1,
    __in_opt  PVOID Argument2
    )
{
    PXENIFACE_EVTCHN_CONTEXT Context = _Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Context != NULL);

    KeSetEvent(Context->Event, 0, FALSE);

    (VOID) XENBUS_EVTCHN(Unmask,
                         &Context->Fdo->EvtchnInterface,
                         Context->Channel,
                         FALSE,
                         TRUE);
}

_Function_class_(KSERVICE_ROUTINE)
_IRQL_requires_(HIGH_LEVEL)
_IRQL_requires_same_
static DECLSPEC_NOINLINE
BOOLEAN
EvtchnInterruptHandler(
    __in      PKINTERRUPT Interrupt,
    __in_opt  PVOID Argument
    )
{
    PXENIFACE_EVTCHN_CONTEXT Context = Argument;
    PROCESSOR_NUMBER ProcNumber;
    ULONG ProcIndex;

    UNREFERENCED_PARAMETER(Interrupt);

    ASSERT(Context != NULL);

    KeGetCurrentProcessorNumberEx(&ProcNumber);
    ProcIndex = KeGetProcessorIndexFromNumber(&ProcNumber);

    (VOID) KeInsertQueueDpc(&Context->Dpc, NULL, NULL);

    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL) // needed for KeFlushQueuedDpcs
VOID
EvtchnFree(
    __in     PXENIFACE_FDO Fdo,
    __inout  PXENIFACE_EVTCHN_CONTEXT Context
    )
{
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Trace("Context %p, LocalPort %d, FO %p\n",
                       Context, Context->LocalPort, Context->FileObject);

    XENBUS_EVTCHN(Close,
                  &Fdo->EvtchnInterface,
                  Context->Channel);

    // There may still be a pending event at this time.
    // Wait for our DPCs to complete.
    KeFlushQueuedDpcs();

    ObDereferenceObject(Context->Event);
    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
}

_Requires_exclusive_lock_held_(Fdo->EvtchnLock)
static
PXENIFACE_EVTCHN_CONTEXT
EvtchnFindChannel(
    __in      PXENIFACE_FDO Fdo,
    __in      ULONG         LocalPort,
    __in_opt  PFILE_OBJECT  FileObject
    )
{
    PXENIFACE_EVTCHN_CONTEXT Context, Found = NULL;
    PLIST_ENTRY Node;

    Node = Fdo->EvtchnList.Flink;
    while (Node->Flink != Fdo->EvtchnList.Flink) {
        Context = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);

        Node = Node->Flink;
        if (Context->LocalPort != LocalPort)
            continue;

        if (FileObject != NULL &&
            FileObject != Context->FileObject) {
            continue;
        }

        Found = Context;
        break;
    }

    return Found;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnBindUnbound(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PXENIFACE_EVTCHN_BIND_UNBOUND_IN In = Buffer;
    PXENIFACE_EVTCHN_BIND_UNBOUND_OUT Out = Buffer;
    PXENIFACE_EVTCHN_CONTEXT Context;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_EVTCHN_BIND_UNBOUND_IN) ||
        OutLen != sizeof(XENIFACE_EVTCHN_BIND_UNBOUND_OUT)) {
        goto fail1;
    }

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_EVTCHN_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail2;

    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    Context->FileObject = FileObject;

    Trace("> RemoteDomain %d, Mask %d, FO %p\n",
                       In->RemoteDomain, In->Mask, FileObject);

    status = ObReferenceObjectByHandle(In->Event,
                                       EVENT_MODIFY_STATE,
                                       *ExEventObjectType,
                                       UserMode,
                                       &Context->Event,
                                       NULL);
    if (!NT_SUCCESS(status))
        goto fail3;

    KeInitializeDpc(&Context->Dpc, EvtchnNotificationDpc, Context);

    status = STATUS_UNSUCCESSFUL;
    Context->Channel = XENBUS_EVTCHN(Open,
                                     &Fdo->EvtchnInterface,
                                     XENBUS_EVTCHN_TYPE_UNBOUND,
                                     EvtchnInterruptHandler,
                                     Context,
                                     In->RemoteDomain,
                                     TRUE);
    if (Context->Channel == NULL)
        goto fail4;

    Context->LocalPort = XENBUS_EVTCHN(GetPort,
                                       &Fdo->EvtchnInterface,
                                       Context->Channel);

    Context->Fdo = Fdo;

    ExInterlockedInsertTailList(&Fdo->EvtchnList, &Context->Entry, &Fdo->EvtchnLock);

    Out->LocalPort = Context->LocalPort;
    *Info = sizeof(XENIFACE_EVTCHN_BIND_UNBOUND_OUT);

    if (!In->Mask) {
        (VOID) XENBUS_EVTCHN(Unmask,
                             &Fdo->EvtchnInterface,
                             Context->Channel,
                             FALSE,
                             TRUE);
    }

    Trace("< LocalPort %lu, Context %p\n", Context->LocalPort, Context);
    return STATUS_SUCCESS;

fail4:
    Error("Fail4\n");
    ObDereferenceObject(Context->Event);

fail3:
    Error("Fail3\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnBindInterdomain(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PXENIFACE_EVTCHN_BIND_INTERDOMAIN_IN In = Buffer;
    PXENIFACE_EVTCHN_BIND_INTERDOMAIN_OUT Out = Buffer;
    PXENIFACE_EVTCHN_CONTEXT Context;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_EVTCHN_BIND_INTERDOMAIN_IN) ||
        OutLen != sizeof(XENIFACE_EVTCHN_BIND_INTERDOMAIN_OUT)) {
        goto fail1;
    }

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_EVTCHN_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail2;

    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    Context->FileObject = FileObject;

    Trace("> RemoteDomain %d, RemotePort %lu, Mask %d, FO %p\n",
                       In->RemoteDomain, In->RemotePort, In->Mask, FileObject);

    status = ObReferenceObjectByHandle(In->Event,
                                       EVENT_MODIFY_STATE,
                                       *ExEventObjectType,
                                       UserMode,
                                       &Context->Event,
                                       NULL);
    if (!NT_SUCCESS(status))
        goto fail3;

    KeInitializeDpc(&Context->Dpc, EvtchnNotificationDpc, Context);

    status = STATUS_UNSUCCESSFUL;
    Context->Channel = XENBUS_EVTCHN(Open,
                                     &Fdo->EvtchnInterface,
                                     XENBUS_EVTCHN_TYPE_INTER_DOMAIN,
                                     EvtchnInterruptHandler,
                                     Context,
                                     In->RemoteDomain,
                                     In->RemotePort,
                                     TRUE);
    if (Context->Channel == NULL)
        goto fail4;

    Context->LocalPort = XENBUS_EVTCHN(GetPort,
                                       &Fdo->EvtchnInterface,
                                       Context->Channel);

    Context->Fdo = Fdo;

    ExInterlockedInsertTailList(&Fdo->EvtchnList, &Context->Entry, &Fdo->EvtchnLock);

    Out->LocalPort = Context->LocalPort;
    *Info = sizeof(XENIFACE_EVTCHN_BIND_INTERDOMAIN_OUT);

    if (!In->Mask) {
        (VOID) XENBUS_EVTCHN(Unmask,
                             &Fdo->EvtchnInterface,
                             Context->Channel,
                             FALSE,
                             TRUE);
    }

    Trace("< LocalPort %lu, Context %p\n", Context->LocalPort, Context);

    return STATUS_SUCCESS;

fail4:
    Error("Fail4\n");
    ObDereferenceObject(Context->Event);

fail3:
    Error("Fail3\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_EVTCHN_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnClose(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    )
{
    NTSTATUS status;
    PXENIFACE_EVTCHN_CLOSE_IN In = Buffer;
    PXENIFACE_EVTCHN_CONTEXT Context;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_EVTCHN_CLOSE_IN) ||
        OutLen != 0) {
        goto fail1;
    }

    Trace("> LocalPort %lu, FO %p\n", In->LocalPort, FileObject);

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    status = STATUS_NOT_FOUND;
    Context = EvtchnFindChannel(Fdo, In->LocalPort, FileObject);
    if (Context == NULL)
        goto fail2;

    RemoveEntryList(&Context->Entry);
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);
    EvtchnFree(Fdo, Context);

    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

_Requires_lock_not_held_(Fdo->EvtchnLock)
DECLSPEC_NOINLINE
NTSTATUS
EvtchnNotify(
    __in      PXENIFACE_FDO Fdo,
    __in      ULONG         LocalPort,
    __in_opt  PFILE_OBJECT  FileObject
    )
{
    NTSTATUS status;
    PXENIFACE_EVTCHN_CONTEXT Context;
    KIRQL Irql;

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);

    Context = EvtchnFindChannel(Fdo, LocalPort, FileObject);

    status = STATUS_NOT_FOUND;
    if (Context == NULL)
        goto fail1;

    XENBUS_EVTCHN(Send,
                  &Fdo->EvtchnInterface,
                  Context->Channel);

    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("Fail1 (%08x)\n", status);
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);
    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnNotify(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    )
{
    NTSTATUS status;
    PXENIFACE_EVTCHN_NOTIFY_IN In = Buffer;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_EVTCHN_NOTIFY_IN) ||
        OutLen != 0) {
        goto fail1;
    }

#if DBG
    Info("> LocalPort %d, FO %p\n", In->LocalPort, FileObject);
#endif

    return EvtchnNotify(Fdo, In->LocalPort, FileObject);

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlEvtchnUnmask(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    )
{
    NTSTATUS status;
    PXENIFACE_EVTCHN_UNMASK_IN In = Buffer;
    PXENIFACE_EVTCHN_CONTEXT Context;
    KIRQL Irql;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_EVTCHN_UNMASK_IN) ||
        OutLen != 0) {
        goto fail1;
    }

    Trace("> LocalPort %d, FO %p\n", In->LocalPort, FileObject);

    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);

    Context = EvtchnFindChannel(Fdo, In->LocalPort, FileObject);

    status = STATUS_INVALID_PARAMETER;
    if (Context == NULL)
        goto fail2;

    (VOID) XENBUS_EVTCHN(Unmask,
                         &Fdo->EvtchnInterface,
                         Context->Channel,
                         FALSE,
                         TRUE);

    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}
