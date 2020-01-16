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

#include "driver.h"
#include "ioctls.h"
#include "xeniface_ioctls.h"
#include "log.h"

DECLSPEC_NOINLINE
NTSTATUS
IoctlSuspendGetCount(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS    status;
    PULONG      Value;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != 0)
        goto fail1;

    if (OutLen != sizeof(ULONG))
        goto fail2;

    Value = (PULONG)Buffer;
    *Value = XENBUS_SUSPEND(GetCount, &Fdo->SuspendInterface); 
    *Info = (ULONG_PTR)sizeof(ULONG);
    status = STATUS_SUCCESS;

    return status;

fail2:
    Error("Fail2\n");
fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlSuspendRegister(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PXENIFACE_SUSPEND_REGISTER_IN In = Buffer;
    PXENIFACE_SUSPEND_REGISTER_OUT Out = Buffer;
    PXENIFACE_SUSPEND_CONTEXT Context;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_SUSPEND_REGISTER_IN) ||
        OutLen != sizeof(XENIFACE_SUSPEND_REGISTER_OUT)) {
        goto fail1;
    }

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_SUSPEND_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail2;

    RtlZeroMemory(Context, sizeof(XENIFACE_SUSPEND_CONTEXT));

    Context->FileObject = FileObject;

    status = ObReferenceObjectByHandle(In->Event,
                                       EVENT_MODIFY_STATE,
                                       *ExEventObjectType,
                                       UserMode,
                                       &Context->Event,
                                       NULL);
    if (!NT_SUCCESS(status))
        goto fail3;

    Trace("> Suspend Event %p, FO %p\n", In->Event, FileObject);
    ExInterlockedInsertTailList(&Fdo->SuspendList, &Context->Entry, &Fdo->SuspendLock);

    Out->Context = Context;
    *Info = sizeof(XENIFACE_SUSPEND_REGISTER_OUT);

    return status;

fail3:
    Error("Fail3\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_SUSPEND_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
SuspendFreeEvent(
    __in     PXENIFACE_FDO Fdo,
    __inout  PXENIFACE_SUSPEND_CONTEXT Context
    )
{
    Trace("Context %p, FO %p\n",
                       Context, Context->FileObject);

    ObDereferenceObject(Context->Event);
    RtlZeroMemory(Context, sizeof(XENIFACE_SUSPEND_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlSuspendDeregister(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    )
{
    NTSTATUS status;
    PXENIFACE_SUSPEND_REGISTER_OUT In = Buffer;
    PXENIFACE_SUSPEND_CONTEXT Context = NULL;
    KIRQL Irql;
    PLIST_ENTRY Node;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_SUSPEND_REGISTER_OUT) ||
        OutLen != 0) {
        goto fail1;
    }

    Trace("> Context %p, FO %p\n", In->Context, FileObject);

    KeAcquireSpinLock(&Fdo->SuspendLock, &Irql);
    Node = Fdo->SuspendList.Flink;
    while (Node->Flink != Fdo->SuspendList.Flink) {
        Context = CONTAINING_RECORD(Node, XENIFACE_SUSPEND_CONTEXT, Entry);

        Node = Node->Flink;
        if (Context != In->Context ||
            Context->FileObject != FileObject) {
            continue;
        }

        RemoveEntryList(&Context->Entry);
        break;
    }
    KeReleaseSpinLock(&Fdo->SuspendLock, Irql);

    status = STATUS_NOT_FOUND;
    if (Context == NULL || Context != In->Context)
        goto fail2;

    SuspendFreeEvent(Fdo, Context);

    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

VOID
SuspendEventFire(
    __in    PXENIFACE_FDO   Fdo
    )
{
    KIRQL       Irql;
    PLIST_ENTRY Node;
    PXENIFACE_SUSPEND_CONTEXT Context;

    KeAcquireSpinLock(&Fdo->SuspendLock, &Irql);
    Node = Fdo->SuspendList.Flink;
    while (Node->Flink != Fdo->SuspendList.Flink) {
        Context = CONTAINING_RECORD(Node, XENIFACE_SUSPEND_CONTEXT, Entry);

        KeSetEvent(Context->Event, IO_NO_INCREMENT, FALSE);

        Node = Node->Flink;
    }
    KeReleaseSpinLock(&Fdo->SuspendLock, Irql);
}
