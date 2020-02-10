/* Copyright (c) Citrix Systems Inc.
 * Copyright (c) Rafal Wojdyla <omeg@invisiblethingslab.com>
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

NTSTATUS
__CaptureUserBuffer(
    __in  PVOID Buffer,
    __in  ULONG Length,
    __out PVOID *CapturedBuffer
    )
{
    NTSTATUS Status;
    PVOID TempBuffer = NULL;

    if (Length == 0) {
        *CapturedBuffer = NULL;
        return STATUS_SUCCESS;
    }

    Status = STATUS_NO_MEMORY;
    TempBuffer = ExAllocatePoolWithTag(NonPagedPool, Length, XENIFACE_POOL_TAG);
    if (TempBuffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = STATUS_SUCCESS;

#pragma prefast(suppress: 6320) // we want to catch all exceptions
    try {
        ProbeForRead(Buffer, Length, 1);
        RtlCopyMemory(TempBuffer, Buffer, Length);
    } except(EXCEPTION_EXECUTE_HANDLER) {
        Error("Exception while probing/reading buffer at %p, size 0x%lx\n", Buffer, Length);
        ExFreePoolWithTag(TempBuffer, XENIFACE_POOL_TAG);
        TempBuffer = NULL;
        Status = GetExceptionCode();
    }

    *CapturedBuffer = TempBuffer;

    return Status;
}

VOID
__FreeCapturedBuffer(
    __in  PVOID CapturedBuffer
    )
{
    if (CapturedBuffer != NULL) {
        ExFreePoolWithTag(CapturedBuffer, XENIFACE_POOL_TAG);
    }
}

static FORCEINLINE
BOOLEAN
__IsValidStr(
    __in  PCHAR             Str,
    __in  ULONG             Len
    )
{
    for ( ; Len--; ++Str) {
        if (*Str == '\0')
            return TRUE;
        if (*Str == '\n' || *Str == '\r')
            continue; // newline is allowed
        if (!isprint((unsigned char)*Str))
            break;
    }
    return FALSE;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlLog(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS    status;
	PCHAR		ptr;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0 || InLen > XENIFACE_LOG_MAX_LENGTH || OutLen != 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

	// remove whitespace from end of buffer
	for (ptr = Buffer + InLen - 1; ptr != Buffer; --ptr) {
        if (*ptr != '\n' && *ptr != '\r' && *ptr != '\0')
            break;

        *ptr = '\0';
    }

    Info("USER: %s\n", Buffer);
    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");
fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

// Cleanup store watches and event channels, called on file object close.
_IRQL_requires_(PASSIVE_LEVEL) // EvtchnFree calls KeFlushQueuedDpcs
VOID
XenIfaceCleanup(
    __in  PXENIFACE_FDO Fdo,
    __in_opt  PFILE_OBJECT  FileObject
    )
{
    PLIST_ENTRY Node;
    PXENIFACE_STORE_CONTEXT StoreContext;
    PXENIFACE_EVTCHN_CONTEXT EvtchnContext;
    PXENIFACE_SUSPEND_CONTEXT SuspendContext;
    KIRQL Irql;
    LIST_ENTRY ToFree;

    // store watches
    InitializeListHead(&ToFree);
    KeAcquireSpinLock(&Fdo->StoreWatchLock, &Irql);
    Node = Fdo->StoreWatchList.Flink;
    while (Node->Flink != Fdo->StoreWatchList.Flink) {
        StoreContext = CONTAINING_RECORD(Node, XENIFACE_STORE_CONTEXT, Entry);

        Node = Node->Flink;
        if (FileObject != NULL &&
            StoreContext->FileObject != FileObject)
            continue;

        Trace("Store context %p\n", StoreContext);
        RemoveEntryList(&StoreContext->Entry);
        // StoreFreeWatch requires PASSIVE_LEVEL and we're inside a lock
        InsertTailList(&ToFree, &StoreContext->Entry);
    }
    KeReleaseSpinLock(&Fdo->StoreWatchLock, Irql);

    Node = ToFree.Flink;
    while (Node->Flink != ToFree.Flink) {
        StoreContext = CONTAINING_RECORD(Node, XENIFACE_STORE_CONTEXT, Entry);
        Node = Node->Flink;

        RemoveEntryList(&StoreContext->Entry);
        StoreFreeWatch(Fdo, StoreContext);
    }

    // event channels
    InitializeListHead(&ToFree);
    KeAcquireSpinLock(&Fdo->EvtchnLock, &Irql);
    Node = Fdo->EvtchnList.Flink;
    while (Node->Flink != Fdo->EvtchnList.Flink) {
        EvtchnContext = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);

        Node = Node->Flink;
        if (FileObject != NULL &&
            EvtchnContext->FileObject != FileObject)
            continue;

        Trace("Evtchn context %p\n", EvtchnContext);
        RemoveEntryList(&EvtchnContext->Entry);
        // EvtchnFree requires PASSIVE_LEVEL and we're inside a lock
        InsertTailList(&ToFree, &EvtchnContext->Entry);
    }
    KeReleaseSpinLock(&Fdo->EvtchnLock, Irql);

    Node = ToFree.Flink;
    while (Node->Flink != ToFree.Flink) {
        EvtchnContext = CONTAINING_RECORD(Node, XENIFACE_EVTCHN_CONTEXT, Entry);
        Node = Node->Flink;

        RemoveEntryList(&EvtchnContext->Entry);
        EvtchnFree(Fdo, EvtchnContext);
    }
     
    // suspend events
    KeAcquireSpinLock(&Fdo->SuspendLock, &Irql);
    Node = Fdo->SuspendList.Flink;
    while (Node->Flink != Fdo->SuspendList.Flink) {
        SuspendContext = CONTAINING_RECORD(Node, XENIFACE_SUSPEND_CONTEXT, Entry);

        Node = Node->Flink;
        if (FileObject != NULL &&
            SuspendContext->FileObject != FileObject)
            continue;

        Trace("Suspend context %p\n", SuspendContext);
        RemoveEntryList(&SuspendContext->Entry);
        SuspendFreeEvent(Fdo, SuspendContext);
    }
    KeReleaseSpinLock(&Fdo->SuspendLock, Irql);
}

NTSTATUS
XenIfaceIoctl(
    __in     PXENIFACE_FDO     Fdo,
    __inout  PIRP              Irp
    )
{
    NTSTATUS            status;
    PIO_STACK_LOCATION  Stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID               Buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG               InLen = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG               OutLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    status = STATUS_DEVICE_NOT_READY;
    if (Fdo->InterfacesAcquired == FALSE)
        goto done;

    switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
        // store
    case IOCTL_XENIFACE_STORE_READ:
        status = IoctlStoreRead(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_STORE_WRITE:
        status = IoctlStoreWrite(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_STORE_DIRECTORY:
        status = IoctlStoreDirectory(Fdo, (PCHAR)Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_STORE_REMOVE:
        status = IoctlStoreRemove(Fdo, (PCHAR)Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_STORE_SET_PERMISSIONS:
        status = IoctlStoreSetPermissions(Fdo, Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_STORE_ADD_WATCH:
        status = IoctlStoreAddWatch(Fdo, Buffer, InLen, OutLen, Stack->FileObject, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_STORE_REMOVE_WATCH:
        status = IoctlStoreRemoveWatch(Fdo, Buffer, InLen, OutLen, Stack->FileObject);
        break;

        // evtchn
    case IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND:
        status = IoctlEvtchnBindUnbound(Fdo, Buffer, InLen, OutLen, Stack->FileObject, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN:
        status = IoctlEvtchnBindInterdomain(Fdo, Buffer, InLen, OutLen, Stack->FileObject, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_EVTCHN_CLOSE:
        status = IoctlEvtchnClose(Fdo, Buffer, InLen, OutLen, Stack->FileObject);
        break;

    case IOCTL_XENIFACE_EVTCHN_NOTIFY:
        status = IoctlEvtchnNotify(Fdo, Buffer, InLen, OutLen, Stack->FileObject);
        break;

    case IOCTL_XENIFACE_EVTCHN_UNMASK:
        status = IoctlEvtchnUnmask(Fdo, Buffer, InLen, OutLen, Stack->FileObject);
        break;

        // gnttab
    case IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS: // this is a METHOD_NEITHER IOCTL
        status = IoctlGnttabPermitForeignAccess(Fdo, Stack->Parameters.DeviceIoControl.Type3InputBuffer, InLen, OutLen, Irp);
        break;

    case IOCTL_XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS:
        status = IoctlGnttabRevokeForeignAccess(Fdo, Buffer, InLen, OutLen);
        break;

    case IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES: // this is a METHOD_NEITHER IOCTL
        status = IoctlGnttabMapForeignPages(Fdo, Stack->Parameters.DeviceIoControl.Type3InputBuffer, InLen, OutLen, Irp);
        break;

    case IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES:
        status = IoctlGnttabUnmapForeignPages(Fdo, Buffer, InLen, OutLen);
        break;

        // suspend
    case IOCTL_XENIFACE_SUSPEND_GET_COUNT:
        status = IoctlSuspendGetCount(Fdo, Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_SUSPEND_REGISTER:
        status = IoctlSuspendRegister(Fdo, Buffer, InLen, OutLen, Stack->FileObject, &Irp->IoStatus.Information);
        break;

    case IOCTL_XENIFACE_SUSPEND_DEREGISTER:
        status = IoctlSuspendDeregister(Fdo, Buffer, InLen, OutLen, Stack->FileObject);
        break;

        // sharedinfo
    case IOCTL_XENIFACE_SHAREDINFO_GET_TIME:
        status = IoctlSharedInfoGetTime(Fdo, Buffer, InLen, OutLen, &Irp->IoStatus.Information);
        break;

        // misc
    case IOCTL_XENIFACE_LOG:
        status = IoctlLog(Fdo, Buffer, InLen, OutLen);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

done:

    Irp->IoStatus.Status = status;

    if (status != STATUS_PENDING)
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

