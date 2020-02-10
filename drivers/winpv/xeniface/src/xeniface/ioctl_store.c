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

#include "driver.h"
#include "ioctls.h"
#include "xeniface_ioctls.h"
#include "log.h"

#define XENSTORE_ABS_PATH_MAX 3072
#define XENSTORE_REL_PATH_MAX 2048

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
        if (!isprint((unsigned char)*Str))
            break;
    }
    return FALSE;
}

static FORCEINLINE
ULONG
__MultiSzLen(
    __in  PCHAR             Str,
    __out PULONG            Count
    )
{
    ULONG Length = 0;
    if (Count)  *Count = 0;
    do {
        for ( ; *Str; ++Str, ++Length) ;
        ++Str; ++Length;
        if (*Count) ++(*Count);
    } while (*Str);
    return Length;
}

static FORCEINLINE
VOID
__DisplayMultiSz(
    __in PCHAR              Str
    )
{
    PCHAR   Ptr;
    ULONG   Idx;
    ULONG   Len;

    for (Ptr = Str, Idx = 0; *Ptr; ++Idx) {
        Len = (ULONG)strlen(Ptr);
        Trace("> [%d]=(%d)->\"%s\"\n", Idx, Len, Ptr);
        Ptr += (Len + 1);
    }
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRead(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS    status;
    PCHAR       Value;
    ULONG       Length;
    BOOLEAN     SquashError = FALSE;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    status = XENBUS_STORE(Read, &Fdo->StoreInterface, NULL, NULL, Buffer, &Value);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND)
            SquashError = TRUE;

        goto fail3;
    }

    Length = (ULONG)strlen(Value) + 1;

    status = STATUS_BUFFER_OVERFLOW;
    if (OutLen == 0) {
        Trace("(\"%s\")=(%d)\n", Buffer, Length);
        goto done;
    }

    status = STATUS_INVALID_PARAMETER;
    if (OutLen < Length)
        goto fail4;

    Trace("(\"%s\")=(%d)->\"%s\"\n", Buffer, Length, Value);

    RtlCopyMemory(Buffer, Value, Length);
    Buffer[Length - 1] = 0;
    status = STATUS_SUCCESS;

done:
    *Info = (ULONG_PTR)Length;
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
    return status;

fail4:
    Error("Fail4 (\"%s\")=(%d < %d)\n", Buffer, OutLen, Length);
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
fail3:
    if (!SquashError)
        Error("Fail3 (\"%s\")\n", Buffer);
fail2:
    if (!SquashError)
        Error("Fail2\n");
fail1:
    if (!SquashError)
        Error("Fail1 (%08x)\n", status);

    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreWrite(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS    status;
    PCHAR       Value;
    ULONG       Length;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0 || OutLen != 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    Length = (ULONG)strlen(Buffer) + 1;
    Value = Buffer + Length;

    if (!__IsValidStr(Value, InLen - Length))
        goto fail3;

    status = XENBUS_STORE(Printf, &Fdo->StoreInterface, NULL, NULL, Buffer, "%s", Value);
    if (!NT_SUCCESS(status))
        goto fail4;

    Trace("(\"%s\"=\"%s\")\n", Buffer, Value);
    return status;

fail4:
    Error("Fail4 (\"%s\")\n", Value);
fail3:
    Error("Fail3 (\"%s\")\n", Buffer);
fail2:
    Error("Fail2\n");
fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreDirectory(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS    status;
    PCHAR       Value;
    ULONG       Length;
    ULONG       Count;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    status = XENBUS_STORE(Directory, &Fdo->StoreInterface, NULL, NULL, Buffer, &Value);
    if (!NT_SUCCESS(status))
        goto fail3;

    Length = __MultiSzLen(Value, &Count) + 1;

    status = STATUS_BUFFER_OVERFLOW;
    if (OutLen == 0) {
        Trace("(\"%s\")=(%d)(%d)\n", Buffer, Length, Count);
        goto done;
    }

    status = STATUS_INVALID_PARAMETER;
    if (OutLen < Length)
        goto fail4;

    Info("(\"%s\")=(%d)(%d)\n", Buffer, Length, Count);
#if DBG
    __DisplayMultiSz(Value);
#endif

    RtlCopyMemory(Buffer, Value, Length);
    Buffer[Length - 2] = 0;
    Buffer[Length - 1] = 0;
    status = STATUS_SUCCESS;

done:
    *Info = (ULONG_PTR)Length;
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
    return status;

fail4:
    Error("Fail4 (\"%s\")=(%d < %d)\n", Buffer, OutLen, Length);
    XENBUS_STORE(Free, &Fdo->StoreInterface, Value);
fail3:
    Error("Fail3 (\"%s\")\n", Buffer);
fail2:
    Error("Fail2\n");
fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRemove(
    __in  PXENIFACE_FDO     Fdo,
    __in  PCHAR             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS    status;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen == 0 || OutLen != 0)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (!__IsValidStr(Buffer, InLen))
        goto fail2;

    status = XENBUS_STORE(Remove, &Fdo->StoreInterface, NULL, NULL, Buffer);
    if (!NT_SUCCESS(status))
        goto fail3;

    Trace("(\"%s\")\n", Buffer);
    return status;

fail3:
    Error("Fail3 (\"%s\")\n", Buffer);
fail2:
    Error("Fail2\n");
fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

static
PXENBUS_STORE_PERMISSION
__ConvertPermissions(
    __in  ULONG                       NumberPermissions,
    __in  PXENIFACE_STORE_PERMISSION  XenifacePermissions
)
{
    PXENBUS_STORE_PERMISSION          XenbusPermissions;
    ULONG                             Index;

    if (NumberPermissions > 255)
        goto fail1;

    XenbusPermissions = ExAllocatePoolWithTag(NonPagedPool, NumberPermissions * sizeof(XENBUS_STORE_PERMISSION), XENIFACE_POOL_TAG);
    if (XenbusPermissions == NULL)
        goto fail2;

#pragma warning(push)
#pragma warning(disable:6385)
#pragma warning(disable:6386)

    // Currently XENIFACE_STORE_PERMISSION is the same as XENBUS_STORE_PERMISSION,
    // but we convert them here in case something changes in the future.
    for (Index = 0; Index < NumberPermissions; Index++) {
        XENIFACE_STORE_PERMISSION_MASK  Mask = XenifacePermissions[Index].Mask;

        if (Mask & ~XENIFACE_STORE_ALLOWED_PERMISSIONS)
            goto fail3;

        XenbusPermissions[Index].Domain = XenifacePermissions[Index].Domain;
        XenbusPermissions[Index].Mask = 0;

        if (Mask & XENIFACE_STORE_PERM_READ)
            XenbusPermissions[Index].Mask |= XENBUS_STORE_PERM_READ;
        if (Mask & XENIFACE_STORE_PERM_WRITE)
            XenbusPermissions[Index].Mask |= XENBUS_STORE_PERM_WRITE;
    }

#pragma warning(pop)

    return XenbusPermissions;

fail3:
    Error("Fail3\n");
    ExFreePoolWithTag(XenbusPermissions, XENIFACE_POOL_TAG);

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1\n");
    return NULL;
}

static
VOID
__FreePermissions(
    __in  PXENBUS_STORE_PERMISSION    Permissions
    )
{
    ExFreePoolWithTag(Permissions, XENIFACE_POOL_TAG);
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreSetPermissions(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen
    )
{
    NTSTATUS status;
    PXENIFACE_STORE_SET_PERMISSIONS_IN In = Buffer;
    PXENBUS_STORE_PERMISSION Permissions;
    ULONG Index;
    PCHAR Path;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen < sizeof(XENIFACE_STORE_SET_PERMISSIONS_IN) ||
        OutLen != 0) {
        goto fail1;
    }

    if (InLen != (ULONG)FIELD_OFFSET(XENIFACE_STORE_SET_PERMISSIONS_IN, Permissions[In->NumberPermissions]))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (In->PathLength == 0 ||
        In->PathLength > XENSTORE_ABS_PATH_MAX) {
        goto fail3;
    }

    Permissions = __ConvertPermissions(In->NumberPermissions, In->Permissions);
    if (Permissions == NULL)
        goto fail4;

    status = __CaptureUserBuffer(In->Path, In->PathLength, &Path);
    if (!NT_SUCCESS(status))
        goto fail5;

    Path[In->PathLength - 1] = 0;
    Trace("> Path '%s', NumberPermissions %lu\n", Path, In->NumberPermissions);

    for (Index = 0; Index < In->NumberPermissions; Index++) {
        Trace("> %lu: Domain %d, Mask 0x%x\n",
                           Index, Permissions[Index].Domain, Permissions[Index].Mask);
    }

    status = XENBUS_STORE(PermissionsSet,
                          &Fdo->StoreInterface,
                          NULL, // transaction
                          NULL, // prefix
                          Path,
                          Permissions,
                          In->NumberPermissions);

    if (!NT_SUCCESS(status))
        goto fail6;

    __FreeCapturedBuffer(Path);
    return status;

fail6:
    Error("Fail6\n");
    __FreeCapturedBuffer(Path);

fail5:
    Error("Fail5\n");
    __FreePermissions(Permissions);

fail4:
    Error("Fail4\n");

fail3:
    Error("Fail3\n");

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

static NTSTATUS
StoreWatch(
    IN  PXENIFACE_THREAD    Self,
    IN  PVOID               _Context
    )
{
    PXENIFACE_STORE_CONTEXT Context = _Context;
    PKEVENT                 Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        Info("%s\n", Context->Path);

        KeSetEvent(Context->Event, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_SUCCESS;
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreAddWatch(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject,
    __out PULONG_PTR        Info
    )
{
    NTSTATUS status;
    PXENIFACE_STORE_ADD_WATCH_IN In = Buffer;
    PXENIFACE_STORE_ADD_WATCH_OUT Out = Buffer;
    PCHAR Path;
    PXENIFACE_STORE_CONTEXT Context;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_STORE_ADD_WATCH_IN) ||
        OutLen != sizeof(XENIFACE_STORE_ADD_WATCH_OUT)) {
        goto fail1;
    }

    status = STATUS_INVALID_PARAMETER;
    if (In->PathLength == 0 ||
        In->PathLength > XENSTORE_ABS_PATH_MAX) {
        goto fail2;
    }

    status = __CaptureUserBuffer(In->Path, In->PathLength, &Path);
    if (!NT_SUCCESS(status))
        goto fail3;

    Path[In->PathLength - 1] = 0;

    status = STATUS_NO_MEMORY;
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENIFACE_STORE_CONTEXT), XENIFACE_POOL_TAG);
    if (Context == NULL)
        goto fail4;

    RtlZeroMemory(Context, sizeof(XENIFACE_STORE_CONTEXT));

    Context->FileObject = FileObject;

    status = ObReferenceObjectByHandle(In->Event,
                                       EVENT_MODIFY_STATE,
                                       *ExEventObjectType,
                                       UserMode,
                                       &Context->Event,
                                       NULL);
    if (!NT_SUCCESS(status))
        goto fail5;

    Trace("> Path '%s', Event %p, FO %p\n", Path, In->Event, FileObject);

    Context->Path = Path;

    status = ThreadCreate(StoreWatch, Context, &Context->Thread);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = XENBUS_STORE(WatchAdd,
                          &Fdo->StoreInterface,
                          NULL, // prefix
                          Context->Path,
                          ThreadGetEvent(Context->Thread),
                          &Context->Watch);

    if (!NT_SUCCESS(status))
        goto fail7;

    ExInterlockedInsertTailList(&Fdo->StoreWatchList, &Context->Entry, &Fdo->StoreWatchLock);

    Trace("< Context %p, Watch %p\n", Context, Context->Watch);

    Out->Context = Context;
    *Info = sizeof(XENIFACE_STORE_ADD_WATCH_OUT);

    return status;

fail7:
    __FreeCapturedBuffer(Context->Path);

    Error("Fail7\n");
    ThreadAlert(Context->Thread);
    ThreadJoin(Context->Thread);

fail6:
    Error("Fail6\n");
    ObDereferenceObject(Context->Event);

fail5:
    Error("Fail5\n");
    RtlZeroMemory(Context, sizeof(XENIFACE_STORE_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);

fail4:
    Error("Fail4\n");
    __FreeCapturedBuffer(Path);

fail3:
    Error("Fail3\n");

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
StoreFreeWatch(
    __in     PXENIFACE_FDO Fdo,
    __inout  PXENIFACE_STORE_CONTEXT Context
    )
{
    NTSTATUS status;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Trace("Context %p, Watch %p, FO %p\n",
                       Context, Context->Watch, Context->FileObject);

    status = XENBUS_STORE(WatchRemove,
                          &Fdo->StoreInterface,
                          Context->Watch);

    ASSERT(NT_SUCCESS(status)); // this is fatal since we'd leave an active watch without cleaning it up

    ThreadAlert(Context->Thread);
    ThreadJoin(Context->Thread);

    __FreeCapturedBuffer(Context->Path);

    ObDereferenceObject(Context->Event);
    RtlZeroMemory(Context, sizeof(XENIFACE_STORE_CONTEXT));
    ExFreePoolWithTag(Context, XENIFACE_POOL_TAG);
}

DECLSPEC_NOINLINE
NTSTATUS
IoctlStoreRemoveWatch(
    __in  PXENIFACE_FDO     Fdo,
    __in  PVOID             Buffer,
    __in  ULONG             InLen,
    __in  ULONG             OutLen,
    __in  PFILE_OBJECT      FileObject
    )
{
    NTSTATUS status;
    PXENIFACE_STORE_REMOVE_WATCH_IN In = Buffer;
    PXENIFACE_STORE_CONTEXT Context = NULL;
    KIRQL Irql;
    PLIST_ENTRY Node;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != sizeof(XENIFACE_STORE_REMOVE_WATCH_IN) ||
        OutLen != 0) {
        goto fail1;
    }

    Trace("> Context %p, FO %p\n", In->Context, FileObject);

    KeAcquireSpinLock(&Fdo->StoreWatchLock, &Irql);
    Node = Fdo->StoreWatchList.Flink;
    while (Node->Flink != Fdo->StoreWatchList.Flink) {
        Context = CONTAINING_RECORD(Node, XENIFACE_STORE_CONTEXT, Entry);

        Node = Node->Flink;
        if (Context != In->Context ||
            Context->FileObject != FileObject) {
            continue;
        }

        RemoveEntryList(&Context->Entry);
        break;
    }
    KeReleaseSpinLock(&Fdo->StoreWatchLock, Irql);

    status = STATUS_NOT_FOUND;
    if (Context == NULL || Context != In->Context)
        goto fail2;

    StoreFreeWatch(Fdo, Context);

    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}
