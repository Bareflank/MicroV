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

#include "high.h"
#include "debug.h"
#include "fdo.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define MAXIMUM_PREFIX_LENGTH   32

struct _XENBUS_DEBUG_CALLBACK {
    LIST_ENTRY              ListEntry;
    PVOID                   Caller;
    CHAR                    Prefix[MAXIMUM_PREFIX_LENGTH];
    XENBUS_DEBUG_FUNCTION   Function;
    PVOID                   Argument;
};

struct _XENBUS_DEBUG_CONTEXT {
    PXENBUS_FDO                 Fdo;
    KSPIN_LOCK                  Lock;
    LONG                        References;
    KBUGCHECK_CALLBACK_RECORD   CallbackRecord;
    LIST_ENTRY                  CallbackList;
    const CHAR                  *CallbackPrefix;
    HIGH_LOCK                   CallbackLock;
};

#define XENBUS_DEBUG_TAG    'UBED'

static FORCEINLINE PVOID
__DebugAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_DEBUG_TAG);
}

static FORCEINLINE VOID
__DebugFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_DEBUG_TAG);
}

extern USHORT
RtlCaptureStackBackTrace(
    __in        ULONG   FramesToSkip,
    __in        ULONG   FramesToCapture,
    __out       PVOID   *BackTrace,
    __out_opt   PULONG  BackTraceHash
    );

static NTSTATUS
DebugRegister(
    IN  PINTERFACE              Interface,
    IN  PCHAR                   Prefix,
    IN  XENBUS_DEBUG_FUNCTION   Function,
    IN  PVOID                   Argument OPTIONAL,
    OUT PXENBUS_DEBUG_CALLBACK  *Callback
    )
{
    PXENBUS_DEBUG_CONTEXT       Context = Interface->Context;
    ULONG                       Length;
    KIRQL                       Irql;
    NTSTATUS                    status;

    *Callback = __DebugAllocate(sizeof (XENBUS_DEBUG_CALLBACK));

    status = STATUS_NO_MEMORY;
    if (*Callback == NULL)
        goto fail1;

    (VOID) RtlCaptureStackBackTrace(1, 1, &(*Callback)->Caller, NULL);    

    Length = (ULONG)__min(strlen(Prefix), MAXIMUM_PREFIX_LENGTH - 1);
    RtlCopyMemory((*Callback)->Prefix, Prefix, Length);

    (*Callback)->Function = Function;
    (*Callback)->Argument = Argument;

    AcquireHighLock(&Context->CallbackLock, &Irql);
    InsertTailList(&Context->CallbackList, &(*Callback)->ListEntry);
    ReleaseHighLock(&Context->CallbackLock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
DebugPrintf(
    IN  PINTERFACE              Interface,
    IN  const CHAR              *Format,
    ...
    )
{
    PXENBUS_DEBUG_CONTEXT       Context = Interface->Context;
    va_list                     Arguments;

    ASSERT(Context->CallbackPrefix != NULL);

    LogPrintf(LOG_LEVEL_INFO,
              "%s: ",
              Context->CallbackPrefix);

    va_start(Arguments, Format);
    LogVPrintf(LOG_LEVEL_INFO,
               Format,
               Arguments);
    va_end(Arguments);
}

static VOID
DebugDeregister(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_DEBUG_CALLBACK  Callback
    )
{
    PXENBUS_DEBUG_CONTEXT       Context = Interface->Context;
    KIRQL                       Irql;

    AcquireHighLock(&Context->CallbackLock, &Irql);
    RemoveEntryList(&Callback->ListEntry);
    ReleaseHighLock(&Context->CallbackLock, Irql);

    __DebugFree(Callback);
}

static VOID
DebugCallback(
    IN  PXENBUS_DEBUG_CONTEXT   Context,
    IN  PXENBUS_DEBUG_CALLBACK  Callback,
    IN  BOOLEAN                 Crashing
    )
{
    PCHAR                       Name;
    ULONG_PTR                   Offset;

    ModuleLookup((ULONG_PTR)Callback->Function, &Name, &Offset);

    if (Name == NULL) {
        ModuleLookup((ULONG_PTR)Callback->Caller, &Name, &Offset);

        if (Name != NULL) {
            LogPrintf(LOG_LEVEL_INFO,
                      "XEN|DEBUG: SKIPPING %p PREFIX '%s' REGISTERED BY %s + %p\n",
                      Callback->Function,
                      Callback->Prefix,
                      Name,
                      Offset);
        } else {
            LogPrintf(LOG_LEVEL_INFO,
                      "XEN|DEBUG: SKIPPING %p PREFIX '%s' REGISTERED BY %p\n",
                      Callback->Function,
                      Callback->Prefix,
                      Callback->Caller);
        }
    } else {
        LogPrintf(LOG_LEVEL_INFO,
                  "XEN|DEBUG: ====> (%s + %p)\n",
                  Name,
                  Offset);

        Context->CallbackPrefix = Callback->Prefix;
        Callback->Function(Callback->Argument, Crashing);
        Context->CallbackPrefix = NULL;

        LogPrintf(LOG_LEVEL_INFO,
                  "XEN|DEBUG: <==== (%s + %p)\n",
                  Name,
                  Offset);
    }
}

static VOID
DebugTriggerLocked(
    IN  PXENBUS_DEBUG_CONTEXT   Context,
    IN  PXENBUS_DEBUG_CALLBACK  Callback OPTIONAL,
    IN  BOOLEAN                 Crashing
    )
{
    if (Callback == NULL) {
        PLIST_ENTRY ListEntry;

        for (ListEntry = Context->CallbackList.Flink;
             ListEntry != &Context->CallbackList;
             ListEntry = ListEntry->Flink) {

            Callback = CONTAINING_RECORD(ListEntry,
                                         XENBUS_DEBUG_CALLBACK,
                                         ListEntry);

            DebugCallback(Context, Callback, Crashing);
        }
    } else {
        DebugCallback(Context, Callback, Crashing);
    }
}
    
static VOID
DebugTrigger(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_DEBUG_CALLBACK  Callback OPTIONAL
    )
{
    PXENBUS_DEBUG_CONTEXT       Context = Interface->Context;
    KIRQL                       Irql;

    Trace("====>\n");

    AcquireHighLock(&Context->CallbackLock, &Irql);
    DebugTriggerLocked(Context, Callback, FALSE);
    ReleaseHighLock(&Context->CallbackLock, Irql);

    Trace("<====\n");
}

static 
_Function_class_(KBUGCHECK_CALLBACK_ROUTINE)
_IRQL_requires_same_
VOID                     
DebugBugCheckCallback(
    IN  PVOID               Argument,
    IN  ULONG               Length
    )
{
    PXENBUS_DEBUG_CONTEXT   Context = Argument;

    if (Length >= sizeof (XENBUS_DEBUG_CONTEXT))
        DebugTriggerLocked(Context, NULL, TRUE);
}

static NTSTATUS
DebugAcquire(
    PINTERFACE              Interface
    )
{
    PXENBUS_DEBUG_CONTEXT   Context = Interface->Context;
    KIRQL                   Irql;
    NTSTATUS                status;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    KeInitializeCallbackRecord(&Context->CallbackRecord);

    status = STATUS_UNSUCCESSFUL;
    if (!KeRegisterBugCheckCallback(&Context->CallbackRecord,
                                    DebugBugCheckCallback,
                                    Context,
                                    sizeof (XENBUS_DEBUG_CONTEXT),
                                    (PUCHAR)__MODULE__))
        goto fail1;

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    RtlZeroMemory(&Context->CallbackRecord, sizeof (KBUGCHECK_CALLBACK_RECORD));

    --Context->References;
    ASSERT3U(Context->References, ==, 0);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return status;
}

static VOID
DebugRelease(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_DEBUG_CONTEXT   Context = Interface->Context;
    KIRQL                   Irql;
    BOOLEAN                 Success;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    (VOID) __AcquireHighLock(&Context->CallbackLock);
    if (!IsListEmpty(&Context->CallbackList))
        BUG("OUTSTANDING CALLBACKS");
    ReleaseHighLock(&Context->CallbackLock, DISPATCH_LEVEL);

    Success = KeDeregisterBugCheckCallback(&Context->CallbackRecord);
    ASSERT(Success);

    RtlZeroMemory(&Context->CallbackRecord, sizeof (KBUGCHECK_CALLBACK_RECORD));

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);
}

static struct _XENBUS_DEBUG_INTERFACE_V1 DebugInterfaceVersion1 = {
    { sizeof (struct _XENBUS_DEBUG_INTERFACE_V1), 1, NULL, NULL, NULL },
    DebugAcquire,
    DebugRelease,
    DebugRegister,
    DebugPrintf,
    DebugTrigger,
    DebugDeregister
};
                     
NTSTATUS
DebugInitialize(
    IN  PXENBUS_FDO             Fdo,
    OUT PXENBUS_DEBUG_CONTEXT   *Context
    )
{
    NTSTATUS                    status;

    Trace("====>\n");

    *Context = __DebugAllocate(sizeof (XENBUS_DEBUG_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (*Context == NULL)
        goto fail1;

    InitializeListHead(&(*Context)->CallbackList);
    KeInitializeSpinLock(&(*Context)->Lock);

    (*Context)->Fdo = Fdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
DebugGetInterface(
    IN      PXENBUS_DEBUG_CONTEXT   Context,
    IN      ULONG                   Version,
    IN OUT  PINTERFACE              Interface,
    IN      ULONG                   Size
    )
{
    NTSTATUS                        status;

    ASSERT(Context != NULL);
        
    switch (Version) {
    case 1: {
        struct _XENBUS_DEBUG_INTERFACE_V1   *DebugInterface;

        DebugInterface = (struct _XENBUS_DEBUG_INTERFACE_V1 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENBUS_DEBUG_INTERFACE_V1))
            break;

        *DebugInterface = DebugInterfaceVersion1;

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
DebugGetReferences(
    IN  PXENBUS_DEBUG_CONTEXT   Context
    )
{
    return Context->References;
}

VOID
DebugTeardown(
    IN  PXENBUS_DEBUG_CONTEXT   Context
    )
{
    Trace("====>\n");

    Context->Fdo = NULL;

    RtlZeroMemory(&Context->Lock, sizeof (KSPIN_LOCK));
    RtlZeroMemory(&Context->CallbackList, sizeof (LIST_ENTRY));

    ASSERT(IsZeroMemory(Context, sizeof (XENBUS_DEBUG_CONTEXT)));
    __DebugFree(Context);

    Trace("<====\n");
}
