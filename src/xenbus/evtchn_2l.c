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

#include "evtchn_2l.h"
#include "shared_info.h"
#include "fdo.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

typedef struct _XENBUS_EVTCHN_TWO_LEVEL_CONTEXT {
    PXENBUS_FDO                     Fdo;
    KSPIN_LOCK                      Lock;
    LONG                            References;
    XENBUS_SHARED_INFO_INTERFACE    SharedInfoInterface;
} XENBUS_EVTCHN_TWO_LEVEL_CONTEXT, *PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT;

#define XENBUS_EVTCHN_TWO_LEVEL_TAG  'L2'

static FORCEINLINE PVOID
__EvtchnTwoLevelAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_EVTCHN_TWO_LEVEL_TAG);
}

static FORCEINLINE VOID
__EvtchnTwoLevelFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_EVTCHN_TWO_LEVEL_TAG);
}

static BOOLEAN
EvtchnTwoLevelIsProcessorEnabled(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  _Context,
    IN  ULONG                       Index
    )
{
    unsigned int                    vcpu_id;
    NTSTATUS                        status;

    UNREFERENCED_PARAMETER(_Context);

    status = SystemVirtualCpuIndex(Index, &vcpu_id);
    if (!NT_SUCCESS(status))
        return FALSE;

    if (vcpu_id != 0)
        return FALSE;

    return TRUE;
}

static BOOLEAN
EvtchnTwoLevelPoll(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context,
    IN  ULONG                           Index,
    IN  XENBUS_EVTCHN_ABI_EVENT         Event,
    IN  PVOID                           Argument
    )
{
    PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT    Context = (PVOID)_Context;

    return XENBUS_SHARED_INFO(EvtchnPoll,
                              &Context->SharedInfoInterface,
                              Index,
                              Event,
                              Argument);
}

static NTSTATUS
EvtchnTwoLevelPortEnable(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context,
    IN  ULONG                           Port
    )
{
    UNREFERENCED_PARAMETER(_Context);
    UNREFERENCED_PARAMETER(Port);

    return STATUS_SUCCESS;
}

static VOID
EvtchnTwoLevelPortDisable(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context,
    IN  ULONG                           Port
    )
{
    PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT    Context = (PVOID)_Context;

    XENBUS_SHARED_INFO(EvtchnMask,
                       &Context->SharedInfoInterface,
                       Port);
}

static VOID
EvtchnTwoLevelPortAck(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context,
    IN  ULONG                           Port
    )
{
    PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT    Context = (PVOID)_Context;

    XENBUS_SHARED_INFO(EvtchnAck,
                       &Context->SharedInfoInterface,
                       Port);
}

static VOID
EvtchnTwoLevelPortMask(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context,
    IN  ULONG                           Port
    )
{
    PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT    Context = (PVOID)_Context;

    XENBUS_SHARED_INFO(EvtchnMask,
                       &Context->SharedInfoInterface,
                       Port);
}

static BOOLEAN
EvtchnTwoLevelPortUnmask(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context,
    IN  ULONG                           Port
    )
{
    PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT    Context = (PVOID)_Context;

    return XENBUS_SHARED_INFO(EvtchnUnmask,
                              &Context->SharedInfoInterface,
                              Port);
}

static NTSTATUS
EvtchnTwoLevelAcquire(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context
    )
{
    PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT    Context = (PVOID)_Context;
    KIRQL                               Irql;
    NTSTATUS                            status;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    status = XENBUS_SHARED_INFO(Acquire, &Context->SharedInfoInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    XENBUS_SHARED_INFO(Release, &Context->SharedInfoInterface);

    --Context->References;
    ASSERT3U(Context->References, ==, 0);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return status;
}

VOID
EvtchnTwoLevelRelease(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context
    )
{
    PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT    Context = (PVOID)_Context;
    KIRQL                               Irql;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    XENBUS_SHARED_INFO(Release, &Context->SharedInfoInterface);

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);
}

static XENBUS_EVTCHN_ABI EvtchnAbiTwoLevel = {
    NULL,
    EvtchnTwoLevelAcquire,
    EvtchnTwoLevelRelease,
    EvtchnTwoLevelIsProcessorEnabled,
    EvtchnTwoLevelPoll,
    EvtchnTwoLevelPortEnable,
    EvtchnTwoLevelPortDisable,
    EvtchnTwoLevelPortAck,
    EvtchnTwoLevelPortMask,
    EvtchnTwoLevelPortUnmask
};

NTSTATUS
EvtchnTwoLevelInitialize(
    IN  PXENBUS_FDO                     Fdo,
    OUT PXENBUS_EVTCHN_ABI_CONTEXT      *_Context
    )
{
    PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT    Context;
    NTSTATUS                            status;

    Trace("====>\n");

    Context = __EvtchnTwoLevelAllocate(sizeof (XENBUS_EVTCHN_TWO_LEVEL_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (Context == NULL)
        goto fail1;

    status = SharedInfoGetInterface(FdoGetSharedInfoContext(Fdo),
                                    XENBUS_SHARED_INFO_INTERFACE_VERSION_MAX,
                                    (PINTERFACE)&Context->SharedInfoInterface,
                                    sizeof (Context->SharedInfoInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT(Context->SharedInfoInterface.Interface.Context != NULL);

    KeInitializeSpinLock(&Context->Lock);

    Context->Fdo = Fdo;

    *_Context = (PVOID)Context;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
EvtchnTwoLevelGetAbi(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context,
    OUT PXENBUS_EVTCHN_ABI              Abi)
{
    *Abi = EvtchnAbiTwoLevel;

    Abi->Context = (PVOID)_Context;
}

VOID
EvtchnTwoLevelTeardown(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT      _Context
    )
{
    PXENBUS_EVTCHN_TWO_LEVEL_CONTEXT    Context = (PVOID)_Context;

    Trace("====>\n");

    Context->Fdo = NULL;

    RtlZeroMemory(&Context->Lock, sizeof (KSPIN_LOCK));

    RtlZeroMemory(&Context->SharedInfoInterface,
                  sizeof (XENBUS_SHARED_INFO_INTERFACE));

    ASSERT(IsZeroMemory(Context, sizeof (XENBUS_EVTCHN_TWO_LEVEL_CONTEXT)));
    __EvtchnTwoLevelFree(Context);

    Trace("<====\n");
}
