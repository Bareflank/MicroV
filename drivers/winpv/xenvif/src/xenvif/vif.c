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

#include "pdo.h"
#include "parse.h"
#include "vif.h"
#include "mrsw.h"
#include "thread.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

struct _XENVIF_VIF_CONTEXT {
    PXENVIF_PDO                 Pdo;
    XENVIF_MRSW_LOCK            Lock;
    LONG                        References;
    PXENVIF_FRONTEND            Frontend;
    BOOLEAN                     Enabled;
    ULONG                       Version;
    XENVIF_VIF_CALLBACK         Callback;
    PVOID                       Argument;
    PXENVIF_THREAD              MacThread;
    KEVENT                      MacEvent;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
};

#define XENVIF_VIF_TAG  'FIV'

static FORCEINLINE PVOID
__VifAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENVIF_VIF_TAG);
}

static FORCEINLINE VOID
__VifFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_VIF_TAG);
}

static NTSTATUS
VifMac(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           _Context
    )
{
    PXENVIF_VIF_CONTEXT Context = _Context;
    PKEVENT             Event;

    Trace("====>\n");

    Event = ThreadGetEvent(Self);

    for (;;) {
        Trace("waiting...\n");

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        Trace("awake\n");

        if (ThreadIsAlerted(Self))
            break;
        
        if (Context->Enabled)
            Context->Callback(Context->Argument,
                              XENVIF_MAC_STATE_CHANGE);

        KeSetEvent(&Context->MacEvent, IO_NO_INCREMENT, FALSE);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
VifSuspendCallbackLate(
    IN  PVOID           Argument
    )
{
    PXENVIF_VIF_CONTEXT Context = Argument;
    NTSTATUS            status;

    if (!Context->Enabled)
        return;

    status = FrontendSetState(Context->Frontend, FRONTEND_ENABLED);
    ASSERT(NT_SUCCESS(status));

    // We do this three times to make sure switches take note
    FrontendAdvertiseIpAddresses(Context->Frontend);
    FrontendAdvertiseIpAddresses(Context->Frontend);
    FrontendAdvertiseIpAddresses(Context->Frontend);
}

static NTSTATUS
VifEnable(
    IN  PINTERFACE          Interface,
    IN  XENVIF_VIF_CALLBACK Callback,
    IN  PVOID               Argument
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    KIRQL                   Irql;
    BOOLEAN                 Exclusive;
    NTSTATUS                status;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);
    Exclusive = TRUE;

    if (Context->Enabled)
        goto done;

    Context->Callback = Callback;
    Context->Argument = Argument;

    Context->Enabled = TRUE;

    KeMemoryBarrier();

    status = XENBUS_SUSPEND(Acquire, &Context->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = FrontendSetState(Context->Frontend, FRONTEND_ENABLED);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_SUSPEND(Register,
                            &Context->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            VifSuspendCallbackLate,
                            Context,
                            &Context->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail3;

done:
    ASSERT(Exclusive);
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    (VOID) FrontendSetState(Context->Frontend, FRONTEND_CONNECTED);

    ReleaseMrswLockExclusive(&Context->Lock, Irql, TRUE);
    Exclusive = FALSE;

    ReceiverWaitForPackets(FrontendGetReceiver(Context->Frontend));
    TransmitterAbortPackets(FrontendGetTransmitter(Context->Frontend));

    Trace("waiting for mac thread..\n");

    KeClearEvent(&Context->MacEvent);
    ThreadWake(Context->MacThread);

    (VOID) KeWaitForSingleObject(&Context->MacEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    Trace("done\n");

fail2:
    Error("fail2\n");

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    Context->Enabled = FALSE;

    KeMemoryBarrier();

    Context->Argument = NULL;
    Context->Callback = NULL;

    if (Exclusive)
        ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);
    else
        ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifDisable(
    IN  PINTERFACE      Interface
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;
    KIRQL               Irql;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (!Context->Enabled) {
        ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);
        goto done;
    }

    Context->Enabled = FALSE;

    KeMemoryBarrier();

    XENBUS_SUSPEND(Deregister,
                   &Context->SuspendInterface,
                   Context->SuspendCallbackLate);
    Context->SuspendCallbackLate = NULL;

    (VOID) FrontendSetState(Context->Frontend, FRONTEND_CONNECTED);

    ReleaseMrswLockExclusive(&Context->Lock, Irql, TRUE);

    ReceiverWaitForPackets(FrontendGetReceiver(Context->Frontend));
    TransmitterAbortPackets(FrontendGetTransmitter(Context->Frontend));

    Trace("waiting for mac thread..\n");

    KeClearEvent(&Context->MacEvent);
    ThreadWake(Context->MacThread);

    (VOID) KeWaitForSingleObject(&Context->MacEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    Trace("done\n");

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

    Context->Argument = NULL;
    Context->Callback = NULL;

    ReleaseMrswLockShared(&Context->Lock);

done:
    Trace("<====\n");
}

static NTSTATUS
VifQueryStatistic(
    IN  PINTERFACE              Interface,
    IN  XENVIF_VIF_STATISTIC    Index,
    OUT PULONGLONG              Value
    )
{
    PXENVIF_VIF_CONTEXT         Context = Interface->Context;
    NTSTATUS                    status;

    status = STATUS_INVALID_PARAMETER;
    if (Index >= XENVIF_VIF_STATISTIC_COUNT)
        goto done;
        
    AcquireMrswLockShared(&Context->Lock);

    FrontendQueryStatistic(Context->Frontend, Index, Value);

    ReleaseMrswLockShared(&Context->Lock);
    status = STATUS_SUCCESS;

done:
    return status;
}

static VOID
VifQueryRingCount(
    IN  PINTERFACE      Interface,
    OUT PULONG          Count
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    *Count = FrontendGetNumQueues(Context->Frontend);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifUpdateHashMapping(
    IN  PINTERFACE          Interface,
    IN  PPROCESSOR_NUMBER   Mapping,
    IN  ULONG               Order
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    NTSTATUS                status;

    AcquireMrswLockShared(&Context->Lock);

    status = ReceiverUpdateHashMapping(FrontendGetReceiver(Context->Frontend),
                                       Mapping,
                                       Order);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifReceiverReturnPacket(
    IN  PINTERFACE      Interface,
    IN  PVOID           Cookie
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverReturnPacket(FrontendGetReceiver(Context->Frontend),
                         Cookie);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifTransmitterQueuePacketVersion6(
    IN  PINTERFACE                  Interface,
    IN  PMDL                        Mdl,
    IN  ULONG                       Offset,
    IN  ULONG                       Length,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions,
    IN  USHORT                      MaximumSegmentSize,
    IN  USHORT                      TagControlInformation,
    IN  PXENVIF_PACKET_HASH         Hash,
    IN  PVOID                       Cookie
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                        status;

    AcquireMrswLockShared(&Context->Lock);

    status = STATUS_UNSUCCESSFUL;
    if (!Context->Enabled)
        goto done;

    status = TransmitterQueuePacket(FrontendGetTransmitter(Context->Frontend),
                                    Mdl,
                                    Offset,
                                    Length,
                                    OffloadOptions,
                                    MaximumSegmentSize,
                                    TagControlInformation,
                                    Hash,
                                    FALSE,
                                    Cookie);

done:
    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifTransmitterQueuePacket(
    IN  PINTERFACE                  Interface,
    IN  PMDL                        Mdl,
    IN  ULONG                       Offset,
    IN  ULONG                       Length,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions,
    IN  USHORT                      MaximumSegmentSize,
    IN  USHORT                      TagControlInformation,
    IN  PXENVIF_PACKET_HASH         Hash,
    IN  BOOLEAN                     More,
    IN  PVOID                       Cookie
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                        status;

    AcquireMrswLockShared(&Context->Lock);

    status = STATUS_UNSUCCESSFUL;
    if (!Context->Enabled)
        goto done;

    status = TransmitterQueuePacket(FrontendGetTransmitter(Context->Frontend),
                                    Mdl,
                                    Offset,
                                    Length,
                                    OffloadOptions,
                                    MaximumSegmentSize,
                                    TagControlInformation,
                                    Hash,
                                    More,
                                    Cookie);

done:
    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifTransmitterQueryOffloadOptions(
    IN  PINTERFACE                  Interface,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS Options
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    TransmitterQueryOffloadOptions(FrontendGetTransmitter(Context->Frontend),
                                   Options);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifTransmitterQueryLargePacketSize(
    IN  PINTERFACE      Interface,
    IN  UCHAR           Version,
    OUT PULONG          Size
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    TransmitterQueryLargePacketSize(FrontendGetTransmitter(Context->Frontend),
                                    Version,
                                    Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifReceiverSetOffloadOptions(
    IN  PINTERFACE                  Interface,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  Options
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverSetOffloadOptions(FrontendGetReceiver(Context->Frontend),
                              Options);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifReceiverSetBackfillSize(
    IN  PINTERFACE      Interface,
    IN  ULONG           Size
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverSetBackfillSize(FrontendGetReceiver(Context->Frontend),
                            Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifReceiverSetHashAlgorithm(
    IN  PINTERFACE                      Interface,
    IN  XENVIF_PACKET_HASH_ALGORITHM    Algorithm
    )
{
    PXENVIF_VIF_CONTEXT                 Context = Interface->Context;
    NTSTATUS                            status;

    AcquireMrswLockShared(&Context->Lock);

    status = ReceiverSetHashAlgorithm(FrontendGetReceiver(Context->Frontend),
                                      Algorithm);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifReceiverQueryHashCapabilities(
    IN  PINTERFACE      Interface,
    ...
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;
    va_list             Arguments;
    PULONG              Types;
    NTSTATUS            status;

    AcquireMrswLockShared(&Context->Lock);

    va_start(Arguments, Interface);

    Types = va_arg(Arguments, PULONG);

    status = ReceiverQueryHashCapabilities(FrontendGetReceiver(Context->Frontend),
                                           Types);

    va_end(Arguments);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifReceiverUpdateHashParameters(
    IN  PINTERFACE      Interface,
    ...
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;
    va_list             Arguments;
    ULONG               Types;
    PUCHAR              Key;
    NTSTATUS            status;

    AcquireMrswLockShared(&Context->Lock);

    va_start(Arguments, Interface);

    Types = va_arg(Arguments, ULONG);
    Key = va_arg(Arguments, PUCHAR);

    status = ReceiverUpdateHashParameters(FrontendGetReceiver(Context->Frontend),
                                          Types,
                                          Key);

    va_end(Arguments);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifMacQueryState(
    IN  PINTERFACE                  Interface,
    OUT PNET_IF_MEDIA_CONNECT_STATE MediaConnectState OPTIONAL,
    OUT PULONG64                    LinkSpeed OPTIONAL,
    OUT PNET_IF_MEDIA_DUPLEX_STATE  MediaDuplexState OPTIONAL
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryState(FrontendGetMac(Context->Frontend),
                  MediaConnectState,
                  LinkSpeed,
                  MediaDuplexState);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryMaximumFrameSize(
    IN  PINTERFACE      Interface,
    OUT PULONG          Size
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryMaximumFrameSize(FrontendGetMac(Context->Frontend), Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryPermanentAddress(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryPermanentAddress(FrontendGetMac(Context->Frontend), Address);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryCurrentAddress(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryCurrentAddress(FrontendGetMac(Context->Frontend), Address);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifMacQueryMulticastAddresses(
    IN      PINTERFACE          Interface,
    OUT     PETHERNET_ADDRESS   Address OPTIONAL,
    IN OUT  PULONG              Count
    )
{
    PXENVIF_VIF_CONTEXT         Context = Interface->Context;
    NTSTATUS                    status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacQueryMulticastAddresses(FrontendGetMac(Context->Frontend),
                                        Address,
                                        Count);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifMacSetMulticastAddresses(
    IN  PINTERFACE          Interface,
    IN  PETHERNET_ADDRESS   Address,
    IN  ULONG               Count
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    ULONG                   Index;
    NTSTATUS                status;

    status = STATUS_INVALID_PARAMETER;
    for (Index = 0; Index < Count; Index++) {
        if (!(Address[Index].Byte[0] & 0x01))
            goto done;
    }

    AcquireMrswLockShared(&Context->Lock);

    status = FrontendSetMulticastAddresses(Context->Frontend,
                                           Address,
                                           Count);

    ReleaseMrswLockShared(&Context->Lock);

done:
    return status;
}

static NTSTATUS
VifMacQueryFilterLevel(
    IN  PINTERFACE                  Interface,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    OUT PXENVIF_MAC_FILTER_LEVEL    Level
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacQueryFilterLevel(FrontendGetMac(Context->Frontend),
                                 Type,
                                 Level);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifMacSetFilterLevel(
    IN  PINTERFACE                  Interface,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    IN  XENVIF_MAC_FILTER_LEVEL     Level
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                        status;

    AcquireMrswLockShared(&Context->Lock);

    status = FrontendSetFilterLevel(Context->Frontend, Type, Level);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifReceiverQueryRingSize(
    IN  PINTERFACE          Interface,
    OUT PULONG              Size
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverQueryRingSize(FrontendGetReceiver(Context->Frontend), Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifTransmitterQueryRingSize(
    IN  PINTERFACE          Interface,
    OUT PULONG              Size
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    TransmitterQueryRingSize(FrontendGetTransmitter(Context->Frontend), Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifAcquire(
    PINTERFACE              Interface
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    KIRQL                   Irql;

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    Context->Frontend = PdoGetFrontend(Context->Pdo);
    Context->Version = Interface->Version;

    Trace("<====\n");

done:
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    return STATUS_SUCCESS;
}

VOID
VifRelease(
    IN  PINTERFACE          Interface
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    KIRQL                   Irql;

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    ASSERT(!Context->Enabled);

    Context->Version = 0;
    Context->Frontend = NULL;

    Trace("<====\n");

done:
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);
}

static struct _XENVIF_VIF_INTERFACE_V6 VifInterfaceVersion6 = {
    { sizeof (struct _XENVIF_VIF_INTERFACE_V6), 6, NULL, NULL, NULL },
    VifAcquire,
    VifRelease,
    VifEnable,
    VifDisable,
    VifQueryStatistic,
    VifQueryRingCount,
    VifUpdateHashMapping,
    VifReceiverReturnPacket,
    VifReceiverSetOffloadOptions,
    VifReceiverSetBackfillSize,
    VifReceiverQueryRingSize,
    VifReceiverSetHashAlgorithm,
    VifReceiverQueryHashCapabilities,
    VifReceiverUpdateHashParameters,
    VifTransmitterQueuePacketVersion6,
    VifTransmitterQueryOffloadOptions,
    VifTransmitterQueryLargePacketSize,
    VifTransmitterQueryRingSize,
    VifMacQueryState,
    VifMacQueryMaximumFrameSize,
    VifMacQueryPermanentAddress,
    VifMacQueryCurrentAddress,
    VifMacQueryMulticastAddresses,
    VifMacSetMulticastAddresses,
    VifMacSetFilterLevel,
    VifMacQueryFilterLevel
};

static struct _XENVIF_VIF_INTERFACE_V7 VifInterfaceVersion7 = {
    { sizeof (struct _XENVIF_VIF_INTERFACE_V7), 7, NULL, NULL, NULL },
    VifAcquire,
    VifRelease,
    VifEnable,
    VifDisable,
    VifQueryStatistic,
    VifQueryRingCount,
    VifUpdateHashMapping,
    VifReceiverReturnPacket,
    VifReceiverSetOffloadOptions,
    VifReceiverSetBackfillSize,
    VifReceiverQueryRingSize,
    VifReceiverSetHashAlgorithm,
    VifReceiverQueryHashCapabilities,
    VifReceiverUpdateHashParameters,
    VifTransmitterQueuePacket,
    VifTransmitterQueryOffloadOptions,
    VifTransmitterQueryLargePacketSize,
    VifTransmitterQueryRingSize,
    VifMacQueryState,
    VifMacQueryMaximumFrameSize,
    VifMacQueryPermanentAddress,
    VifMacQueryCurrentAddress,
    VifMacQueryMulticastAddresses,
    VifMacSetMulticastAddresses,
    VifMacSetFilterLevel,
    VifMacQueryFilterLevel
};

static struct _XENVIF_VIF_INTERFACE_V8 VifInterfaceVersion8 = {
    { sizeof (struct _XENVIF_VIF_INTERFACE_V8), 8, NULL, NULL, NULL },
    VifAcquire,
    VifRelease,
    VifEnable,
    VifDisable,
    VifQueryStatistic,
    VifQueryRingCount,
    VifUpdateHashMapping,
    VifReceiverReturnPacket,
    VifReceiverSetOffloadOptions,
    VifReceiverSetBackfillSize,
    VifReceiverQueryRingSize,
    VifReceiverSetHashAlgorithm,
    VifReceiverQueryHashCapabilities,
    VifReceiverUpdateHashParameters,
    VifTransmitterQueuePacket,
    VifTransmitterQueryOffloadOptions,
    VifTransmitterQueryLargePacketSize,
    VifTransmitterQueryRingSize,
    VifMacQueryState,
    VifMacQueryMaximumFrameSize,
    VifMacQueryPermanentAddress,
    VifMacQueryCurrentAddress,
    VifMacQueryMulticastAddresses,
    VifMacSetMulticastAddresses,
    VifMacSetFilterLevel,
    VifMacQueryFilterLevel
};

NTSTATUS
VifInitialize(
    IN  PXENVIF_PDO         Pdo,
    OUT PXENVIF_VIF_CONTEXT *Context
    )
{
    NTSTATUS                status;

    Trace("====>\n");

    *Context = __VifAllocate(sizeof (XENVIF_VIF_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (*Context == NULL)
        goto fail1;

    InitializeMrswLock(&(*Context)->Lock);

    FdoGetSuspendInterface(PdoGetFdo(Pdo),&(*Context)->SuspendInterface);

    KeInitializeEvent(&(*Context)->MacEvent, NotificationEvent, FALSE);

    status = ThreadCreate(VifMac,
                          *Context,
                          &(*Context)->MacThread);
    if (!NT_SUCCESS(status))
        goto fail2;

    (*Context)->Pdo = Pdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail3\n");

    RtlZeroMemory(&(*Context)->MacEvent, sizeof (KEVENT));

    RtlZeroMemory(&(*Context)->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&(*Context)->Lock, sizeof (XENVIF_MRSW_LOCK));

    ASSERT(IsZeroMemory(*Context, sizeof (XENVIF_VIF_CONTEXT)));
    __VifFree(*Context);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
VifGetInterface(
    IN      PXENVIF_VIF_CONTEXT Context,
    IN      ULONG               Version,
    IN OUT  PINTERFACE          Interface,
    IN      ULONG               Size
    )
{
    NTSTATUS                    status;

    switch (Version) {
    case 6: {
        struct _XENVIF_VIF_INTERFACE_V6 *VifInterface;

        VifInterface = (struct _XENVIF_VIF_INTERFACE_V6 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENVIF_VIF_INTERFACE_V6))
            break;

        *VifInterface = VifInterfaceVersion6;

        ASSERT3U(Interface->Version, ==, Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    case 7: {
        struct _XENVIF_VIF_INTERFACE_V7 *VifInterface;

        VifInterface = (struct _XENVIF_VIF_INTERFACE_V7 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENVIF_VIF_INTERFACE_V7))
            break;

        *VifInterface = VifInterfaceVersion7;

        ASSERT3U(Interface->Version, ==, Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    case 8: {
        struct _XENVIF_VIF_INTERFACE_V8 *VifInterface;

        VifInterface = (struct _XENVIF_VIF_INTERFACE_V8 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENVIF_VIF_INTERFACE_V8))
            break;

        *VifInterface = VifInterfaceVersion8;

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

VOID
VifTeardown(
    IN  PXENVIF_VIF_CONTEXT Context
    )
{
    Trace("====>\n");

    Context->Pdo = NULL;
    Context->Version = 0;

    ThreadAlert(Context->MacThread);
    ThreadJoin(Context->MacThread);
    Context->MacThread = NULL;

    RtlZeroMemory(&Context->MacEvent, sizeof (KEVENT));

    RtlZeroMemory(&Context->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&Context->Lock, sizeof (XENVIF_MRSW_LOCK));

    ASSERT(IsZeroMemory(Context, sizeof (XENVIF_VIF_CONTEXT)));
    __VifFree(Context);

    Trace("<====\n");
}

static FORCEINLINE VOID
__VifReceiverQueuePacketVersion6(
    IN  PXENVIF_VIF_CONTEXT             Context,
    IN  ULONG                           Index,
    IN  PMDL                            Mdl,
    IN  ULONG                           Offset,
    IN  ULONG                           Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS    Flags,
    IN  USHORT                          MaximumSegmentSize,
    IN  USHORT                          TagControlInformation,
    IN  PXENVIF_PACKET_INFO             Info,
    IN  PXENVIF_PACKET_HASH             Hash,
    IN  BOOLEAN                         More,
    IN  PVOID                           Cookie
    )
{
    UNREFERENCED_PARAMETER(Index);
    UNREFERENCED_PARAMETER(More);

    Context->Callback(Context->Argument,
                      XENVIF_RECEIVER_QUEUE_PACKET,
                      Mdl,
                      Offset,
                      Length,
                      Flags,
                      MaximumSegmentSize,
                      TagControlInformation,
                      Info,
                      Hash,
                      Cookie);
}

static FORCEINLINE VOID
__VifReceiverQueuePacketVersion7(
    IN  PXENVIF_VIF_CONTEXT             Context,
    IN  ULONG                           Index,
    IN  PMDL                            Mdl,
    IN  ULONG                           Offset,
    IN  ULONG                           Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS    Flags,
    IN  USHORT                          MaximumSegmentSize,
    IN  USHORT                          TagControlInformation,
    IN  PXENVIF_PACKET_INFO             Info,
    IN  PXENVIF_PACKET_HASH             Hash,
    IN  BOOLEAN                         More,
    IN  PVOID                           Cookie
    )
{
    UNREFERENCED_PARAMETER(Index);

    Context->Callback(Context->Argument,
                      XENVIF_RECEIVER_QUEUE_PACKET,
                      Mdl,
                      Offset,
                      Length,
                      Flags,
                      MaximumSegmentSize,
                      TagControlInformation,
                      Info,
                      Hash,
                      More,
                      Cookie);
}

static FORCEINLINE VOID
__VifReceiverQueuePacket(
    IN  PXENVIF_VIF_CONTEXT             Context,
    IN  ULONG                           Index,
    IN  PMDL                            Mdl,
    IN  ULONG                           Offset,
    IN  ULONG                           Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS    Flags,
    IN  USHORT                          MaximumSegmentSize,
    IN  USHORT                          TagControlInformation,
    IN  PXENVIF_PACKET_INFO             Info,
    IN  PXENVIF_PACKET_HASH             Hash,
    IN  BOOLEAN                         More,
    IN  PVOID                           Cookie
    )
{
    Context->Callback(Context->Argument,
                      XENVIF_RECEIVER_QUEUE_PACKET,
                      Index,
                      Mdl,
                      Offset,
                      Length,
                      Flags,
                      MaximumSegmentSize,
                      TagControlInformation,
                      Info,
                      Hash,
                      More,
                      Cookie);

}

VOID
VifReceiverQueuePacket(
    IN  PXENVIF_VIF_CONTEXT             Context,
    IN  ULONG                           Index,
    IN  PMDL                            Mdl,
    IN  ULONG                           Offset,
    IN  ULONG                           Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS    Flags,
    IN  USHORT                          MaximumSegmentSize,
    IN  USHORT                          TagControlInformation,
    IN  PXENVIF_PACKET_INFO             Info,
    IN  PXENVIF_PACKET_HASH             Hash,
    IN  BOOLEAN                         More,
    IN  PVOID                           Cookie
    )
{
    KIRQL                               Irql;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    switch (Context->Version) {
    case 6:
        __VifReceiverQueuePacketVersion6(Context,
                                         Index,
                                         Mdl,
                                         Offset,
                                         Length,
                                         Flags,
                                         MaximumSegmentSize,
                                         TagControlInformation,
                                         Info,
                                         Hash,
                                         More,
                                         Cookie);
        break;

    case 7:
        __VifReceiverQueuePacketVersion7(Context,
                                         Index,
                                         Mdl,
                                         Offset,
                                         Length,
                                         Flags,
                                         MaximumSegmentSize,
                                         TagControlInformation,
                                         Info,
                                         Hash,
                                         More,
                                         Cookie);
        break;

    case 8:
        __VifReceiverQueuePacket(Context,
                                 Index,
                                 Mdl,
                                 Offset,
                                 Length,
                                 Flags,
                                 MaximumSegmentSize,
                                 TagControlInformation,
                                 Info,
                                 Hash,
                                 More,
                                 Cookie);
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    KeLowerIrql(Irql);
}

VOID
VifTransmitterReturnPacket(
    IN  PXENVIF_VIF_CONTEXT                         Context,
    IN  PVOID                                       Cookie,
    IN  PXENVIF_TRANSMITTER_PACKET_COMPLETION_INFO  Completion
    )
{
    switch (Context->Version) {
    case 6:
    case 7:
    case 8:
        Context->Callback(Context->Argument,
                          XENVIF_TRANSMITTER_RETURN_PACKET,
                          Cookie,
                          Completion);
        break;

    default:
        ASSERT(FALSE);
        break;
    }
}

PXENVIF_THREAD
VifGetMacThread(
    IN  PXENVIF_VIF_CONTEXT Context
    )
{
    return Context->MacThread;
}
