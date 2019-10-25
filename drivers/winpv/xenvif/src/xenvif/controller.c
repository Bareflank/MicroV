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
 *     following disclaimer in the documetation and/or other
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
#include <procgrp.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <stdlib.h>
#include <xen.h>

#include <debug_interface.h>
#include <store_interface.h>
#include <cache_interface.h>
#include <gnttab_interface.h>
#include <evtchn_interface.h>

#include "pdo.h"
#include "frontend.h"
#include "controller.h"
#include "vif.h"
#include "thread.h"
#include "registry.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

extern ULONG
NTAPI
RtlRandomEx (
    __inout PULONG Seed
    );

#define MAXNAMELEN  128

struct _XENVIF_CONTROLLER {
    PXENVIF_FRONTEND                    Frontend;
    KSPIN_LOCK                          Lock;
    PXENBUS_GNTTAB_CACHE                GnttabCache;
    PMDL                                Mdl;
    xen_netif_ctrl_front_ring_t         Front;
    xen_netif_ctrl_sring_t              *Shared;
    PXENBUS_GNTTAB_ENTRY                Entry;
    PXENBUS_EVTCHN_CHANNEL              Channel;
    ULONG                               Events;
    BOOLEAN                             Connected;
    USHORT                              RequestId;
    struct xen_netif_ctrl_request       Request;
    struct xen_netif_ctrl_response      Response;
    XENBUS_GNTTAB_INTERFACE             GnttabInterface;
    XENBUS_EVTCHN_INTERFACE             EvtchnInterface;
    XENBUS_STORE_INTERFACE              StoreInterface;
    XENBUS_DEBUG_INTERFACE              DebugInterface;
    PXENBUS_DEBUG_CALLBACK              DebugCallback;
};

#define XENVIF_CONTROLLER_TAG  'TNOC'

static FORCEINLINE PVOID
__ControllerAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENVIF_CONTROLLER_TAG);
}

static FORCEINLINE VOID
__ControllerFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_CONTROLLER_TAG);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__ControllerAcquireLock(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Controller->Lock);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__ControllerReleaseLock(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
#pragma prefast(suppress:26110) // Caller failing to hold lock
    KeReleaseSpinLockFromDpcLevel(&Controller->Lock);
}

static VOID
ControllerAcquireLock(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    __ControllerAcquireLock(Controller);
}

static VOID
ControllerReleaseLock(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    __ControllerReleaseLock(Controller);
}

static FORCEINLINE VOID
__ControllerSend(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    (VOID) XENBUS_EVTCHN(Send,
                         &Controller->EvtchnInterface,
                         Controller->Channel);
}

VOID
ControllerPoll(
    IN  PXENVIF_CONTROLLER          Controller
    )
{
    RING_IDX                        rsp_prod;
    RING_IDX                        rsp_cons;
    struct xen_netif_ctrl_response  *rsp;

    KeMemoryBarrier();

    rsp_prod = Controller->Shared->rsp_prod;
    rsp_cons = Controller->Front.rsp_cons;

    KeMemoryBarrier();

    if (rsp_cons == rsp_prod)
        return;

    rsp = RING_GET_RESPONSE(&Controller->Front, rsp_cons);
    rsp_cons++;

    Controller->Response = *rsp;

    KeMemoryBarrier();

    Controller->Front.rsp_cons = rsp_cons;
    Controller->Shared->rsp_event = rsp_cons + 1;
}

static NTSTATUS
ControllerPutRequest(
    IN  PXENVIF_CONTROLLER          Controller,
    IN  USHORT                      Type,
    IN  ULONG                       Data0,
    IN  ULONG                       Data1,
    IN  ULONG                       Data2
    )
{
    RING_IDX                        req_prod;
    struct xen_netif_ctrl_request   *req;
    BOOLEAN                         Notify;
    NTSTATUS                        status;

    status = STATUS_NOT_SUPPORTED;
    if (!Controller->Connected)
        goto fail1;

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (RING_FULL(&Controller->Front))
        goto fail2;

    Controller->Request.type = Type;

    Controller->Request.id = Controller->RequestId++;
    if (Controller->Request.id == 0) // Make sure we skip zero
        Controller->Request.id = Controller->RequestId++;

    Controller->Request.data[0] = Data0;
    Controller->Request.data[1] = Data1;
    Controller->Request.data[2] = Data2;

    req_prod = Controller->Front.req_prod_pvt;

    req = RING_GET_REQUEST(&Controller->Front, req_prod);
    req_prod++;

    *req = Controller->Request;

    KeMemoryBarrier();

    Controller->Front.req_prod_pvt = req_prod;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Controller->Front, Notify);

#pragma warning (pop)

    if (Notify)
        __ControllerSend(Controller);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define XENVIF_CONTROLLER_POLL_PERIOD 100 // ms

static NTSTATUS
ControllerGetResponse(
    IN  PXENVIF_CONTROLLER          Controller,
    OUT PULONG                      Data OPTIONAL
    )
{
    LARGE_INTEGER                   Timeout;
    NTSTATUS                        status;

    Timeout.QuadPart = TIME_RELATIVE(TIME_MS(XENVIF_CONTROLLER_POLL_PERIOD));

    for (;;) {
        ULONG   Count;

        Count = XENBUS_EVTCHN(GetCount,
                              &Controller->EvtchnInterface,
                              Controller->Channel);

        ControllerPoll(Controller);
        KeMemoryBarrier();

        if (Controller->Response.id == Controller->Request.id)
            break;

        status = XENBUS_EVTCHN(Wait,
                               &Controller->EvtchnInterface,
                               Controller->Channel,
                               Count + 1,
                               &Timeout);
        if (status == STATUS_TIMEOUT)
            __ControllerSend(Controller);
    }

    ASSERT3U(Controller->Response.type, ==, Controller->Request.type);

    switch (Controller->Response.status) {
    case XEN_NETIF_CTRL_STATUS_SUCCESS:
        status = STATUS_SUCCESS;
        break;

    case XEN_NETIF_CTRL_STATUS_NOT_SUPPORTED:
        status = STATUS_NOT_SUPPORTED;
        break;

    case XEN_NETIF_CTRL_STATUS_INVALID_PARAMETER:
        status = STATUS_INVALID_PARAMETER;
        break;

    case XEN_NETIF_CTRL_STATUS_BUFFER_OVERFLOW:
        status = STATUS_BUFFER_OVERFLOW;
        break;

    default:
        status = STATUS_UNSUCCESSFUL;
        break;
    }

    if (NT_SUCCESS(status) && Data != NULL)
        *Data = Controller->Response.data;

    RtlZeroMemory(&Controller->Request,
                  sizeof (struct xen_netif_ctrl_request));
    RtlZeroMemory(&Controller->Response,
                  sizeof (struct xen_netif_ctrl_response));

    return status;
}

KSERVICE_ROUTINE    ControllerEvtchnCallback;

BOOLEAN
ControllerEvtchnCallback(
    IN  PKINTERRUPT             InterruptObject,
    IN  PVOID                   Argument
    )
{
    PXENVIF_CONTROLLER          Controller = Argument;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Controller != NULL);

    Controller->Events++;

    return TRUE;
}

static VOID
ControllerDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Crashing);
}

NTSTATUS
ControllerInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_CONTROLLER  *Controller
    )
{
    LARGE_INTEGER           Now;
    ULONG                   Seed;
    NTSTATUS                status;

    *Controller = __ControllerAllocate(sizeof (XENVIF_CONTROLLER));

    status = STATUS_NO_MEMORY;
    if (*Controller == NULL)
        goto fail1;

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Controller)->DebugInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Controller)->StoreInterface);

    FdoGetGnttabInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Controller)->GnttabInterface);

    FdoGetEvtchnInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Controller)->EvtchnInterface);

    KeInitializeSpinLock(&(*Controller)->Lock);

    KeQuerySystemTime(&Now);
    Seed = Now.LowPart;

    (*Controller)->RequestId = (USHORT)RtlRandomEx(&Seed);

    (*Controller)->Frontend = Frontend;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ControllerConnect(
    IN  PXENVIF_CONTROLLER      Controller
    )
{
    PXENVIF_FRONTEND            Frontend;
    PCHAR                       Buffer;
    BOOLEAN                     Feature;
    PFN_NUMBER                  Pfn;
    CHAR                        Name[MAXNAMELEN];
    ULONG                       Index;
    NTSTATUS                    status;

    Trace("====>\n");

    Frontend = Controller->Frontend;

    status = XENBUS_DEBUG(Acquire, &Controller->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Controller->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_EVTCHN(Acquire, &Controller->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_GNTTAB(Acquire, &Controller->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_STORE(Read,
                          &Controller->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-ctrl-ring",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Feature = FALSE;
    } else {
        Feature = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Controller->StoreInterface,
                     Buffer);
    }

    if (!Feature)
        goto done;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_controller",
                                FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail5;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_GNTTAB(CreateCache,
                           &Controller->GnttabInterface,
                           Name,
                           0,
                           ControllerAcquireLock,
                           ControllerReleaseLock,
                           Controller,
                           &Controller->GnttabCache);
    if (!NT_SUCCESS(status))
        goto fail6;

    Controller->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Controller->Mdl == NULL)
        goto fail7;

    ASSERT(Controller->Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    Controller->Shared = Controller->Mdl->MappedSystemVa;
    ASSERT(Controller->Shared != NULL);

    SHARED_RING_INIT(Controller->Shared);
    FRONT_RING_INIT(&Controller->Front, Controller->Shared, PAGE_SIZE);
    ASSERT3P(Controller->Front.sring, ==, Controller->Shared);

    Pfn = MmGetMdlPfnArray(Controller->Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Controller->GnttabInterface,
                           Controller->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           FALSE,
                           &Controller->Entry);
    if (!NT_SUCCESS(status))
        goto fail8;

    Controller->Channel = XENBUS_EVTCHN(Open,
                                        &Controller->EvtchnInterface,
                                        XENBUS_EVTCHN_TYPE_UNBOUND,
                                        ControllerEvtchnCallback,
                                        Controller,
                                        FrontendGetBackendDomain(Frontend),
                                        FALSE);

    status = STATUS_UNSUCCESSFUL;
    if (Controller->Channel == NULL)
        goto fail9;

    (VOID) XENBUS_EVTCHN(Unmask,
                         &Controller->EvtchnInterface,
                         Controller->Channel,
                         FALSE,
                         TRUE);

    status = XENBUS_DEBUG(Register,
                          &Controller->DebugInterface,
                          __MODULE__ "|CONTROLLER",
                          ControllerDebugCallback,
                          Controller,
                          &Controller->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail10;

    __ControllerAcquireLock(Controller);

    Controller->Connected = TRUE;

    __ControllerReleaseLock(Controller);

done:
    Trace("<====\n");
    return STATUS_SUCCESS;

fail10:
    Error("fail10\n");

    XENBUS_EVTCHN(Close,
                  &Controller->EvtchnInterface,
                  Controller->Channel);
    Controller->Channel = NULL;

    Controller->Events = 0;

fail9:
    Error("fail9\n");

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Controller->Entry);
    Controller->Entry = NULL;

fail8:
    Error("fail8\n");

    RtlZeroMemory(&Controller->Front,
                  sizeof (struct xen_netif_ctrl_front_ring));
    RtlZeroMemory(Controller->Shared, PAGE_SIZE);

    Controller->Shared = NULL;
    __FreePage(Controller->Mdl);
    Controller->Mdl = NULL;

fail7:
    Error("fail7\n");

    XENBUS_GNTTAB(DestroyCache,
                  &Controller->GnttabInterface,
                  Controller->GnttabCache);
    Controller->GnttabCache = NULL;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    XENBUS_GNTTAB(Release, &Controller->GnttabInterface);

fail4:
    Error("fail4\n");

    XENBUS_EVTCHN(Release, &Controller->EvtchnInterface);

fail3:
    Error("fail3\n");

    XENBUS_STORE(Release, &Controller->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Controller->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ControllerStoreWrite(
    IN  PXENVIF_CONTROLLER          Controller,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend;
    ULONG                           Port;
    NTSTATUS                        status;

    if (!Controller->Connected)
        goto done;

    Frontend = Controller->Frontend;

    status = XENBUS_STORE(Printf,
                          &Controller->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "ctrl-ring-ref",
                          "%u",
                          XENBUS_GNTTAB(GetReference,
                                        &Controller->GnttabInterface,
                                        Controller->Entry));
    if (!NT_SUCCESS(status))
        goto fail1;

    Port = XENBUS_EVTCHN(GetPort,
                         &Controller->EvtchnInterface,
                         Controller->Channel);

    status = XENBUS_STORE(Printf,
                          &Controller->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "event-channel-ctrl",
                          "%u",
                          Port);
    if (!NT_SUCCESS(status))
        goto fail2;

done:
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
ControllerEnable(
    IN  PXENVIF_CONTROLLER      Controller
    )
{
    UNREFERENCED_PARAMETER(Controller);

    Trace("<===>\n");
}

VOID
ControllerDisable(
    IN  PXENVIF_CONTROLLER      Controller
    )
{
    UNREFERENCED_PARAMETER(Controller);

    Trace("<===>\n");
}

VOID
ControllerDisconnect(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    Trace("====>\n");

    __ControllerAcquireLock(Controller);

    if (!Controller->Connected) {
        __ControllerReleaseLock(Controller);
        goto done;
    }

    Controller->Connected = FALSE;

    __ControllerReleaseLock(Controller);

    XENBUS_DEBUG(Deregister,
                 &Controller->DebugInterface,
                 Controller->DebugCallback);
    Controller->DebugCallback = NULL;

    XENBUS_EVTCHN(Close,
                  &Controller->EvtchnInterface,
                  Controller->Channel);
    Controller->Channel = NULL;

    Controller->Events = 0;

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Controller->Entry);
    Controller->Entry = NULL;

    RtlZeroMemory(&Controller->Front,
                  sizeof (struct xen_netif_ctrl_front_ring));
    RtlZeroMemory(Controller->Shared, PAGE_SIZE);

    Controller->Shared = NULL;
    __FreePage(Controller->Mdl);
    Controller->Mdl = NULL;

    XENBUS_GNTTAB(DestroyCache,
                  &Controller->GnttabInterface,
                  Controller->GnttabCache);
    Controller->GnttabCache = NULL;

done:
    XENBUS_GNTTAB(Release, &Controller->GnttabInterface);

    XENBUS_EVTCHN(Release, &Controller->EvtchnInterface);

    XENBUS_STORE(Release, &Controller->StoreInterface);

    XENBUS_DEBUG(Release, &Controller->DebugInterface);

    Trace("<====\n");
}

VOID
ControllerTeardown(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Controller->Frontend = NULL;

    Controller->RequestId = 0;

    RtlZeroMemory(&Controller->Lock,
                  sizeof (KSPIN_LOCK));

    RtlZeroMemory(&Controller->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    RtlZeroMemory(&Controller->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Controller->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Controller->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    ASSERT(IsZeroMemory(Controller, sizeof (XENVIF_CONTROLLER)));
    __ControllerFree(Controller);
}

NTSTATUS
ControllerSetHashAlgorithm(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  ULONG               Algorithm
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_ALGORITHM,
                                  Algorithm,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = ControllerGetResponse(Controller, NULL);
    if (!NT_SUCCESS(status))
        goto fail2;

    __ControllerReleaseLock(Controller);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

NTSTATUS
ControllerGetHashFlags(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  PULONG              Flags
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_GET_HASH_FLAGS,
                                  0,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = ControllerGetResponse(Controller, Flags);
    if (!NT_SUCCESS(status))
        goto fail2;

    __ControllerReleaseLock(Controller);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

NTSTATUS
ControllerSetHashFlags(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  ULONG               Flags
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_FLAGS,
                                  Flags,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = ControllerGetResponse(Controller, NULL);
    if (!NT_SUCCESS(status))
        goto fail2;

    __ControllerReleaseLock(Controller);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

NTSTATUS
ControllerSetHashKey(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  PUCHAR              Key,
    IN  ULONG               Size
    )
{
    PXENVIF_FRONTEND        Frontend;
    PMDL                    Mdl;
    PUCHAR                  Buffer;
    PFN_NUMBER              Pfn;
    PXENBUS_GNTTAB_ENTRY    Entry;
    NTSTATUS                status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Mdl == NULL)
        goto fail1;

    ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    Buffer = Mdl->MappedSystemVa;
    ASSERT(Buffer != NULL);

    RtlCopyMemory(Buffer, Key, Size);

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Controller->GnttabInterface,
                           Controller->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           FALSE,
                           &Entry);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_KEY,
                                  XENBUS_GNTTAB(GetReference,
                                                &Controller->GnttabInterface,
                                                Entry),
                                  Size,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ControllerGetResponse(Controller, NULL);
    if (!NT_SUCCESS(status))
        goto fail4;

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Entry);

    __FreePage(Mdl);

    __ControllerReleaseLock(Controller);

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Entry);

fail2:
    Error("fail2\n");

    __FreePage(Mdl);

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

NTSTATUS
ControllerGetHashMappingSize(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  PULONG              Size
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_GET_HASH_MAPPING_SIZE,
                                  0,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = ControllerGetResponse(Controller, Size);
    if (!NT_SUCCESS(status))
        goto fail2;

    __ControllerReleaseLock(Controller);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

NTSTATUS
ControllerSetHashMappingSize(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  ULONG               Size
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_MAPPING_SIZE,
                                  Size,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = ControllerGetResponse(Controller, NULL);
    if (!NT_SUCCESS(status))
        goto fail2;

    __ControllerReleaseLock(Controller);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

NTSTATUS
ControllerSetHashMapping(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  PULONG              Mapping,
    IN  ULONG               Size,
    IN  ULONG               Offset
    )
{
    PXENVIF_FRONTEND        Frontend;
    PMDL                    Mdl;
    PUCHAR                  Buffer;
    PFN_NUMBER              Pfn;
    PXENBUS_GNTTAB_ENTRY    Entry;
    NTSTATUS                status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = STATUS_INVALID_PARAMETER;
    if (Size * sizeof (ULONG) > PAGE_SIZE)
        goto fail1;

    Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Mdl == NULL)
        goto fail2;

    ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    Buffer = Mdl->MappedSystemVa;
    ASSERT(Buffer != NULL);

    RtlCopyMemory(Buffer, Mapping, Size * sizeof (ULONG));

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Controller->GnttabInterface,
                           Controller->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           FALSE,
                           &Entry);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_MAPPING,
                                  XENBUS_GNTTAB(GetReference,
                                                &Controller->GnttabInterface,
                                                Entry),
                                  Size,
                                  Offset);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = ControllerGetResponse(Controller, NULL);
    if (!NT_SUCCESS(status))
        goto fail5;

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Entry);

    __FreePage(Mdl);

    __ControllerReleaseLock(Controller);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Entry);

fail3:
    Error("fail3\n");

    __FreePage(Mdl);

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}
