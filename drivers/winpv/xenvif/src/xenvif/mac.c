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
#include <stdlib.h>
#include <ethernet.h>

#include "pdo.h"
#include "registry.h"
#include "frontend.h"
#include "mac.h"
#include "thread.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

typedef struct _XENVIF_MAC_MULTICAST {
    LIST_ENTRY          ListEntry;
    ETHERNET_ADDRESS    Address;
} XENVIF_MAC_MULTICAST, *PXENVIF_MAC_MULTICAST;

struct _XENVIF_MAC {
    PXENVIF_FRONTEND        Frontend;
    EX_SPIN_LOCK            Lock;
    BOOLEAN                 Connected;
    BOOLEAN                 Enabled;
    ULONG                   Speed;
    ULONG                   MaximumFrameSize;
    ETHERNET_ADDRESS        PermanentAddress;
    ETHERNET_ADDRESS        CurrentAddress;
    ETHERNET_ADDRESS        BroadcastAddress;
    LIST_ENTRY              MulticastList;
    ULONG                   MulticastCount;
    XENVIF_MAC_FILTER_LEVEL FilterLevel[ETHERNET_ADDRESS_TYPE_COUNT];
    XENBUS_DEBUG_INTERFACE  DebugInterface;
    PXENBUS_DEBUG_CALLBACK  DebugCallback;
    XENBUS_STORE_INTERFACE  StoreInterface;
    PXENBUS_STORE_WATCH     DisconnectWatch;
    PXENBUS_STORE_WATCH     SpeedWatch;
};

#define XENVIF_MAC_TAG  'CAM'

static FORCEINLINE PVOID
__MacAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENVIF_MAC_TAG);
}

static FORCEINLINE VOID
__MacFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_MAC_TAG);
}

static FORCEINLINE NTSTATUS
__MacSetPermanentAddress(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Mac->Frontend;

    status = STATUS_INVALID_PARAMETER;
    if (Address->Byte[0] & 0x01)
        goto fail1;

    Mac->PermanentAddress = *Address;

    Info("%s: %02X:%02X:%02X:%02X:%02X:%02X\n",
         FrontendGetPrefix(Frontend),
         Mac->PermanentAddress.Byte[0],
         Mac->PermanentAddress.Byte[1],
         Mac->PermanentAddress.Byte[2],
         Mac->PermanentAddress.Byte[3],
         Mac->PermanentAddress.Byte[4],
         Mac->PermanentAddress.Byte[5]);

    return STATUS_SUCCESS;

fail1:
    return status;
}

VOID
MacQueryPermanentAddress(
    IN  PXENVIF_MAC         Mac,
    OUT PETHERNET_ADDRESS   Address
    )
{
    *Address = Mac->PermanentAddress;
}

static FORCEINLINE NTSTATUS
__MacSetCurrentAddress(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Mac->Frontend;

    status = STATUS_INVALID_PARAMETER;
    if (Address->Byte[0] & 0x01)
        goto fail1;

    Mac->CurrentAddress = *Address;

    Info("%s: %02X:%02X:%02X:%02X:%02X:%02X\n",
         FrontendGetPrefix(Frontend),
         Mac->CurrentAddress.Byte[0],
         Mac->CurrentAddress.Byte[1],
         Mac->CurrentAddress.Byte[2],
         Mac->CurrentAddress.Byte[3],
         Mac->CurrentAddress.Byte[4],
         Mac->CurrentAddress.Byte[5]);

    return STATUS_SUCCESS;

fail1:
    return status;
}

VOID
MacQueryCurrentAddress(
    IN  PXENVIF_MAC         Mac,
    OUT PETHERNET_ADDRESS   Address
    )
{
    *Address = Mac->CurrentAddress;
}

static VOID
MacDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_MAC         Mac = Argument;
    PXENVIF_FRONTEND    Frontend;

    UNREFERENCED_PARAMETER(Crashing);

    Frontend = Mac->Frontend;

    XENBUS_DEBUG(Printf,
                 &Mac->DebugInterface,
                 "FilterLevel[ETHERNET_ADDRESS_UNICAST] = %s\n",
                 (Mac->FilterLevel[ETHERNET_ADDRESS_UNICAST] == XENVIF_MAC_FILTER_ALL) ? "All" :
                 (Mac->FilterLevel[ETHERNET_ADDRESS_UNICAST] == XENVIF_MAC_FILTER_MATCHING) ? "Matching" :
                 "None");

    XENBUS_DEBUG(Printf,
                 &Mac->DebugInterface,
                 "FilterLevel[ETHERNET_ADDRESS_MULTICAST] = %s\n",
                 (Mac->FilterLevel[ETHERNET_ADDRESS_MULTICAST] == XENVIF_MAC_FILTER_ALL) ? "All" :
                 (Mac->FilterLevel[ETHERNET_ADDRESS_MULTICAST] == XENVIF_MAC_FILTER_MATCHING) ? "Matching" :
                 "None");

    XENBUS_DEBUG(Printf,
                 &Mac->DebugInterface,
                 "FilterLevel[ETHERNET_ADDRESS_BROADCAST] = %s\n",
                 (Mac->FilterLevel[ETHERNET_ADDRESS_BROADCAST] == XENVIF_MAC_FILTER_ALL) ? "All" :
                 (Mac->FilterLevel[ETHERNET_ADDRESS_BROADCAST] == XENVIF_MAC_FILTER_MATCHING) ? "Matching" :
                 "None");
}

NTSTATUS
MacInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_MAC         *Mac
    )
{
    HANDLE                  ParametersKey;
    ULONG                   MacSpeed;
    NTSTATUS                status;

    *Mac = __MacAllocate(sizeof (XENVIF_MAC));

    status = STATUS_NO_MEMORY;
    if (*Mac == NULL)
        goto fail1;

    ParametersKey = DriverGetParametersKey();

    (*Mac)->Speed = 100;

    if (ParametersKey != NULL) {
        status = RegistryQueryDwordValue(ParametersKey,
                                         "MacSpeed",
                                        &MacSpeed);
        if (NT_SUCCESS(status))
            (*Mac)->Speed = MacSpeed;
    }

    InitializeListHead(&(*Mac)->MulticastList);

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Mac)->DebugInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Mac)->StoreInterface);

    (*Mac)->Frontend = Frontend;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n");

    return status;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__MacAcquireLockExclusive(
    IN  PXENVIF_MAC     Mac
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    ExAcquireSpinLockExclusiveAtDpcLevel(&Mac->Lock);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__MacReleaseLockExclusive(
    IN  PXENVIF_MAC     Mac
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

#pragma prefast(disable:26110)
    ExReleaseSpinLockExclusiveFromDpcLevel(&Mac->Lock);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__MacAcquireLockShared(
    IN  PXENVIF_MAC     Mac
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    ExAcquireSpinLockSharedAtDpcLevel(&Mac->Lock);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__MacReleaseLockShared(
    IN  PXENVIF_MAC     Mac
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

#pragma prefast(disable:26110)
    ExReleaseSpinLockSharedFromDpcLevel(&Mac->Lock);
}

static NTSTATUS
MacDumpAddressTable(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    PETHERNET_ADDRESS   Address;
    ULONG               Count;
    PLIST_ENTRY         ListEntry;
    ULONG               Index;
    KIRQL               Irql;
    NTSTATUS            status;

    Trace("====>\n");

    Frontend = Mac->Frontend;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __MacAcquireLockShared(Mac);

    status  = STATUS_UNSUCCESSFUL;
    if (!Mac->Connected)
        goto fail1;

    Count = 1 + Mac->MulticastCount;

    Address = __MacAllocate(sizeof (ETHERNET_ADDRESS) *
                            Count);

    status = STATUS_NO_MEMORY;
    if (Address == NULL)
        goto fail2;

    Index = 0;

    MacQueryCurrentAddress(Mac, &Address[Index]);
    Index++;

    for (ListEntry = Mac->MulticastList.Flink;
         ListEntry != &Mac->MulticastList;
         ListEntry = ListEntry->Flink) {
        PXENVIF_MAC_MULTICAST   Multicast;

        Multicast = CONTAINING_RECORD(ListEntry,
                                      XENVIF_MAC_MULTICAST,
                                      ListEntry);

        Address[Index++] = Multicast->Address;
    }

    ASSERT3U(Index, ==, Count);

    __MacReleaseLockShared(Mac);
    KeLowerIrql(Irql);

    (VOID) XENBUS_STORE(Remove,
                        &Mac->StoreInterface,
                        NULL,
                        FrontendGetPrefix(Frontend),
                        "mac");

    for (Index = 0; Index < Count; Index++) {
        CHAR    Node[sizeof ("mac/XX")];

        status = RtlStringCbPrintfA(Node,
                                    sizeof (Node),
                                    "mac/%u",
                                    Index);
        ASSERT(NT_SUCCESS(status));

        (VOID) XENBUS_STORE(Printf,
                            &Mac->StoreInterface,
                            NULL,
                            FrontendGetPrefix(Frontend),
                            Node,
                            "%02x:%02x:%02x:%02x:%02x:%02x",
                            Address[Index].Byte[0],
                            Address[Index].Byte[1],
                            Address[Index].Byte[2],
                            Address[Index].Byte[3],
                            Address[Index].Byte[4],
                            Address[Index].Byte[5]);
    }

    if (Address != NULL)
        __MacFree(Address);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    __MacReleaseLockExclusive(Mac);
    KeLowerIrql(Irql);

    return status;
}

NTSTATUS
MacConnect(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    PETHERNET_ADDRESS   Address;
    PCHAR               Buffer;
    ULONG64             Mtu;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Frontend = Mac->Frontend;

    status = XENBUS_DEBUG(Acquire, &Mac->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Mac->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    Address = PdoGetPermanentAddress(FrontendGetPdo(Frontend));

    status = __MacSetPermanentAddress(Mac, Address);
    if (!NT_SUCCESS(status))
        goto fail3;

    Address = PdoGetCurrentAddress(FrontendGetPdo(Frontend));

    status = __MacSetCurrentAddress(Mac, Address);
    if (!NT_SUCCESS(status))
        __MacSetCurrentAddress(Mac, &Mac->PermanentAddress);

    RtlFillMemory(Mac->BroadcastAddress.Byte, ETHERNET_ADDRESS_LENGTH, 0xFF);

    status = XENBUS_STORE(Read,
                          &Mac->StoreInterface,
                          NULL,
                          FrontendGetPath(Frontend),
                          "mtu",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Mtu = ETHERNET_MTU;
    } else {
        Mtu = strtol(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Mac->StoreInterface,
                     Buffer);
    }

    status = STATUS_INVALID_PARAMETER;
    if (Mtu < ETHERNET_MIN)
        goto fail4;

    Mac->MaximumFrameSize = (ULONG)Mtu + sizeof (ETHERNET_TAGGED_HEADER);

    status = XENBUS_DEBUG(Register,
                          &Mac->DebugInterface,
                          __MODULE__ "|MAC",
                          MacDebugCallback,
                          Mac,
                          &Mac->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail5;

    __MacAcquireLockExclusive(Mac);

    ASSERT(!Mac->Connected);
    Mac->Connected = TRUE;

    __MacReleaseLockExclusive(Mac);

    (VOID) MacDumpAddressTable(Mac);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    Mac->MaximumFrameSize = 0;

fail4:
    Error("fail4\n");

    RtlZeroMemory(&Mac->BroadcastAddress, sizeof (ETHERNET_ADDRESS));
    RtlZeroMemory(&Mac->CurrentAddress, sizeof (ETHERNET_ADDRESS));
    RtlZeroMemory(&Mac->PermanentAddress, sizeof (ETHERNET_ADDRESS));

    (VOID) XENBUS_STORE(Remove,
                        &Mac->StoreInterface,
                        NULL,
                        FrontendGetPrefix(Frontend),
                        "mac");

fail3:
    Error("fail3\n");

    XENBUS_STORE(Release, &Mac->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Mac->DebugInterface);

fail1:
    Error("fail1 (%08x)\n");

    return status;
}

NTSTATUS
MacEnable(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    PXENVIF_THREAD      Thread;
    NTSTATUS            status;

    Trace("====>\n");

    Frontend = Mac->Frontend;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    __MacAcquireLockExclusive(Mac);

    Thread = VifGetMacThread(PdoGetVifContext(FrontendGetPdo(Frontend)));

    status = XENBUS_STORE(WatchAdd,
                          &Mac->StoreInterface,
                          FrontendGetPath(Frontend),
                          "disconnect",
                          ThreadGetEvent(Thread),
                          &Mac->DisconnectWatch);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(WatchAdd,
                          &Mac->StoreInterface,
                          FrontendGetPath(Frontend),
                          "speed",
                          ThreadGetEvent(Thread),
                          &Mac->SpeedWatch);
    if (!NT_SUCCESS(status))
        goto fail2;

    ASSERT(!Mac->Enabled);
    Mac->Enabled = TRUE;

    __MacReleaseLockExclusive(Mac);

    Trace("<====\n");
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    (VOID) XENBUS_STORE(WatchRemove,
                        &Mac->StoreInterface,
                        Mac->DisconnectWatch);
    Mac->DisconnectWatch = NULL;

fail1:
    Error("fail1 (%08x)\n");

    __MacReleaseLockExclusive(Mac);

    return status;
}

VOID
MacDisable(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;

    Trace("====>\n");

    Frontend = Mac->Frontend;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    __MacAcquireLockExclusive(Mac);

    ASSERT(Mac->Enabled);
    Mac->Enabled = FALSE;

    (VOID) XENBUS_STORE(WatchRemove,
                        &Mac->StoreInterface,
                        Mac->SpeedWatch);
    Mac->SpeedWatch = NULL;

    (VOID) XENBUS_STORE(WatchRemove,
                        &Mac->StoreInterface,
                        Mac->DisconnectWatch);
    Mac->DisconnectWatch = NULL;

    __MacReleaseLockExclusive(Mac);

    Trace("<====\n");
}

VOID
MacDisconnect(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;

    Frontend = Mac->Frontend;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    __MacAcquireLockExclusive(Mac);

    ASSERT(Mac->Connected);
    Mac->Connected = FALSE;

    __MacReleaseLockExclusive(Mac);

    XENBUS_DEBUG(Deregister,
                 &Mac->DebugInterface,
                 Mac->DebugCallback);
    Mac->DebugCallback = NULL;

    Mac->MaximumFrameSize = 0;

    RtlZeroMemory(&Mac->BroadcastAddress, sizeof (ETHERNET_ADDRESS));
    RtlZeroMemory(&Mac->CurrentAddress, sizeof (ETHERNET_ADDRESS));
    RtlZeroMemory(&Mac->PermanentAddress, sizeof (ETHERNET_ADDRESS));

    (VOID) XENBUS_STORE(Remove,
                        &Mac->StoreInterface,
                        NULL,
                        FrontendGetPrefix(Frontend),
                        "mac");

    XENBUS_STORE(Release, &Mac->StoreInterface);

    XENBUS_DEBUG(Release, &Mac->DebugInterface);
}

VOID
MacTeardown(
    IN  PXENVIF_MAC Mac
    )
{
    while (!IsListEmpty(&Mac->MulticastList)) {
        PLIST_ENTRY             ListEntry;
        PXENVIF_MAC_MULTICAST   Multicast;

        ListEntry = RemoveHeadList(&Mac->MulticastList);
        ASSERT3P(ListEntry, !=, &Mac->MulticastList);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Multicast = CONTAINING_RECORD(ListEntry,
                                      XENVIF_MAC_MULTICAST,
                                      ListEntry);
        __MacFree(Multicast);

        --Mac->MulticastCount;
    }
    ASSERT3U(Mac->MulticastCount, ==, 0);

    RtlZeroMemory(&Mac->MulticastList, sizeof (LIST_ENTRY));

    RtlZeroMemory(&Mac->FilterLevel,
                  ETHERNET_ADDRESS_TYPE_COUNT * sizeof (XENVIF_MAC_FILTER_LEVEL));

    Mac->Frontend = NULL;

    RtlZeroMemory(&Mac->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Mac->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    Mac->Lock = 0;

    Mac->Speed = 0;

    ASSERT(IsZeroMemory(Mac, sizeof (XENVIF_MAC)));
    __MacFree(Mac);
}

static FORCEINLINE ULONG64
__MacGetSpeed(
    IN  PXENVIF_MAC Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    PCHAR               Buffer;
    ULONG64             Speed;
    PCHAR               Unit;
    NTSTATUS            status;

    Frontend = Mac->Frontend;

    status = XENBUS_STORE(Read,
                          &Mac->StoreInterface,
                          NULL,
                          FrontendGetPath(Mac->Frontend),
                          "speed",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Speed = Mac->Speed;
        Unit = "G";
    } else {
        Speed = _strtoui64(Buffer, &Unit, 10);
        if (*Unit == '\0')
            Unit = "G";

        XENBUS_STORE(Free,
                     &Mac->StoreInterface,
                     Buffer);
    }

    if (*(Unit + 1) != '\0') {
        Warning("INVALID SPEED: %s\n", Buffer);
        return 0;
    }

    switch (*Unit) {
    case 'g':
    case 'G':
        Speed *= 1000000000ull;
        break;

    case 'm':
    case 'M':
        Speed *= 1000000ull;
        break;

    case 'k':
    case 'K':
        Speed *= 1000ull;
        break;

    default:
        Warning("INVALID SPEED UNIT: %c\n", *Unit);
        return 0;
    }

    return Speed;
}

static FORCEINLINE BOOLEAN
__MacGetDisconnect(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    PCHAR               Buffer;
    BOOLEAN             Disconnect;
    NTSTATUS            status;

    Frontend = Mac->Frontend;

    status = XENBUS_STORE(Read,
                          &Mac->StoreInterface,
                          NULL,
                          FrontendGetPath(Mac->Frontend),
                          "disconnect",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Disconnect = FALSE;
    } else {
        Disconnect = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Mac->StoreInterface,
                     Buffer);
    }

    return Disconnect;
}

VOID
MacQueryState(
    IN  PXENVIF_MAC                 Mac,
    OUT PNET_IF_MEDIA_CONNECT_STATE MediaConnectState OPTIONAL,
    OUT PULONG64                    LinkSpeed OPTIONAL,
    OUT PNET_IF_MEDIA_DUPLEX_STATE  MediaDuplexState OPTIONAL
    )
{
    ULONG64 Speed = __MacGetSpeed(Mac);
    BOOLEAN Disconnect = __MacGetDisconnect(Mac);

    if (Speed == 0)
        Disconnect = TRUE;

    if (MediaConnectState != NULL || MediaDuplexState != NULL) {
        if (MediaConnectState != NULL)
            *MediaConnectState = (Disconnect) ?
                                 MediaConnectStateDisconnected :
                                 MediaConnectStateConnected;

        if (MediaDuplexState != NULL)
            *MediaDuplexState = (Disconnect) ?
                                MediaDuplexStateUnknown :
                                MediaDuplexStateFull;
    }

    if (LinkSpeed != NULL)
        *LinkSpeed = Speed;
}

VOID
MacQueryMaximumFrameSize(
    IN  PXENVIF_MAC Mac,
    OUT PULONG      Size                     
    )
{
    *Size = Mac->MaximumFrameSize;
}

NTSTATUS
MacAddMulticastAddress(
    IN      PXENVIF_MAC         Mac,
    IN      PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_MAC_MULTICAST       Multicast;
    KIRQL                       Irql;
    NTSTATUS                    status;

    Frontend = Mac->Frontend;

    ASSERT(Address->Byte[0] & 0x01);

    Multicast = __MacAllocate(sizeof (XENVIF_MAC_MULTICAST));

    status = STATUS_NO_MEMORY;
    if (Multicast == NULL)
        goto fail1;

    Multicast->Address = *Address;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __MacAcquireLockExclusive(Mac);

    InsertTailList(&Mac->MulticastList, &Multicast->ListEntry);
    Mac->MulticastCount++;

    __MacReleaseLockExclusive(Mac);
    KeLowerIrql(Irql);

    (VOID) MacDumpAddressTable(Mac);

    Trace("%s: %02X:%02X:%02X:%02X:%02X:%02X\n",
          FrontendGetPrefix(Frontend),
          Address->Byte[0],
          Address->Byte[1],
          Address->Byte[2],
          Address->Byte[3],
          Address->Byte[4],
          Address->Byte[5]);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
MacRemoveMulticastAddress(
    IN      PXENVIF_MAC         Mac,
    IN      PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND            Frontend;
    PLIST_ENTRY                 ListEntry;
    PXENVIF_MAC_MULTICAST       Multicast;
    KIRQL                       Irql;
    NTSTATUS                    status;

    Frontend = Mac->Frontend;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __MacAcquireLockExclusive(Mac);

    for (ListEntry = Mac->MulticastList.Flink;
         ListEntry != &Mac->MulticastList;
         ListEntry = ListEntry->Flink) {
        Multicast = CONTAINING_RECORD(ListEntry,
                                      XENVIF_MAC_MULTICAST,
                                      ListEntry);

        if (RtlEqualMemory(&Multicast->Address,
                           Address,
                           ETHERNET_ADDRESS_LENGTH))
            goto found;
    }

    status = STATUS_OBJECT_NAME_NOT_FOUND;
    goto fail1;

found:
    ASSERT(Mac->MulticastCount != 0);
    --Mac->MulticastCount;

    RemoveEntryList(&Multicast->ListEntry);
    __MacFree(Multicast);

    __MacReleaseLockExclusive(Mac);
    KeLowerIrql(Irql);

    (VOID) MacDumpAddressTable(Mac);

    Trace("%s: %02X:%02X:%02X:%02X:%02X:%02X\n",
          FrontendGetPrefix(Frontend),
          Address->Byte[0],
          Address->Byte[1],
          Address->Byte[2],
          Address->Byte[3],
          Address->Byte[4],
          Address->Byte[5]);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    __MacReleaseLockExclusive(Mac);
    KeLowerIrql(Irql);

    return status;
}

NTSTATUS
MacQueryMulticastAddresses(
    IN      PXENVIF_MAC         Mac,
    IN      PETHERNET_ADDRESS   Address OPTIONAL,
    IN OUT  PULONG              Count
    )
{
    PLIST_ENTRY                 ListEntry;
    KIRQL                       Irql;
    NTSTATUS                    status;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __MacAcquireLockShared(Mac);

    status = STATUS_BUFFER_OVERFLOW;
    if (Address == NULL || *Count < Mac->MulticastCount)
        goto fail1;

    *Count = 0;
    for (ListEntry = Mac->MulticastList.Flink;
         ListEntry != &Mac->MulticastList;
         ListEntry = ListEntry->Flink) {
        PXENVIF_MAC_MULTICAST   Multicast;

        Multicast = CONTAINING_RECORD(ListEntry,
                                      XENVIF_MAC_MULTICAST,
                                      ListEntry);

        Address[(*Count)++] = Multicast->Address;
    }
    ASSERT3U(*Count, ==, Mac->MulticastCount);

    __MacReleaseLockShared(Mac);
    KeLowerIrql(Irql);

    return STATUS_SUCCESS;

fail1:
    *Count = Mac->MulticastCount;

    __MacReleaseLockExclusive(Mac);
    KeLowerIrql(Irql);

    return status;
}

VOID
MacQueryBroadcastAddress(
    IN  PXENVIF_MAC         Mac,
    OUT PETHERNET_ADDRESS   Address
    )
{
    *Address = Mac->BroadcastAddress;
}

NTSTATUS
MacSetFilterLevel(
    IN  PXENVIF_MAC             Mac,
    IN  ETHERNET_ADDRESS_TYPE   Type,
    IN  XENVIF_MAC_FILTER_LEVEL Level
    )
{
    KIRQL                       Irql;
    NTSTATUS                    status;

    status = STATUS_INVALID_PARAMETER;
    if (Type >= ETHERNET_ADDRESS_TYPE_COUNT)
        goto fail1;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __MacAcquireLockExclusive(Mac);

    status = STATUS_INVALID_PARAMETER;
    if (Level > XENVIF_MAC_FILTER_ALL || Level < XENVIF_MAC_FILTER_NONE)
        goto fail2;

    Mac->FilterLevel[Type] = Level;

    __MacReleaseLockExclusive(Mac);
    KeLowerIrql(Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __MacReleaseLockExclusive(Mac);
    KeLowerIrql(Irql);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
MacQueryFilterLevel(
    IN  PXENVIF_MAC                 Mac,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    OUT PXENVIF_MAC_FILTER_LEVEL    Level
    )
{
    KIRQL                           Irql;
    NTSTATUS                        status;

    status = STATUS_INVALID_PARAMETER;
    if (Type >= ETHERNET_ADDRESS_TYPE_COUNT)
        goto fail1;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __MacAcquireLockShared(Mac);

    *Level = Mac->FilterLevel[Type];

    __MacReleaseLockShared(Mac);
    KeLowerIrql(Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

BOOLEAN
MacApplyFilters(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   DestinationAddress
    )
{
    ETHERNET_ADDRESS_TYPE   Type;
    BOOLEAN                 Allow;
    KIRQL                   Irql;

    Type = GET_ETHERNET_ADDRESS_TYPE(DestinationAddress);
    Allow = FALSE;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __MacAcquireLockShared(Mac);

    switch (Type) {
    case ETHERNET_ADDRESS_UNICAST:
        switch (Mac->FilterLevel[ETHERNET_ADDRESS_UNICAST]) {
        case XENVIF_MAC_FILTER_NONE:
            break;

        case XENVIF_MAC_FILTER_MATCHING:
            if (RtlEqualMemory(&Mac->CurrentAddress,
                               DestinationAddress,
                               ETHERNET_ADDRESS_LENGTH))
                Allow = TRUE;

            break;

        case XENVIF_MAC_FILTER_ALL:
            Allow = TRUE;
            break;

        default:
            ASSERT(FALSE);
            break;
        }
        break;

    case ETHERNET_ADDRESS_MULTICAST:
        switch (Mac->FilterLevel[ETHERNET_ADDRESS_MULTICAST]) {
        case XENVIF_MAC_FILTER_NONE:
            break;

        case XENVIF_MAC_FILTER_MATCHING: {
            PXENVIF_FRONTEND    Frontend;
            PXENVIF_TRANSMITTER Transmitter;
            PLIST_ENTRY         ListEntry;

            Frontend = Mac->Frontend;
            Transmitter = FrontendGetTransmitter(Frontend);

            if (TransmitterHasMulticastControl(Transmitter)) {
                Allow = TRUE;
                break;
            }

            for (ListEntry = Mac->MulticastList.Flink;
                 ListEntry != &Mac->MulticastList;
                 ListEntry = ListEntry->Flink) {
                PXENVIF_MAC_MULTICAST   Multicast;

                Multicast = CONTAINING_RECORD(ListEntry,
                                              XENVIF_MAC_MULTICAST,
                                              ListEntry);

                if (RtlEqualMemory(&Multicast->Address,
                                   DestinationAddress,
                                   ETHERNET_ADDRESS_LENGTH)) {
                    Allow = TRUE;
                    break;
                }
            }

            break;
        }
        case XENVIF_MAC_FILTER_ALL:
            Allow = TRUE;
            break;

        default:
            ASSERT(FALSE);
            break;
        }
        break;

    case ETHERNET_ADDRESS_BROADCAST:
        switch (Mac->FilterLevel[ETHERNET_ADDRESS_BROADCAST]) {
        case XENVIF_MAC_FILTER_NONE:
            break;

        case XENVIF_MAC_FILTER_MATCHING:
        case XENVIF_MAC_FILTER_ALL:
            Allow = TRUE;
            break;

        default:
            ASSERT(FALSE);
            break;
        }
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    __MacReleaseLockShared(Mac);
    KeLowerIrql(Irql);

    return Allow;
}
