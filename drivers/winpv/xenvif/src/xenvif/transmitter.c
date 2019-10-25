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
#include <stdlib.h>
#include <netioapi.h>
#include <xen.h>
#include <ethernet.h>
#include <tcpip.h>

#include <debug_interface.h>
#include <store_interface.h>
#include <cache_interface.h>
#include <gnttab_interface.h>
#include <range_set_interface.h>
#include <evtchn_interface.h>

#include "pdo.h"
#include "frontend.h"
#include "checksum.h"
#include "parse.h"
#include "transmitter.h"
#include "mac.h"
#include "vif.h"
#include "thread.h"
#include "registry.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#ifndef XEN_NETIF_GSO_TYPE_TCPV6
#define XEN_NETIF_GSO_TYPE_TCPV6    2
#endif

#define MAXNAMELEN  128

#define XENVIF_TRANSMITTER_MAXIMUM_HEADER_LENGTH    512

typedef struct _XENVIF_TRANSMITTER_PACKET {
    LIST_ENTRY                                  ListEntry;
    PVOID                                       Cookie;
    ULONG                                       Reference;
    XENVIF_VIF_OFFLOAD_OPTIONS                  OffloadOptions;
    USHORT                                      MaximumSegmentSize;
    USHORT                                      TagControlInformation;
    PMDL                                        Mdl;
    ULONG                                       Offset;
    ULONG                                       Length;
    PUCHAR                                      Header;
    XENVIF_PACKET_HASH                          Hash;
    XENVIF_PACKET_INFO                          Info;
    XENVIF_PACKET_PAYLOAD                       Payload;
    XENVIF_PACKET_CHECKSUM_FLAGS                Flags;
    XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO   Completion;
} XENVIF_TRANSMITTER_PACKET, *PXENVIF_TRANSMITTER_PACKET;

typedef struct _XENVIF_TRANSMITTER_REQUEST_ARP_PARAMETERS {
    IPV4_ADDRESS    Address;
} XENVIF_TRANSMITTER_REQUEST_ARP_PARAMETERS, *PXENVIF_TRANSMITTER_REQUEST_ARP_PARAMETERS;

typedef struct _XENVIF_TRANSMITTER_REQUEST_NEIGHBOUR_ADVERTISEMENT_PARAMETERS {
    IPV6_ADDRESS    Address;
} XENVIF_TRANSMITTER_REQUEST_NEIGHBOUR_ADVERTISEMENT_PARAMETERS, *PXENVIF_TRANSMITTER_REQUEST_NEIGHBOUR_ADVERTISEMENT_PARAMETERS;

typedef struct _XENVIF_TRANSMITTER_REQUEST_MULTICAST_CONTROL_PARAMETERS {
    ETHERNET_ADDRESS    Address;
    BOOLEAN             Add;
} XENVIF_TRANSMITTER_REQUEST_MULTICAST_CONTROL_PARAMETERS, *PXENVIF_TRANSMITTER_REQUEST_MULTICAST_CONTROL_PARAMETERS;

typedef enum _XENVIF_TRANSMITTER_REQUEST_TYPE {
    XENVIF_TRANSMITTER_REQUEST_TYPE_INVALID = 0,
    XENVIF_TRANSMITTER_REQUEST_TYPE_ARP,
    XENVIF_TRANSMITTER_REQUEST_TYPE_NEIGHBOUR_ADVERTISEMENT,
    XENVIF_TRANSMITTER_REQUEST_TYPE_MULTICAST_CONTROL
} XENVIF_TRANSMITTER_REQUEST_TYPE, *PXENVIF_TRANSMITTER_REQUEST_TYPE;

#pragma warning(push)
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

typedef struct _XENVIF_TRANSMITTER_REQUEST {
    LIST_ENTRY                      ListEntry;
    XENVIF_TRANSMITTER_REQUEST_TYPE Type;
    union {
        XENVIF_TRANSMITTER_REQUEST_ARP_PARAMETERS                       Arp;
        XENVIF_TRANSMITTER_REQUEST_NEIGHBOUR_ADVERTISEMENT_PARAMETERS   NeighbourAdvertisement;
        XENVIF_TRANSMITTER_REQUEST_MULTICAST_CONTROL_PARAMETERS         MulticastControl;
    };
} XENVIF_TRANSMITTER_REQUEST, *PXENVIF_TRANSMITTER_REQUEST;

#pragma warning(pop)

typedef struct _XENVIF_TRANSMITTER_BUFFER {
    PMDL        Mdl;
    PVOID       Context;
    ULONG       Reference;
} XENVIF_TRANSMITTER_BUFFER, *PXENVIF_TRANSMITTER_BUFFER;

typedef enum _XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE {
    XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_INVALID = 0,
    XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_ADD,
    XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_REMOVE
} XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE, *PXENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE;

typedef struct _XENVIF_TRANSMITTER_MULTICAST_CONTROL {
    XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE   Type;
    ETHERNET_ADDRESS                            Address;
    ULONG                                       Reference;
} XENVIF_TRANSMITTER_MULTICAST_CONTROL, *PXENVIF_TRANSMITTER_MULTICAST_CONTROL;

typedef enum _XENVIF_TRANSMITTER_FRAGMENT_TYPE {
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID = 0,
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET,
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER,
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_MULTICAST_CONTROL
} XENVIF_TRANSMITTER_FRAGMENT_TYPE, *PXENVIF_TRANSMITTER_FRAGMENT_TYPE;

typedef struct _XENVIF_TRANSMITTER_FRAGMENT {
    LIST_ENTRY                          ListEntry;
    USHORT                              Id;
    XENVIF_TRANSMITTER_FRAGMENT_TYPE    Type;
    PVOID                               Context;
    PXENBUS_GNTTAB_ENTRY                Entry;
    ULONG                               Offset;
    ULONG                               Length;
    ULONG                               Extra;
} XENVIF_TRANSMITTER_FRAGMENT, *PXENVIF_TRANSMITTER_FRAGMENT;

#define XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID  0x03FF

typedef struct _XENVIF_TRANSMITTER_STATE {
    PXENVIF_TRANSMITTER_PACKET          Packet;
    LIST_ENTRY                          List;
    ULONG                               Count;
} XENVIF_TRANSMITTER_STATE, *PXENVIF_TRANSMITTER_STATE;

#define XENVIF_TRANSMITTER_RING_SIZE   (__CONST_RING_SIZE(netif_tx, PAGE_SIZE))

typedef struct _XENVIF_TRANSMITTER_RING {
    PXENVIF_TRANSMITTER             Transmitter;
    ULONG                           Index;
    PCHAR                           Path;
    PXENBUS_CACHE                   BufferCache;
    PXENBUS_CACHE                   MulticastControlCache;
    PXENBUS_CACHE                   FragmentCache;
    PXENBUS_GNTTAB_CACHE            GnttabCache;
    PXENBUS_RANGE_SET               RangeSet;
    PXENBUS_CACHE                   RequestCache;
    PMDL                            Mdl;
    netif_tx_front_ring_t           Front;
    netif_tx_sring_t                *Shared;
    PXENBUS_GNTTAB_ENTRY            Entry;
    PXENBUS_EVTCHN_CHANNEL          Channel;
    KDPC                            PollDpc;
    ULONG                           PollDpcs;
    ULONG                           Events;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;
    BOOLEAN                         Stopped;
    PVOID                           Lock;
    PKTHREAD                        LockThread;
    LIST_ENTRY                      PacketQueue;
    LIST_ENTRY                      RequestQueue;
    XENVIF_TRANSMITTER_STATE        State;
    ULONG                           PacketsQueued;
    ULONG                           PacketsGranted;
    ULONG                           PacketsCopied;
    ULONG                           PacketsFaked;
    ULONG                           PacketsUnprepared;
    ULONG                           PacketsPrepared;
    PXENVIF_TRANSMITTER_FRAGMENT    Pending[XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID + 1];
    ULONG                           RequestsPosted;
    ULONG                           RequestsPushed;
    ULONG                           ResponsesProcessed;
    ULONG                           PacketsSent;
    LIST_ENTRY                      PacketComplete;
    ULONG                           PacketsCompleted;
    PXENBUS_DEBUG_CALLBACK          DebugCallback;
    PXENVIF_THREAD                  WatchdogThread;
} XENVIF_TRANSMITTER_RING, *PXENVIF_TRANSMITTER_RING;

struct _XENVIF_TRANSMITTER {
    PXENVIF_FRONTEND            Frontend;
    XENBUS_CACHE_INTERFACE      CacheInterface;
    XENBUS_GNTTAB_INTERFACE     GnttabInterface;
    XENBUS_RANGE_SET_INTERFACE  RangeSetInterface;
    XENBUS_EVTCHN_INTERFACE     EvtchnInterface;
    PXENVIF_TRANSMITTER_RING    *Ring;
    BOOLEAN                     MulticastControl;
    ULONG                       DisableIpVersion4Gso;
    ULONG                       DisableIpVersion6Gso;
    ULONG                       AlwaysCopy;
    ULONG                       ValidateChecksums;
    ULONG                       DisableMulticastControl;
    KSPIN_LOCK                  Lock;
    PXENBUS_CACHE               PacketCache;
    XENBUS_STORE_INTERFACE      StoreInterface;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
};

#define XENVIF_TRANSMITTER_TAG  'NART'
#define XENVIF_PACKET_CACHE_RESERVATION 32

static FORCEINLINE PVOID
__TransmitterAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENVIF_TRANSMITTER_TAG);
}

static FORCEINLINE VOID
__TransmitterFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_TRANSMITTER_TAG);
}

static VOID
TransmitterPacketAcquireLock(
    IN  PVOID           Argument
    )
{
    PXENVIF_TRANSMITTER Transmitter = Argument;

    KeAcquireSpinLockAtDpcLevel(&Transmitter->Lock);
}

static VOID
TransmitterPacketReleaseLock(
    IN  PVOID           Argument
    )
{
    PXENVIF_TRANSMITTER Transmitter = Argument;

#pragma prefast(suppress:26110)
    KeReleaseSpinLockFromDpcLevel(&Transmitter->Lock);
}

static NTSTATUS
TransmitterPacketCtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_TRANSMITTER_PACKET  Packet = Object;
    PUCHAR                      Header;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(Argument);

    ASSERT(IsZeroMemory(Packet, sizeof (XENVIF_TRANSMITTER_PACKET)));

    Header = __TransmitterAllocate(XENVIF_TRANSMITTER_MAXIMUM_HEADER_LENGTH);

    status = STATUS_NO_MEMORY;
    if (Header == NULL)
        goto fail1;

    Packet->Header = Header;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(Packet, sizeof (XENVIF_TRANSMITTER_PACKET)));

    return status;
}

static VOID
TransmitterPacketDtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_TRANSMITTER_PACKET  Packet = Object;
    PUCHAR                      Header;

    UNREFERENCED_PARAMETER(Argument);

    Header = Packet->Header;
    Packet->Header = NULL;

    ASSERT(IsZeroMemory(Header, XENVIF_TRANSMITTER_MAXIMUM_HEADER_LENGTH));
    __TransmitterFree(Header);

    ASSERT(IsZeroMemory(Packet, sizeof (XENVIF_TRANSMITTER_PACKET)));
}

static FORCEINLINE PXENVIF_TRANSMITTER_PACKET
__TransmitterGetPacket(
    IN  PXENVIF_TRANSMITTER         Transmitter
    )
{
    return XENBUS_CACHE(Get,
                        &Transmitter->CacheInterface,
                        Transmitter->PacketCache,
                        FALSE);
}

static FORCEINLINE VOID
__TransmitterPutPacket(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    ASSERT(IsZeroMemory(&Packet->ListEntry, sizeof (LIST_ENTRY)));
    ASSERT3U(Packet->Reference, ==, 0);
    Packet->Cookie = NULL;

    Packet->OffloadOptions.Value = 0;
    Packet->MaximumSegmentSize = 0;
    Packet->TagControlInformation = 0;
    Packet->Mdl = NULL;
    Packet->Offset = 0;
    Packet->Length = 0;

    RtlZeroMemory(Packet->Header, XENVIF_TRANSMITTER_MAXIMUM_HEADER_LENGTH);
    RtlZeroMemory(&Packet->Info, sizeof (XENVIF_PACKET_INFO));
    RtlZeroMemory(&Packet->Hash, sizeof (XENVIF_PACKET_HASH));
    RtlZeroMemory(&Packet->Payload, sizeof (XENVIF_PACKET_PAYLOAD));

    Packet->Flags.Value = 0;
    RtlZeroMemory(&Packet->Completion, sizeof (XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO));

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Transmitter->PacketCache,
                 Packet,
                 FALSE);
}

static NTSTATUS
TransmitterBufferCtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_TRANSMITTER_BUFFER  Buffer = Object;
    PMDL		                Mdl;
    NTSTATUS	                status;

    UNREFERENCED_PARAMETER(Argument);

    ASSERT(IsZeroMemory(Buffer, sizeof (XENVIF_TRANSMITTER_BUFFER)));

    Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Mdl == NULL)
	goto fail1;

    Mdl->ByteCount = 0;
    Buffer->Mdl = Mdl;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(Buffer, sizeof (XENVIF_TRANSMITTER_BUFFER)));

    return status;
}

static VOID
TransmitterBufferDtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_TRANSMITTER_BUFFER  Buffer = Object;
    PMDL                        Mdl;

    UNREFERENCED_PARAMETER(Argument);

    Mdl = Buffer->Mdl;
    Buffer->Mdl = NULL;

    Mdl->ByteCount = PAGE_SIZE;

    __FreePage(Mdl);

    ASSERT(IsZeroMemory(Buffer, sizeof (XENVIF_TRANSMITTER_BUFFER)));
}

static FORCEINLINE PXENVIF_TRANSMITTER_BUFFER
__TransmitterGetBuffer(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Buffer = XENBUS_CACHE(Get,
                          &Transmitter->CacheInterface,
                          Ring->BufferCache,
                          TRUE);

    ASSERT(IMPLY(Buffer != NULL, Buffer->Mdl->ByteCount == 0));

    return Buffer;
}

static FORCEINLINE VOID
__TransmitterPutBuffer(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_BUFFER  Buffer
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Buffer->Reference, ==, 0);
    ASSERT3P(Buffer->Context, ==, NULL);

    Buffer->Mdl->ByteCount = 0;

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Ring->BufferCache,
                 Buffer,
                 TRUE);
}

static NTSTATUS
TransmitterMulticastControlCtor(
    IN  PVOID   Argument,
    IN  PVOID   Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);

    return STATUS_SUCCESS;
}

static VOID
TransmitterMulticastControlDtor(
    IN  PVOID   Argument,
    IN  PVOID   Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static FORCEINLINE PXENVIF_TRANSMITTER_MULTICAST_CONTROL
__TransmitterGetMulticastControl(
    IN  PXENVIF_TRANSMITTER_RING            Ring
    )
{
    PXENVIF_TRANSMITTER                     Transmitter;
    PXENVIF_FRONTEND                        Frontend;
    PXENVIF_TRANSMITTER_MULTICAST_CONTROL   Control;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Control = XENBUS_CACHE(Get,
                           &Transmitter->CacheInterface,
                           Ring->MulticastControlCache,
                           TRUE);

    return Control;
}

static FORCEINLINE VOID
__TransmitterPutMulticastControl(
    IN  PXENVIF_TRANSMITTER_RING                Ring,
    IN  PXENVIF_TRANSMITTER_MULTICAST_CONTROL   Control
    )
{
    PXENVIF_TRANSMITTER                         Transmitter;
    PXENVIF_FRONTEND                            Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Control->Reference, ==, 0);

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Ring->MulticastControlCache,
                 Control,
                 TRUE);
}

static NTSTATUS
TransmitterFragmentCtor(
    IN  PVOID                       Argument,
    IN  PVOID                       Object
    )
{
    PXENVIF_TRANSMITTER_RING        Ring = Argument;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment = Object;
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    LONGLONG                        Id;
    NTSTATUS	                    status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_TRANSMITTER_FRAGMENT)));

    status = XENBUS_RANGE_SET(Pop,
                              &Transmitter->RangeSetInterface,
                              Ring->RangeSet,
                              1,
                              &Id);
    if (!NT_SUCCESS(status))
        goto fail1;

    Fragment->Id = (USHORT)Id;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_TRANSMITTER_FRAGMENT)));

    return status;
}

static VOID
TransmitterFragmentDtor(
    IN  PVOID                       Argument,
    IN  PVOID                       Object
    )
{
    PXENVIF_TRANSMITTER_RING        Ring = Argument;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment = Object;
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    LONGLONG                        Id;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Id = Fragment->Id;
    Fragment->Id = 0;

    XENBUS_RANGE_SET(Put,
                     &Transmitter->RangeSetInterface,
                     Ring->RangeSet,
                     Id,
                     1);

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_TRANSMITTER_FRAGMENT)));
}

static FORCEINLINE PXENVIF_TRANSMITTER_FRAGMENT
__TransmitterGetFragment(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    return XENBUS_CACHE(Get,
                        &Transmitter->CacheInterface,
                        Ring->FragmentCache,
                        TRUE);
}

static FORCEINLINE
__TransmitterPutFragment(
    IN  PXENVIF_TRANSMITTER_RING        Ring,
    IN  PXENVIF_TRANSMITTER_FRAGMENT    Fragment
    )
{
    PXENVIF_TRANSMITTER                 Transmitter;
    PXENVIF_FRONTEND                    Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Fragment->Length, ==, 0);
    ASSERT3U(Fragment->Offset, ==, 0);
    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID);
    ASSERT3P(Fragment->Context, ==, NULL);
    ASSERT3P(Fragment->Entry, ==, NULL);
    ASSERT3U(Fragment->Extra, ==, 0);

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Ring->FragmentCache,
                 Fragment,
                 TRUE);
}

static NTSTATUS
TransmitterRequestCtor(
    IN  PVOID   Argument,
    IN  PVOID   Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);

    return STATUS_SUCCESS;
}

static VOID
TransmitterRequestDtor(
    IN  PVOID   Argument,
    IN  PVOID   Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static FORCEINLINE PXENVIF_TRANSMITTER_REQUEST
__TransmitterGetRequest(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_TRANSMITTER_REQUEST     Request;

    Transmitter = Ring->Transmitter;

    Request = XENBUS_CACHE(Get,
                           &Transmitter->CacheInterface,
                           Ring->RequestCache,
                           TRUE);

    return Request;
}

static FORCEINLINE VOID
__TransmitterPutRequest(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_REQUEST Request
    )
{
    PXENVIF_TRANSMITTER             Transmitter;

    Transmitter = Ring->Transmitter;

    ASSERT3U(Request->Type, ==, XENVIF_TRANSMITTER_REQUEST_TYPE_INVALID);

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Ring->RequestCache,
                 Request,
                 TRUE);
}

static VOID
TransmitterRingDebugCallback(
    IN  PVOID                   Argument,
    IN  BOOLEAN                 Crashing
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Argument;
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;

    UNREFERENCED_PARAMETER(Crashing);

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "0x%p [%s]\n",
                 Ring,
                 (Ring->Enabled) ? "ENABLED" : "DISABLED");

    // Dump front ring
    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
                 Ring->Front.req_prod_pvt,
                 Ring->Front.rsp_cons,
                 Ring->Front.nr_ents,
                 Ring->Front.sring);

    // Dump shared ring
    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
                 Ring->Shared->req_prod,
                 Ring->Shared->req_event,
                 Ring->Shared->rsp_prod,
                 Ring->Shared->rsp_event);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
                 Ring->RequestsPosted,
                 Ring->RequestsPushed,
                 Ring->ResponsesProcessed);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "State:\n");

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "- Packet = %p\n",
                 Ring->State.Packet);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "- Count = %u\n",
                 Ring->State.Count);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "PacketsGranted = %u PacketsCopied = %u PacketsFaked = %u\n",
                 Ring->PacketsGranted,
                 Ring->PacketsCopied,
                 Ring->PacketsFaked);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "PacketsQueued = %u PacketsPrepared = %u PacketsUnprepared = %u PacketsSent = %u PacketsCompleted = %u\n",
                 Ring->PacketsQueued,
                 Ring->PacketsPrepared,
                 Ring->PacketsUnprepared,
                 Ring->PacketsSent,
                 Ring->PacketsCompleted);

    if (FrontendIsSplit(Frontend)) {
        // Dump event channel
        XENBUS_DEBUG(Printf,
                     &Transmitter->DebugInterface,
                     "Events = %lu PollDpcs = %lu\n",
                     Ring->Events,
                     Ring->PollDpcs);
    }
}

static BOOLEAN
TransmitterPullup(
    IN      PVOID                   Argument,
    IN      PUCHAR                  DestinationVa,
    IN OUT  PXENVIF_PACKET_PAYLOAD  Payload,
    IN      ULONG                   Length
    )
{
    PMDL                            Mdl;
    ULONG                           Offset;

    UNREFERENCED_PARAMETER(Argument);

    Mdl = Payload->Mdl;
    Offset = Payload->Offset;

    if (Payload->Length < Length)
        goto fail1;

    Payload->Length -= Length;

    while (Length != 0) {
        PUCHAR  SourceVa;
        ULONG   MdlByteCount;
        ULONG   CopyLength;

        ASSERT(Mdl != NULL);

        SourceVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        ASSERT(SourceVa != NULL);

        SourceVa += Offset;

        MdlByteCount = Mdl->ByteCount - Offset;

        CopyLength = __min(MdlByteCount, Length);

        RtlCopyMemory(DestinationVa, SourceVa, CopyLength);
        DestinationVa += CopyLength;

        Offset += CopyLength;
        Length -= CopyLength;

        MdlByteCount -= CopyLength;
        if (MdlByteCount == 0) {
            Mdl = Mdl->Next;
            Offset = 0;
        }
    }

    Payload->Mdl = Mdl;
    Payload->Offset = Offset;

    return TRUE;

fail1:
    return FALSE;
}

static FORCEINLINE NTSTATUS
__TransmitterRingCopyPayload(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    XENVIF_PACKET_PAYLOAD           Payload;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;
    Payload = Packet->Payload;

    ASSERT(Packet != NULL);
    ASSERT3U(Packet->Reference, ==, 1);

    while (Payload.Length != 0) {
        PMDL        Mdl;
        ULONG       Length;
        PUCHAR      BaseVa;
        PFN_NUMBER  Pfn;

        Buffer = __TransmitterGetBuffer(Ring);

        status = STATUS_NO_MEMORY;
        if (Buffer == NULL)
            goto fail1;

        Buffer->Context = Packet;
        Packet->Reference++;

        Mdl = Buffer->Mdl;

        Length = __min(Payload.Length, PAGE_SIZE);

        ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
        BaseVa = Mdl->MappedSystemVa;
        ASSERT(BaseVa != NULL);

        (VOID) TransmitterPullup(Transmitter, BaseVa, &Payload, Length);

        Mdl->ByteCount = Length;

        Fragment = __TransmitterGetFragment(Ring);

        status = STATUS_NO_MEMORY;
        if (Fragment == NULL)
            goto fail2;

        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
        Fragment->Context = Buffer;
        Buffer->Reference++;

        Pfn = MmGetMdlPfnArray(Mdl)[0];

        status = XENBUS_GNTTAB(PermitForeignAccess,
                               &Transmitter->GnttabInterface,
                               Ring->GnttabCache,
                               TRUE,
                               FrontendGetBackendDomain(Frontend),
                               Pfn,
                               TRUE,
                               &Fragment->Entry);
        if (!NT_SUCCESS(status))
            goto fail3;

        Fragment->Offset = 0;
        Fragment->Length = Mdl->ByteCount;

        ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
        InsertTailList(&State->List, &Fragment->ListEntry);
        State->Count++;

        ASSERT3U(State->Count, <=, XEN_NETIF_NR_SLOTS_MIN);
    }

    Ring->PacketsCopied++;
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
    ASSERT3P(Buffer, ==, Fragment->Context);
    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail2:
    Error("fail2\n");

    ASSERT3P(Buffer->Context, ==, Packet);
    Buffer->Context = NULL;        

    --Packet->Reference;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    while (Packet->Reference != 1) {
        PLIST_ENTRY         ListEntry;

        ASSERT(State->Count != 0);
        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        Fragment->Length = 0;
        Fragment->Offset = 0;

        (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                             &Transmitter->GnttabInterface,
                             Ring->GnttabCache,
                             TRUE,
                             Fragment->Entry);
        Fragment->Entry = NULL;

        ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
        Buffer = Fragment->Context;
        Fragment->Context = NULL;
        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

        ASSERT(Buffer->Reference != 0);
        --Buffer->Reference;

        __TransmitterPutFragment(Ring, Fragment);

        ASSERT3P(Buffer->Context, ==, Packet);
        Buffer->Context = NULL;        

        --Packet->Reference;

        __TransmitterPutBuffer(Ring, Buffer);
    }

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingGrantPayload(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PMDL                            Mdl;
    ULONG                           Offset;
    ULONG                           Length;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;
    Payload = &Packet->Payload;

    ASSERT(Packet != NULL);
    ASSERT3U(Packet->Reference, ==, 1);

    Mdl = Payload->Mdl;
    Offset = Payload->Offset;
    Length = Payload->Length;

    while (Length != 0) {
        ULONG   MdlOffset;
        ULONG   MdlByteCount;
        ULONG   MdlLength;

        MdlOffset = Mdl->ByteOffset + Offset;
        MdlByteCount = Mdl->ByteCount - Offset;

        MdlLength = __min(MdlByteCount, Length);

        while (MdlLength != 0) {
            PFN_NUMBER          Pfn;
            ULONG               PageOffset;
            ULONG               PageLength;

            Fragment = __TransmitterGetFragment(Ring);

            status = STATUS_NO_MEMORY;
            if (Fragment == NULL)
                goto fail1;

            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET;
            Fragment->Context = Packet;
            Packet->Reference++;

            Pfn = MmGetMdlPfnArray(Mdl)[MdlOffset / PAGE_SIZE];
            PageOffset = MdlOffset & (PAGE_SIZE - 1);
            PageLength = __min(MdlLength, PAGE_SIZE - PageOffset);

            status = XENBUS_GNTTAB(PermitForeignAccess,
                                   &Transmitter->GnttabInterface,
                                   Ring->GnttabCache,
                                   TRUE,
                                   FrontendGetBackendDomain(Frontend),
                                   Pfn,
                                   TRUE,
                                   &Fragment->Entry);
            if (!NT_SUCCESS(status))
                goto fail2;

            Fragment->Offset = PageOffset;
            Fragment->Length = PageLength;

            ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
            InsertTailList(&State->List, &Fragment->ListEntry);
            State->Count++;

            Fragment = NULL;

            // Bounce the packet if it is too highly fragmented
            status = STATUS_BUFFER_OVERFLOW;
            if (State->Count > XEN_NETIF_NR_SLOTS_MIN)
                goto fail3;

            MdlOffset += PageLength;

            ASSERT3U(MdlLength, >=, PageLength);
            MdlLength -= PageLength;

            ASSERT3U(Length, >=, PageLength);
            Length -= PageLength;
        }

        Mdl = Mdl->Next;
        Offset = 0;
    }

    Ring->PacketsGranted++;
    return STATUS_SUCCESS;

fail3:
fail2:
    if (status != STATUS_BUFFER_OVERFLOW)
        Error("fail2\n");

    if (Fragment != NULL) {
        ASSERT3P(Fragment->Context, ==, Packet);
        Fragment->Context = NULL;
        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

        --Packet->Reference;

        __TransmitterPutFragment(Ring, Fragment);
    }

fail1:
    if (status != STATUS_BUFFER_OVERFLOW)
        Error("fail1 (%08x)\n", status);

    ASSERT3P(Fragment, ==, NULL);

    while (Packet->Reference != 1) {
        PLIST_ENTRY         ListEntry;

        ASSERT(State->Count != 0);
        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        Fragment->Length = 0;
        Fragment->Offset = 0;

        (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                             &Transmitter->GnttabInterface,
                             Ring->GnttabCache,
                             TRUE,
                             Fragment->Entry);
        Fragment->Entry = NULL;

        ASSERT3P(Fragment->Context, ==, Packet);
        Fragment->Context = NULL;
        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

        --Packet->Reference;

        __TransmitterPutFragment(Ring, Fragment);
    }

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareHeader(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PXENVIF_PACKET_INFO             Info;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    PMDL                            Mdl;
    PUCHAR                          BaseVa;
    PFN_NUMBER                      Pfn;
    PETHERNET_HEADER                EthernetHeader;
    BOOLEAN                         SquashError;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    State = &Ring->State;
    Packet = State->Packet;

    Payload = &Packet->Payload;
    Info = &Packet->Info;

    SquashError = FALSE;

    status = STATUS_UNSUCCESSFUL;
    if (Info->Length == 0)
        goto fail1;

    ASSERT3U(Packet->Reference, ==, 0);

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail2;

    Buffer->Context = Packet;
    Packet->Reference++;

    Mdl = Buffer->Mdl;

    ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    BaseVa = Mdl->MappedSystemVa;
    ASSERT(BaseVa != NULL);

    RtlCopyMemory(BaseVa, Packet->Header, Info->Length);

    Mdl->ByteCount = Info->Length;

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Fragment == NULL)
        goto fail3;

    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
    Fragment->Context = Buffer;
 
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Transmitter->GnttabInterface,
                           Ring->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           TRUE,
                           &Fragment->Entry);
    if (!NT_SUCCESS(status))
        goto fail4;

    Fragment->Offset = 0;
    Fragment->Length = Mdl->ByteCount + Payload->Length;

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(BaseVa + Info->EthernetHeader.Offset);

    if (Packet->OffloadOptions.OffloadTagManipulation) {
        ULONG   Offset;

        Offset = FIELD_OFFSET(ETHERNET_TAGGED_HEADER, Tag);

        RtlMoveMemory((PUCHAR)EthernetHeader + Offset + sizeof (ETHERNET_TAG),
                      (PUCHAR)EthernetHeader + Offset,
                      Mdl->ByteCount - Offset);

        // Insert the tag
        EthernetHeader->Tagged.Tag.ProtocolID = HTONS(ETHERTYPE_TPID);
        EthernetHeader->Tagged.Tag.ControlInformation = HTONS(Packet->TagControlInformation);
        ASSERT(ETHERNET_HEADER_IS_TAGGED(EthernetHeader));

        Packet->Length += sizeof (ETHERNET_TAG);
        Mdl->ByteCount += sizeof (ETHERNET_TAG);
        Fragment->Length += sizeof (ETHERNET_TAG);

        // Fix up the packet information
        Info->EthernetHeader.Length += sizeof (ETHERNET_TAG);
        Info->Length += sizeof (ETHERNET_TAG);

        if (Info->IpHeader.Length != 0)
            Info->IpHeader.Offset += sizeof (ETHERNET_TAG);

        if (Info->IpOptions.Length != 0)
            Info->IpOptions.Offset += sizeof (ETHERNET_TAG);

        if (Info->UdpHeader.Length != 0)
            Info->UdpHeader.Offset += sizeof (ETHERNET_TAG);

        if (Info->TcpHeader.Length != 0)
            Info->TcpHeader.Offset += sizeof (ETHERNET_TAG);

        if (Info->TcpOptions.Length != 0)
            Info->TcpOptions.Offset += sizeof (ETHERNET_TAG);
    }

    if (Packet->OffloadOptions.OffloadIpVersion4LargePacket) {
        PIP_HEADER  IpHeader;
        PTCP_HEADER TcpHeader;
        ULONG       Length;

        ASSERT(!Info->IsAFragment);

        ASSERT(Info->IpHeader.Length != 0);
        IpHeader = (PIP_HEADER)(BaseVa + Info->IpHeader.Offset);

        ASSERT(Info->TcpHeader.Length != 0);
        TcpHeader = (PTCP_HEADER)(BaseVa + Info->TcpHeader.Offset);

        // Fix up the IP packet length
        Length = Info->IpHeader.Length +
                 Info->IpOptions.Length + 
                 Info->TcpHeader.Length + 
                 Info->TcpOptions.Length + 
                 Payload->Length;

        ASSERT3U((USHORT)Length, ==, Length);

        ASSERT3U(IpHeader->Version, ==, 4);

        IpHeader->Version4.PacketLength = HTONS((USHORT)Length);

        // IP checksum calulcation must be offloaded for large packets
        Packet->OffloadOptions.OffloadIpVersion4HeaderChecksum = 1;

        // TCP checksum calulcation must be offloaded for large packets
        Packet->OffloadOptions.OffloadIpVersion4TcpChecksum = 1;

        // If the MSS is such that the payload would constitute only a single fragment then
        // we no longer need trate the packet as a large packet.
        ASSERT3U(Packet->MaximumSegmentSize, <=, Payload->Length);
        if (Packet->MaximumSegmentSize == Payload->Length)
            Packet->OffloadOptions.OffloadIpVersion4LargePacket = 0;
    }
    
    if (Packet->OffloadOptions.OffloadIpVersion6LargePacket) {
        PIP_HEADER  IpHeader;
        PTCP_HEADER TcpHeader;
        ULONG       Length;

        ASSERT(!Info->IsAFragment);

        ASSERT(Info->IpHeader.Length != 0);
        IpHeader = (PIP_HEADER)(BaseVa + Info->IpHeader.Offset);

        ASSERT(Info->TcpHeader.Length != 0);
        TcpHeader = (PTCP_HEADER)(BaseVa + Info->TcpHeader.Offset);

        // Fix up the IP payload length
        Length = Info->IpOptions.Length + 
                 Info->TcpHeader.Length + 
                 Info->TcpOptions.Length + 
                 Payload->Length;

        ASSERT3U((USHORT)Length, ==, Length);

        ASSERT3U(IpHeader->Version, ==, 6);

        IpHeader->Version6.PayloadLength = HTONS((USHORT)Length);

        // TCP checksum calulcation must be offloaded for large packets
        Packet->OffloadOptions.OffloadIpVersion6TcpChecksum = 1;

        // If the MSS is such that the payload would constitute only a single fragment then
        // we no longer need treat the packet as a large packet.
        ASSERT3U(Packet->MaximumSegmentSize, <=, Payload->Length);
        if (Packet->MaximumSegmentSize == Payload->Length)
            Packet->OffloadOptions.OffloadIpVersion6LargePacket = 0;
    }

    // Non-GSO packets must not exceed MTU
    if (!Packet->OffloadOptions.OffloadIpVersion4LargePacket &&
        !Packet->OffloadOptions.OffloadIpVersion6LargePacket) {
        ULONG   MaximumFrameSize;

        MacQueryMaximumFrameSize(Mac, &MaximumFrameSize);
        
        if (Fragment->Length > MaximumFrameSize) {
            status = STATUS_INVALID_PARAMETER;
            SquashError = TRUE;
            goto fail5;
        }
    }

    if (Info->IpHeader.Length != 0) {
        PIP_HEADER  IpHeader;

        IpHeader = (PIP_HEADER)(BaseVa + Info->IpHeader.Offset);

        if (IpHeader->Version == 4) {
            if (Packet->OffloadOptions.OffloadIpVersion4HeaderChecksum) {
                IpHeader->Version4.Checksum = ChecksumIpVersion4Header(BaseVa, Info);

                Packet->Flags.IpChecksumNotValidated = 1;
            } else if (Transmitter->ValidateChecksums != 0) {
                USHORT      Embedded;
                USHORT      Calculated;

                Embedded = IpHeader->Version4.Checksum;

                Calculated = ChecksumIpVersion4Header(BaseVa, Info);

                if (ChecksumVerify(Calculated, Embedded))
                    Packet->Flags.IpChecksumSucceeded = 1;
                else
                    Packet->Flags.IpChecksumFailed = 1;
            } else {
                Packet->Flags.IpChecksumNotValidated = 1;
            }
        }
    }

    if (Info->TcpHeader.Length != 0) {
        PTCP_HEADER TcpHeader;

        TcpHeader = (PTCP_HEADER)(BaseVa + Info->TcpHeader.Offset);

        if (Packet->OffloadOptions.OffloadIpVersion4TcpChecksum ||
            Packet->OffloadOptions.OffloadIpVersion6TcpChecksum) {
            TcpHeader->Checksum = ChecksumPseudoHeader(BaseVa, Info);

            Packet->Flags.TcpChecksumNotValidated = 1;
        } else if (Transmitter->ValidateChecksums != 0) {
            USHORT      Embedded;
            USHORT      Calculated;

            Embedded = TcpHeader->Checksum;

            Calculated = ChecksumPseudoHeader(BaseVa, Info);
            Calculated = ChecksumTcpPacket(BaseVa, Info, Calculated, Payload);

            if (ChecksumVerify(Calculated, Embedded))
                Packet->Flags.TcpChecksumSucceeded = 1;
            else
                Packet->Flags.TcpChecksumFailed = 1;
        } else {
            Packet->Flags.TcpChecksumNotValidated = 1;
        }
    }

    if (Info->UdpHeader.Length != 0) {
        PUDP_HEADER UdpHeader;

        UdpHeader = (PUDP_HEADER)(BaseVa + Info->UdpHeader.Offset);

        if (Packet->OffloadOptions.OffloadIpVersion4UdpChecksum ||
            Packet->OffloadOptions.OffloadIpVersion6UdpChecksum) {
            UdpHeader->Checksum = ChecksumPseudoHeader(BaseVa, Info);

            Packet->Flags.UdpChecksumNotValidated = 1;
        } else if (Transmitter->ValidateChecksums != 0) {
            PIP_HEADER  IpHeader;
            USHORT      Embedded;

            ASSERT(Info->IpHeader.Length != 0);
            IpHeader = (PIP_HEADER)(BaseVa + Info->IpHeader.Offset);

            Embedded = UdpHeader->Checksum;

            // Tolarate zero checksum for IPv4/UDP
            if (IpHeader->Version == 4 && Embedded == 0) {
                Packet->Flags.UdpChecksumSucceeded = 1;
            } else {
                USHORT  Calculated;

                Calculated = ChecksumPseudoHeader(BaseVa, Info);
                Calculated = ChecksumUdpPacket(BaseVa, Info, Calculated, Payload);

                if (ChecksumVerify(Calculated, Embedded))
                    Packet->Flags.UdpChecksumSucceeded = 1;
                else
                    Packet->Flags.UdpChecksumFailed = 1;
            }
        } else {
            Packet->Flags.UdpChecksumNotValidated = 1;
        }
    }

    return STATUS_SUCCESS;

fail5:
    if (!SquashError)
        Error("fail5\n");

    ASSERT(State->Count != 0);
    --State->Count;

    RemoveEntryList(&Fragment->ListEntry);
    RtlZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY));

    Fragment->Length = 0;
    Fragment->Offset = 0;

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Transmitter->GnttabInterface,
                         Ring->GnttabCache,
                         TRUE,
                         Fragment->Entry);
    Fragment->Entry = NULL;

fail4:
    if (!SquashError)
        Error("fail4\n");

    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail3:
    if (!SquashError)
        Error("fail3\n");

    --Packet->Reference;
    Buffer->Context = NULL;

    __TransmitterPutBuffer(Ring, Buffer);

fail2:
    if (!SquashError)
        Error("fail2\n");

    ASSERT3U(Packet->Reference, ==, 0);

fail1:
    if (!SquashError)
        Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE PXENVIF_TRANSMITTER_PACKET
__TransmitterRingUnprepareFragments(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    ULONG                           Count;
    PXENVIF_TRANSMITTER_PACKET      Packet;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Count = State->Count;

    while (Count != 0) {
        PLIST_ENTRY                     ListEntry;
        PXENVIF_TRANSMITTER_FRAGMENT    Fragment;

        --Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        Fragment->Length = 0;
        Fragment->Offset = 0;

        (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                             &Transmitter->GnttabInterface,
                             Ring->GnttabCache,
                             TRUE,
                             Fragment->Entry);
        Fragment->Entry = NULL;

        switch (Fragment->Type) {
        case XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER: {
            PXENVIF_TRANSMITTER_BUFFER  Buffer;

            Buffer = Fragment->Context;
            Fragment->Context = NULL;
            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

            Packet = Buffer->Context;
            Buffer->Context = NULL;

            ASSERT(Buffer->Reference != 0);
            --Buffer->Reference;
            __TransmitterPutBuffer(Ring, Buffer);

            break;
        }
        case XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET:
            Packet = Fragment->Context;
            Fragment->Context = NULL;
            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

            break;

        case XENVIF_TRANSMITTER_FRAGMENT_TYPE_MULTICAST_CONTROL: {
            PXENVIF_TRANSMITTER_MULTICAST_CONTROL Control;

            Control = Fragment->Context;
            Fragment->Context = NULL;
            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

            switch (Control->Type) {
            case XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_ADD:
            case XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_REMOVE:
                break;
            default:
                ASSERT(FALSE);
                break;
            }

            ASSERT(Control->Reference != 0);
            --Control->Reference;
            __TransmitterPutMulticastControl(Ring, Control);

            Packet = NULL;
            break;
            }
        default:
            ASSERT(FALSE);
            Packet = NULL;
            break;
        }

        if (Packet != NULL)
            --Packet->Reference;

        __TransmitterPutFragment(Ring, Fragment);
    }

    if (State->Count != 0) {
        ASSERT(IsListEmpty(&State->List));
        RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

        State->Count = 0;
    }

    Packet = State->Packet;

    if (Packet != NULL) {
        Ring->PacketsUnprepared++;

        State->Packet = NULL;
    }

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return Packet;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPreparePacket(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PXENVIF_PACKET_INFO             Info;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    Transmitter = Ring->Transmitter;

    State = &Ring->State;

    State->Packet = Packet;

    InitializeListHead(&State->List);
    ASSERT3U(State->Count, ==, 0);

    status = __TransmitterRingPrepareHeader(Ring);
    if (!NT_SUCCESS(status))
        goto fail1;

    ASSERT3U(State->Count, ==, Packet->Reference);

    Info = &Packet->Info;
    Payload = &Packet->Payload;

    // Is the packet too short?
    if (Info->Length + Payload->Length < ETHERNET_MIN) {
        ULONG   Trailer;
        BOOLEAN SingleFragment;

        Trailer = ETHERNET_MIN - Payload->Length - Info->Length;
        SingleFragment = (Payload->Length == 0) ? TRUE : FALSE;

        status = __TransmitterRingCopyPayload(Ring);

        if (NT_SUCCESS(status)) {
            PLIST_ENTRY                     ListEntry;
            PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
            PXENVIF_TRANSMITTER_BUFFER      Buffer;
            PMDL                            Mdl;
            PUCHAR                          BaseVa;

            // Add padding to the tail buffer
            ListEntry = State->List.Blink;
            Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

            ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
            Buffer = Fragment->Context;

            Mdl = Buffer->Mdl;

            ASSERT3U(Mdl->ByteCount, <=, PAGE_SIZE - Trailer);

            ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
            BaseVa = Mdl->MappedSystemVa;
            ASSERT(BaseVa != NULL);

            BaseVa += Mdl->ByteCount;

            RtlZeroMemory(BaseVa, Trailer);
            Mdl->ByteCount += Trailer;

            if (!SingleFragment) {
                ASSERT3P(State->List.Flink, !=, ListEntry);
                Fragment->Length += Trailer;
            }

            // Adjust length of header fragment
            ListEntry = State->List.Flink;
            Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

            Fragment->Length += Trailer;
            ASSERT3U(Fragment->Length, ==, ETHERNET_MIN);
        }
    } else {
        if (Transmitter->AlwaysCopy == 0)
            status = __TransmitterRingGrantPayload(Ring);

        if (Transmitter->AlwaysCopy != 0 ||
            (!NT_SUCCESS(status) && status == STATUS_BUFFER_OVERFLOW)) {
            ASSERT3U(State->Count, ==, Packet->Reference);

            status = __TransmitterRingCopyPayload(Ring);
        }
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    ASSERT3U(State->Count, ==, Packet->Reference);

    Ring->PacketsPrepared++;
    return STATUS_SUCCESS;

fail2:
    __TransmitterRingUnprepareFragments(Ring);

fail1:
    ASSERT(IsListEmpty(&State->List));
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    State->Packet = NULL;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareArp(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PIPV4_ADDRESS               Address
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    PMDL                            Mdl;
    PUCHAR                          BaseVa;
    PETHERNET_UNTAGGED_HEADER       EthernetHeader;
    PARP_HEADER                     ArpHeader;
    ETHERNET_ADDRESS                SenderHardwareAddress;
    IPV4_ADDRESS                    SenderProtocolAddress;
    ETHERNET_ADDRESS                TargetHardwareAddress;
    IPV4_ADDRESS                    TargetProtocolAddress;
    PFN_NUMBER                      Pfn;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    SenderProtocolAddress = *Address;
    TargetProtocolAddress = *Address;
    MacQueryCurrentAddress(Mac, &SenderHardwareAddress);
    MacQueryBroadcastAddress(Mac, &TargetHardwareAddress);

    State = &Ring->State;

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Mdl = Buffer->Mdl;

    ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    BaseVa = Mdl->MappedSystemVa;
    ASSERT(BaseVa != NULL);

    EthernetHeader = (PETHERNET_UNTAGGED_HEADER)BaseVa;

    MacQueryBroadcastAddress(Mac, &EthernetHeader->DestinationAddress);
    MacQueryCurrentAddress(Mac, &EthernetHeader->SourceAddress);
    EthernetHeader->TypeOrLength = HTONS(ETHERTYPE_ARP);

    BaseVa += sizeof (ETHERNET_UNTAGGED_HEADER);

    ArpHeader = (PARP_HEADER)BaseVa;

    ArpHeader->HardwareType = HTONS(HARDWARE_ETHER);
    ArpHeader->ProtocolType = HTONS(PROTOCOL_IPV4);
    ArpHeader->HardwareAddressLength = ETHERNET_ADDRESS_LENGTH;
    ArpHeader->ProtocolAddressLength = IPV4_ADDRESS_LENGTH;
    ArpHeader->Operation = HTONS(ARP_REQUEST);

    BaseVa += sizeof (ARP_HEADER);

    RtlCopyMemory(BaseVa, SenderHardwareAddress.Byte, ETHERNET_ADDRESS_LENGTH);
    BaseVa += ETHERNET_ADDRESS_LENGTH;

    RtlCopyMemory(BaseVa, SenderProtocolAddress.Byte, IPV4_ADDRESS_LENGTH);
    BaseVa += IPV4_ADDRESS_LENGTH;

    RtlCopyMemory(BaseVa, TargetHardwareAddress.Byte, ETHERNET_ADDRESS_LENGTH);
    BaseVa += ETHERNET_ADDRESS_LENGTH;

    RtlCopyMemory(BaseVa, TargetProtocolAddress.Byte, IPV4_ADDRESS_LENGTH);
    BaseVa += IPV4_ADDRESS_LENGTH;

    Mdl->ByteCount = (ULONG)(BaseVa - (PUCHAR)(Mdl->MappedSystemVa));

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Fragment == NULL)
        goto fail2;

    Fragment->Context = Buffer;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Transmitter->GnttabInterface,
                           Ring->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           TRUE,
                           &Fragment->Entry);
    if (!NT_SUCCESS(status))
        goto fail3;

    Fragment->Offset = 0;
    Fragment->Length = Mdl->ByteCount;

    InitializeListHead(&State->List);

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
    ASSERT3P(Buffer, ==, Fragment->Context);
    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail2:
    Error("fail2\n");

    Mdl->ByteCount = 0;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareNeighbourAdvertisement(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PIPV6_ADDRESS               Address
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    PMDL                            Mdl;
    PUCHAR                          BaseVa;
    PETHERNET_UNTAGGED_HEADER       EthernetHeader;
    PIPV6_HEADER                    IpHeader;
    PICMPV6_HEADER                  IcmpHeader;
    IPV6_ADDRESS                    TargetProtocolAddress;
    ETHERNET_ADDRESS                SenderHardwareAddress;
    USHORT                          PayloadLength;
    ULONG                           Accumulator;
    PFN_NUMBER                      Pfn;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    TargetProtocolAddress = *Address;
    MacQueryCurrentAddress(Mac, &SenderHardwareAddress);

    State = &Ring->State;

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Mdl = Buffer->Mdl;

    ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    BaseVa = Mdl->MappedSystemVa;
    ASSERT(BaseVa != NULL);

    EthernetHeader = (PETHERNET_UNTAGGED_HEADER)BaseVa;

    MacQueryBroadcastAddress(Mac, &EthernetHeader->DestinationAddress);
    MacQueryCurrentAddress(Mac, &EthernetHeader->SourceAddress);
    EthernetHeader->TypeOrLength = HTONS(ETHERTYPE_IPV6);

    BaseVa += sizeof (ETHERNET_UNTAGGED_HEADER);

    IpHeader = (PIPV6_HEADER)BaseVa;
    RtlZeroMemory(IpHeader, sizeof (IPV6_HEADER));

    IpHeader->Version = 6;
    IpHeader->NextHeader = IPPROTO_ICMPV6;
    IpHeader->HopLimit = 255;

    RtlCopyMemory(IpHeader->SourceAddress.Byte, 
                  Address,
                  IPV6_ADDRESS_LENGTH);

    // Destination is all-nodes multicast address
    IpHeader->DestinationAddress.Byte[0] = 0xFF;
    IpHeader->DestinationAddress.Byte[1] = 0x02;
    IpHeader->DestinationAddress.Byte[15] = 0x02;

    PayloadLength = 0;
    BaseVa += sizeof (IPV6_HEADER);

    IcmpHeader = (PICMPV6_HEADER)BaseVa;

    IcmpHeader->Type = ICMPV6_TYPE_NA;
    IcmpHeader->Code = 0;
    IcmpHeader->Data = HTONL(0x02); // Override flag

    PayloadLength += sizeof (ICMPV6_HEADER);
    BaseVa += sizeof (ICMPV6_HEADER);

    RtlCopyMemory(BaseVa, TargetProtocolAddress.Byte, IPV6_ADDRESS_LENGTH);

    PayloadLength += IPV6_ADDRESS_LENGTH;
    BaseVa += IPV6_ADDRESS_LENGTH;

    RtlCopyMemory(BaseVa, SenderHardwareAddress.Byte, ETHERNET_ADDRESS_LENGTH);

    PayloadLength += ETHERNET_ADDRESS_LENGTH;
    BaseVa += ETHERNET_ADDRESS_LENGTH;

    Mdl->ByteCount = (ULONG)(BaseVa - (PUCHAR)(Mdl->MappedSystemVa));

    // Fix up IP payload length and ICMPv6 checksum
    IpHeader->PayloadLength = HTONS(PayloadLength);

    Accumulator = ChecksumIpVersion6PseudoHeader(&IpHeader->SourceAddress,
                                                 &IpHeader->DestinationAddress,
                                                 PayloadLength,
                                                 IPPROTO_ICMPV6);
    AccumulateChecksum(&Accumulator, IcmpHeader, PayloadLength);

    IcmpHeader->Checksum = (USHORT)~Accumulator;

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Fragment == NULL)
        goto fail2;

    Fragment->Context = Buffer;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Transmitter->GnttabInterface,
                           Ring->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           TRUE,
                           &Fragment->Entry);
    if (!NT_SUCCESS(status))
        goto fail3;

    Fragment->Offset = 0;
    Fragment->Length = Mdl->ByteCount;

    InitializeListHead(&State->List);

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
    ASSERT3P(Buffer, ==, Fragment->Context);
    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail2:
    Error("fail2\n");

    Mdl->ByteCount = 0;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareMulticastControl(
    IN  PXENVIF_TRANSMITTER_RING            Ring,
    IN  PETHERNET_ADDRESS                   Address,
    IN  BOOLEAN                             Add
    )
{
    PXENVIF_TRANSMITTER_STATE               State;
    PXENVIF_TRANSMITTER_FRAGMENT            Fragment;
    PXENVIF_TRANSMITTER_MULTICAST_CONTROL   Control;
    NTSTATUS                                status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    State = &Ring->State;

    Control = __TransmitterGetMulticastControl(Ring);

    status = STATUS_NO_MEMORY;
    if (Control == NULL)
        goto fail1;

    Control->Type = (Add) ?
                    XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_ADD :
                    XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_REMOVE;
    Control->Address = *Address;

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Fragment == NULL)
        goto fail2;

    Fragment->Context = Control;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_MULTICAST_CONTROL;
    Control->Reference++;

    InitializeListHead(&State->List);

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __TransmitterPutMulticastControl(Ring, Control);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;
}

#define RING_SLOTS_AVAILABLE(_Front, _req_prod, _rsp_cons)   \
        (RING_SIZE(_Front) - ((_req_prod) - (_rsp_cons)))

static FORCEINLINE NTSTATUS
__TransmitterRingPostFragments(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    XENVIF_VIF_OFFLOAD_OPTIONS      OffloadOptions;
    USHORT                          MaximumSegmentSize;
    XENVIF_PACKET_HASH              Hash;
    RING_IDX                        req_prod;
    RING_IDX                        rsp_cons;
    ULONG                           Extra;
    BOOLEAN                         FirstRequest;
    PLIST_ENTRY                     ListEntry;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    netif_tx_request_t              *req;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;

    if (Packet != NULL) {
        OffloadOptions = Packet->OffloadOptions;
        MaximumSegmentSize = Packet->MaximumSegmentSize;
        Hash = Packet->Hash;
    } else {
        OffloadOptions.Value = 0;
        MaximumSegmentSize = 0;
        RtlZeroMemory(&Hash, sizeof (Hash));
    }

    ASSERT(!IsListEmpty(&State->List));
    ASSERT(State->Count != 0);
    ASSERT3U(State->Count, <=, XEN_NETIF_NR_SLOTS_MIN);

    req_prod = Ring->Front.req_prod_pvt;
    rsp_cons = Ring->Front.rsp_cons;

    ListEntry = State->List.Flink;
    Fragment = CONTAINING_RECORD(ListEntry,
                                 XENVIF_TRANSMITTER_FRAGMENT,
                                 ListEntry);

    Extra = 0;

    if (OffloadOptions.OffloadIpVersion4LargePacket ||
        OffloadOptions.OffloadIpVersion6LargePacket)
        Extra++;

    if (Fragment->Type == XENVIF_TRANSMITTER_FRAGMENT_TYPE_MULTICAST_CONTROL) {
        ASSERT(Transmitter->MulticastControl);
        Extra++;
    }

    if (Hash.Algorithm == XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ &&
        Hash.Type != XENVIF_PACKET_HASH_TYPE_NONE)
        Extra++;

    ASSERT3U(State->Count + Extra, <=, RING_SIZE(&Ring->Front));

    status = STATUS_ALLOTTED_SPACE_EXCEEDED;
    if (State->Count + Extra > RING_SLOTS_AVAILABLE(&Ring->Front, req_prod, rsp_cons))
        goto fail1;

    req = NULL;

    FirstRequest = TRUE;
    while (State->Count != 0) {
        --State->Count;

        ListEntry = RemoveHeadList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry,
                                     XENVIF_TRANSMITTER_FRAGMENT,
                                     ListEntry);

        req = RING_GET_REQUEST(&Ring->Front, req_prod);
        req_prod++;
        Ring->RequestsPosted++;

        req->id = Fragment->Id;
        req->gref = (Fragment->Entry != NULL) ?
                    XENBUS_GNTTAB(GetReference,
                                  &Transmitter->GnttabInterface,
                                  Fragment->Entry) :
                    0;
        req->offset = (USHORT)Fragment->Offset;
        req->size = (USHORT)Fragment->Length;
        req->flags = NETTXF_more_data;

        if (FirstRequest) {
            struct netif_extra_info *extra = NULL;

            FirstRequest = FALSE;

            if (OffloadOptions.OffloadIpVersion4TcpChecksum ||
                OffloadOptions.OffloadIpVersion4UdpChecksum ||
                OffloadOptions.OffloadIpVersion6TcpChecksum ||
                OffloadOptions.OffloadIpVersion6UdpChecksum)
                req->flags |= NETTXF_csum_blank | NETTXF_data_validated;

            if (OffloadOptions.OffloadIpVersion4LargePacket ||
                OffloadOptions.OffloadIpVersion6LargePacket) {
                ASSERT(req->flags & (NETTXF_csum_blank | NETTXF_data_validated));

                Fragment->Extra++;

                ASSERT(!(req->flags & NETTXF_extra_info));
                req->flags |= NETTXF_extra_info;

                extra = (struct netif_extra_info *)RING_GET_REQUEST(&Ring->Front, req_prod);
                req_prod++;
                Ring->RequestsPosted++;

                RtlZeroMemory(extra, sizeof (struct netif_extra_info));

                extra->type = XEN_NETIF_EXTRA_TYPE_GSO;

                extra->u.gso.type = (OffloadOptions.OffloadIpVersion4LargePacket) ?
                                    XEN_NETIF_GSO_TYPE_TCPV4 :
                                    XEN_NETIF_GSO_TYPE_TCPV6;
                extra->u.gso.size = MaximumSegmentSize;
            }

            if (Fragment->Type == XENVIF_TRANSMITTER_FRAGMENT_TYPE_MULTICAST_CONTROL) {
                PXENVIF_TRANSMITTER_MULTICAST_CONTROL   Control;

                Fragment->Extra++;

                if (req->flags & NETTXF_extra_info) {
                    ASSERT(extra != NULL);
                    extra->flags |= XEN_NETIF_EXTRA_FLAG_MORE;
                } else {
                    req->flags |= NETTXF_extra_info;
                }

                extra = (struct netif_extra_info *)RING_GET_REQUEST(&Ring->Front, req_prod);
                req_prod++;
                Ring->RequestsPosted++;

                RtlZeroMemory(extra, sizeof (struct netif_extra_info));

                Control = Fragment->Context;
                switch (Control->Type) {
                case XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_ADD:
                    extra->type = XEN_NETIF_EXTRA_TYPE_MCAST_ADD;
                    break;

                case XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_REMOVE:
                    extra->type = XEN_NETIF_EXTRA_TYPE_MCAST_DEL;
                    break;

                default:
                    ASSERT(FALSE);
                    break;
                }

                RtlCopyMemory(&extra->u.mcast.addr,
                              &Control->Address.Byte[0],
                              ETHERNET_ADDRESS_LENGTH);
            }

            if (Hash.Algorithm == XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ &&
                Hash.Type != XENVIF_PACKET_HASH_TYPE_NONE) {

                if (req->flags & NETTXF_extra_info) {
                    ASSERT(extra != NULL);
                    extra->flags |= XEN_NETIF_EXTRA_FLAG_MORE;
                } else {
                    req->flags |= NETTXF_extra_info;
                }

                Fragment->Extra++;

                extra = (struct netif_extra_info *)RING_GET_REQUEST(&Ring->Front, req_prod);
                req_prod++;
                Ring->RequestsPosted++;

                RtlZeroMemory(extra, sizeof (struct netif_extra_info));

                extra->type = XEN_NETIF_EXTRA_TYPE_HASH;

                switch (Hash.Type) {
                case XENVIF_PACKET_HASH_TYPE_IPV4:
                    extra->u.hash.type = _XEN_NETIF_CTRL_HASH_TYPE_IPV4;
                    break;

                case XENVIF_PACKET_HASH_TYPE_IPV4_TCP:
                    extra->u.hash.type = _XEN_NETIF_CTRL_HASH_TYPE_IPV4_TCP;
                    break;

                case XENVIF_PACKET_HASH_TYPE_IPV6:
                    extra->u.hash.type = _XEN_NETIF_CTRL_HASH_TYPE_IPV6;
                    break;

                case XENVIF_PACKET_HASH_TYPE_IPV6_TCP:
                    extra->u.hash.type = _XEN_NETIF_CTRL_HASH_TYPE_IPV6_TCP;
                    break;

                default:
                    ASSERT(FALSE);
                    break;
                }

                *(uint32_t *)extra->u.hash.value = Hash.Value;
            }
        }

        // Store a copy of the request in case we need to fake a response ourselves
        ASSERT3U(req->id, <=, XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);
        ASSERT3P(Ring->Pending[req->id], ==, NULL);
        Ring->Pending[req->id] = Fragment;
    }
    ASSERT(!FirstRequest);

    ASSERT(req != NULL);
    req->flags &= ~NETTXF_more_data;

    Ring->Front.req_prod_pvt = req_prod;

    ASSERT3U(State->Count, ==, 0);
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    if (Packet != NULL) {
        State->Packet = NULL;

        Ring->PacketsSent++;
    }

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return STATUS_SUCCESS;

fail1:
    return status;
}

#undef  RING_SLOTS_AVAILABLE

static FORCEINLINE VOID
__TransmitterRingFakeResponses(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    RING_IDX                        rsp_prod;
    USHORT                          id;
    ULONG                           Count;

    // This is only called when the backend went away. We need
    // to mimic the behavior of the backend and turn requests into
    // appropriate responses.

    KeMemoryBarrier();

    // We can't trust anything in the shared ring
    SHARED_RING_INIT(Ring->Shared);
    rsp_prod = Ring->Front.rsp_cons;

    KeMemoryBarrier();

    Count = 0;
    for (id = 0; id <= XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID; id++) {
        PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
        netif_tx_response_t             *rsp;
        ULONG                           Extra;

        Fragment = Ring->Pending[id];

        if (Fragment == NULL)
            continue;

        rsp = RING_GET_RESPONSE(&Ring->Front, rsp_prod);
        rsp_prod++;
        Count++;

        rsp->id = Fragment->Id;
        rsp->status = NETIF_RSP_DROPPED;

        for (Extra = 0; Extra < Fragment->Extra; Extra++) {
            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_prod);
            rsp_prod++;
            Count++;

            rsp->status = NETIF_RSP_NULL;
        }
    }

    KeMemoryBarrier();

    Ring->Shared->rsp_prod = rsp_prod;

    KeMemoryBarrier();

    ASSERT3U(Ring->Shared->rsp_prod, ==, Ring->Front.req_prod_pvt);

    if (Count != 0) {
        PXENVIF_TRANSMITTER Transmitter;
        PXENVIF_FRONTEND    Frontend;

        Transmitter = Ring->Transmitter;
        Frontend = Transmitter->Frontend;

        Info("%s[%u]: faked %lu responses\n",
             FrontendGetPath(Frontend),
             Ring->Index,
             Count);
    }
}

static FORCEINLINE VOID
__TransmitterRingCompletePacket(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    InsertTailList(&Ring->PacketComplete, &Packet->ListEntry);
    Ring->PacketsCompleted++;
}

static DECLSPEC_NOINLINE ULONG
TransmitterRingPoll(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    ULONG                           Count;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Count = 0;

    if (!Ring->Enabled)
        goto done;

    for (;;) {
        RING_IDX    rsp_prod;
        RING_IDX    rsp_cons;
        ULONG       Extra;

        KeMemoryBarrier();

        rsp_prod = Ring->Shared->rsp_prod;
        rsp_cons = Ring->Front.rsp_cons;

        KeMemoryBarrier();

        if (rsp_cons == rsp_prod) {
            RING_IDX WorkToDo;

            RING_FINAL_CHECK_FOR_RESPONSES(&Ring->Front, WorkToDo);
            if (WorkToDo)
                continue;

            break;
        }

        Extra = 0;
        while (rsp_cons != rsp_prod) {
            netif_tx_response_t             *rsp;
            uint16_t                        id;
            PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
            PXENVIF_TRANSMITTER_PACKET      Packet;

            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_cons);
            rsp_cons++;
            Ring->ResponsesProcessed++;
            Count++;

            Ring->Stopped = FALSE;

            if (rsp->status == NETIF_RSP_NULL) {
                ASSERT(Extra != 0);
                --Extra;
                continue;
            }

            ASSERT3U(Extra, ==, 0);

            id = rsp->id;

            ASSERT3U(id, <=, XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);
            Fragment = Ring->Pending[id];
            Ring->Pending[id] = NULL;

            ASSERT(Fragment != NULL);
            ASSERT3U(Fragment->Id, ==, id);

            switch (Fragment->Type) {
            case XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER: {
                PXENVIF_TRANSMITTER_BUFFER  Buffer;

                Buffer = Fragment->Context;
                Fragment->Context = NULL;
                Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

                Packet = Buffer->Context;
                Buffer->Context = NULL;

                ASSERT(Buffer->Reference != 0);
                --Buffer->Reference;
                __TransmitterPutBuffer(Ring, Buffer);

                break;
            }
            case XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET:
                Packet = Fragment->Context;
                Fragment->Context = NULL;
                Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

                break;

            case XENVIF_TRANSMITTER_FRAGMENT_TYPE_MULTICAST_CONTROL: {
                PXENVIF_TRANSMITTER_MULTICAST_CONTROL   Control;

                Control = Fragment->Context;
                Fragment->Context = NULL;
                Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

                switch (Control->Type) {
                case XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_ADD:
                case XENVIF_TRANSMITTER_MULTICAST_CONTROL_TYPE_REMOVE:
                    break;
                default:
                    ASSERT(FALSE);
                    break;
                }

                ASSERT(Control->Reference != 0);
                --Control->Reference;
                __TransmitterPutMulticastControl(Ring, Control);

                Packet = NULL;
                break;
            }
            default:
                ASSERT(FALSE);
                Packet = NULL;
                break;
            }

            Fragment->Length = 0;
            Fragment->Offset = 0;

            if (Fragment->Entry != NULL) {
                (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                                     &Transmitter->GnttabInterface,
                                     Ring->GnttabCache,
                                     TRUE,
                                     Fragment->Entry);
                Fragment->Entry = NULL;
            }

            Extra = Fragment->Extra;
            Fragment->Extra = 0;
            __TransmitterPutFragment(Ring, Fragment);

            if (Packet == NULL)
                continue;

            --Packet->Reference;

            if (rsp->status != NETIF_RSP_OKAY &&
                Packet->Completion.Status == 0) {
                switch (rsp->status) {
                case NETIF_RSP_DROPPED:
                    Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_DROPPED;
                    break;

                case NETIF_RSP_ERROR:
                    Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_ERROR;
                    break;

                default:
                    ASSERT(FALSE);
                    break;
                }
            }

            if (Packet->Reference != 0)
                continue;

            if (Packet->Completion.Status == 0)
                Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_OK;

            __TransmitterRingCompletePacket(Ring, Packet);
        }
        ASSERT3U(Extra, ==, 0);

        KeMemoryBarrier();

        Ring->Front.rsp_cons = rsp_cons;
    }

done:
    return Count;
}

static FORCEINLINE VOID
__TransmitterRingTrigger(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    if (!Ring->Connected)
        return;

    if (FrontendIsSplit(Frontend)) {
        ASSERT(Ring->Channel != NULL);

        (VOID) XENBUS_EVTCHN(Trigger,
                             &Transmitter->EvtchnInterface,
                             Ring->Channel);
    } else {
        ReceiverTrigger(FrontendGetReceiver(Frontend),
                        Ring->Index);
    }
}

static FORCEINLINE VOID
__TransmitterRingSend(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    if (!Ring->Connected)
        return;

    if (FrontendIsSplit(Frontend)) {
        ASSERT(Ring->Channel != NULL);

        (VOID) XENBUS_EVTCHN(Send,
                             &Transmitter->EvtchnInterface,
                             Ring->Channel);
    } else {
        ReceiverSend(FrontendGetReceiver(Frontend),
                     Ring->Index);
    }
}

static FORCEINLINE VOID
__TransmitterRingPushRequests(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    BOOLEAN                         Notify;

    if (Ring->RequestsPosted == Ring->RequestsPushed)
        return;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Ring->Front, Notify);

#pragma warning (pop)

    if (Notify)
        __TransmitterRingSend(Ring);

    Ring->RequestsPushed = Ring->RequestsPosted;
}

#define XENVIF_TRANSMITTER_ADVERTISEMENT_COUNT 3

#define XENVIF_TRANSMITTER_LOCK_BIT ((ULONG_PTR)1)

static DECLSPEC_NOINLINE VOID
TransmitterRingSwizzle(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       New;
    PLIST_ENTRY                     ListEntry;
    LIST_ENTRY                      List;
    ULONG                           Count;

    ASSERT3P(Ring->LockThread, ==, KeGetCurrentThread());

    InitializeListHead(&List);

    New = XENVIF_TRANSMITTER_LOCK_BIT;    
    Old = (ULONG_PTR)InterlockedExchangePointer(&Ring->Lock, (PVOID)New);

    ASSERT(Old & XENVIF_TRANSMITTER_LOCK_BIT);
    ListEntry = (PVOID)(Old & ~XENVIF_TRANSMITTER_LOCK_BIT);

    if (ListEntry == NULL)
        return;

    // Packets are held in the atomic packet list in reverse order
    // so that the most recent is always head of the list. This is
    // necessary to allow addition to the list to be done atomically.

    for (Count = 0; ListEntry != NULL; ++Count) {
        PLIST_ENTRY     NextEntry;

        NextEntry = ListEntry->Blink;
        ListEntry->Flink = ListEntry->Blink = ListEntry;

        InsertHeadList(&List, ListEntry);

        ListEntry = NextEntry;
    }

    if (!IsListEmpty(&List)) {
        ListEntry = List.Flink;

        RemoveEntryList(&List);
        AppendTailList(&Ring->PacketQueue, ListEntry);

        Ring->PacketsQueued += Count;
    }
}

static DECLSPEC_NOINLINE VOID
TransmitterRingSchedule(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER_STATE       State;
    BOOLEAN                         Polled;

    if(!Ring->Enabled)
        return;

    State = &Ring->State;
    Polled = FALSE;

    while (!Ring->Stopped) {
        NTSTATUS    status;

        if (State->Count != 0) {
            status = __TransmitterRingPostFragments(Ring);
            if (!NT_SUCCESS(status))
                Ring->Stopped = TRUE;
        }

        if (Ring->Stopped) {
            if (!Polled) {
                TransmitterRingPoll(Ring);
                Polled = TRUE;
            }

            continue;
        }

        if (Ring->RequestsPosted - Ring->RequestsPushed >=
            RING_SIZE(&Ring->Front) / 4)
            __TransmitterRingPushRequests(Ring);

        ASSERT3U(State->Count, ==, 0);

        if (!IsListEmpty(&Ring->RequestQueue)) {
            PLIST_ENTRY                 ListEntry;
            PXENVIF_TRANSMITTER_REQUEST Request;

            ListEntry = RemoveHeadList(&Ring->RequestQueue);
            ASSERT3P(ListEntry, !=, &Ring->RequestQueue);

            RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

            Request = CONTAINING_RECORD(ListEntry,
                                        XENVIF_TRANSMITTER_REQUEST,
                                        ListEntry);

            switch (Request->Type) {
            case XENVIF_TRANSMITTER_REQUEST_TYPE_ARP:
                (VOID) __TransmitterRingPrepareArp(Ring,
                                                   &Request->Arp.Address);
                break;

            case XENVIF_TRANSMITTER_REQUEST_TYPE_NEIGHBOUR_ADVERTISEMENT:
                (VOID) __TransmitterRingPrepareNeighbourAdvertisement(Ring,
                                                                      &Request->NeighbourAdvertisement.Address);
                break;

            case XENVIF_TRANSMITTER_REQUEST_TYPE_MULTICAST_CONTROL:
                (VOID) __TransmitterRingPrepareMulticastControl(Ring,
                                                                &Request->MulticastControl.Address,
                                                                Request->MulticastControl.Add);
                break;

            default:
                break;
            }

            Request->Type = XENVIF_TRANSMITTER_REQUEST_TYPE_INVALID;
            __TransmitterPutRequest(Ring, Request);
            continue;
        }

        if (!IsListEmpty(&Ring->PacketQueue)) {
            PLIST_ENTRY                 ListEntry;
            PXENVIF_TRANSMITTER_PACKET  Packet;

            ListEntry = RemoveHeadList(&Ring->PacketQueue);
            ASSERT3P(ListEntry, !=, &Ring->PacketQueue);

            RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

            Packet = CONTAINING_RECORD(ListEntry,
                                       XENVIF_TRANSMITTER_PACKET,
                                       ListEntry);

            Packet->Reference = 0;

            ASSERT3U(Packet->Completion.Status, ==, 0);

            status = __TransmitterRingPreparePacket(Ring, Packet);
            if (!NT_SUCCESS(status)) {
                PXENVIF_TRANSMITTER Transmitter;
                PXENVIF_FRONTEND    Frontend;

                Transmitter = Ring->Transmitter;
                Frontend = Transmitter->Frontend;

                ASSERT(status != STATUS_BUFFER_OVERFLOW);

                // Fake that we prapared and sent this packet
                Ring->PacketsPrepared++;
                Ring->PacketsSent++;
                Ring->PacketsFaked++;

                Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_DROPPED;

                __TransmitterRingCompletePacket(Ring, Packet);
            }

            ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
            continue;
        }

        break;
    }

    __TransmitterRingPushRequests(Ring);
}

static FORCEINLINE VOID
__TransmitterSetCompletionInfo(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PXENVIF_PACKET_INFO             Info;
    PUCHAR                          BaseVa;
    PETHERNET_HEADER                EthernetHeader;
    PETHERNET_ADDRESS               DestinationAddress;
    ETHERNET_ADDRESS_TYPE           Type;

    Frontend = Transmitter->Frontend;

    ASSERT(Packet->Completion.Status != 0);

    if (Packet->Completion.Status != XENVIF_TRANSMITTER_PACKET_OK) {
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_PACKETS_DROPPED,
                                   1);

        if (Packet->Completion.Status == XENVIF_TRANSMITTER_PACKET_ERROR)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_BACKEND_ERRORS,
                                       1);

        return;
    }

    BaseVa = Packet->Header;
    Info = &Packet->Info;
    Payload = &Packet->Payload;

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(BaseVa + Info->EthernetHeader.Offset);

    DestinationAddress = &EthernetHeader->DestinationAddress;

    Type = GET_ETHERNET_ADDRESS_TYPE(DestinationAddress);

    switch (Type) {
    case ETHERNET_ADDRESS_UNICAST:
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_UNICAST_PACKETS,
                                   1);
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_UNICAST_OCTETS,
                                   Packet->Length);
        break;

    case ETHERNET_ADDRESS_MULTICAST:
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_MULTICAST_PACKETS,
                                   1);
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_MULTICAST_OCTETS,
                                   Packet->Length);
        break;

    case ETHERNET_ADDRESS_BROADCAST:
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_BROADCAST_PACKETS,
                                   1);
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_BROADCAST_OCTETS,
                                   Packet->Length);
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    if (ETHERNET_HEADER_IS_TAGGED(EthernetHeader))
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_TAGGED_PACKETS,
                                   1);

    if (Info->LLCSnapHeader.Length != 0)
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_LLC_SNAP_PACKETS,
                                   1);

    if (Info->IpHeader.Length != 0) {
        PIP_HEADER  IpHeader = (PIP_HEADER)(BaseVa + Info->IpHeader.Offset);

        if (IpHeader->Version == 4) {
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_IPV4_PACKETS,
                                       1);
        } else {
            ASSERT3U(IpHeader->Version, ==, 6);

            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_IPV6_PACKETS,
                                       1);
        }
    }

    if (Info->TcpHeader.Length != 0)
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_TCP_PACKETS,
                                   1);

    if (Info->UdpHeader.Length != 0)
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_UDP_PACKETS,
                                   1);

    if (Packet->MaximumSegmentSize != 0)
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_GSO_PACKETS,
                                   1);

   if (Packet->Flags.IpChecksumSucceeded != 0)
       FrontendIncrementStatistic(Frontend,
                                  XENVIF_TRANSMITTER_IPV4_CHECKSUM_SUCCEEDED,
                                  1);

   if (Packet->Flags.IpChecksumFailed != 0)
       FrontendIncrementStatistic(Frontend,
                                  XENVIF_TRANSMITTER_IPV4_CHECKSUM_FAILED,
                                  1);

   if (Packet->Flags.IpChecksumNotValidated != 0)
       FrontendIncrementStatistic(Frontend,
                                  XENVIF_TRANSMITTER_IPV4_CHECKSUM_NOT_VALIDATED,
                                  1);

   if (Packet->Flags.TcpChecksumSucceeded != 0)
       FrontendIncrementStatistic(Frontend,
                                  XENVIF_TRANSMITTER_TCP_CHECKSUM_SUCCEEDED,
                                  1);

   if (Packet->Flags.TcpChecksumFailed != 0)
       FrontendIncrementStatistic(Frontend,
                                  XENVIF_TRANSMITTER_TCP_CHECKSUM_FAILED,
                                  1);

   if (Packet->Flags.TcpChecksumNotValidated != 0)
       FrontendIncrementStatistic(Frontend,
                                  XENVIF_TRANSMITTER_TCP_CHECKSUM_NOT_VALIDATED,
                                  1);

   if (Packet->Flags.UdpChecksumSucceeded != 0)
       FrontendIncrementStatistic(Frontend,
                                  XENVIF_TRANSMITTER_UDP_CHECKSUM_SUCCEEDED,
                                  1);

   if (Packet->Flags.UdpChecksumFailed != 0)
       FrontendIncrementStatistic(Frontend,
                                  XENVIF_TRANSMITTER_UDP_CHECKSUM_FAILED,
                                  1);

   if (Packet->Flags.UdpChecksumNotValidated != 0)
       FrontendIncrementStatistic(Frontend,
                                  XENVIF_TRANSMITTER_UDP_CHECKSUM_NOT_VALIDATED,
                                  1);

    Packet->Completion.Type = Type;
    Packet->Completion.PacketLength = (USHORT)Packet->Length;
    Packet->Completion.PayloadLength = (USHORT)Payload->Length;
}

static FORCEINLINE VOID
__TransmitterReturnPackets(
    IN  PXENVIF_TRANSMITTER Transmitter,
    IN  PLIST_ENTRY         List
    )
{
    PXENVIF_FRONTEND        Frontend;
    PXENVIF_VIF_CONTEXT     Context;

    Frontend = Transmitter->Frontend;
    Context = PdoGetVifContext(FrontendGetPdo(Frontend));

    while (!IsListEmpty(List)) {
        PLIST_ENTRY                 ListEntry;
        PXENVIF_TRANSMITTER_PACKET  Packet;

        ListEntry = RemoveHeadList(List);
        ASSERT3P(ListEntry, !=, List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Packet = CONTAINING_RECORD(ListEntry,
                                   XENVIF_TRANSMITTER_PACKET,
                                   ListEntry);

        __TransmitterSetCompletionInfo(Transmitter, Packet);

        VifTransmitterReturnPacket(Context,
                                   Packet->Cookie,
                                   &Packet->Completion);

        __TransmitterPutPacket(Transmitter, Packet);
    }
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingTryAcquireLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       New;
    BOOLEAN                         Acquired;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeMemoryBarrier();

    Old = (ULONG_PTR)Ring->Lock & ~XENVIF_TRANSMITTER_LOCK_BIT;
    New = Old | XENVIF_TRANSMITTER_LOCK_BIT;

    Acquired = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock,
                                                             (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;

    KeMemoryBarrier();

    if (Acquired) {
        ASSERT3P(Ring->LockThread, ==, NULL);
        Ring->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Acquired;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingAcquireLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    for (;;) {
        if (__TransmitterRingTryAcquireLock(Ring))
            break;

        _mm_pause();
    }
}

static VOID
TransmitterRingAcquireLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingTryReleaseLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       New;
    BOOLEAN                         Released;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3P(KeGetCurrentThread(), ==, Ring->LockThread);

    Old = XENVIF_TRANSMITTER_LOCK_BIT;
    New = 0;

    Ring->LockThread = NULL;

    KeMemoryBarrier();

    Released = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock,
                                                             (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;

    KeMemoryBarrier();

    if (!Released) {
        ASSERT3P(Ring->LockThread, ==, NULL);
        Ring->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Released;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingReleaseLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    LIST_ENTRY                      List;

    InitializeListHead(&List);

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    // As lock holder it is our responsibility to drain the atomic
    // packet list into the transmit queue before we actually drop the
    // lock. This may, of course, take a few attempts as another
    // thread could be simuntaneously adding to the list.

    do {
        TransmitterRingSwizzle(Ring);
        TransmitterRingSchedule(Ring);

        if (!IsListEmpty(&Ring->PacketComplete)) {
            PLIST_ENTRY     ListEntry = Ring->PacketComplete.Flink;

            RemoveEntryList(&Ring->PacketComplete);
            InitializeListHead(&Ring->PacketComplete);
            AppendTailList(&List, ListEntry);
        }
    } while (!__TransmitterRingTryReleaseLock(Ring));

    if (!IsListEmpty(&List)) {
        PXENVIF_TRANSMITTER Transmitter;

        Transmitter = Ring->Transmitter;

        __TransmitterReturnPackets(Transmitter, &List);
    }
}

static DECLSPEC_NOINLINE VOID
TransmitterRingReleaseLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE BOOLEAN
__TransmitterRingUnmask(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  BOOLEAN                     Force
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    if (!Ring->Connected || !FrontendIsSplit(Frontend))
        return TRUE;

    return !XENBUS_EVTCHN(Unmask,
                          &Transmitter->EvtchnInterface,
                          Ring->Channel,
                          FALSE,
                          Force);
}

__drv_functionClass(KDEFERRED_ROUTINE)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_sameIRQL
static VOID
TransmitterRingPollDpc(
    IN  PKDPC                   Dpc,
    IN  PVOID                   Context,
    IN  PVOID                   Argument1,
    IN  PVOID                   Argument2
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Context;
    ULONG                       Count;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Ring != NULL);

    Count = 0;

    for (;;) {
        __TransmitterRingAcquireLock(Ring);
        Count += TransmitterRingPoll(Ring);
        __TransmitterRingReleaseLock(Ring);

        if (__TransmitterRingUnmask(Ring,
                                    (Count > XENVIF_TRANSMITTER_RING_SIZE)))
            break;
    }
}

KSERVICE_ROUTINE    TransmitterRingEvtchnCallback;

BOOLEAN
TransmitterRingEvtchnCallback(
    IN  PKINTERRUPT             InterruptObject,
    IN  PVOID                   Argument
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Argument;
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Ring != NULL);

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT(FrontendIsSplit(Frontend));

    Ring->Events++;

    if (KeInsertQueueDpc(&Ring->PollDpc, NULL, NULL))
        Ring->PollDpcs++;

    return TRUE;
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define XENVIF_TRANSMITTER_WATCHDOG_PERIOD  30

static NTSTATUS
TransmitterRingWatchdog(
    IN  PXENVIF_THREAD          Self,
    IN  PVOID                   Context
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Context;
    PROCESSOR_NUMBER            ProcNumber;
    GROUP_AFFINITY              Affinity;
    LARGE_INTEGER               Timeout;
    ULONG                       PacketsQueued;
    NTSTATUS                    status;

    Trace("====>\n");

    if (RtlIsNtDdiVersionAvailable(NTDDI_WIN7) ) {
        //
        // Affinitize this thread to the same CPU as the event channel
        // and DPC.
        //
        // The following functions don't work before Windows 7
        //
        status = KeGetProcessorNumberFromIndex(Ring->Index, &ProcNumber);
        ASSERT(NT_SUCCESS(status));

        Affinity.Group = ProcNumber.Group;
        Affinity.Mask = (KAFFINITY)1 << ProcNumber.Number;
        KeSetSystemGroupAffinityThread(&Affinity, NULL);
    }

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(XENVIF_TRANSMITTER_WATCHDOG_PERIOD));
    PacketsQueued = 0;

    for (;;) { 
        PKEVENT Event;
        KIRQL   Irql;

        Event = ThreadGetEvent(Self);

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     &Timeout);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        KeRaiseIrql(DISPATCH_LEVEL, &Irql);
        __TransmitterRingAcquireLock(Ring);

        if (Ring->Enabled) {
            if (Ring->PacketsQueued == PacketsQueued &&
                Ring->PacketsCompleted != PacketsQueued) {
                PXENVIF_TRANSMITTER Transmitter;

                Transmitter = Ring->Transmitter;

                XENBUS_DEBUG(Trigger,
                             &Transmitter->DebugInterface,
                             Ring->DebugCallback);

                // Try to move things along
                __TransmitterRingTrigger(Ring);
                __TransmitterRingSend(Ring);
            }

            PacketsQueued = Ring->PacketsQueued;
        }

        __TransmitterRingReleaseLock(Ring);
        KeLowerIrql(Irql);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__TransmitterRingInitialize(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  ULONG                       Index,
    OUT PXENVIF_TRANSMITTER_RING    *Ring
    )
{
    PXENVIF_FRONTEND                Frontend;
    CHAR                            Name[MAXNAMELEN];
    NTSTATUS                        status;

    Frontend = Transmitter->Frontend;

    *Ring = __TransmitterAllocate(sizeof (XENVIF_TRANSMITTER_RING));

    status = STATUS_NO_MEMORY;
    if (*Ring == NULL)
        goto fail1;

    (*Ring)->Transmitter = Transmitter;
    (*Ring)->Index = Index;

    (*Ring)->Path = FrontendFormatPath(Frontend, Index);
    if ((*Ring)->Path == NULL)
        goto fail2;

    InitializeListHead(&(*Ring)->PacketQueue);
    InitializeListHead(&(*Ring)->RequestQueue);
    InitializeListHead(&(*Ring)->PacketComplete);

    KeInitializeDpc(&(*Ring)->PollDpc, TransmitterRingPollDpc, *Ring);

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_buffer",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail3;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Transmitter->CacheInterface,
                          Name,
                          sizeof (XENVIF_TRANSMITTER_BUFFER),
                          0,
                          0,
                          TransmitterBufferCtor,
                          TransmitterBufferDtor,
                          TransmitterRingAcquireLock,
                          TransmitterRingReleaseLock,
                          *Ring,
                          &(*Ring)->BufferCache);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_multicast_control",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail5;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Transmitter->CacheInterface,
                          Name,
                          sizeof (XENVIF_TRANSMITTER_MULTICAST_CONTROL),
                          0,
                          0,
                          TransmitterMulticastControlCtor,
                          TransmitterMulticastControlDtor,
                          TransmitterRingAcquireLock,
                          TransmitterRingReleaseLock,
                          *Ring,
                          &(*Ring)->MulticastControlCache);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_req_id",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail7;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_RANGE_SET(Create,
                              &Transmitter->RangeSetInterface,
                              Name,
                              &(*Ring)->RangeSet);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = XENBUS_RANGE_SET(Put,
                              &Transmitter->RangeSetInterface,
                              (*Ring)->RangeSet,
                              1,
                              XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);
    if (!NT_SUCCESS(status))
        goto fail9;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_fragment",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail10;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Transmitter->CacheInterface,
                          Name,
                          sizeof (XENVIF_TRANSMITTER_FRAGMENT),
                          0,
                          0,
                          TransmitterFragmentCtor,
                          TransmitterFragmentDtor,
                          TransmitterRingAcquireLock,
                          TransmitterRingReleaseLock,
                          *Ring,
                          &(*Ring)->FragmentCache);
    if (!NT_SUCCESS(status))
        goto fail11;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_request",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail12;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Transmitter->CacheInterface,
                          Name,
                          sizeof (XENVIF_TRANSMITTER_REQUEST),
                          0,
                          0,
                          TransmitterRequestCtor,
                          TransmitterRequestDtor,
                          TransmitterRingAcquireLock,
                          TransmitterRingReleaseLock,
                          *Ring,
                          &(*Ring)->RequestCache);
    if (!NT_SUCCESS(status))
        goto fail13;

    status = ThreadCreate(TransmitterRingWatchdog,
                          *Ring,
                          &(*Ring)->WatchdogThread);
    if (!NT_SUCCESS(status))
        goto fail14;

    return STATUS_SUCCESS;

fail14:
    Error("fail14\n");

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 (*Ring)->RequestCache);
    (*Ring)->RequestCache = NULL;

fail13:
    Error("fail13\n");

fail12:
    Error("fail12\n");

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 (*Ring)->FragmentCache);
    (*Ring)->FragmentCache = NULL;

fail11:
    Error("fail11\n");

fail10:
    Error("fail10\n");

    (VOID) XENBUS_RANGE_SET(Get,
                            &Transmitter->RangeSetInterface,
                            (*Ring)->RangeSet,
                            1,
                            XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);

fail9:
    Error("fail9\n");

    XENBUS_RANGE_SET(Destroy,
                     &Transmitter->RangeSetInterface,
                     (*Ring)->RangeSet);
    (*Ring)->RangeSet = NULL;

fail8:
    Error("fail8\n");

fail7:
    Error("fail7\n");

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 (*Ring)->MulticastControlCache);
    (*Ring)->MulticastControlCache = NULL;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 (*Ring)->BufferCache);
    (*Ring)->BufferCache = NULL;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    RtlZeroMemory(&(*Ring)->PollDpc, sizeof (KDPC));

    RtlZeroMemory(&(*Ring)->PacketComplete, sizeof (LIST_ENTRY));
    RtlZeroMemory(&(*Ring)->RequestQueue, sizeof (LIST_ENTRY));
    RtlZeroMemory(&(*Ring)->PacketQueue, sizeof (LIST_ENTRY));

    FrontendFreePath(Frontend, (*Ring)->Path);
    (*Ring)->Path = NULL;

fail2:
    Error("fail2\n");

    (*Ring)->Index = 0;
    (*Ring)->Transmitter = NULL;

    ASSERT(IsZeroMemory(*Ring, sizeof (XENVIF_TRANSMITTER_RING)));
    __TransmitterFree(*Ring);
    *Ring = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingConnect(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PFN_NUMBER                      Pfn;
    CHAR                            Name[MAXNAMELEN];
    ULONG                           Index;
    PROCESSOR_NUMBER                ProcNumber;
    NTSTATUS                        status;

    ASSERT(!Ring->Connected);

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter",
                                Ring->Path);
    if (!NT_SUCCESS(status))
        goto fail1;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_GNTTAB(CreateCache,
                           &Transmitter->GnttabInterface,
                           Name,
                           0,
                           TransmitterRingAcquireLock,
                           TransmitterRingReleaseLock,
                           Ring,
                           &Ring->GnttabCache);
    if (!NT_SUCCESS(status))
        goto fail2;

    Ring->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Ring->Mdl == NULL)
        goto fail3;

    ASSERT(Ring->Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    Ring->Shared = Ring->Mdl->MappedSystemVa;
    ASSERT(Ring->Shared != NULL);

    SHARED_RING_INIT(Ring->Shared);
    FRONT_RING_INIT(&Ring->Front, Ring->Shared, PAGE_SIZE);
    ASSERT3P(Ring->Front.sring, ==, Ring->Shared);

    Pfn = MmGetMdlPfnArray(Ring->Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Transmitter->GnttabInterface,
                           Ring->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           FALSE,
                           &Ring->Entry);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                __MODULE__ "|TRANSMITTER[%u]",
                                Ring->Index);
    if (!NT_SUCCESS(status))
        goto fail5;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    if (FrontendIsSplit(Frontend)) {
        Ring->Channel = XENBUS_EVTCHN(Open,
                                      &Transmitter->EvtchnInterface,
                                      XENBUS_EVTCHN_TYPE_UNBOUND,
                                      TransmitterRingEvtchnCallback,
                                      Ring,
                                      FrontendGetBackendDomain(Frontend),
                                      TRUE);

        status = STATUS_UNSUCCESSFUL;
        if (Ring->Channel == NULL)
            goto fail6;

        status = KeGetProcessorNumberFromIndex(Ring->Index, &ProcNumber);
        ASSERT(NT_SUCCESS(status));

        KeSetTargetProcessorDpcEx(&Ring->PollDpc, &ProcNumber);

        (VOID) XENBUS_EVTCHN(Bind,
                             &Transmitter->EvtchnInterface,
                             Ring->Channel,
                             ProcNumber.Group,
                             ProcNumber.Number);

        (VOID) XENBUS_EVTCHN(Unmask,
                             &Transmitter->EvtchnInterface,
                             Ring->Channel,
                             FALSE,
                             TRUE);
    }

    status = XENBUS_DEBUG(Register,
                          &Transmitter->DebugInterface,
                          Name,
                          TransmitterRingDebugCallback,
                          Ring,
                          &Ring->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail7;

    Ring->Connected = TRUE;

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    XENBUS_EVTCHN(Close,
                  &Transmitter->EvtchnInterface,
                  Ring->Channel);
    Ring->Channel = NULL;

    Ring->Events = 0;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Transmitter->GnttabInterface,
                         Ring->GnttabCache,
                         TRUE,
                         Ring->Entry);
    Ring->Entry = NULL;

fail4:
    Error("fail4\n");

    RtlZeroMemory(&Ring->Front, sizeof (netif_tx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

fail3:
    Error("fail3\n");

    XENBUS_GNTTAB(DestroyCache,
                  &Transmitter->GnttabInterface,
                  Ring->GnttabCache);
    Ring->GnttabCache = NULL;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingStoreWrite(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    ULONG                           Port;
    PCHAR                           Path;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Path = (FrontendGetNumQueues(Frontend) == 1) ?
           FrontendGetPath(Frontend) :
           Ring->Path;

    status = XENBUS_STORE(Printf,
                          &Transmitter->StoreInterface,
                          Transaction,
                          Path,
                          "tx-ring-ref",
                          "%u",
                          XENBUS_GNTTAB(GetReference,
                                        &Transmitter->GnttabInterface,
                                        Ring->Entry));
    if (!NT_SUCCESS(status))
        goto fail1;

    if (!FrontendIsSplit(Frontend))
        goto done;

    Port = XENBUS_EVTCHN(GetPort,
                         &Transmitter->EvtchnInterface,
                         Ring->Channel);

    status = XENBUS_STORE(Printf,
                          &Transmitter->StoreInterface,
                          Transaction,
                          Path,
                          "event-channel-tx",
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

static FORCEINLINE NTSTATUS
__TransmitterRingEnable(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Info("%s[%u]: ====>\n",
         FrontendGetPath(Frontend),
         Ring->Index);

    __TransmitterRingAcquireLock(Ring);

    ASSERT(!Ring->Enabled);
    Ring->Enabled = TRUE;

    KeInsertQueueDpc(&Ring->PollDpc, NULL, NULL);

    __TransmitterRingReleaseLock(Ring);

    Info("%s[%u]: <====\n",
         FrontendGetPath(Frontend),
         Ring->Index);

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
__TransmitterRingDisable(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{    
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PCHAR                           Buffer;
    XenbusState                     State;
    ULONG                           Attempt;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Info("%s[%u]: ====>\n",
         FrontendGetPath(Frontend),
         Ring->Index);

    __TransmitterRingAcquireLock(Ring);

    ASSERT(Ring->Enabled);

    // Release any fragments associated with a pending packet
    Packet = __TransmitterRingUnprepareFragments(Ring);

    // Put any packet back on the head of the queue
    if (Packet != NULL)
        InsertHeadList(&Ring->PacketQueue, &Packet->ListEntry);

    // Discard any pending requests
    while (!IsListEmpty(&Ring->RequestQueue)) {
        PLIST_ENTRY                 ListEntry;
        PXENVIF_TRANSMITTER_REQUEST Request;

        ListEntry = RemoveHeadList(&Ring->RequestQueue);
        ASSERT3P(ListEntry, !=, &Ring->RequestQueue);

        Request = CONTAINING_RECORD(ListEntry,
                                    XENVIF_TRANSMITTER_REQUEST,
                                    ListEntry);

        Request->Type = XENVIF_TRANSMITTER_REQUEST_TYPE_INVALID;
        __TransmitterPutRequest(Ring, Request);
    }

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "state",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        State = XenbusStateUnknown;
    } else {
        State = (XenbusState)strtol(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    Attempt = 0;
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);
    while (Ring->ResponsesProcessed != Ring->RequestsPushed) {
        Attempt++;
        ASSERT(Attempt < 100);

        // Try to move things along
        __TransmitterRingSend(Ring);
        (VOID) TransmitterRingPoll(Ring);

        if (State != XenbusStateConnected)
            __TransmitterRingFakeResponses(Ring);

        // We are waiting for a watch event at DISPATCH_LEVEL so
        // it is our responsibility to poll the store ring.
        XENBUS_STORE(Poll,
                     &Transmitter->StoreInterface);

        KeStallExecutionProcessor(1000);    // 1ms
    }

    Ring->Enabled = FALSE;

    __TransmitterRingReleaseLock(Ring);

    Info("%s[%u]: <====\n",
         FrontendGetPath(Frontend),
         Ring->Index);
}

static FORCEINLINE VOID
__TransmitterRingDisconnect(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    ASSERT(Ring->Connected);
    Ring->Connected = FALSE;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    if (Ring->Channel != NULL) {
        XENBUS_EVTCHN(Close,
                      &Transmitter->EvtchnInterface,
                      Ring->Channel);
        Ring->Channel = NULL;

        Ring->Events = 0;
    }

    Ring->PollDpcs = 0;

    ASSERT3U(Ring->ResponsesProcessed, ==, Ring->RequestsPushed);
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);

    Ring->ResponsesProcessed = 0;
    Ring->RequestsPushed = 0;
    Ring->RequestsPosted = 0;

    XENBUS_DEBUG(Deregister,
                 &Transmitter->DebugInterface,
                 Ring->DebugCallback);
    Ring->DebugCallback = NULL;

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Transmitter->GnttabInterface,
                         Ring->GnttabCache,
                         TRUE,
                         Ring->Entry);
    Ring->Entry = NULL;

    RtlZeroMemory(&Ring->Front, sizeof (netif_tx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

    XENBUS_GNTTAB(DestroyCache,
                  &Transmitter->GnttabInterface,
                  Ring->GnttabCache);
    Ring->GnttabCache = NULL;
}

static FORCEINLINE VOID
__TransmitterRingTeardown(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Ring->PollDpcs = 0;

    RtlZeroMemory(&Ring->PollDpc, sizeof (KDPC));

    ASSERT3U(Ring->PacketsCompleted, ==, Ring->PacketsSent);
    ASSERT3U(Ring->PacketsSent, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);
    ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    ASSERT3U(Ring->PacketsQueued, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);

    Ring->PacketsCompleted = 0;
    Ring->PacketsSent = 0;
    Ring->PacketsCopied = 0;
    Ring->PacketsGranted = 0;
    Ring->PacketsFaked = 0;
    Ring->PacketsUnprepared = 0;
    Ring->PacketsPrepared = 0;
    Ring->PacketsQueued = 0;

    ThreadAlert(Ring->WatchdogThread);
    ThreadJoin(Ring->WatchdogThread);
    Ring->WatchdogThread = NULL;

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Ring->RequestCache);
    Ring->RequestCache = NULL;

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Ring->FragmentCache);
    Ring->FragmentCache = NULL;

    (VOID) XENBUS_RANGE_SET(Get,
                            &Transmitter->RangeSetInterface,
                            Ring->RangeSet,
                            1,
                            XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);

    XENBUS_RANGE_SET(Destroy,
                     &Transmitter->RangeSetInterface,
                     Ring->RangeSet);
    Ring->RangeSet = NULL;

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Ring->MulticastControlCache);
    Ring->MulticastControlCache = NULL;

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Ring->BufferCache);
    Ring->BufferCache = NULL;

    ASSERT(IsListEmpty(&Ring->PacketComplete));
    RtlZeroMemory(&Ring->PacketComplete, sizeof (LIST_ENTRY));

    ASSERT(IsListEmpty(&Ring->RequestQueue));
    RtlZeroMemory(&Ring->RequestQueue, sizeof (LIST_ENTRY));

    ASSERT(IsListEmpty(&Ring->PacketQueue));
    RtlZeroMemory(&Ring->PacketQueue, sizeof (LIST_ENTRY));

    FrontendFreePath(Frontend, Ring->Path);
    Ring->Path = NULL;

    Ring->Index = 0;
    Ring->Transmitter = NULL;

    ASSERT(IsZeroMemory(Ring, sizeof (XENVIF_TRANSMITTER_RING)));
    __TransmitterFree(Ring);
}

static FORCEINLINE VOID
__TransmitterRingQueuePacket(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet,
    IN  BOOLEAN                     More
    )
{
    PLIST_ENTRY                     ListEntry;
    ULONG_PTR                       Old;
    ULONG_PTR                       LockBit;
    ULONG_PTR                       New;

    ListEntry = &Packet->ListEntry;

    do {
        Old = (ULONG_PTR)Ring->Lock;
        LockBit = Old & XENVIF_TRANSMITTER_LOCK_BIT;

        ListEntry->Blink = (PVOID)(Old & ~XENVIF_TRANSMITTER_LOCK_BIT);
        New = (ULONG_PTR)ListEntry;
        ASSERT((New & XENVIF_TRANSMITTER_LOCK_BIT) == 0);
        New |= LockBit;
    } while ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock, (PVOID)New, (PVOID)Old) != Old);

    // __TransmitterRingReleaseLock() drains the atomic packet list into the transmit queue therefore,
    // after adding to the list we need to attempt to grab and release the lock. If we can't
    // grab it then that's ok because whichever thread is holding it will have to call
    // __TransmitterRingReleaseLock() and will therefore drain the atomic packet list.

    if (More)
        return;

    if (__TransmitterRingTryAcquireLock(Ring))
        __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__TransmitterRingAbortPackets(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    ULONG                           Count;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    __TransmitterRingAcquireLock(Ring);

    TransmitterRingSwizzle(Ring);

    Count = 0;
    while (!IsListEmpty(&Ring->PacketQueue)) {
        PLIST_ENTRY                 ListEntry;
        PXENVIF_TRANSMITTER_PACKET  Packet;
        
        ListEntry = RemoveHeadList(&Ring->PacketQueue);
        ASSERT3P(ListEntry, !=, &Ring->PacketQueue);

        Packet = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_PACKET, ListEntry);
        Packet->ListEntry.Flink = Packet->ListEntry.Blink = NULL;

        // Fake that we prapared and sent this packet
        Ring->PacketsPrepared++;
        Ring->PacketsSent++;
        Ring->PacketsFaked++;

        Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_DROPPED;

        __TransmitterRingCompletePacket(Ring, Packet);
        Count++;
    }

    Info("%s[%u]: aborted %u packets\n",
         FrontendGetPath(Frontend),
         Ring->Index,
         Count);

    ASSERT3U(Ring->PacketsSent, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);
    ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    ASSERT3U(Ring->PacketsQueued, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);

    ASSERT3P((ULONG_PTR)Ring->Lock, ==, XENVIF_TRANSMITTER_LOCK_BIT);
    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE NTSTATUS
__TransmitterRingQueueArp(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PIPV4_ADDRESS               Address
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_REQUEST     Request;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    __TransmitterRingAcquireLock(Ring);

    status = STATUS_UNSUCCESSFUL;
    if (!Ring->Enabled)
        goto fail1;

    Request = __TransmitterGetRequest(Ring);

    status = STATUS_NO_MEMORY;
    if (Request == NULL)
        goto fail2;

    Request->Type = XENVIF_TRANSMITTER_REQUEST_TYPE_ARP;
    Request->Arp.Address = *Address;

    InsertTailList(&Ring->RequestQueue, &Request->ListEntry);

    __TransmitterRingReleaseLock(Ring);

    Info("%s[%u]: %u.%u.%u.%u\n",
         FrontendGetPath(Frontend),
         Ring->Index,
         Address->Byte[0],
         Address->Byte[1],
         Address->Byte[2],
         Address->Byte[3]);

    return STATUS_SUCCESS;

fail2:
fail1:
    __TransmitterRingReleaseLock(Ring);

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingQueueNeighbourAdvertisement(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PIPV6_ADDRESS               Address
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_REQUEST     Request;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    __TransmitterRingAcquireLock(Ring);

    status = STATUS_UNSUCCESSFUL;
    if (!Ring->Enabled)
        goto fail1;

    Request = __TransmitterGetRequest(Ring);

    status = STATUS_NO_MEMORY;
    if (Request == NULL)
        goto fail2;

    Request->Type = XENVIF_TRANSMITTER_REQUEST_TYPE_NEIGHBOUR_ADVERTISEMENT;
    Request->NeighbourAdvertisement.Address = *Address;

    InsertTailList(&Ring->RequestQueue, &Request->ListEntry);

    __TransmitterRingReleaseLock(Ring);

    Info("%s[%u]: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
         FrontendGetPath(Frontend),
         Ring->Index,
         HTONS(Address->Word[0]),
         HTONS(Address->Word[1]),
         HTONS(Address->Word[2]),
         HTONS(Address->Word[3]),
         HTONS(Address->Word[4]),
         HTONS(Address->Word[5]),
         HTONS(Address->Word[6]),
         HTONS(Address->Word[7]));

    return STATUS_SUCCESS;

fail2:
fail1:
    __TransmitterRingReleaseLock(Ring);

    return status;
}

static FORCEINLINE BOOLEAN
__TransmitterHasMulticastControl(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    return Transmitter->MulticastControl;
}

BOOLEAN
TransmitterHasMulticastControl(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    return __TransmitterHasMulticastControl(Transmitter);
}

static FORCEINLINE NTSTATUS
__TransmitterRingQueueMulticastControl(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PETHERNET_ADDRESS           Address,
    IN  BOOLEAN                     Add
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_REQUEST     Request;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;

    status = STATUS_NOT_SUPPORTED;
    if (!__TransmitterHasMulticastControl(Transmitter))
        goto fail1;

    Frontend = Transmitter->Frontend;

    __TransmitterRingAcquireLock(Ring);

    status = STATUS_UNSUCCESSFUL;
    if (!Ring->Enabled)
        goto fail2;

    Request = __TransmitterGetRequest(Ring);

    status = STATUS_NO_MEMORY;
    if (Request == NULL)
        goto fail3;

    Request->Type = XENVIF_TRANSMITTER_REQUEST_TYPE_MULTICAST_CONTROL;
    Request->MulticastControl.Address = *Address;
    Request->MulticastControl.Add = Add;

    InsertTailList(&Ring->RequestQueue, &Request->ListEntry);

    __TransmitterRingReleaseLock(Ring);

    Info("%s[%u]: %s %02X:%02X:%02X:%02X:%02X:%02X\n",
         FrontendGetPath(Frontend),
         Ring->Index,
         (Add) ? "ADD" : "REMOVE",
         Address->Byte[0],
         Address->Byte[1],
         Address->Byte[2],
         Address->Byte[3],
         Address->Byte[4],
         Address->Byte[5]);

    return STATUS_SUCCESS;

fail3:
fail2:
    __TransmitterRingReleaseLock(Ring);

fail1:
    return status;
}

static VOID
TransmitterDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Crashing);
}

NTSTATUS
TransmitterInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_TRANSMITTER *Transmitter
    )
{
    HANDLE                  ParametersKey;
    CHAR                    Name[MAXNAMELEN];
    LONG                    MaxQueues;
    LONG                    Index;
    NTSTATUS                status;

    *Transmitter = __TransmitterAllocate(sizeof (XENVIF_TRANSMITTER));

    status = STATUS_NO_MEMORY;
    if (*Transmitter == NULL)
        goto fail1;

    ParametersKey = DriverGetParametersKey();

    (*Transmitter)->DisableIpVersion4Gso = 0;
    (*Transmitter)->DisableIpVersion6Gso = 0;
    (*Transmitter)->AlwaysCopy = 0;
    (*Transmitter)->ValidateChecksums = 0;
    (*Transmitter)->DisableMulticastControl = 0;

    if (ParametersKey != NULL) {
        ULONG   TransmitterDisableIpVersion4Gso;
        ULONG   TransmitterDisableIpVersion6Gso;
        ULONG   TransmitterAlwaysCopy;
        ULONG   TransmitterValidateChecksums;
        ULONG   TransmitterDisableMulticastControl;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterDisableIpVersion4Gso",
                                         &TransmitterDisableIpVersion4Gso);
        if (NT_SUCCESS(status))
            (*Transmitter)->DisableIpVersion4Gso = TransmitterDisableIpVersion4Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterDisableIpVersion6Gso",
                                         &TransmitterDisableIpVersion6Gso);
        if (NT_SUCCESS(status))
            (*Transmitter)->DisableIpVersion6Gso = TransmitterDisableIpVersion6Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterAlwaysCopy",
                                         &TransmitterAlwaysCopy);
        if (NT_SUCCESS(status))
            (*Transmitter)->AlwaysCopy = TransmitterAlwaysCopy;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterValidateChecksums",
                                         &TransmitterValidateChecksums);
        if (NT_SUCCESS(status))
            (*Transmitter)->ValidateChecksums = TransmitterValidateChecksums;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterDisableMulticastControl",
                                         &TransmitterDisableMulticastControl);
        if (NT_SUCCESS(status))
            (*Transmitter)->DisableMulticastControl = TransmitterDisableMulticastControl;
    }

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Transmitter)->DebugInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Transmitter)->StoreInterface);

    FdoGetRangeSetInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                            &(*Transmitter)->RangeSetInterface);

    FdoGetCacheInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Transmitter)->CacheInterface);

    FdoGetGnttabInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Transmitter)->GnttabInterface);

    FdoGetEvtchnInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Transmitter)->EvtchnInterface);

    (*Transmitter)->Frontend = Frontend;
    KeInitializeSpinLock(&(*Transmitter)->Lock);

    status = XENBUS_RANGE_SET(Acquire, &(*Transmitter)->RangeSetInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_CACHE(Acquire, &(*Transmitter)->CacheInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_packet",
                                FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail4;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &(*Transmitter)->CacheInterface,
                          Name,
                          sizeof (XENVIF_TRANSMITTER_PACKET),
                          XENVIF_PACKET_CACHE_RESERVATION,
                          0,
                          TransmitterPacketCtor,
                          TransmitterPacketDtor,
                          TransmitterPacketAcquireLock,
                          TransmitterPacketReleaseLock,
                          *Transmitter,
                          &(*Transmitter)->PacketCache);
    if (!NT_SUCCESS(status))
        goto fail5;

    MaxQueues = FrontendGetMaxQueues(Frontend);
    (*Transmitter)->Ring = __TransmitterAllocate(sizeof (PXENVIF_TRANSMITTER_RING) *
                                                 MaxQueues);

    status = STATUS_NO_MEMORY;
    if ((*Transmitter)->Ring == NULL)
        goto fail6;

    Index = 0;
    while (Index < MaxQueues) {
        PXENVIF_TRANSMITTER_RING    Ring;

        status = __TransmitterRingInitialize(*Transmitter, Index, &Ring);
        if (!NT_SUCCESS(status))
            goto fail7;

        (*Transmitter)->Ring[Index] = Ring;
        Index++;
    }

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    while (--Index > 0) {
        PXENVIF_TRANSMITTER_RING    Ring = (*Transmitter)->Ring[Index];

        (*Transmitter)->Ring[Index] = NULL;
        __TransmitterRingTeardown(Ring);
    }

    __TransmitterFree((*Transmitter)->Ring);
    (*Transmitter)->Ring = NULL;

fail6:
    Error("fail6\n");

    XENBUS_CACHE(Destroy,
                 &(*Transmitter)->CacheInterface,
                 (*Transmitter)->PacketCache);
    (*Transmitter)->PacketCache = NULL;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

    XENBUS_CACHE(Release, &(*Transmitter)->CacheInterface);

fail3:
    Error("fail3\n");

    XENBUS_RANGE_SET(Release, &(*Transmitter)->RangeSetInterface);

fail2:
    Error("fail2\n");

    (*Transmitter)->Frontend = NULL;

    RtlZeroMemory(&(*Transmitter)->Lock,
                  sizeof (KSPIN_LOCK));

    RtlZeroMemory(&(*Transmitter)->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->RangeSetInterface,
                  sizeof (XENBUS_RANGE_SET_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    (*Transmitter)->DisableIpVersion4Gso = 0;
    (*Transmitter)->DisableIpVersion6Gso = 0;
    (*Transmitter)->AlwaysCopy = 0;
    (*Transmitter)->ValidateChecksums = 0;
    (*Transmitter)->DisableMulticastControl = 0;
    
    ASSERT(IsZeroMemory(*Transmitter, sizeof (XENVIF_TRANSMITTER)));
    __TransmitterFree(*Transmitter);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
TransmitterConnect(
    IN  PXENVIF_TRANSMITTER     Transmitter
    )
{
    PXENVIF_FRONTEND            Frontend;
    PCHAR                       Buffer;
    LONG                        Index;
    NTSTATUS                    status;

    Trace("====>\n");

    Frontend = Transmitter->Frontend;

    status = XENBUS_DEBUG(Acquire, &Transmitter->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Transmitter->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_EVTCHN(Acquire, &Transmitter->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_GNTTAB(Acquire, &Transmitter->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    if (Transmitter->DisableMulticastControl == 0) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-dynamic-multicast-control",
                              &Buffer);
        if (NT_SUCCESS(status)) {
            Transmitter->MulticastControl = (BOOLEAN)strtol(Buffer, NULL, 2);

            XENBUS_STORE(Free,
                         &Transmitter->StoreInterface,
                         Buffer);
        }
    }

    Index = 0;
    while (Index < (LONG)FrontendGetNumQueues(Frontend)) {
        PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[Index];

        status = __TransmitterRingConnect(Ring);
        if (!NT_SUCCESS(status))
            goto fail5;

        Index++;
    }    

    status = XENBUS_DEBUG(Register,
                          &Transmitter->DebugInterface,
                          __MODULE__ "|TRANSMITTER",
                          TransmitterDebugCallback,
                          Transmitter,
                          &Transmitter->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail6;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

    Index = FrontendGetNumQueues(Frontend);

fail5:
    Error("fail5\n");

    while (--Index >= 0) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = Transmitter->Ring[Index];

        __TransmitterRingDisconnect(Ring);
    }

    Transmitter->MulticastControl = FALSE;

    XENBUS_GNTTAB(Release, &Transmitter->GnttabInterface);

fail4:
    Error("fail4\n");

    XENBUS_EVTCHN(Release, &Transmitter->EvtchnInterface);

fail3:
    Error("fail3\n");

    XENBUS_STORE(Release, &Transmitter->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Transmitter->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRequestMulticastControl(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  BOOLEAN                     Enabled
    )
{
    PXENVIF_FRONTEND                Frontend;
    NTSTATUS                        status;

    Frontend = Transmitter->Frontend;

    status = XENBUS_STORE(Printf,
                          &Transmitter->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "request-multicast-control",
                          "%u",
                          Enabled);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
TransmitterRequestMulticastControl(
    IN  PXENVIF_TRANSMITTER Transmitter,
    IN  BOOLEAN             Enabled
    )
{
    NTSTATUS                status;

    status = STATUS_NOT_SUPPORTED;
    if (!__TransmitterHasMulticastControl(Transmitter))
        goto fail1;

    status = __TransmitterRequestMulticastControl(Transmitter, NULL,
                                                  Enabled);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
fail1:
    return status;
}

NTSTATUS
TransmitterStoreWrite(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend;
    NTSTATUS                        status;
    LONG                            Index;

    Frontend = Transmitter->Frontend;

    if (__TransmitterHasMulticastControl(Transmitter)) {
        status = __TransmitterRequestMulticastControl(Transmitter,
                                                      Transaction,
                                                      TRUE);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    Index = 0;
    while (Index < (LONG)FrontendGetNumQueues(Frontend)) {
        PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[Index];

        status = __TransmitterRingStoreWrite(Ring, Transaction);
        if (!NT_SUCCESS(status))
            goto fail2;

        Index++;
    }    

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
TransmitterEnable(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;

    Trace("====>\n");

    Frontend = Transmitter->Frontend;

    Index = 0;
    while (Index < (LONG)FrontendGetNumQueues(Frontend)) {
        PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[Index];

        __TransmitterRingEnable(Ring);
        Index++;
    }    

    Trace("<====\n");
    return STATUS_SUCCESS;
}

VOID
TransmitterDisable(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PXENVIF_FRONTEND       Frontend;
    LONG                   Index;

    Trace("====>\n");

    Frontend = Transmitter->Frontend;

    Index = FrontendGetNumQueues(Frontend);
    while (--Index >= 0) {
        PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[Index];

        __TransmitterRingDisable(Ring);
    }

    Trace("<====\n");
}

VOID
TransmitterDisconnect(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;

    Trace("====>\n");

    Frontend = Transmitter->Frontend;

    XENBUS_DEBUG(Deregister,
                 &Transmitter->DebugInterface,
                 Transmitter->DebugCallback);
    Transmitter->DebugCallback = NULL;

    Index = FrontendGetNumQueues(Frontend);
    while (--Index >= 0) {
        PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[Index];

        __TransmitterRingDisconnect(Ring);
    }

    Transmitter->MulticastControl = FALSE;

    XENBUS_GNTTAB(Release, &Transmitter->GnttabInterface);

    XENBUS_EVTCHN(Release, &Transmitter->EvtchnInterface);

    XENBUS_STORE(Release, &Transmitter->StoreInterface);

    XENBUS_DEBUG(Release, &Transmitter->DebugInterface);

    Trace("<====\n");
}

VOID
TransmitterTeardown(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;

    Frontend = Transmitter->Frontend;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    KeFlushQueuedDpcs();

    Index = FrontendGetMaxQueues(Frontend);
    while (--Index >= 0) {
        PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[Index];

        Transmitter->Ring[Index] = NULL;
        __TransmitterRingTeardown(Ring);
    }

    __TransmitterFree(Transmitter->Ring);
    Transmitter->Ring = NULL;

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Transmitter->PacketCache);
    Transmitter->PacketCache = NULL;

    XENBUS_CACHE(Release, &Transmitter->CacheInterface);

    XENBUS_RANGE_SET(Release, &Transmitter->RangeSetInterface);

    Transmitter->Frontend = NULL;

    RtlZeroMemory(&Transmitter->Lock,
                  sizeof (KSPIN_LOCK));

    RtlZeroMemory(&Transmitter->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    RtlZeroMemory(&Transmitter->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&Transmitter->RangeSetInterface,
                  sizeof (XENBUS_RANGE_SET_INTERFACE));

    RtlZeroMemory(&Transmitter->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Transmitter->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Transmitter->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    Transmitter->DisableIpVersion4Gso = 0;
    Transmitter->DisableIpVersion6Gso = 0;
    Transmitter->AlwaysCopy = 0;
    Transmitter->ValidateChecksums = 0;
    Transmitter->DisableMulticastControl = 0;

    ASSERT(IsZeroMemory(Transmitter, sizeof (XENVIF_TRANSMITTER)));
    __TransmitterFree(Transmitter);
}

static FORCEINLINE VOID
__TransmitterHashAccumulate(
    IN OUT  PULONG  Accumulator,
    IN      PUCHAR  Array,
    IN      ULONG   Length
    )
{
    ULONG           Current;
    ULONG           Index;

    Current = *Accumulator;

    for (Index = 0; Index < Length; Index++) {
        ULONG   Overflow;

        Current = (Current << 4) + Array[Index];

        Overflow = Current & 0x000fff00;
        if (Overflow != 0) {
            Current ^= Overflow >> 8;
            Current ^= Overflow;
        }
    }

    *Accumulator = Current;
}

static FORCEINLINE ULONG
__TransmitterHashPacket(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    PXENVIF_FRONTEND                Frontend;
    PUCHAR                          BaseVa;
    PXENVIF_PACKET_INFO             Info;
    PIP_HEADER                      IpHeader;
    ULONG                           Value;

    Frontend = Transmitter->Frontend;

    BaseVa = Packet->Header;
    Info = &Packet->Info;

    if (Info->IpHeader.Length == 0) {
        Value = KeGetCurrentProcessorNumberEx(NULL);
        goto done;
    }

    IpHeader = (PIP_HEADER)(BaseVa + Info->IpHeader.Offset);

    Value = 0;

    if (FrontendGetNumQueues(Frontend) == 1)
        goto done;

    if (IpHeader->Version == 4) {
        PIPV4_HEADER    Version4 = &IpHeader->Version4;

        __TransmitterHashAccumulate(&Value,
                                    Version4->SourceAddress.Byte,
                                    IPV4_ADDRESS_LENGTH);
        __TransmitterHashAccumulate(&Value,
                                    Version4->DestinationAddress.Byte,
                                    IPV4_ADDRESS_LENGTH);
    } else {
        PIPV6_HEADER    Version6 = &IpHeader->Version6;

        ASSERT3U(IpHeader->Version, ==, 6);

        __TransmitterHashAccumulate(&Value,
                                    Version6->SourceAddress.Byte,
                                    IPV6_ADDRESS_LENGTH);
        __TransmitterHashAccumulate(&Value,
                                    Version6->DestinationAddress.Byte,
                                    IPV6_ADDRESS_LENGTH);
    }

    if (Info->TcpHeader.Length != 0) {
        PTCP_HEADER TcpHeader;

        TcpHeader = (PTCP_HEADER)(BaseVa + Info->TcpHeader.Offset);

        __TransmitterHashAccumulate(&Value,
                                    (PUCHAR)&TcpHeader->SourcePort,
                                    sizeof (USHORT));
        __TransmitterHashAccumulate(&Value,
                                    (PUCHAR)&TcpHeader->DestinationPort,
                                    sizeof (USHORT));
    } else if (Info->UdpHeader.Length != 0) {
        PUDP_HEADER UdpHeader;

        ASSERT(Info->UdpHeader.Length != 0);

        UdpHeader = (PUDP_HEADER)(BaseVa + Info->UdpHeader.Offset);

        __TransmitterHashAccumulate(&Value,
                                    (PUCHAR)&UdpHeader->SourcePort,
                                    sizeof (USHORT));
        __TransmitterHashAccumulate(&Value,
                                    (PUCHAR)&UdpHeader->DestinationPort,
                                    sizeof (USHORT));
    }

done:
    return Value;
}

NTSTATUS
TransmitterQueuePacket(
    IN  PXENVIF_TRANSMITTER         Transmitter,
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
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PUCHAR                          BaseVa;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PXENVIF_PACKET_INFO             Info;
    XENVIF_PACKET_HASH_ALGORITHM    Algorithm;
    ULONG                           Value;
    ULONG                           Index;
    PXENVIF_TRANSMITTER_RING        Ring;
    NTSTATUS                        status;

    Frontend = Transmitter->Frontend;

    Packet = __TransmitterGetPacket(Transmitter);

    status = STATUS_NO_MEMORY;
    if (Packet == NULL)
        goto fail1;

    Packet->Mdl = Mdl;
    Packet->Offset = Offset;
    Packet->Length = Length;
    Packet->OffloadOptions = OffloadOptions;
    Packet->MaximumSegmentSize = MaximumSegmentSize;
    Packet->TagControlInformation = TagControlInformation;
    Packet->Hash = *Hash;
    Packet->Cookie = Cookie;

    BaseVa = Packet->Header;

    Payload = &Packet->Payload;
    Payload->Mdl = Packet->Mdl;
    Payload->Offset = Packet->Offset;
    Payload->Length = Packet->Length;

    Info = &Packet->Info;

    (VOID) ParsePacket(BaseVa, TransmitterPullup, Transmitter, Payload, Info);

    Algorithm = Hash->Algorithm;

    switch (Algorithm) {
    case XENVIF_PACKET_HASH_ALGORITHM_NONE:
        Value = __TransmitterHashPacket(Transmitter, Packet);
        More = FALSE;
        break;

    case XENVIF_PACKET_HASH_ALGORITHM_UNSPECIFIED:
        Value = Hash->Value;
        More = FALSE;
        break;

    case XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ:
        Value = Hash->Value;
        break;

    default:
        ASSERT(FALSE);
        Value = 0;
        break;
    }

    Index = FrontendGetQueue(Frontend, Algorithm, Value);
    Ring = Transmitter->Ring[Index];

    __TransmitterRingQueuePacket(Ring, Packet, More);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
TransmitterAbortPackets(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PXENVIF_FRONTEND        Frontend;
    KIRQL                   Irql;
    LONG                    Index;

    Frontend = Transmitter->Frontend;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    Index = FrontendGetNumQueues(Frontend);
    while (--Index >= 0) {
        PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[Index];

        __TransmitterRingAbortPackets(Ring);
    }    

    KeLowerIrql(Irql);
}

VOID
TransmitterQueueArp(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  PIPV4_ADDRESS           Address
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[0];

    (VOID) __TransmitterRingQueueArp(Ring, Address);
}

VOID
TransmitterQueueNeighbourAdvertisement(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  PIPV6_ADDRESS           Address
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[0];

    (VOID) __TransmitterRingQueueNeighbourAdvertisement(Ring, Address);
}

VOID
TransmitterQueueMulticastControl(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  PETHERNET_ADDRESS       Address,
    IN  BOOLEAN                 Add
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Transmitter->Ring[0];

    (VOID) __TransmitterRingQueueMulticastControl(Ring, Address, Add);
}

VOID
TransmitterQueryRingSize(
    IN  PXENVIF_TRANSMITTER Transmitter,
    OUT PULONG              Size
    )
{
    UNREFERENCED_PARAMETER(Transmitter);

    *Size = XENVIF_TRANSMITTER_RING_SIZE;
}

VOID
TransmitterNotify(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  ULONG                   Index
    )
{
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_TRANSMITTER_RING    Ring;

    Frontend = Transmitter->Frontend;

    ASSERT(!FrontendIsSplit(Frontend));

    Ring = Transmitter->Ring[Index];

    if (KeInsertQueueDpc(&Ring->PollDpc, NULL, NULL))
        Ring->PollDpcs++;
}

VOID
TransmitterQueryOffloadOptions(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS Options
    )
{
    PXENVIF_FRONTEND                Frontend;
    PCHAR                           Buffer;
    NTSTATUS                        status;

    Frontend = Transmitter->Frontend;

    Options->Value = 0;

    Options->OffloadTagManipulation = 1;

    if (Transmitter->DisableIpVersion4Gso == 0) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv4",
                              &Buffer);
    } else {
        Buffer = NULL;
        status = STATUS_NOT_SUPPORTED;
    }

    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion4LargePacket = 0;
    } else {
        Options->OffloadIpVersion4LargePacket = (USHORT)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    if (Transmitter->DisableIpVersion6Gso == 0) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv6",
                              &Buffer);
    } else {
        Buffer = NULL;
        status = STATUS_NOT_SUPPORTED;
    }

    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion6LargePacket = 0;
    } else {
        Options->OffloadIpVersion6LargePacket = (USHORT)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    Options->OffloadIpVersion4HeaderChecksum = 1;

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-no-csum-offload",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion4TcpChecksum = 1;
        Options->OffloadIpVersion4UdpChecksum = 1;
    } else {
        BOOLEAN Flag;

        Flag = (BOOLEAN)strtol(Buffer, NULL, 2);

        Options->OffloadIpVersion4TcpChecksum = (Flag) ? 0 : 1;
        Options->OffloadIpVersion4UdpChecksum = (Flag) ? 0 : 1;

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-ipv6-csum-offload",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion6TcpChecksum = 0;
        Options->OffloadIpVersion6UdpChecksum = 0;
    } else {
        BOOLEAN Flag;

        Flag = (BOOLEAN)strtol(Buffer, NULL, 2);

        Options->OffloadIpVersion6TcpChecksum = (Flag) ? 1 : 0;
        Options->OffloadIpVersion6UdpChecksum = (Flag) ? 1 : 0;

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }
}

#define XENVIF_TRANSMITTER_MAXIMUM_REQ_SIZE  ((1 << (RTL_FIELD_SIZE(netif_tx_request_t, size) * 8)) - 1)

#define XENVIF_TRANSMITTER_MAXIMUM_TCPV4_PAYLOAD_SIZE   (XENVIF_TRANSMITTER_MAXIMUM_REQ_SIZE -  \
                                                         sizeof (ETHERNET_HEADER) -             \
                                                         MAXIMUM_IPV4_HEADER_LENGTH -           \
                                                         MAXIMUM_TCP_HEADER_LENGTH)

#define XENVIF_TRANSMITTER_MAXIMUM_TCPV6_PAYLOAD_SIZE   (XENVIF_TRANSMITTER_MAXIMUM_REQ_SIZE -  \
                                                         sizeof (ETHERNET_HEADER) -             \
                                                         MAXIMUM_IPV6_HEADER_LENGTH -           \
                                                         MAXIMUM_IPV6_OPTIONS_LENGTH -          \
                                                         MAXIMUM_TCP_HEADER_LENGTH)

VOID
TransmitterQueryLargePacketSize(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  UCHAR                   Version,
    OUT PULONG                  Size
    )
{
    PXENVIF_FRONTEND            Frontend;
    PCHAR                       Buffer;
    ULONG                       OffloadIpLargePacket;
    NTSTATUS                    status;

    Frontend = Transmitter->Frontend;

    if (Version == 4) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv4",
                              &Buffer);
    } else if (Version == 6) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv6",
                              &Buffer);
    } else {
        Buffer = NULL;
        status = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status)) {
        OffloadIpLargePacket = 0;
    } else {
        OffloadIpLargePacket = (ULONG)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    // The OffloadParity certification test requires that we have a single LSO size for IPv4 and IPv6 packets
    *Size = (OffloadIpLargePacket) ?
            __min(XENVIF_TRANSMITTER_MAXIMUM_TCPV4_PAYLOAD_SIZE,
                 XENVIF_TRANSMITTER_MAXIMUM_TCPV6_PAYLOAD_SIZE) :
            0;
}
