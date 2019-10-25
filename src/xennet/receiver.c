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

#include <ndis.h>
#include <procgrp.h>
#include <tcpip.h>
#include <xen.h>

#include "util.h"
#include "receiver.h"
#include "adapter.h"
#include "dbg_print.h"
#include "assert.h"

typedef struct _XENNET_RECEIVER_QUEUE {
    KSPIN_LOCK          Lock;
    PNET_BUFFER_LIST    Head;
    PNET_BUFFER_LIST    Tail;
    ULONG               Count;
} XENNET_RECEIVER_QUEUE, *PXENNET_RECEIVER_QUEUE;

struct _XENNET_RECEIVER {
    PXENNET_ADAPTER             Adapter;
    NDIS_HANDLE                 NetBufferListPool;
    PNET_BUFFER_LIST            PutList;
    PNET_BUFFER_LIST            GetList[HVM_MAX_VCPUS];
    XENNET_RECEIVER_QUEUE       Queue[HVM_MAX_VCPUS];
    LONG                        Indicated;
    LONG                        Returned;
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
};

#define RECEIVER_POOL_TAG       'RteN'
#define IN_NDIS_MAX             1024

typedef struct _NET_BUFFER_LIST_RESERVED {
    PVOID   Cookie;
} NET_BUFFER_LIST_RESERVED, *PNET_BUFFER_LIST_RESERVED;

C_ASSERT(sizeof (NET_BUFFER_LIST_RESERVED) <= RTL_FIELD_SIZE(NET_BUFFER_LIST, MiniportReserved));

static FORCEINLINE PNET_BUFFER_LIST
__ReceiverGetNetBufferList(
    IN  PXENNET_RECEIVER    Receiver
    )
{
    ULONG                   Index;
    PNET_BUFFER_LIST        NetBufferList;

    Index = KeGetCurrentProcessorNumberEx(NULL);

    NetBufferList = Receiver->GetList[Index];

    if (NetBufferList == NULL)
        Receiver->GetList[Index] =
            InterlockedExchangePointer(&Receiver->PutList, NULL);

    NetBufferList = Receiver->GetList[Index];

    if (NetBufferList == NULL)
        return NULL;

    Receiver->GetList[Index] = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
    NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

    return NetBufferList;
}

static FORCEINLINE VOID
__ReceiverPutNetBufferList(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList
    )
{
    PNET_BUFFER_LIST        Old;
    PNET_BUFFER_LIST        New;

    ASSERT3P(NET_BUFFER_LIST_NEXT_NBL(NetBufferList), ==, NULL);

    do {
        Old = Receiver->PutList;

        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = Old;
        New = NetBufferList;
    } while (InterlockedCompareExchangePointer(&Receiver->PutList, New, Old) != Old);
}

static PNET_BUFFER_LIST
__ReceiverAllocateNetBufferList(
    IN  PXENNET_RECEIVER        Receiver,
    IN  PMDL                    Mdl,
    IN  ULONG                   Offset,
    IN  ULONG                   Length,
    IN  PVOID                   Cookie
    )
{
    PNET_BUFFER_LIST            NetBufferList;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    NetBufferList = __ReceiverGetNetBufferList(Receiver);
    if (NetBufferList != NULL) {
        PNET_BUFFER NetBuffer;

        NET_BUFFER_LIST_INFO(NetBufferList, TcpIpChecksumNetBufferListInfo) = NULL;
        NET_BUFFER_LIST_INFO(NetBufferList, Ieee8021QNetBufferListInfo) = NULL;
        NET_BUFFER_LIST_INFO(NetBufferList, NetBufferListHashInfo) = NULL;
        NET_BUFFER_LIST_INFO(NetBufferList, NetBufferListHashValue) = NULL;

        NetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
        NET_BUFFER_FIRST_MDL(NetBuffer) = Mdl;
        NET_BUFFER_CURRENT_MDL(NetBuffer) = Mdl;
        NET_BUFFER_DATA_OFFSET(NetBuffer) = Offset;
        NET_BUFFER_DATA_LENGTH(NetBuffer) = Length;
        NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) = Offset;

        ASSERT3P(NET_BUFFER_NEXT_NB(NetBuffer), ==, NULL);
    } else {
        NetBufferList = NdisAllocateNetBufferAndNetBufferList(Receiver->NetBufferListPool,
                                                              0,
                                                              0,
                                                              Mdl,
                                                              Offset,
                                                              Length);
        ASSERT(IMPLY(NetBufferList != NULL, NET_BUFFER_LIST_NEXT_NBL(NetBufferList) == NULL));
    }

    if (NetBufferList != NULL) {
        PNET_BUFFER_LIST_RESERVED   ListReserved;

        ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);
        ASSERT3P(ListReserved->Cookie, ==, NULL);
        ListReserved->Cookie = Cookie;
    }

    return NetBufferList;
}        

static PVOID
__ReceiverReleaseNetBufferList(
    IN  PXENNET_RECEIVER        Receiver,
    IN  PNET_BUFFER_LIST        NetBufferList,
    IN  BOOLEAN                 Cache
    )
{
    PNET_BUFFER_LIST_RESERVED   ListReserved;
    PVOID                       Cookie;

    ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);
    Cookie = ListReserved->Cookie;
    ListReserved->Cookie = NULL;

    if (Cache)
        __ReceiverPutNetBufferList(Receiver, NetBufferList);
    else
        NdisFreeNetBufferList(NetBufferList);

    return Cookie;
}

static FORCEINLINE VOID
__ReceiverReturnNetBufferLists(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  BOOLEAN             Cache
    )
{
    PXENVIF_VIF_INTERFACE   VifInterface;
    LONG                    Count;

    VifInterface = AdapterGetVifInterface(Receiver->Adapter);

    Count = 0;

    while (NetBufferList != NULL) {
        PNET_BUFFER_LIST        Next;
        PVOID                   Cookie;

        Next = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

        Cookie = __ReceiverReleaseNetBufferList(Receiver, NetBufferList, Cache);

        XENVIF_VIF(ReceiverReturnPacket,
                   VifInterface,
                   Cookie);

        Count++;

        NetBufferList = Next;
    }

    (VOID) InterlockedAdd(&Receiver->Returned, Count);
}

static PNET_BUFFER_LIST
__ReceiverReceivePacket(
    IN  PXENNET_RECEIVER                        Receiver,
    IN  PMDL                                    Mdl,
    IN  ULONG                                   Offset,
    IN  ULONG                                   Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS            Flags,
    IN  USHORT                                  MaximumSegmentSize,
    IN  USHORT                                  TagControlInformation,
    IN  PXENVIF_PACKET_INFO                     Info,
    IN  PXENVIF_PACKET_HASH                     Hash,
    IN  PVOID                                   Cookie
    )
{
    PNET_BUFFER_LIST                            NetBufferList;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO   csumInfo;

    UNREFERENCED_PARAMETER(MaximumSegmentSize);
    UNREFERENCED_PARAMETER(Info);

    NetBufferList = __ReceiverAllocateNetBufferList(Receiver,
                                                    Mdl,
                                                    Offset,
                                                    Length,
                                                    Cookie);
    if (NetBufferList == NULL)
        goto fail1;

    NetBufferList->SourceHandle = AdapterGetHandle(Receiver->Adapter);

    csumInfo.Value = 0;

    csumInfo.Receive.IpChecksumSucceeded = Flags.IpChecksumSucceeded;
    csumInfo.Receive.IpChecksumFailed = Flags.IpChecksumFailed;

    csumInfo.Receive.TcpChecksumSucceeded = Flags.TcpChecksumSucceeded;
    csumInfo.Receive.TcpChecksumFailed = Flags.TcpChecksumFailed;

    csumInfo.Receive.UdpChecksumSucceeded = Flags.UdpChecksumSucceeded;
    csumInfo.Receive.UdpChecksumFailed = Flags.UdpChecksumFailed;

    NET_BUFFER_LIST_INFO(NetBufferList, TcpIpChecksumNetBufferListInfo) = (PVOID)(ULONG_PTR)csumInfo.Value;

    if (TagControlInformation != 0) {
        NDIS_NET_BUFFER_LIST_8021Q_INFO Ieee8021QInfo;

        UNPACK_TAG_CONTROL_INFORMATION(TagControlInformation,
                                       Ieee8021QInfo.TagHeader.UserPriority,
                                       Ieee8021QInfo.TagHeader.CanonicalFormatId,
                                       Ieee8021QInfo.TagHeader.VlanId);

        if (Ieee8021QInfo.TagHeader.VlanId != 0)
            goto fail2;

        NET_BUFFER_LIST_INFO(NetBufferList, Ieee8021QNetBufferListInfo) = Ieee8021QInfo.Value;
    }

    switch (Hash->Algorithm) {
    case XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ:
        NET_BUFFER_LIST_SET_HASH_FUNCTION(NetBufferList,
                                          NdisHashFunctionToeplitz);
        break;

    default:
        goto done;
    }

    switch (Hash->Type) {
    case XENVIF_PACKET_HASH_TYPE_IPV4:
        NET_BUFFER_LIST_SET_HASH_TYPE(NetBufferList,
                                      NDIS_HASH_IPV4);
        break;

    case XENVIF_PACKET_HASH_TYPE_IPV4_TCP:
        NET_BUFFER_LIST_SET_HASH_TYPE(NetBufferList,
                                      NDIS_HASH_TCP_IPV4);
        break;

    case XENVIF_PACKET_HASH_TYPE_IPV6:
        NET_BUFFER_LIST_SET_HASH_TYPE(NetBufferList,
                                      NDIS_HASH_IPV6);
        break;

    case XENVIF_PACKET_HASH_TYPE_IPV6_TCP:
        NET_BUFFER_LIST_SET_HASH_TYPE(NetBufferList,
                                      NDIS_HASH_TCP_IPV6);
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    NET_BUFFER_LIST_SET_HASH_VALUE(NetBufferList,
                                   Hash->Value);

done:
    return NetBufferList;

fail2:
    (VOID) __ReceiverReleaseNetBufferList(Receiver, NetBufferList, TRUE);

fail1:
    return NULL;
}

static FORCEINLINE VOID __IndicateReceiveNetBufferLists(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               NumberOfNetBufferLists,
    IN  ULONG               ReceiveFlags
    )
{
    PXENNET_ADAPTER         Adapter = Receiver->Adapter;
    NDIS_HANDLE             MiniportAdapterHandle = AdapterGetHandle(Adapter);
    PXENVIF_VIF_INTERFACE   VifInterface;
    ULONG                   Count;

    VifInterface = AdapterGetVifInterface(Receiver->Adapter);

    Count = 0;
    while (NetBufferLists != NULL) {
        PNET_BUFFER_LIST        Next;

        Next = NET_BUFFER_LIST_NEXT_NBL(NetBufferLists);
        NET_BUFFER_LIST_NEXT_NBL(NetBufferLists) = NULL;

        NdisMIndicateReceiveNetBufferLists(MiniportAdapterHandle,
                                           NetBufferLists,
                                           PortNumber,
                                           1,
                                           ReceiveFlags);

        if (ReceiveFlags & NDIS_RECEIVE_FLAGS_RESOURCES) {
            PVOID   Cookie;

            Cookie = __ReceiverReleaseNetBufferList(Receiver,
                                                    NetBufferLists,
                                                    FALSE);

            XENVIF_VIF(ReceiverReturnPacket,
                       VifInterface,
                       Cookie);

            (VOID) InterlockedIncrement(&Receiver->Returned);
        }

        Count++;
        NetBufferLists = Next;
    }
    ASSERT3U(Count, ==, NumberOfNetBufferLists);
}

static VOID
__ReceiverPushPackets(
    IN  PXENNET_RECEIVER    Receiver,
    IN  ULONG               Index
    )
{
    ULONG                   Flags;
    LONG                    Indicated;
    LONG                    Returned;
    PXENNET_RECEIVER_QUEUE  Queue;
    PNET_BUFFER_LIST        NetBufferList;
    ULONG                   Count;

    Queue = &Receiver->Queue[Index];

    KeAcquireSpinLockAtDpcLevel(&Queue->Lock);

    NetBufferList = Queue->Head;
    Count = Queue->Count;

    Queue->Tail = Queue->Head = NULL;
    Queue->Count = 0;

    KeReleaseSpinLockFromDpcLevel(&Queue->Lock);

    (VOID) InterlockedAdd(&Receiver->Indicated, Count);

    Returned = Receiver->Returned;

    KeMemoryBarrier();

    Indicated = Receiver->Indicated;

    Flags = NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL |
            NDIS_RECEIVE_FLAGS_PERFECT_FILTERED;

    ASSERT3S(Indicated - Returned, >=, 0);
    if (Indicated - Returned > IN_NDIS_MAX)
        Flags |= NDIS_RECEIVE_FLAGS_RESOURCES;

    __IndicateReceiveNetBufferLists(Receiver,
                                    NetBufferList,
                                    NDIS_DEFAULT_PORT_NUMBER,
                                    Count,
                                    Flags);
}

NDIS_STATUS
ReceiverInitialize(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PXENNET_RECEIVER    *Receiver
    )
{
    NET_BUFFER_LIST_POOL_PARAMETERS Params;
    ULONG                           Index;
    NDIS_STATUS                     status;

    *Receiver = ExAllocatePoolWithTag(NonPagedPool,
                                      sizeof(XENNET_RECEIVER),
                                      RECEIVER_POOL_TAG);

    status = NDIS_STATUS_RESOURCES;
    if (*Receiver == NULL)
        goto fail1;

    RtlZeroMemory(*Receiver, sizeof(XENNET_RECEIVER));
    (*Receiver)->Adapter = Adapter;

    RtlZeroMemory(&Params, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
    Params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    Params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    Params.Header.Size = sizeof(Params);
    Params.ProtocolId = 0;
    Params.ContextSize = 0;
    Params.fAllocateNetBuffer = TRUE;
    Params.PoolTag = 'PteN';

    (*Receiver)->NetBufferListPool = NdisAllocateNetBufferListPool(AdapterGetHandle(Adapter),
                                                                   &Params);

    status = NDIS_STATUS_RESOURCES;
    if ((*Receiver)->NetBufferListPool == NULL)
        goto fail2;

    for (Index = 0; Index < HVM_MAX_VCPUS; Index++) {
        PXENNET_RECEIVER_QUEUE  Queue = &(*Receiver)->Queue[Index];

        KeInitializeSpinLock(&Queue->Lock);
    }

    return NDIS_STATUS_SUCCESS;

fail2:
fail1:
    return status;
}

VOID
ReceiverTeardown(
    IN  PXENNET_RECEIVER    Receiver
    )
{
    ULONG                   Index;
    PNET_BUFFER_LIST        NetBufferList;

    ASSERT(Receiver != NULL);

    ASSERT3U(Receiver->Returned, ==, Receiver->Indicated);

    for (Index = 0; Index < HVM_MAX_VCPUS; Index++) {
        NetBufferList = Receiver->GetList[Index];

        while (NetBufferList != NULL) {
            PNET_BUFFER_LIST    Next;

            Next = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
            NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

            NdisFreeNetBufferList(NetBufferList);

            NetBufferList = Next;
        }
    }

    NetBufferList = Receiver->PutList;
    while (NetBufferList != NULL) {
        PNET_BUFFER_LIST    Next;

        Next = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

        NdisFreeNetBufferList(NetBufferList);

        NetBufferList = Next;
    }

    NdisFreeNetBufferListPool(Receiver->NetBufferListPool);
    Receiver->NetBufferListPool = NULL;

    Receiver->Adapter = NULL;

    ExFreePoolWithTag(Receiver, RECEIVER_POOL_TAG);
}

VOID
ReceiverReturnNetBufferLists(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  ULONG               ReturnFlags
    )
{
    UNREFERENCED_PARAMETER(ReturnFlags);

    __ReceiverReturnNetBufferLists(Receiver, NetBufferList, TRUE);
}

VOID
ReceiverQueuePacket(
    IN  PXENNET_RECEIVER                Receiver,
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
    PXENVIF_VIF_INTERFACE               VifInterface;
    PNET_BUFFER_LIST                    NetBufferList;
    PXENNET_RECEIVER_QUEUE              Queue;

    VifInterface = AdapterGetVifInterface(Receiver->Adapter);

    NetBufferList = __ReceiverReceivePacket(Receiver,
                                            Mdl,
                                            Offset,
                                            Length,
                                            Flags,
                                            MaximumSegmentSize,
                                            TagControlInformation,
                                            Info,
                                            Hash,
                                            Cookie);
    if (NetBufferList == NULL) {
        XENVIF_VIF(ReceiverReturnPacket,
                   VifInterface,
                   Cookie);
        goto done;
    }

    Queue = &Receiver->Queue[Index];

    KeAcquireSpinLockAtDpcLevel(&Queue->Lock);

    if (Queue->Head == NULL) {
        ASSERT3U(Queue->Count, ==, 0);
        Queue->Head = Queue->Tail = NetBufferList;
    } else {
        NET_BUFFER_LIST_NEXT_NBL(Queue->Tail) = NetBufferList;
        Queue->Tail = NetBufferList;
    }
    Queue->Count++;

    KeReleaseSpinLockFromDpcLevel(&Queue->Lock);

done:
    if (!More)
        __ReceiverPushPackets(Receiver, Index);
}

PXENVIF_VIF_OFFLOAD_OPTIONS
ReceiverOffloadOptions(
    IN  PXENNET_RECEIVER    Receiver
    )
{
    return &Receiver->OffloadOptions;
}

VOID
ReceiverEnable(
    IN  PXENNET_RECEIVER    Receiver
    )
{
    PXENNET_ADAPTER         Adapter = Receiver->Adapter;

    Info("%ws: <====>\n",
         AdapterGetLocation(Adapter));
}

VOID
ReceiverDisable(
    IN  PXENNET_RECEIVER    Receiver
    )
{
    PXENNET_ADAPTER         Adapter = Receiver->Adapter;

    Info("%ws: <====> (Indicated = %u Returned = %u)\n",
         AdapterGetLocation(Adapter),
         Receiver->Indicated,
         Receiver->Returned);
}
