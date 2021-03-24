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
#include "transmitter.h"
#include "adapter.h"
#include <vif_interface.h>
#include <tcpip.h>
#include "dbg_print.h"
#include "assert.h"
#include "thread.h"
#include "util.h"

typedef struct _XENNET_SEND_INFO {
    LIST_ENTRY              ListEntry;
    PNET_BUFFER_LIST        NetBufferList;
} XENNET_SEND_INFO, *PXENNET_SEND_INFO;

struct _XENNET_TRANSMITTER {
    PXENNET_ADAPTER             Adapter;
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
    PXENNET_THREAD              SendThread;
    KSPIN_LOCK                  SendLock;
    LIST_ENTRY                  SendList;
};

typedef struct _NET_BUFFER_LIST_RESERVED {
    LONG    Reference;
    LONG    Status;
} NET_BUFFER_LIST_RESERVED, *PNET_BUFFER_LIST_RESERVED;

C_ASSERT(sizeof (NET_BUFFER_LIST_RESERVED) <= RTL_FIELD_SIZE(NET_BUFFER_LIST, MiniportReserved));

#define TRANSMITTER_POOL_TAG        'TteN'

static FORCEINLINE PVOID
__TransmitterAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, TRANSMITTER_POOL_TAG);
}

static FORCEINLINE VOID
__TransmitterFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, TRANSMITTER_POOL_TAG);
}

static VOID
__TransmitterCompleteNetBufferList(
    IN  PXENNET_TRANSMITTER     Transmitter,
    IN  PNET_BUFFER_LIST        NetBufferList,
    IN  NDIS_STATUS             Status
    )
{
    ASSERT3P(NET_BUFFER_LIST_NEXT_NBL(NetBufferList), ==, NULL);

    NET_BUFFER_LIST_STATUS(NetBufferList) = Status;

    if (Status == NDIS_STATUS_SUCCESS) {
        PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO   LargeSendInfo;

        LargeSendInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)
                                &NET_BUFFER_LIST_INFO(NetBufferList,
                                                      TcpLargeSendNetBufferListInfo);
        if (LargeSendInfo->LsoV2Transmit.MSS != 0)
            LargeSendInfo->LsoV2TransmitComplete.Reserved = 0;
    }

    NdisMSendNetBufferListsComplete(AdapterGetHandle(Transmitter->Adapter),
                                    NetBufferList,
                                    0);
}

__TransmitterGetNetBufferList(
    IN  PXENNET_TRANSMITTER     Transmitter,
    IN  PNET_BUFFER_LIST        NetBufferList
    )
{
    PNET_BUFFER_LIST_RESERVED   ListReserved;

    UNREFERENCED_PARAMETER(Transmitter);

    ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);

    if (InterlockedIncrement(&ListReserved->Reference) == 1)
        ListReserved->Status = NDIS_STATUS_PENDING;
}

__TransmitterPutNetBufferList(
    IN  PXENNET_TRANSMITTER     Transmitter,
    IN  PNET_BUFFER_LIST        NetBufferList
    )
{
    PNET_BUFFER_LIST_RESERVED   ListReserved;

    UNREFERENCED_PARAMETER(Transmitter);

    ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);

    ASSERT(ListReserved->Reference != 0);
    if (InterlockedDecrement(&ListReserved->Reference) == 0)
        __TransmitterCompleteNetBufferList(Transmitter,
                                           NetBufferList,
                                           ListReserved->Status);
}

static VOID
__TransmitterReturnPacket(
    IN  PXENNET_TRANSMITTER     Transmitter,
    IN  PVOID                   Cookie,
    IN  NDIS_STATUS             Status
    )
{
    PNET_BUFFER_LIST            NetBufferList = Cookie;
    PNET_BUFFER_LIST_RESERVED   ListReserved;

    ASSERT(NetBufferList != NULL);

    ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);

    (VOID) InterlockedExchange(&ListReserved->Status, Status);
    __TransmitterPutNetBufferList(Transmitter, NetBufferList);
}

_IRQL_requires_max_(APC_LEVEL)
static VOID
__TransmitterOffloadOptions(
    IN  PNET_BUFFER_LIST            NetBufferList,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS OffloadOptions,
    OUT PUSHORT                     TagControlInformation,
    OUT PUSHORT                     MaximumSegmentSize
    )
{
    PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO   LargeSendInfo;
    PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO          ChecksumInfo;
    PNDIS_NET_BUFFER_LIST_8021Q_INFO                    Ieee8021QInfo;

    LargeSendInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)&NET_BUFFER_LIST_INFO(NetBufferList,
                                                                                                TcpLargeSendNetBufferListInfo);
    ChecksumInfo = (PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO)&NET_BUFFER_LIST_INFO(NetBufferList,
                                                                                        TcpIpChecksumNetBufferListInfo);
    Ieee8021QInfo = (PNDIS_NET_BUFFER_LIST_8021Q_INFO)&NET_BUFFER_LIST_INFO(NetBufferList,
                                                                            Ieee8021QNetBufferListInfo);

    OffloadOptions->Value = 0;
    *TagControlInformation = 0;
    *MaximumSegmentSize = 0;

    if (ChecksumInfo->Transmit.IsIPv4) {
        if (ChecksumInfo->Transmit.IpHeaderChecksum)
            OffloadOptions->OffloadIpVersion4HeaderChecksum = 1;

        if (ChecksumInfo->Transmit.TcpChecksum)
            OffloadOptions->OffloadIpVersion4TcpChecksum = 1;

        if (ChecksumInfo->Transmit.UdpChecksum)
            OffloadOptions->OffloadIpVersion4UdpChecksum = 1;
    }

    if (ChecksumInfo->Transmit.IsIPv6) {
        if (ChecksumInfo->Transmit.TcpChecksum)
            OffloadOptions->OffloadIpVersion6TcpChecksum = 1;

        if (ChecksumInfo->Transmit.UdpChecksum)
            OffloadOptions->OffloadIpVersion6UdpChecksum = 1;
    }

    if (Ieee8021QInfo->TagHeader.UserPriority != 0) {
        OffloadOptions->OffloadTagManipulation = 1;

        ASSERT3U(Ieee8021QInfo->TagHeader.CanonicalFormatId, ==, 0);
        ASSERT3U(Ieee8021QInfo->TagHeader.VlanId, ==, 0);

        PACK_TAG_CONTROL_INFORMATION(*TagControlInformation,
                                        Ieee8021QInfo->TagHeader.UserPriority,
                                        Ieee8021QInfo->TagHeader.CanonicalFormatId,
                                        Ieee8021QInfo->TagHeader.VlanId);
    }


    if (LargeSendInfo->LsoV2Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE) {
        ASSERT(LargeSendInfo->LsoV2Transmit.TcpHeaderOffset != 0);

        if (LargeSendInfo->LsoV2Transmit.IPVersion == NDIS_TCP_LARGE_SEND_OFFLOAD_IPv4)
            OffloadOptions->OffloadIpVersion4LargePacket = 1;

        if (LargeSendInfo->LsoV2Transmit.IPVersion == NDIS_TCP_LARGE_SEND_OFFLOAD_IPv6)
            OffloadOptions->OffloadIpVersion6LargePacket = 1;

        ASSERT3U(LargeSendInfo->LsoV2Transmit.MSS >> 16, ==, 0);
        *MaximumSegmentSize = (USHORT)LargeSendInfo->LsoV2Transmit.MSS;
    }
}

static VOID
__TransmitterHash(
    IN  PNET_BUFFER_LIST        NetBufferList,
    OUT PXENVIF_PACKET_HASH     Hash
    )
{
    switch (NET_BUFFER_LIST_GET_HASH_FUNCTION(NetBufferList)) {
    case NdisHashFunctionToeplitz:
        Hash->Algorithm = XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ;
        break;

    default:
        Hash->Algorithm = XENVIF_PACKET_HASH_ALGORITHM_NONE;
        break;
    }

    switch (NET_BUFFER_LIST_GET_HASH_TYPE(NetBufferList)) {
    case NDIS_HASH_IPV4:
        Hash->Type = XENVIF_PACKET_HASH_TYPE_IPV4;
        break;

    case NDIS_HASH_TCP_IPV4:
        Hash->Type = XENVIF_PACKET_HASH_TYPE_IPV4_TCP;
        break;

    case NDIS_HASH_IPV6:
        Hash->Type = XENVIF_PACKET_HASH_TYPE_IPV6;
        break;

    case NDIS_HASH_TCP_IPV6:
        Hash->Type = XENVIF_PACKET_HASH_TYPE_IPV6_TCP;
        break;

    default:
        break;
    }

    Hash->Value = NET_BUFFER_LIST_GET_HASH_VALUE(NetBufferList);
}

_IRQL_requires_max_(APC_LEVEL)
static VOID
__TransmitterSendNetBufferList(
    IN  PXENNET_TRANSMITTER     Transmitter,
    IN  PNET_BUFFER_LIST        NetBufferList
    )
{
    PNET_BUFFER_LIST_RESERVED   ListReserved;
    PNET_BUFFER                 NetBuffer;
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
    USHORT                      TagControlInformation;
    USHORT                      MaximumSegmentSize;
    XENVIF_PACKET_HASH          Hash;

    ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);
    RtlZeroMemory(ListReserved, sizeof (NET_BUFFER_LIST_RESERVED));

    __TransmitterOffloadOptions(NetBufferList,
                                &OffloadOptions,
                                &TagControlInformation,
                                &MaximumSegmentSize);

    if (OffloadOptions.Value & ~Transmitter->OffloadOptions.Value) {
        NET_BUFFER_LIST_STATUS(NetBufferList) = NDIS_STATUS_FAILURE;

        NdisMSendNetBufferListsComplete(AdapterGetHandle(Transmitter->Adapter),
                                        NetBufferList,
                                        0);
        return;
    }

    __TransmitterHash(NetBufferList, &Hash);

    __TransmitterGetNetBufferList(Transmitter, NetBufferList);

    NetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
    while (NetBuffer != NULL) {
        PNET_BUFFER         NetBufferListNext = NET_BUFFER_NEXT_NB(NetBuffer);
        PVOID               Cookie = NetBufferList;
        NTSTATUS            status;

        __TransmitterGetNetBufferList(Transmitter, NetBufferList);

#pragma warning(suppress: 28182) // Dereferencing NULL pointer 'NetBuffer'
        status = XENVIF_VIF(TransmitterQueuePacket,
                            AdapterGetVifInterface(Transmitter->Adapter),
                            NET_BUFFER_CURRENT_MDL(NetBuffer),
                            NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer),
                            NET_BUFFER_DATA_LENGTH(NetBuffer),
                            OffloadOptions,
                            MaximumSegmentSize,
                            TagControlInformation,
                            &Hash,
                            (NetBufferListNext != NULL) ? TRUE : FALSE,
                            Cookie);
        if (!NT_SUCCESS(status)) {
            __TransmitterReturnPacket(Transmitter, Cookie,
                                      NDIS_STATUS_NOT_ACCEPTED);
            break;
        }

        NetBuffer = NetBufferListNext;
    }

    __TransmitterPutNetBufferList(Transmitter, NetBufferList);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TransmitterSendNetBufferLists(
    IN  PXENNET_TRANSMITTER     Transmitter,
    IN  PNET_BUFFER_LIST        NetBufferList,
    IN  NDIS_PORT_NUMBER        PortNumber,
    IN  ULONG                   SendFlags
    )
{
    UNREFERENCED_PARAMETER(PortNumber);

    KIRQL                       Irql;
    PXENNET_SEND_INFO           Info;

    Info = __TransmitterAllocate(sizeof(XENNET_SEND_INFO));
    if (Info == NULL) {
        NET_BUFFER_LIST_STATUS(NetBufferList) = NDIS_STATUS_FAILURE;

        NdisMSendNetBufferListsComplete(AdapterGetHandle(Transmitter->Adapter),
                                        NetBufferList,
                                        SendFlags);
        return;
    }

    Info->NetBufferList = NetBufferList;

    KeAcquireSpinLock(&Transmitter->SendLock, &Irql);
    InsertTailList(&Transmitter->SendList, &Info->ListEntry);
    KeReleaseSpinLock(&Transmitter->SendLock, Irql);

    ThreadWake(Transmitter->SendThread);
}

static NTSTATUS
SendNbl(
    IN  PXENNET_THREAD    Self,
    IN  PVOID             Context
)
{
    PXENNET_TRANSMITTER   Transmitter = Context;

    for (;;) {
        PKEVENT Event = ThreadGetEvent(Self);

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        for (;;) {
            KIRQL             Irql;
            PXENNET_SEND_INFO Info;
            PLIST_ENTRY       ListEntry;
            PNET_BUFFER_LIST  NetBufferList;

            KeAcquireSpinLock(&Transmitter->SendLock, &Irql);

            if (IsListEmpty(&Transmitter->SendList)) {
                KeReleaseSpinLock(&Transmitter->SendLock, Irql);
                break;
            }

            ListEntry = RemoveHeadList(&Transmitter->SendList);
            KeReleaseSpinLock(&Transmitter->SendLock, Irql);

            Info = CONTAINING_RECORD(ListEntry, XENNET_SEND_INFO, ListEntry);
            NetBufferList = Info->NetBufferList;

            while (NetBufferList != NULL) {
                PNET_BUFFER_LIST ListNext;

                ListNext = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
                NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

                __TransmitterSendNetBufferList(Transmitter, NetBufferList);

                NetBufferList = ListNext;
            }

            __TransmitterFree(Info);
        }
    }

    return STATUS_SUCCESS;
}

VOID
TransmitterReturnPacket(
    IN  PXENNET_TRANSMITTER                         Transmitter,
    IN  PVOID                                       Cookie,
    IN  PXENVIF_TRANSMITTER_PACKET_COMPLETION_INFO  Completion
    )
{
    NDIS_STATUS                                     Status;

    UNREFERENCED_PARAMETER(Completion);

    Status = (Completion->Status == XENVIF_TRANSMITTER_PACKET_OK) ?
             NDIS_STATUS_SUCCESS :
             NDIS_STATUS_NOT_ACCEPTED;

    __TransmitterReturnPacket(Transmitter, Cookie, Status);
}

PXENVIF_VIF_OFFLOAD_OPTIONS
TransmitterOffloadOptions(
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    return &Transmitter->OffloadOptions;
}

NDIS_STATUS
TransmitterInitialize (
    IN  PXENNET_ADAPTER     Adapter,
    OUT PXENNET_TRANSMITTER *Transmitter
    )
{
    NTSTATUS                status;

    *Transmitter = __TransmitterAllocate(sizeof(XENNET_TRANSMITTER));

    status = STATUS_NO_MEMORY;
    if (*Transmitter == NULL)
        goto fail1;

    RtlZeroMemory(*Transmitter, sizeof(XENNET_TRANSMITTER));

    KeInitializeSpinLock(&(*Transmitter)->SendLock);
    InitializeListHead(&(*Transmitter)->SendList);
    (*Transmitter)->Adapter = Adapter;

    status = ThreadCreate(SendNbl, *Transmitter, &(*Transmitter)->SendThread);
    if (!NT_SUCCESS(status))
       goto fail2;

    return NDIS_STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RtlZeroMemory(*Transmitter, sizeof(XENNET_TRANSMITTER));
    __TransmitterFree(*Transmitter);

fail1:
    Error("fail1\n (%08x)", status);

    return NDIS_STATUS_FAILURE;
}

VOID
TransmitterTeardown(
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    ThreadAlert(Transmitter->SendThread);
    ThreadJoin(Transmitter->SendThread);
    Transmitter->SendThread = NULL;

    RtlZeroMemory(&Transmitter->SendLock, sizeof (KSPIN_LOCK));
    RtlZeroMemory(&Transmitter->SendList, sizeof (LIST_ENTRY));

    Transmitter->Adapter = NULL;
    Transmitter->OffloadOptions.Value = 0;

    __TransmitterFree(Transmitter);
}
