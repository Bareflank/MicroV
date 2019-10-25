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
#include <procgrp.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <xen.h>
#include <ethernet.h>
#include <tcpip.h>

#include <debug_interface.h>
#include <store_interface.h>
#include <cache_interface.h>
#include <gnttab_interface.h>
#include <evtchn_interface.h>

#include "pdo.h"
#include "registry.h"
#include "frontend.h"
#include "checksum.h"
#include "parse.h"
#include "mac.h"
#include "transmitter.h"
#include "vif.h"
#include "receiver.h"
#include "thread.h"
#include "driver.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define MAXNAMELEN  128

typedef struct _XENVIF_RECEIVER_FRAGMENT {
    LIST_ENTRY              ListEntry;
    ULONG                   Next;
    PVOID                   Context;
    PXENBUS_GNTTAB_ENTRY    Entry;
} XENVIF_RECEIVER_FRAGMENT, *PXENVIF_RECEIVER_FRAGMENT;

typedef struct _XENVIF_RECEIVER_HASH {
    XENVIF_PACKET_HASH_ALGORITHM    Algorithm;
    ULONG                           Types;
} XENVIF_RECEIVER_HASH, *PXENVIF_RECEIVER_HASH;

#define XENVIF_RECEIVER_RING_SIZE   (__CONST_RING_SIZE(netif_rx, PAGE_SIZE))

#define XENVIF_RECEIVER_MAXIMUM_FRAGMENT_ID (XENVIF_RECEIVER_RING_SIZE - 1)

typedef struct _XENVIF_RECEIVER_RING {
    PXENVIF_RECEIVER            Receiver;
    ULONG                       Index;
    PCHAR                       Path;
    KSPIN_LOCK                  Lock;
    PXENBUS_CACHE               PacketCache;
    PXENBUS_CACHE               FragmentCache;
    PXENBUS_GNTTAB_CACHE        GnttabCache;
    PMDL                        Mdl;
    netif_rx_front_ring_t       Front;
    netif_rx_sring_t            *Shared;
    PXENBUS_GNTTAB_ENTRY        Entry;
    PXENBUS_EVTCHN_CHANNEL      Channel;
    KDPC                        PollDpc;
    ULONG                       PollDpcs;
    ULONG                       Events;
    PXENVIF_RECEIVER_FRAGMENT   Pending[XENVIF_RECEIVER_MAXIMUM_FRAGMENT_ID + 1];
    ULONG                       RequestsPosted;
    ULONG                       RequestsPushed;
    ULONG                       ResponsesProcessed;
    BOOLEAN                     Connected;
    BOOLEAN                     Enabled;
    BOOLEAN                     Stopped;
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
    ULONG                       BackfillSize;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENVIF_THREAD              WatchdogThread;
    PLIST_ENTRY                 PacketQueue;
    KDPC                        QueueDpc;
    ULONG                       QueueDpcs;
    LIST_ENTRY                  PacketComplete;
    XENVIF_RECEIVER_HASH        Hash;
} XENVIF_RECEIVER_RING, *PXENVIF_RECEIVER_RING;

typedef struct _XENVIF_RECEIVER_PACKET {
    LIST_ENTRY                      ListEntry;
    XENVIF_PACKET_INFO              Info;
    XENVIF_PACKET_HASH              Hash;
    ULONG                           Offset;
    ULONG                           Length;
    XENVIF_PACKET_CHECKSUM_FLAGS    Flags;
    USHORT                          MaximumSegmentSize;
    USHORT                          TagControlInformation;
    PXENVIF_RECEIVER_RING           Ring;
    MDL                             Mdl;
    PFN_NUMBER                      __Pfn;
    PMDL                            SystemMdl;
} XENVIF_RECEIVER_PACKET, *PXENVIF_RECEIVER_PACKET;

struct _XENVIF_RECEIVER {
    PXENVIF_FRONTEND                Frontend;
    XENBUS_CACHE_INTERFACE          CacheInterface;
    XENBUS_GNTTAB_INTERFACE         GnttabInterface;
    XENBUS_EVTCHN_INTERFACE         EvtchnInterface;
    PXENVIF_RECEIVER_RING           *Ring;
    LONG                            Loaned;
    LONG                            Returned;
    KEVENT                          Event;
    ULONG                           CalculateChecksums;
    ULONG                           AllowGsoPackets;
    ULONG                           DisableIpVersion4Gso;
    ULONG                           DisableIpVersion6Gso;
    ULONG                           IpAlignOffset;
    ULONG                           AlwaysPullup;
    XENBUS_STORE_INTERFACE          StoreInterface;
    XENBUS_DEBUG_INTERFACE          DebugInterface;
    PXENBUS_DEBUG_CALLBACK          DebugCallback;
};

#define XENVIF_RECEIVER_TAG 'ECER'

static FORCEINLINE PVOID
__ReceiverAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENVIF_RECEIVER_TAG);
}

static FORCEINLINE VOID
__ReceiverFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_RECEIVER_TAG);
}

static VOID FORCEINLINE
__ReceiverPacketMdlInit(
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PMDL    Mdl = Packet->SystemMdl;

    ASSERT(IsZeroMemory(&Packet->Mdl, sizeof (MDL)));

#pragma warning(push)
#pragma warning(disable:28145) // modifying struct MDL

    Packet->Mdl.Size = sizeof (MDL) + sizeof (PFN_NUMBER);
    Packet->Mdl.MdlFlags = Mdl->MdlFlags;

    ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    Packet->Mdl.StartVa = Mdl->StartVa;
    Packet->Mdl.MappedSystemVa = Mdl->MappedSystemVa;

#pragma warning(pop)
}

static NTSTATUS
ReceiverPacketCtor(
    IN  PVOID               Argument,
    IN  PVOID               Object
    )
{
    PXENVIF_RECEIVER_RING   Ring = Argument;
    PXENVIF_RECEIVER_PACKET Packet = Object;
    PMDL                    Mdl;
    NTSTATUS                status;

    ASSERT(IsZeroMemory(Packet, sizeof (XENVIF_RECEIVER_PACKET)));

    Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Mdl == NULL)
        goto fail1;

    Packet->SystemMdl = Mdl;

    __ReceiverPacketMdlInit(Packet);

    Packet->__Pfn = MmGetMdlPfnArray(Mdl)[0];

    Packet->Ring = Ring;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);
    
    ASSERT(IsZeroMemory(Packet, sizeof (XENVIF_RECEIVER_PACKET)));

    return status;
}

static VOID
ReceiverPacketDtor(
    IN  PVOID               Argument,
    IN  PVOID               Object
    )
{
    PXENVIF_RECEIVER_RING   Ring = Argument;
    PXENVIF_RECEIVER_PACKET Packet = Object;
    PMDL                    Mdl;

    ASSERT3P(Packet->Ring, ==, Ring);
    Packet->Ring = NULL;

    Mdl = Packet->SystemMdl;
    Packet->SystemMdl = NULL;

    __FreePage(Mdl);

    RtlZeroMemory(&Packet->Mdl, sizeof (MDL) + sizeof (PFN_NUMBER));

    ASSERT(IsZeroMemory(Packet, sizeof (XENVIF_RECEIVER_PACKET)));
}

static FORCEINLINE PXENVIF_RECEIVER_PACKET
__ReceiverRingGetPacket(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  BOOLEAN                 Locked
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_RECEIVER_PACKET     Packet;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Packet = XENBUS_CACHE(Get,
                          &Receiver->CacheInterface,
                          Ring->PacketCache,
                          Locked);

    ASSERT(IsZeroMemory(&Packet->Info, sizeof (XENVIF_PACKET_INFO)));
    ASSERT3P(Packet->Ring, ==, Ring);

    return Packet;
}

static FORCEINLINE VOID
__ReceiverRingPutPacket(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet,
    IN  BOOLEAN                 Locked
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    ASSERT3P(Packet->Ring, ==, Ring);
    ASSERT(IsZeroMemory(&Packet->ListEntry, sizeof (LIST_ENTRY)));

    Packet->Offset = 0;
    Packet->Length = 0;
    Packet->Flags.Value = 0;
    Packet->MaximumSegmentSize = 0;
    Packet->TagControlInformation = 0;

    RtlZeroMemory(&Packet->Info, sizeof (XENVIF_PACKET_INFO));
    RtlZeroMemory(&Packet->Hash, sizeof (XENVIF_PACKET_HASH));

    RtlZeroMemory(&Packet->Mdl, sizeof (MDL));

    __ReceiverPacketMdlInit(Packet);

    XENBUS_CACHE(Put,
                 &Receiver->CacheInterface,
                 Ring->PacketCache,
                 Packet,
                 Locked);
}

static FORCEINLINE PMDL
__ReceiverRingGetMdl(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  BOOLEAN                 Locked
    )
{
    PXENVIF_RECEIVER_PACKET     Packet;

    Packet = __ReceiverRingGetPacket(Ring, Locked);
    if (Packet == NULL)
        return NULL;

    return &Packet->Mdl;
}

static FORCEINLINE VOID
__ReceiverRingPutMdl(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PMDL                    Mdl,
    IN  BOOLEAN                 Locked
    )
{
    PXENVIF_RECEIVER_PACKET     Packet;

    Packet = CONTAINING_RECORD(Mdl, XENVIF_RECEIVER_PACKET, Mdl);
    __ReceiverRingPutPacket(Ring, Packet, Locked);
}

static NTSTATUS
ReceiverFragmentCtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_RECEIVER_FRAGMENT   Fragment = Object;

    UNREFERENCED_PARAMETER(Argument);

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_RECEIVER_FRAGMENT)));

    return STATUS_SUCCESS;
}

static VOID
ReceiverFragmentDtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_RECEIVER_FRAGMENT   Fragment = Object;

    UNREFERENCED_PARAMETER(Argument);

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_RECEIVER_FRAGMENT)));
}

static FORCEINLINE PXENVIF_RECEIVER_FRAGMENT
__ReceiverRingGetFragment(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    return XENBUS_CACHE(Get,
                        &Receiver->CacheInterface,
                        Ring->FragmentCache,
                        TRUE);
}

static FORCEINLINE
__ReceiverRingPutFragment(
    IN  PXENVIF_RECEIVER_RING       Ring,
    IN  PXENVIF_RECEIVER_FRAGMENT   Fragment
    )
{
    PXENVIF_RECEIVER                Receiver;
    PXENVIF_FRONTEND                Frontend;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    ASSERT3P(Fragment->Context, ==, NULL);

    XENBUS_CACHE(Put,
                 &Receiver->CacheInterface,
                 Ring->FragmentCache,
                 Fragment,
                 TRUE);
}

static DECLSPEC_NOINLINE VOID
ReceiverRingProcessTag(
    IN  PXENVIF_RECEIVER_RING    Ring,
    IN  PXENVIF_RECEIVER_PACKET  Packet
    )
{
    PXENVIF_PACKET_INFO          Info;
    ULONG                        PayloadLength;
    PUCHAR                       BaseVa;
    PETHERNET_HEADER             EthernetHeader;
    ULONG                        Offset;

    Info = &Packet->Info;

    PayloadLength = Packet->Length - Info->Length;

    ASSERT(Packet->Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    BaseVa = Packet->Mdl.MappedSystemVa;
    ASSERT(BaseVa != NULL);

    BaseVa += Packet->Offset;

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(BaseVa + Info->EthernetHeader.Offset);

    if (!ETHERNET_HEADER_IS_TAGGED(EthernetHeader) ||
        Ring->OffloadOptions.OffloadTagManipulation == 0)
        return;

    Packet->TagControlInformation = NTOHS(EthernetHeader->Tagged.Tag.ControlInformation);

    Offset = FIELD_OFFSET(ETHERNET_TAGGED_HEADER, Tag);
    RtlMoveMemory((PUCHAR)EthernetHeader + sizeof (ETHERNET_TAG),
                  (PUCHAR)EthernetHeader,
                  Offset);

    // Fix up the packet information
    BaseVa += sizeof (ETHERNET_TAG);

    BaseVa -= Packet->Offset;
    Packet->Mdl.MappedSystemVa = BaseVa;

    Packet->Length -= sizeof (ETHERNET_TAG);

    Info->EthernetHeader.Length -= sizeof (ETHERNET_TAG);

    if (Info->IpHeader.Length != 0)
        Info->IpHeader.Offset -= sizeof (ETHERNET_TAG);

    if (Info->IpOptions.Length != 0)
        Info->IpOptions.Offset -= sizeof (ETHERNET_TAG);

    if (Info->UdpHeader.Length != 0)
        Info->UdpHeader.Offset -= sizeof (ETHERNET_TAG);

    if (Info->TcpHeader.Length != 0)
        Info->TcpHeader.Offset -= sizeof (ETHERNET_TAG);

    if (Info->TcpOptions.Length != 0)
        Info->TcpOptions.Offset -= sizeof (ETHERNET_TAG);

    Info->Length -= sizeof (ETHERNET_TAG);

    BaseVa += Packet->Offset;

    EthernetHeader = (PETHERNET_HEADER)(BaseVa + Info->EthernetHeader.Offset);

    ASSERT3U(PayloadLength, ==, Packet->Length - Info->Length);
}

static DECLSPEC_NOINLINE VOID
ReceiverRingProcessChecksum(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_PACKET_INFO         Info;
    XENVIF_PACKET_PAYLOAD       Payload;
    uint16_t                    flags;
    PUCHAR                      BaseVa;
    PIP_HEADER                  IpHeader;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Info = &Packet->Info;

    Payload.Mdl = &Packet->Mdl;
    Payload.Offset = Packet->Offset + Info->Length;
    Payload.Length = Packet->Length - Info->Length;

    ASSERT3U(Payload.Offset, <=, Payload.Mdl->ByteCount);

    // The payload may be in a separate fragment
    if (Payload.Offset == Payload.Mdl->ByteCount) {
        Payload.Mdl = Payload.Mdl->Next;
        Payload.Offset = 0;
    }

    flags = (uint16_t)Packet->Flags.Value;
    Packet->Flags.Value = 0;

    if (Info->IpHeader.Length == 0)
        return;

    ASSERT(Packet->Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    BaseVa = Packet->Mdl.MappedSystemVa;
    ASSERT(BaseVa != NULL);

    BaseVa += Packet->Offset;

    IpHeader = (PIP_HEADER)(BaseVa + Info->IpHeader.Offset);

    if (IpHeader->Version == 4) {
        BOOLEAN OffloadChecksum;

        if (Ring->OffloadOptions.OffloadIpVersion4HeaderChecksum)
            OffloadChecksum = TRUE;
        else
            OffloadChecksum = FALSE;

        // IP header checksums are always present and not validated
        if (OffloadChecksum) {
            USHORT  Embedded;
            USHORT  Calculated;

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

    if (Info->TcpHeader.Length != 0 && !Info->IsAFragment) {
        PTCP_HEADER     TcpHeader;
        BOOLEAN         OffloadChecksum;

        TcpHeader = (PTCP_HEADER)(BaseVa + Info->TcpHeader.Offset);

        if (IpHeader->Version == 4 && Ring->OffloadOptions.OffloadIpVersion4TcpChecksum)
            OffloadChecksum = TRUE;
        else if (IpHeader->Version == 6 && Ring->OffloadOptions.OffloadIpVersion6TcpChecksum)
            OffloadChecksum = TRUE;
        else
            OffloadChecksum = FALSE;

        if (OffloadChecksum) {
            if (flags & NETRXF_data_validated) {    // Checksum may not be present but it is validated
                Packet->Flags.TcpChecksumSucceeded = 1;
            } else {                                // Checksum is present but is not validated
                USHORT  Embedded;
                USHORT  Calculated;

                ASSERT(~flags & NETRXF_csum_blank);

                Embedded = TcpHeader->Checksum;

                Calculated = ChecksumPseudoHeader(BaseVa, Info);
                Calculated = ChecksumTcpPacket(BaseVa, Info, Calculated, &Payload);

                if (ChecksumVerify(Calculated, Embedded))
                    Packet->Flags.TcpChecksumSucceeded = 1;
                else
                    Packet->Flags.TcpChecksumFailed = 1;
            }
        } else {
            Packet->Flags.TcpChecksumNotValidated = 1;
        }
        
        if ((Ring->OffloadOptions.NeedChecksumValue ||
             Receiver->CalculateChecksums != 0) &&
            (flags & NETRXF_data_validated)) {
            USHORT  Calculated;

            Calculated = ChecksumPseudoHeader(BaseVa, Info);
            Calculated = ChecksumTcpPacket(BaseVa, Info, Calculated, &Payload);

            TcpHeader->Checksum = Calculated;
        }
    } else if (Info->UdpHeader.Length != 0 && !Info->IsAFragment) {
        PUDP_HEADER     UdpHeader;
        BOOLEAN         OffloadChecksum;

        UdpHeader = (PUDP_HEADER)(BaseVa + Info->UdpHeader.Offset);

        if (IpHeader->Version == 4 && Ring->OffloadOptions.OffloadIpVersion4UdpChecksum)
            OffloadChecksum = TRUE;
        else if (IpHeader->Version == 6 && Ring->OffloadOptions.OffloadIpVersion6UdpChecksum)
            OffloadChecksum = TRUE;
        else
            OffloadChecksum = FALSE;

        if (OffloadChecksum) {
            if (flags & NETRXF_data_validated) {    // Checksum may not be present but it is validated
                Packet->Flags.UdpChecksumSucceeded = 1;
            } else {                                // Checksum is present but is not validated
                USHORT  Embedded;

                ASSERT(~flags & NETRXF_csum_blank);

                Embedded = UdpHeader->Checksum;

                // Tolarate zero checksum for IPv4/UDP
                if (IpHeader->Version == 4 && Embedded == 0) {
                    Packet->Flags.UdpChecksumSucceeded = 1;
                } else {
                    USHORT  Calculated;

                    Calculated = ChecksumPseudoHeader(BaseVa, Info);
                    Calculated = ChecksumUdpPacket(BaseVa, Info, Calculated, &Payload);

                    if (ChecksumVerify(Calculated, Embedded))
                        Packet->Flags.UdpChecksumSucceeded = 1;
                    else
                        Packet->Flags.UdpChecksumFailed = 1;
                }
            }
        } else {
            Packet->Flags.UdpChecksumNotValidated = 1;
        }

        if ((Ring->OffloadOptions.NeedChecksumValue ||
             Receiver->CalculateChecksums != 0) &&
            (flags & NETRXF_data_validated)) {
            USHORT  Calculated;

            Calculated = ChecksumPseudoHeader(BaseVa, Info);
            Calculated = ChecksumUdpPacket(BaseVa, Info, Calculated, &Payload);

            UdpHeader->Checksum = Calculated;
        }
    }
}

static BOOLEAN
ReceiverRingPullup(
    IN      PVOID                   Argument,
    IN      PUCHAR                  DestinationVa,
    IN OUT  PXENVIF_PACKET_PAYLOAD  Payload,
    IN      ULONG                   Length
    )
{
    PMDL                            Mdl;

    Mdl = Payload->Mdl;
    ASSERT3U(Payload->Offset, ==, 0);

    if (Payload->Length < Length)
        goto fail1;

    Payload->Length -= Length;

    while (Length != 0) {
        PUCHAR  SourceVa;
        ULONG   CopyLength;

        ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
        SourceVa = Mdl->MappedSystemVa;
        ASSERT(SourceVa != NULL);

        CopyLength = __min(Mdl->ByteCount, Length);

        RtlCopyMemory(DestinationVa, SourceVa, CopyLength);

        DestinationVa += CopyLength;

        Mdl->ByteOffset += CopyLength;
        Mdl->MappedSystemVa = SourceVa + CopyLength;
        Length -= CopyLength;

        Mdl->ByteCount -= CopyLength;
        if (Mdl->ByteCount == 0) {
            PXENVIF_RECEIVER_RING   Ring = Argument;
            PMDL                    Next;

            Next = Mdl->Next;
            Mdl->Next = NULL;

            __ReceiverRingPutMdl(Ring, Mdl, FALSE);

            Mdl = Next;
        }
    }

    Payload->Mdl = Mdl;

    return TRUE;

fail1:
    return FALSE;
}

static FORCEINLINE VOID
__ReceiverRingPullupPacket(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PUCHAR                      BaseVa;
    XENVIF_PACKET_PAYLOAD       Payload;
    ULONG                       Length;

    ASSERT(Packet->Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    BaseVa = Packet->Mdl.MappedSystemVa;
    ASSERT(BaseVa != NULL);

    Payload.Mdl = Packet->Mdl.Next;
    Payload.Offset = 0;
    Payload.Length = Packet->Length - Packet->Mdl.ByteCount;

    Length = __min(Payload.Length, PAGE_SIZE - Packet->Mdl.ByteCount);

    Packet->Mdl.Next = NULL;

    (VOID) ReceiverRingPullup(Ring, BaseVa + Packet->Mdl.ByteCount, &Payload, Length);
    Packet->Mdl.ByteCount += Length;

    if (Payload.Length != 0) {
        ASSERT(Payload.Mdl != NULL);
        Packet->Mdl.Next = Payload.Mdl;
    }
}

static FORCEINLINE PXENVIF_RECEIVER_PACKET
__ReceiverRingBuildSegment(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet,
    IN  ULONG                   SegmentSize,
    IN  PXENVIF_PACKET_PAYLOAD  Payload
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_PACKET_INFO         Info;
    PXENVIF_RECEIVER_PACKET     Segment;
    PMDL                        Mdl;
    PUCHAR                      InfoVa;
    PUCHAR                      BaseVa;
    PIP_HEADER                  IpHeader;
    PTCP_HEADER                 TcpHeader;
    ULONG                       Seq;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;

    Info = &Packet->Info;

    ASSERT(Packet->Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    InfoVa = Packet->Mdl.MappedSystemVa;
    ASSERT(InfoVa != NULL);

    InfoVa += Packet->Offset;

    Segment = __ReceiverRingGetPacket(Ring, FALSE);

    status = STATUS_NO_MEMORY;
    if (Segment == NULL)
        goto fail1;

    RtlCopyMemory(Segment,
                  Packet,
                  FIELD_OFFSET(XENVIF_RECEIVER_PACKET, Mdl));

    Segment->MaximumSegmentSize = 0;

    // The segment contains no data as yet
    Segment->Length = 0;

    Mdl = &Segment->Mdl;

    ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    BaseVa = Mdl->MappedSystemVa;
    ASSERT(BaseVa != NULL);

    BaseVa += Segment->Offset;

    Mdl->ByteCount = Segment->Offset;

    // Copy in the header
    RtlCopyMemory(BaseVa, InfoVa, Info->Length);
    Mdl->ByteCount += Info->Length;

    // Adjust the info for the next segment
    IpHeader = (PIP_HEADER)(InfoVa + Info->IpHeader.Offset);
    if (IpHeader->Version == 4) {
        USHORT  PacketID;
        USHORT  PacketLength;

        PacketID = NTOHS(IpHeader->Version4.PacketID);
        IpHeader->Version4.PacketID = HTONS(PacketID + 1);

        PacketLength = NTOHS(IpHeader->Version4.PacketLength);
        IpHeader->Version4.PacketLength = HTONS(PacketLength - (USHORT)SegmentSize);
    } else {
        USHORT  PayloadLength;

        ASSERT3U(IpHeader->Version, ==, 6);

        PayloadLength = NTOHS(IpHeader->Version6.PayloadLength);
        IpHeader->Version6.PayloadLength = HTONS(PayloadLength - (USHORT)SegmentSize);
    }

    TcpHeader = (PTCP_HEADER)(InfoVa + Info->TcpHeader.Offset);

    Seq = NTOHL(TcpHeader->Seq);
    TcpHeader->Seq = HTONL(Seq + SegmentSize);

    TcpHeader->Flags &= ~TCP_CWR;

    // Adjust the segment IP header
    IpHeader = (PIP_HEADER)(BaseVa + Info->IpHeader.Offset);
    if (IpHeader->Version == 4) {
        ULONG   PacketLength;

        PacketLength = Info->IpHeader.Length +
                       Info->IpOptions.Length + 
                       Info->TcpHeader.Length + 
                       Info->TcpOptions.Length + 
                       SegmentSize;

        IpHeader->Version4.PacketLength = HTONS((USHORT)PacketLength);
        IpHeader->Version4.Checksum = ChecksumIpVersion4Header(BaseVa, Info);
    } else {
        ULONG   PayloadLength;

        ASSERT3U(IpHeader->Version, ==, 6);

        PayloadLength = Info->IpOptions.Length + 
                        Info->TcpHeader.Length + 
                        Info->TcpOptions.Length + 
                        SegmentSize;

        IpHeader->Version6.PayloadLength = HTONS((USHORT)PayloadLength);
    }

    // Adjust the segment TCP header
    TcpHeader = (PTCP_HEADER)(BaseVa + Info->TcpHeader.Offset);

    TcpHeader->Flags &= ~(TCP_PSH | TCP_FIN);

    // Copy in the payload
    for (;;) {
        ULONG   Length;

        Mdl->Next = __ReceiverRingGetMdl(Ring, FALSE);
            
        status = STATUS_NO_MEMORY;
        if (Mdl->Next == NULL)
            goto fail2;

        Mdl = Mdl->Next;

        ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
        BaseVa = Mdl->MappedSystemVa;
        ASSERT(BaseVa != NULL);

        Mdl->ByteOffset = Ring->BackfillSize;

        BaseVa += Ring->BackfillSize;
        Mdl->MappedSystemVa = BaseVa;

        Length = __min(SegmentSize - Segment->Length, PAGE_SIZE - Mdl->ByteOffset);
        ASSERT(Length != 0);

        (VOID) ReceiverRingPullup(Ring, BaseVa, Payload, Length);
        Mdl->ByteCount += Length;
        Segment->Length += Length;

        ASSERT3U(Segment->Length, <=, SegmentSize);
        if (Segment->Length == SegmentSize)
            break;

        ASSERT3U(Mdl->ByteCount, ==, PAGE_SIZE - Mdl->ByteOffset);
    }

    Segment->Length += Info->Length;

    if (Receiver->AlwaysPullup != 0)
        __ReceiverRingPullupPacket(Ring, Segment);

    return Segment;

fail2:
    Error("fail2\n");

    Mdl = Segment->Mdl.Next;
    Segment->Mdl.Next = NULL;

    while (Mdl != NULL) {
        PMDL    Next;

        Next = Mdl->Next;
        Mdl->Next = NULL;

        __ReceiverRingPutMdl(Ring, Mdl, FALSE);

        Mdl = Next;
    }

    __ReceiverRingPutPacket(Ring, Segment, FALSE);

fail1:
    Error("fail1 (%08x)\n", status);
    
    return NULL;
}

static VOID
ReceiverRingCompletePacket(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    ReceiverRingProcessTag(Ring, Packet);
    ReceiverRingProcessChecksum(Ring, Packet);

    ASSERT(IsZeroMemory(&Packet->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&Ring->PacketComplete, &Packet->ListEntry);
}

static VOID
ReceiverRingProcessLargePacket(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    BOOLEAN                     Offload;
    PXENVIF_PACKET_INFO         Info;
    uint16_t                    flags;
    XENVIF_PACKET_PAYLOAD       Payload;
    PUCHAR                      InfoVa;
    PIP_HEADER                  IpHeader;
    ULONG                       Length;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Info = &Packet->Info;
    ASSERT(Info->IpHeader.Offset != 0);
    ASSERT(Info->TcpHeader.Offset != 0);
    
    flags = (uint16_t)Packet->Flags.Value;
    ASSERT(flags & NETRXF_csum_blank);
    ASSERT(flags & NETRXF_data_validated);

    Payload.Mdl = Packet->Mdl.Next;
    Payload.Offset = 0;
    Payload.Length = Packet->Length - Info->Length;

    Packet->Mdl.Next = NULL;

    ASSERT(Packet->Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    InfoVa = Packet->Mdl.MappedSystemVa;
    ASSERT(InfoVa != NULL);

    InfoVa += Packet->Offset;

    IpHeader = (PIP_HEADER)(InfoVa + Info->IpHeader.Offset);

    if (IpHeader->Version == 4) {
        Offload = (Ring->OffloadOptions.OffloadIpVersion4LargePacket) ? TRUE : FALSE;
    } else {
        ASSERT3U(IpHeader->Version, ==, 6);
        Offload = (Ring->OffloadOptions.OffloadIpVersion6LargePacket) ? TRUE : FALSE;
    }

    if (IpHeader->Version == 4) {
        USHORT  PacketLength;

        PacketLength = NTOHS(IpHeader->Version4.PacketLength);
        
        Length = (ULONG)PacketLength -
                 Info->TcpOptions.Length -
                 Info->TcpHeader.Length -
                 Info->IpOptions.Length - 
                 Info->IpHeader.Length;
    } else {
        USHORT  PayloadLength;

        ASSERT3U(IpHeader->Version, ==, 6);

        PayloadLength = NTOHS(IpHeader->Version6.PayloadLength);

        Length = (ULONG)PayloadLength -
                 Info->TcpOptions.Length -
                 Info->TcpHeader.Length -
                 Info->IpOptions.Length;
    }

    while (Length > 0) {
        ULONG                   SegmentSize;
        PXENVIF_RECEIVER_PACKET Segment;

        if (Offload &&
            Ring->OffloadOptions.NeedLargePacketSplit == 0)
            break;

        SegmentSize = __min(Length, Packet->MaximumSegmentSize);

        Segment = __ReceiverRingBuildSegment(Ring, Packet, SegmentSize, &Payload);

        status = STATUS_NO_MEMORY;
        if (Segment == NULL)
            goto fail1;

        ASSERT3U(Length, >=, SegmentSize);
        Length -= SegmentSize;

        ReceiverRingCompletePacket(Ring, Segment);

        if (Offload) {
            ASSERT(Ring->OffloadOptions.NeedLargePacketSplit != 0);
            break;
        }
    }

    if (Length != 0) {
        ASSERT(Payload.Mdl != NULL);

        if (IpHeader->Version == 4) {
            USHORT  PacketLength;

            PacketLength = NTOHS(IpHeader->Version4.PacketLength);
        
            ASSERT3U(Length,
                     ==,
                     (ULONG)PacketLength -
                     Info->TcpOptions.Length -
                     Info->TcpHeader.Length -
                     Info->IpOptions.Length - 
                     Info->IpHeader.Length);

            IpHeader->Version4.Checksum = ChecksumIpVersion4Header(InfoVa, Info);
        } else {
            USHORT  PayloadLength;

            ASSERT3U(IpHeader->Version, ==, 6);

            PayloadLength = NTOHS(IpHeader->Version6.PayloadLength);

            ASSERT3U(Length,
                     ==,
                     (ULONG)PayloadLength -
                     Info->TcpOptions.Length -
                     Info->TcpHeader.Length -
                     Info->IpOptions.Length);
        }

        Packet->Mdl.Next = Payload.Mdl;
        Packet->Length = Info->Length + Payload.Length;

        if (Payload.Length < Packet->MaximumSegmentSize)
            Packet->MaximumSegmentSize = 0;

        if (Receiver->AlwaysPullup != 0)
            __ReceiverRingPullupPacket(Ring, Packet);

        ReceiverRingCompletePacket(Ring, Packet);
    } else {
        __ReceiverRingPutPacket(Ring, Packet, FALSE);
    }

    return;

fail1:
    Error("fail1 (%08x)\n", status);

    if (Payload.Length != 0) {
        PMDL    Mdl = Payload.Mdl;

        ASSERT(Mdl != NULL);

        while (Mdl != NULL) {
            PMDL    Next;

            Next = Mdl->Next;
            Mdl->Next = NULL;

            __ReceiverRingPutMdl(Ring, Mdl, FALSE);

            Mdl = Next;
        }
    }

    __ReceiverRingPutPacket(Ring, Packet, FALSE);

    FrontendIncrementStatistic(Frontend,
                               XENVIF_RECEIVER_PACKETS_DROPPED,
                               1);
}

static VOID
ReceiverRingProcessStandardPacket(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_MAC                 Mac;
    PXENVIF_PACKET_INFO         Info;
    XENVIF_PACKET_PAYLOAD       Payload;
    ULONG                       MaximumFrameSize;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;
    Mac = FrontendGetMac(Frontend);

    Info = &Packet->Info;

    Payload.Mdl = Packet->Mdl.Next;
    Payload.Offset = 0;
    Payload.Length = Packet->Length - Info->Length;

    MacQueryMaximumFrameSize(Mac, &MaximumFrameSize);

    status = STATUS_INVALID_PARAMETER;
    if (Packet->Length > MaximumFrameSize)
        goto fail1;

    // Certain HCK tests (e.g. the NDISTest 2c_Priority test) are
    // sufficiently brain-dead that they cannot cope with
    // multi-fragment packets, or at least packets where headers are
    // in different fragments. All these tests seem to use IPX packets
    // and, in practice, little else uses LLC so pull up all LLC
    // packets into a single fragment.
    if (Info->LLCSnapHeader.Length != 0 || Receiver->AlwaysPullup != 0)
        __ReceiverRingPullupPacket(Ring, Packet);
    else if (Payload.Mdl != NULL && Payload.Mdl->ByteOffset < Ring->BackfillSize) {
        PMDL    Mdl;
        PUCHAR  BaseVa;

        // NDIS Header/Data split requires that the data MDL has a minimum length
        // of headroom (i.e. ByteOffset) so that it can pre-pend the header to the data
        // if something up the stack can't cope with the split.

        Mdl = __ReceiverRingGetMdl(Ring, FALSE);

        status = STATUS_NO_MEMORY;
        if (Mdl == NULL)
            goto fail2;

        ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
        BaseVa = Mdl->MappedSystemVa;
        ASSERT(BaseVa != NULL);

        Mdl->ByteOffset = Ring->BackfillSize;
        Mdl->ByteCount = __min(Payload.Mdl->ByteCount,
                               PAGE_SIZE - Mdl->ByteOffset);

        BaseVa += Ring->BackfillSize;
        Mdl->MappedSystemVa = BaseVa;

        (VOID) ReceiverRingPullup(Ring, BaseVa, &Payload, Mdl->ByteCount);

        if (Payload.Length != 0) {
            ASSERT(Payload.Mdl != NULL);
            Mdl->Next = Payload.Mdl;
        }

        Packet->Mdl.Next = Mdl;
    }

    ReceiverRingCompletePacket(Ring, Packet);
    return;

fail2:
fail1:
    if (Payload.Length != 0) {
        PMDL    Mdl = Payload.Mdl;

        ASSERT(Mdl != NULL);

        while (Mdl != NULL) {
            PMDL    Next;

            Next = Mdl->Next;
            Mdl->Next = NULL;

            __ReceiverRingPutMdl(Ring, Mdl, FALSE);

            Mdl = Next;
        }
    }

    Packet->Mdl.Next = NULL;
    __ReceiverRingPutPacket(Ring, Packet, FALSE);

    FrontendIncrementStatistic(Frontend,
                               XENVIF_RECEIVER_PACKETS_DROPPED,
                               1);
}

static VOID
ReceiverRingProcessPacket(
    IN  PXENVIF_RECEIVER_RING       Ring,
    IN  PXENVIF_RECEIVER_PACKET     Packet
    )
{
    PXENVIF_RECEIVER                Receiver;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    ULONG                           Length;
    XENVIF_PACKET_PAYLOAD           Payload;
    PXENVIF_RECEIVER_PACKET         New;
    PXENVIF_PACKET_INFO             Info;
    PUCHAR                          BaseVa;
    PETHERNET_HEADER                EthernetHeader;
    PETHERNET_ADDRESS               DestinationAddress;
    NTSTATUS                        status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;
    Mac = FrontendGetMac(Frontend);

    ASSERT3U(Packet->Offset, ==, 0);
    Length = Packet->Length;
    ASSERT3U(Packet->TagControlInformation, ==, 0);

    Payload.Mdl = &Packet->Mdl;
    Payload.Offset = 0;
    Payload.Length = Length;

    // Get a new packet structure that will just contain the header after
    // parsing. We need to preserve metadata from the original.

    New = __ReceiverRingGetPacket(Ring, FALSE);

    status = STATUS_NO_MEMORY;
    if (New == NULL) {
        FrontendIncrementStatistic(Frontend,
            XENVIF_RECEIVER_FRONTEND_ERRORS,
            1);
        goto fail1;
    }

    RtlCopyMemory(New,
                  Packet,
                  FIELD_OFFSET(XENVIF_RECEIVER_PACKET, Mdl));

    Packet = New;

    // Override offset to align
    Packet->Offset = Receiver->IpAlignOffset;

    ASSERT(Packet->Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    BaseVa = Packet->Mdl.MappedSystemVa;
    ASSERT(BaseVa != NULL);

    BaseVa += Packet->Offset;

    Packet->Mdl.ByteCount = Packet->Offset;

    Info = &Packet->Info;

    status = ParsePacket(BaseVa, ReceiverRingPullup, Ring, &Payload, Info);
    if (!NT_SUCCESS(status)) {
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_RECEIVER_FRONTEND_ERRORS,
                                   1);
        goto fail2;
    }

    ASSERT3U(Packet->Length, ==, Info->Length + Payload.Length);

    Packet->Mdl.ByteCount += Info->Length;

    if (Payload.Length != 0) {
        ASSERT(Payload.Mdl != NULL);
        Packet->Mdl.Next = Payload.Mdl;
    }

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(BaseVa + Info->EthernetHeader.Offset);

    DestinationAddress = &EthernetHeader->DestinationAddress;

    status = STATUS_UNSUCCESSFUL;
    if (!MacApplyFilters(Mac, DestinationAddress))
        goto fail3;

    if (Packet->MaximumSegmentSize != 0)
        ReceiverRingProcessLargePacket(Ring, Packet);
    else
        ReceiverRingProcessStandardPacket(Ring, Packet);

    return;

fail3:
    Packet->Mdl.Next = NULL;

fail2:
    __ReceiverRingPutPacket(Ring, Packet, FALSE);

fail1:
    if (Payload.Length != 0) {
        PMDL    Mdl = Payload.Mdl;

        ASSERT(Mdl != NULL);

        while (Mdl != NULL) {
            PMDL    Next;

            Next = Mdl->Next;
            Mdl->Next = NULL;

            __ReceiverRingPutMdl(Ring, Mdl, FALSE);

            Mdl = Next;
        }
    }

    FrontendIncrementStatistic(Frontend,
                               XENVIF_RECEIVER_PACKETS_DROPPED,
                               1);
}

static FORCEINLINE VOID
__ReceiverRingSwizzle(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_VIF_CONTEXT         Context;
    LIST_ENTRY                  List;
    PLIST_ENTRY                 ListEntry;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;
    Context = PdoGetVifContext(FrontendGetPdo(Frontend));

    InitializeListHead(&List);

    ListEntry = InterlockedExchangePointer(&Ring->PacketQueue, NULL);

    // Packets are held in the queue in reverse order so that the most
    // recent is always head of the list. This is necessary to allow
    // addition to the list to be done atomically.

    while (ListEntry != NULL) {
        PLIST_ENTRY NextEntry;

        NextEntry = ListEntry->Blink;
        ListEntry->Flink = ListEntry->Blink = ListEntry;

        InsertHeadList(&List, ListEntry);

        ListEntry = NextEntry;
    }

    while (!IsListEmpty(&List)) {
        PXENVIF_RECEIVER_PACKET Packet;

        ListEntry = RemoveHeadList(&List);
        ASSERT3P(ListEntry, !=, &List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Packet = CONTAINING_RECORD(ListEntry, XENVIF_RECEIVER_PACKET, ListEntry);
        ReceiverRingProcessPacket(Ring, Packet);
    }

    while (!IsListEmpty(&Ring->PacketComplete)) {
        PXENVIF_RECEIVER_PACKET Packet;
        PXENVIF_PACKET_INFO     Info;
        PUCHAR                  BaseVa;
        PETHERNET_HEADER        EthernetHeader;
        PETHERNET_ADDRESS       DestinationAddress;
        ETHERNET_ADDRESS_TYPE   Type;

        ListEntry = RemoveHeadList(&Ring->PacketComplete);
        ASSERT3P(ListEntry, !=, &Ring->PacketComplete);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Packet = CONTAINING_RECORD(ListEntry,
                                   XENVIF_RECEIVER_PACKET,
                                   ListEntry);

        ASSERT(Packet->Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
        BaseVa = Packet->Mdl.MappedSystemVa;
        ASSERT(BaseVa != NULL);

        BaseVa += Packet->Offset;

        Info = &Packet->Info;

        ASSERT(Info->EthernetHeader.Length != 0);
        EthernetHeader = (PETHERNET_HEADER)(BaseVa + Info->EthernetHeader.Offset);

        DestinationAddress = &EthernetHeader->DestinationAddress;

        Type = GET_ETHERNET_ADDRESS_TYPE(DestinationAddress);

        switch (Type) {
        case ETHERNET_ADDRESS_UNICAST:
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_UNICAST_PACKETS,
                                       1);
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_UNICAST_OCTETS,
                                       Packet->Length);
            break;

        case ETHERNET_ADDRESS_MULTICAST:
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_MULTICAST_PACKETS,
                                       1);
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_MULTICAST_OCTETS,
                                       Packet->Length);
            break;

        case ETHERNET_ADDRESS_BROADCAST:
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_BROADCAST_PACKETS,
                                       1);
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_BROADCAST_OCTETS,
                                       Packet->Length);
            break;

        default:
            ASSERT(FALSE);
            break;
        }

        if (ETHERNET_HEADER_IS_TAGGED(EthernetHeader))
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_TAGGED_PACKETS,
                                       1);

        if (Info->LLCSnapHeader.Length != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_LLC_SNAP_PACKETS,
                                       1);

        if (Info->IpHeader.Length != 0) {
            PIP_HEADER  IpHeader = (PIP_HEADER)(BaseVa + Info->IpHeader.Offset);

            if (IpHeader->Version == 4) {
                FrontendIncrementStatistic(Frontend,
                                           XENVIF_RECEIVER_IPV4_PACKETS,
                                           1);
            } else {
                ASSERT3U(IpHeader->Version, ==, 6);

                FrontendIncrementStatistic(Frontend,
                                           XENVIF_RECEIVER_IPV6_PACKETS,
                                           1);
            }
        }

        if (Info->TcpHeader.Length != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_TCP_PACKETS,
                                       1);

        if (Info->UdpHeader.Length != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_UDP_PACKETS,
                                       1);

        if (Packet->MaximumSegmentSize != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_GSO_PACKETS,
                                       1);

        if (Packet->Flags.IpChecksumSucceeded != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_IPV4_CHECKSUM_SUCCEEDED,
                                       1);

        if (Packet->Flags.IpChecksumFailed != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_IPV4_CHECKSUM_FAILED,
                                       1);

        if (Packet->Flags.IpChecksumNotValidated != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_IPV4_CHECKSUM_NOT_VALIDATED,
                                       1);

        if (Packet->Flags.TcpChecksumSucceeded != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_TCP_CHECKSUM_SUCCEEDED,
                                       1);

        if (Packet->Flags.TcpChecksumFailed != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_TCP_CHECKSUM_FAILED,
                                       1);

        if (Packet->Flags.TcpChecksumNotValidated != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_TCP_CHECKSUM_NOT_VALIDATED,
                                       1);

        if (Packet->Flags.UdpChecksumSucceeded != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_UDP_CHECKSUM_SUCCEEDED,
                                       1);

        if (Packet->Flags.UdpChecksumFailed != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_UDP_CHECKSUM_FAILED,
                                       1);

        if (Packet->Flags.UdpChecksumNotValidated != 0)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_RECEIVER_UDP_CHECKSUM_NOT_VALIDATED,
                                       1);

        (VOID) InterlockedIncrement(&Receiver->Loaned);

        VifReceiverQueuePacket(Context,
                               Ring->Index,
                               &Packet->Mdl,
                               Packet->Offset,
                               Packet->Length,
                               Packet->Flags,
                               Packet->MaximumSegmentSize,
                               Packet->TagControlInformation,
                               &Packet->Info,
                               &Packet->Hash,
                               !IsListEmpty(&Ring->PacketComplete) ? TRUE : FALSE,
                               Packet);
    }
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__ReceiverRingAcquireLock(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Ring->Lock);
}

static DECLSPEC_NOINLINE VOID
ReceiverRingAcquireLock(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    __ReceiverRingAcquireLock(Ring);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__ReceiverRingReleaseLock(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

#pragma prefast(disable:26110)
    KeReleaseSpinLockFromDpcLevel(&Ring->Lock);
}

static DECLSPEC_NOINLINE VOID
ReceiverRingReleaseLock(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    __ReceiverRingReleaseLock(Ring);
}

__drv_functionClass(KDEFERRED_ROUTINE)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
static VOID
ReceiverRingQueueDpc(
    IN  PKDPC               Dpc,
    IN  PVOID               Context,
    IN  PVOID               Argument1,
    IN  PVOID               Argument2
    )
{
    PXENVIF_RECEIVER_RING   Ring = Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Ring != NULL);

    __ReceiverRingSwizzle(Ring);
}

static FORCEINLINE VOID
__ReceiverRingStop(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    Ring->Stopped = TRUE;
}

static FORCEINLINE VOID
__ReceiverRingStart(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    Ring->Stopped = FALSE;
}

static FORCEINLINE BOOLEAN
__ReceiverRingIsStopped(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    return Ring->Stopped;
}

static FORCEINLINE VOID
__ReceiverRingTrigger(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  BOOLEAN                 Locked
    )
{
    PXENVIF_RECEIVER            Receiver;

    Receiver = Ring->Receiver;

    if (!Locked)
        __ReceiverRingAcquireLock(Ring);

    if (Ring->Connected)
        (VOID) XENBUS_EVTCHN(Trigger,
                             &Receiver->EvtchnInterface,
                             Ring->Channel);

    if (!Locked)
        __ReceiverRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__ReceiverRingSend(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  BOOLEAN                 Locked
    )
{
    PXENVIF_RECEIVER            Receiver;

    Receiver = Ring->Receiver;

    if (!Locked)
        __ReceiverRingAcquireLock(Ring);

    if (Ring->Connected)
        (VOID) XENBUS_EVTCHN(Send,
                             &Receiver->EvtchnInterface,
                             Ring->Channel);

    if (!Locked)
        __ReceiverRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__ReceiverRingReturnPacket(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet,
    IN  BOOLEAN                 Locked
    )
{
    PMDL                        Mdl;

    Mdl = &Packet->Mdl;

    while (Mdl != NULL) {
        PMDL    Next;

        Next = Mdl->Next;
        Mdl->Next = NULL;

        __ReceiverRingPutMdl(Ring, Mdl, Locked);

        Mdl = Next;
    }

    if (__ReceiverRingIsStopped(Ring)) {
        KIRQL   Irql;

        KeRaiseIrql(DISPATCH_LEVEL, &Irql);

        if (!Locked)
            __ReceiverRingAcquireLock(Ring);

        if (__ReceiverRingIsStopped(Ring)) {
            __ReceiverRingStart(Ring);
            __ReceiverRingTrigger(Ring, TRUE);
        }

        if (!Locked)
            __ReceiverRingReleaseLock(Ring);

        KeLowerIrql(Irql);
    }
}

static FORCEINLINE PXENVIF_RECEIVER_FRAGMENT
__ReceiverRingPreparePacket(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_RECEIVER_FRAGMENT   Fragment;
    PMDL                        Mdl;
    PFN_NUMBER                  Pfn;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Fragment = __ReceiverRingGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Fragment == NULL)
        goto fail1;

    Mdl = &Packet->Mdl;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Receiver->GnttabInterface,
                           Ring->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           FALSE,
                           &Fragment->Entry);
    if (!NT_SUCCESS(status))
        goto fail2;

    Fragment->Context = Mdl;

    return Fragment;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    __ReceiverRingPutFragment(Ring, Fragment);
    
    return NULL;
}

static FORCEINLINE VOID
__ReceiverRingPushRequests(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    BOOLEAN                     Notify;

    if (Ring->RequestsPosted == Ring->RequestsPushed)
        return;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Ring->Front, Notify);

#pragma warning (pop)

    if (Notify)
        __ReceiverRingSend(Ring, TRUE);

    Ring->RequestsPushed = Ring->RequestsPosted;
}

static VOID
ReceiverRingFill(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    RING_IDX                    req_prod;
    RING_IDX                    rsp_cons;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    KeMemoryBarrier();

    req_prod = Ring->Front.req_prod_pvt;
    rsp_cons = Ring->Front.rsp_cons;

    KeMemoryBarrier();

    while (req_prod - rsp_cons < RING_SIZE(&Ring->Front)) {
        PXENVIF_RECEIVER_PACKET     Packet;
        PXENVIF_RECEIVER_FRAGMENT   Fragment;
        netif_rx_request_t          *req;
        uint16_t                    id;

        Packet = __ReceiverRingGetPacket(Ring, TRUE);

        if (Packet == NULL) {
            __ReceiverRingStop(Ring);
            break;
        }

        Fragment = __ReceiverRingPreparePacket(Ring, Packet);
        
        if (Fragment == NULL) {
            __ReceiverRingPutPacket(Ring, Packet, TRUE);
            break;
        }

        req = RING_GET_REQUEST(&Ring->Front, req_prod);
        id = (uint16_t)(req_prod & (RING_SIZE(&Ring->Front) - 1));

        req_prod++;
        Ring->RequestsPosted++;

        req->id = id;
        req->gref = XENBUS_GNTTAB(GetReference,
                                  &Receiver->GnttabInterface,
                                  Fragment->Entry);

        ASSERT3U(id, <=, XENVIF_RECEIVER_MAXIMUM_FRAGMENT_ID);
        ASSERT3P(Ring->Pending[id], ==, NULL);
        Ring->Pending[id] = Fragment;
    }

    KeMemoryBarrier();

    Ring->Front.req_prod_pvt = req_prod;

    __ReceiverRingPushRequests(Ring);
}

static FORCEINLINE VOID
__ReceiverRingEmpty(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    uint16_t                    id;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    for (id = 0; id <= XENVIF_RECEIVER_MAXIMUM_FRAGMENT_ID; id++) {
        PXENVIF_RECEIVER_FRAGMENT   Fragment;
        PMDL                        Mdl;

        Fragment = Ring->Pending[id];
        Ring->Pending[id] = NULL;

        if (Fragment == NULL)
            continue;

        --Ring->RequestsPosted;
        --Ring->RequestsPushed;

        Mdl = Fragment->Context;
        Fragment->Context = NULL;

        (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                             &Receiver->GnttabInterface,
                             Ring->GnttabCache,
                             TRUE,
                             Fragment->Entry);
        Fragment->Entry = NULL;

        __ReceiverRingPutFragment(Ring, Fragment);

        __ReceiverRingPutMdl(Ring, Mdl, TRUE);
    }
}

static VOID
ReceiverRingDebugCallback(
    IN  PVOID                   Argument,
    IN  BOOLEAN                 Crashing
    )
{
    PXENVIF_RECEIVER_RING       Ring = Argument;
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;

    UNREFERENCED_PARAMETER(Crashing);

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    XENBUS_DEBUG(Printf,
                 &Receiver->DebugInterface,
                 "0x%p [%u] [%s][%s]\n",
                 Ring,
                 Ring->Index,
                 (Ring->Enabled) ? "ENABLED" : "DISABLED",
                 (__ReceiverRingIsStopped(Ring)) ? "STOPPED" : "RUNNING");

    XENBUS_DEBUG(Printf,
                 &Receiver->DebugInterface,
                 "QueueDpcs = %lu\n",
                 Ring->QueueDpcs);

    // Dump front ring
    XENBUS_DEBUG(Printf,
                 &Receiver->DebugInterface,
                 "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
                 Ring->Front.req_prod_pvt,
                 Ring->Front.rsp_cons,
                 Ring->Front.nr_ents,
                 Ring->Front.sring);

    // Dump shared ring
    XENBUS_DEBUG(Printf,
                 &Receiver->DebugInterface,
                 "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
                 Ring->Shared->req_prod,
                 Ring->Shared->req_event,
                 Ring->Shared->rsp_prod,
                 Ring->Shared->rsp_event);

    XENBUS_DEBUG(Printf,
                 &Receiver->DebugInterface,
                 "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
                 Ring->RequestsPosted,
                 Ring->RequestsPushed,
                 Ring->ResponsesProcessed);

    // Dump event channel
    XENBUS_DEBUG(Printf,
                 &Receiver->DebugInterface,
                 "[%s]: Events = %lu PollDpcs = %lu\n",
                 FrontendIsSplit(Frontend) ? "RX" : "COMBINED",
                 Ring->Events,
                 Ring->PollDpcs);
}

static FORCEINLINE VOID
__ReceiverRingQueuePacket(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PLIST_ENTRY                 ListEntry;
    PLIST_ENTRY                 Old;
    PLIST_ENTRY                 New;

    ListEntry = &Packet->ListEntry;

    do {
        Old = Ring->PacketQueue;

        ListEntry->Blink = Ring->PacketQueue;
        New = ListEntry;
    } while (InterlockedCompareExchangePointer(&Ring->PacketQueue, (PVOID)New, (PVOID)Old) != Old);
}

static DECLSPEC_NOINLINE ULONG
ReceiverRingPoll(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    ULONG                       Count;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Count = 0;

    if (!Ring->Enabled)
        goto done;

    for (;;) {
        BOOLEAN                 Error;
        BOOLEAN                 Extra;
        ULONG                   Info;
        USHORT                  MaximumSegmentSize;
        XENVIF_PACKET_HASH      Hash;
        PXENVIF_RECEIVER_PACKET Packet;
        uint16_t                flags;
        PMDL                    TailMdl;
        BOOLEAN                 EOP;
        RING_IDX                rsp_prod;
        RING_IDX                rsp_cons;

        Error = FALSE;
        Extra = FALSE;
        Info = 0;
        MaximumSegmentSize = 0;
        RtlZeroMemory(&Hash, sizeof (Hash));
        Packet = NULL;
        flags = 0;
        TailMdl = NULL;
        EOP = TRUE;

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

        while (rsp_cons != rsp_prod) {
            netif_rx_response_t         *rsp;
            uint16_t                    id;
            PXENVIF_RECEIVER_FRAGMENT   Fragment;
            PMDL                        Mdl;

            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_cons);

            // netback is required to complete requests in order and place
            // the response in the same fragment as the request. This is
            // the only way to figure out the id of an 'extra' fragment.
            id = (uint16_t)(rsp_cons & (RING_SIZE(&Ring->Front) - 1));

            rsp_cons++;
            Ring->ResponsesProcessed++;
            Count++;

            ASSERT3U(id, <=, XENVIF_RECEIVER_MAXIMUM_FRAGMENT_ID);
            Fragment = Ring->Pending[id];
            Ring->Pending[id] = NULL;

            ASSERT(Fragment != NULL);

            Mdl = Fragment->Context;
            Fragment->Context = NULL;

            (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                                 &Receiver->GnttabInterface,
                                 Ring->GnttabCache,
                                 TRUE,
                                 Fragment->Entry);
            Fragment->Entry = NULL;

            __ReceiverRingPutFragment(Ring, Fragment);

            ASSERT(Mdl != NULL);

            if (Extra) {
                struct netif_extra_info *extra;

                __ReceiverRingPutMdl(Ring, Mdl, TRUE);

                extra = (struct netif_extra_info *)rsp;
                Info |= (1 << extra->type);

                switch (extra->type) {
                case XEN_NETIF_EXTRA_TYPE_GSO:
                    MaximumSegmentSize = extra->u.gso.size;
                    break;

                case XEN_NETIF_EXTRA_TYPE_HASH:
                    Hash.Algorithm = XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ;

                    switch (extra->u.hash.type) {
                    case _XEN_NETIF_CTRL_HASH_TYPE_IPV4:
                        Hash.Type = XENVIF_PACKET_HASH_TYPE_IPV4;
                        break;

                    case _XEN_NETIF_CTRL_HASH_TYPE_IPV4_TCP:
                        Hash.Type = XENVIF_PACKET_HASH_TYPE_IPV4_TCP;
                        break;

                    case _XEN_NETIF_CTRL_HASH_TYPE_IPV6:
                        Hash.Type = XENVIF_PACKET_HASH_TYPE_IPV6;
                        break;

                    case _XEN_NETIF_CTRL_HASH_TYPE_IPV6_TCP:
                        Hash.Type = XENVIF_PACKET_HASH_TYPE_IPV6_TCP;
                        break;

                    default:
                        ASSERT(FALSE);
                        Hash.Type = XENVIF_PACKET_HASH_TYPE_NONE;
                        break;
                    }

                    Hash.Value = *(uint32_t *)extra->u.hash.value;
                    break;

                default:
                    ASSERT(FALSE);
                    break;
                }

                Extra = (extra->flags & XEN_NETIF_EXTRA_FLAG_MORE) ? TRUE : FALSE;
            } else {
                PUCHAR  BaseVa;

                ASSERT3U(rsp->id, ==, id);

                ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
                BaseVa = Mdl->MappedSystemVa;
                ASSERT(BaseVa != NULL);

                Mdl->ByteOffset = rsp->offset;

                BaseVa += rsp->offset;
                Mdl->MappedSystemVa = BaseVa;

                Mdl->ByteCount = rsp->status;

                if (rsp->status < 0)
                    Error = TRUE;

                if (Packet == NULL) {   // SOP
                    Packet = CONTAINING_RECORD(Mdl, XENVIF_RECEIVER_PACKET, Mdl);

                    ASSERT3P(TailMdl, ==, NULL);
                    TailMdl = Mdl;

                    flags = rsp->flags;
                    Packet->Length = Mdl->ByteCount;
                } else {
                    ASSERT3P(Mdl->Next, ==, NULL);

                    ASSERT(TailMdl != NULL);
                    TailMdl->Next = Mdl;
                    TailMdl = Mdl;

                    flags |= rsp->flags;
                    Packet->Length += Mdl->ByteCount;
                }

                EOP = (~rsp->flags & NETRXF_more_data) ? TRUE : FALSE;
                Extra = (rsp->flags & NETRXF_extra_info) ? TRUE : FALSE;
            }

            if (EOP && !Extra) {
                ASSERT(Packet != NULL);

                if (Error) {
                    FrontendIncrementStatistic(Frontend,
                                               XENVIF_RECEIVER_BACKEND_ERRORS,
                                               1);

                    __ReceiverRingReturnPacket(Ring, Packet, TRUE);
                } else {
                    if (Info & (1 << XEN_NETIF_EXTRA_TYPE_GSO)) {
                        ASSERT(MaximumSegmentSize != 0);
                        ASSERT(flags & NETRXF_csum_blank);
                        ASSERT(flags & NETRXF_data_validated);
                        Packet->MaximumSegmentSize = MaximumSegmentSize;
                    }

                    if (Info & (1 << XEN_NETIF_EXTRA_TYPE_HASH)) {
                        ASSERT3U(Hash.Algorithm, ==, XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ);

                        if (Hash.Algorithm == Ring->Hash.Algorithm &&
                            ((1u << Hash.Type) & Ring->Hash.Types))
                            Packet->Hash = Hash;
                    }

                    Packet->Flags.Value = flags;

                    ASSERT(IsZeroMemory(&Packet->ListEntry, sizeof (LIST_ENTRY)));
                    __ReceiverRingQueuePacket(Ring, Packet);
                }

                Error = FALSE;
                Info = 0;
                MaximumSegmentSize = 0;
                RtlZeroMemory(&Hash, sizeof (Hash));
                Packet = NULL;
                flags = 0;
                TailMdl = NULL;
            }
        }
        ASSERT(!Error);
        ASSERT(!Extra);
        ASSERT3U(Info, ==, 0);
        ASSERT3P(Packet, ==, NULL);
        ASSERT3U(flags, ==, 0);
        ASSERT3U(MaximumSegmentSize, ==, 0);
        ASSERT(IsZeroMemory(&Hash, sizeof (Hash)));
        ASSERT3P(TailMdl, ==, NULL);
        ASSERT(EOP);

        KeMemoryBarrier();

        Ring->Front.rsp_cons = rsp_cons;
    }

    if (!__ReceiverRingIsStopped(Ring))
        ReceiverRingFill(Ring);

    if (Ring->PacketQueue != NULL &&
        KeInsertQueueDpc(&Ring->QueueDpc, NULL, NULL))
        Ring->QueueDpcs++;

done:
    return Count;
}

static FORCEINLINE BOOLEAN
__ReceiverRingUnmask(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  BOOLEAN                 Force
    )
{
    PXENVIF_RECEIVER            Receiver;

    if (!Ring->Connected)
        return TRUE;

    Receiver = Ring->Receiver;

    return !XENBUS_EVTCHN(Unmask,
                          &Receiver->EvtchnInterface,
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
ReceiverRingPollDpc(
    IN  PKDPC               Dpc,
    IN  PVOID               Context,
    IN  PVOID               Argument1,
    IN  PVOID               Argument2
    )
{
    PXENVIF_RECEIVER_RING   Ring = Context;
    ULONG                   Count;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Ring != NULL);

    Count = 0;

    for (;;) {
        __ReceiverRingAcquireLock(Ring);
        Count += ReceiverRingPoll(Ring);
        __ReceiverRingReleaseLock(Ring);

        if (__ReceiverRingUnmask(Ring,
                                 (Count > XENVIF_RECEIVER_RING_SIZE)))
            break;
    }
}

KSERVICE_ROUTINE    ReceiverRingEvtchnCallback;

BOOLEAN
ReceiverRingEvtchnCallback(
    IN  PKINTERRUPT             InterruptObject,
    IN  PVOID                   Argument
    )
{
    PXENVIF_RECEIVER_RING       Ring = Argument;
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Ring != NULL);

    Ring->Events++;

    if (KeInsertQueueDpc(&Ring->PollDpc, NULL, NULL))
        Ring->PollDpcs++;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    if (!FrontendIsSplit(Frontend))
        TransmitterNotify(FrontendGetTransmitter(Frontend),
                          Ring->Index);

    return TRUE;
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define XENVIF_RECEIVER_WATCHDOG_PERIOD 30

static NTSTATUS
ReceiverRingWatchdog(
    IN  PXENVIF_THREAD      Self,
    IN  PVOID               Context
    )
{
    PXENVIF_RECEIVER_RING   Ring = Context;
    PROCESSOR_NUMBER        ProcNumber;
    GROUP_AFFINITY          Affinity;
    LARGE_INTEGER           Timeout;
    RING_IDX                rsp_prod;
    RING_IDX                rsp_cons;
    NTSTATUS                status;

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

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(XENVIF_RECEIVER_WATCHDOG_PERIOD));

    rsp_prod = 0;
    rsp_cons = 0;

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
        __ReceiverRingAcquireLock(Ring);

        if (Ring->Enabled) {
            KeMemoryBarrier();

            if (Ring->Shared->rsp_prod != rsp_prod &&
                Ring->Front.rsp_cons == rsp_cons) {
                PXENVIF_RECEIVER    Receiver;

                Receiver = Ring->Receiver;

                XENBUS_DEBUG(Trigger,
                             &Receiver->DebugInterface,
                             Ring->DebugCallback);

                // Try to move things along
                __ReceiverRingTrigger(Ring, TRUE);
                __ReceiverRingSend(Ring, TRUE);
            }

            KeMemoryBarrier();

            rsp_prod = Ring->Shared->rsp_prod;
            rsp_cons = Ring->Front.rsp_cons;
        }

        __ReceiverRingReleaseLock(Ring);
        KeLowerIrql(Irql);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__ReceiverRingInitialize(
    IN  PXENVIF_RECEIVER        Receiver,
    IN  ULONG                   Index,
    OUT PXENVIF_RECEIVER_RING   *Ring
    )
{
    PXENVIF_FRONTEND            Frontend;
    CHAR                        Name[MAXNAMELEN];
    NTSTATUS                    status;

    Frontend = Receiver->Frontend;

    *Ring = __ReceiverAllocate(sizeof (XENVIF_RECEIVER_RING));

    status = STATUS_NO_MEMORY;
    if (Ring == NULL)
        goto fail1;

    KeInitializeSpinLock(&(*Ring)->Lock);

    (*Ring)->Receiver = Receiver;
    (*Ring)->Index = Index;

    (*Ring)->Path = FrontendFormatPath(Frontend, Index);
    if ((*Ring)->Path == NULL)
        goto fail2;

    InitializeListHead(&(*Ring)->PacketComplete);

    KeInitializeDpc(&(*Ring)->PollDpc, ReceiverRingPollDpc, *Ring);

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_receiver_packet",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail3;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Receiver->CacheInterface,
                          Name,
                          sizeof (XENVIF_RECEIVER_PACKET),
                          0,
                          0,
                          ReceiverPacketCtor,
                          ReceiverPacketDtor,
                          ReceiverRingAcquireLock,
                          ReceiverRingReleaseLock,
                          *Ring,
                          &(*Ring)->PacketCache);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_receiver_fragment",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail5;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Receiver->CacheInterface,
                          Name,
                          sizeof (XENVIF_RECEIVER_FRAGMENT),
                          0,
                          0,
                          ReceiverFragmentCtor,
                          ReceiverFragmentDtor,
                          ReceiverRingAcquireLock,
                          ReceiverRingReleaseLock,
                          *Ring,
                          &(*Ring)->FragmentCache);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = ThreadCreate(ReceiverRingWatchdog,
                          *Ring,
                          &(*Ring)->WatchdogThread);
    if (!NT_SUCCESS(status))
        goto fail7;

    KeInitializeThreadedDpc(&(*Ring)->QueueDpc, ReceiverRingQueueDpc, *Ring);

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    XENBUS_CACHE(Destroy,
                 &Receiver->CacheInterface,
                 (*Ring)->FragmentCache);
    (*Ring)->FragmentCache = NULL;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    XENBUS_CACHE(Destroy,
                 &Receiver->CacheInterface,
                 (*Ring)->PacketCache);
    (*Ring)->PacketCache = NULL;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    RtlZeroMemory(&(*Ring)->PollDpc, sizeof (KDPC));

    RtlZeroMemory(&(*Ring)->PacketComplete, sizeof (LIST_ENTRY));

    FrontendFreePath(Frontend, (*Ring)->Path);
    (*Ring)->Path = NULL;

fail2:
    Error("fail2\n");

    (*Ring)->Index = 0;
    (*Ring)->Receiver = NULL;

    RtlZeroMemory(&(*Ring)->Lock, sizeof (KSPIN_LOCK));

    ASSERT(IsZeroMemory(*Ring, sizeof (XENVIF_RECEIVER_RING)));
    __ReceiverFree(*Ring);
    *Ring = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__ReceiverRingConnect(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PFN_NUMBER                  Pfn;
    CHAR                        Name[MAXNAMELEN];
    ULONG                       Index;
    PROCESSOR_NUMBER            ProcNumber;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_receiver",
                                Ring->Path);
    if (!NT_SUCCESS(status))
        goto fail1;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_GNTTAB(CreateCache,
                           &Receiver->GnttabInterface,
                           Name,
                           0,
                           ReceiverRingAcquireLock,
                           ReceiverRingReleaseLock,
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
                           &Receiver->GnttabInterface,
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
                                __MODULE__ "|RECEIVER[%u]",
                                Ring->Index);
    if (!NT_SUCCESS(status))
        goto fail5;

    ASSERT(!Ring->Connected);

    Ring->Channel = XENBUS_EVTCHN(Open,
                                  &Receiver->EvtchnInterface,
                                  XENBUS_EVTCHN_TYPE_UNBOUND,
                                  ReceiverRingEvtchnCallback,
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
                         &Receiver->EvtchnInterface,
                         Ring->Channel,
                         ProcNumber.Group,
                         ProcNumber.Number);

    (VOID) XENBUS_EVTCHN(Unmask,
                         &Receiver->EvtchnInterface,
                         Ring->Channel,
                         FALSE,
                         TRUE);

    Ring->Connected = TRUE;

    status = XENBUS_DEBUG(Register,
                          &Receiver->DebugInterface,
                          Name,
                          ReceiverRingDebugCallback,
                          Ring,
                          &Ring->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = KeGetProcessorNumberFromIndex(Ring->Index, &ProcNumber);
    ASSERT(NT_SUCCESS(status));

    KeSetTargetProcessorDpcEx(&Ring->QueueDpc, &ProcNumber);

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    Ring->Connected = FALSE;

    XENBUS_EVTCHN(Close,
                  &Receiver->EvtchnInterface,
                  Ring->Channel);
    Ring->Channel = NULL;

    Ring->Events = 0;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Receiver->GnttabInterface,
                         Ring->GnttabCache,
                         TRUE,
                         Ring->Entry);
    Ring->Entry = NULL;

fail4:
    Error("fail4\n");

    RtlZeroMemory(&Ring->Front, sizeof (netif_rx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

fail3:
    Error("fail3\n");

    XENBUS_GNTTAB(DestroyCache,
                  &Receiver->GnttabInterface,
                  Ring->GnttabCache);
    Ring->GnttabCache = NULL;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__ReceiverRingStoreWrite(
    IN  PXENVIF_RECEIVER_RING       Ring,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_RECEIVER                Receiver;
    PXENVIF_FRONTEND                Frontend;
    ULONG                           Port;
    PCHAR                           Path;
    NTSTATUS                        status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Path = (FrontendGetNumQueues(Frontend) == 1) ?
           FrontendGetPath(Frontend) :
           Ring->Path;

    status = XENBUS_STORE(Printf,
                          &Receiver->StoreInterface,
                          Transaction,
                          Path,
                          "rx-ring-ref",
                          "%u",
                          XENBUS_GNTTAB(GetReference,
                                        &Receiver->GnttabInterface,
                                        Ring->Entry));
    if (!NT_SUCCESS(status))
        goto fail1;

    Port = XENBUS_EVTCHN(GetPort,
                         &Receiver->EvtchnInterface,
                         Ring->Channel);

    status = XENBUS_STORE(Printf,
                          &Receiver->StoreInterface,
                          Transaction,
                          Path,
                          FrontendIsSplit(Frontend) ? "event-channel-rx" : "event-channel",
                          "%u",
                          Port);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__ReceiverRingEnable(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Info("%s[%u]: ====>\n",
         FrontendGetPath(Frontend),
         Ring->Index);

    __ReceiverRingAcquireLock(Ring);

    ASSERT(!Ring->Enabled);

    ReceiverRingFill(Ring);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!RING_FULL(&Ring->Front))
        goto fail1;

    Ring->Enabled = TRUE;

    (VOID) KeInsertQueueDpc(&Ring->PollDpc, NULL, NULL);

    __ReceiverRingReleaseLock(Ring);

    Info("%s[%u]: <====\n",
         FrontendGetPath(Frontend),
         Ring->Index);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    __ReceiverRingReleaseLock(Ring);

    return status;
}

static FORCEINLINE VOID
__ReceiverRingDisable(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{    
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Info("%s[%u]: ====>\n",
         FrontendGetPath(Frontend),
         Ring->Index);

    __ReceiverRingAcquireLock(Ring);

    ASSERT(Ring->Enabled);

    Ring->Enabled = FALSE;
    Ring->Stopped = FALSE;

    if (KeInsertQueueDpc(&Ring->QueueDpc, NULL, NULL))
        Ring->QueueDpcs++;

    __ReceiverRingReleaseLock(Ring);

    Info("%s[%u]: <====\n",
         FrontendGetPath(Frontend),
         Ring->Index);
}

static FORCEINLINE VOID
__ReceiverRingDisconnect(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Ring->QueueDpcs = 0;

    __ReceiverRingEmpty(Ring);

    ASSERT(Ring->Connected);
    Ring->Connected = FALSE;

    XENBUS_EVTCHN(Close,
                  &Receiver->EvtchnInterface,
                  Ring->Channel);
    Ring->Channel = NULL;

    Ring->Events = 0;
    Ring->PollDpcs = 0;

    ASSERT3U(Ring->ResponsesProcessed, ==, Ring->RequestsPushed);
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);

    Ring->ResponsesProcessed = 0;
    Ring->RequestsPushed = 0;
    Ring->RequestsPosted = 0;

    XENBUS_DEBUG(Deregister,
                 &Receiver->DebugInterface,
                 Ring->DebugCallback);
    Ring->DebugCallback = NULL;

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Receiver->GnttabInterface,
                         Ring->GnttabCache,
                         TRUE,
                         Ring->Entry);
    Ring->Entry = NULL;

    RtlZeroMemory(&Ring->Front, sizeof (netif_rx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

    XENBUS_GNTTAB(DestroyCache,
                  &Receiver->GnttabInterface,
                  Ring->GnttabCache);
    Ring->GnttabCache = NULL;
}

static FORCEINLINE VOID
__ReceiverRingTeardown(
    IN  PXENVIF_RECEIVER_RING   Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    RtlZeroMemory(&Ring->Hash, sizeof (XENVIF_RECEIVER_HASH));
    RtlZeroMemory(&Ring->PollDpc, sizeof (KDPC));

    Ring->BackfillSize = 0;
    Ring->OffloadOptions.Value = 0;

    KeFlushQueuedDpcs();
    RtlZeroMemory(&Ring->QueueDpc, sizeof (KDPC));

    ThreadAlert(Ring->WatchdogThread);
    ThreadJoin(Ring->WatchdogThread);
    Ring->WatchdogThread = NULL;

    XENBUS_CACHE(Destroy,
                 &Receiver->CacheInterface,
                 Ring->FragmentCache);
    Ring->FragmentCache = NULL;

    XENBUS_CACHE(Destroy,
                 &Receiver->CacheInterface,
                 Ring->PacketCache);
    Ring->PacketCache = NULL;

    ASSERT(IsListEmpty(&Ring->PacketComplete));
    RtlZeroMemory(&Ring->PacketComplete, sizeof (LIST_ENTRY));

    FrontendFreePath(Frontend, Ring->Path);
    Ring->Path = NULL;

    Ring->Index = 0;
    Ring->Receiver = NULL;

    RtlZeroMemory(&Ring->Lock, sizeof (KSPIN_LOCK));

    ASSERT(IsZeroMemory(Ring, sizeof (XENVIF_RECEIVER_RING)));
    __ReceiverFree(Ring);
}

static FORCEINLINE VOID
__ReceiverRingSetOffloadOptions(
    IN  PXENVIF_RECEIVER_RING       Ring,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  Options
    )
{
    KIRQL                           Irql;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    __ReceiverRingAcquireLock(Ring);
    Ring->OffloadOptions = Options;
    __ReceiverRingReleaseLock(Ring);

    KeLowerIrql(Irql);
}

static FORCEINLINE VOID
__ReceiverRingSetBackfillSize(
    IN  PXENVIF_RECEIVER_RING   Ring,
    IN  ULONG                   Size
    )
{
    KIRQL                       Irql;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    __ReceiverRingAcquireLock(Ring);
    Ring->BackfillSize = Size;
    __ReceiverRingReleaseLock(Ring);

    KeLowerIrql(Irql);
}

static VOID
ReceiverDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_RECEIVER    Receiver = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Receiver->DebugInterface,
                 "Loaned = %d Returned = %d\n",
                 Receiver->Loaned,
                 Receiver->Returned);
}

NTSTATUS
ReceiverInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_RECEIVER    *Receiver
    )
{
    HANDLE                  ParametersKey;
    LONG                    MaxQueues;
    LONG                    Index;
    NTSTATUS                status;

    *Receiver = __ReceiverAllocate(sizeof (XENVIF_RECEIVER));

    status = STATUS_NO_MEMORY;
    if (*Receiver == NULL)
        goto fail1;

    ParametersKey = DriverGetParametersKey();

    (*Receiver)->CalculateChecksums = 1;
    (*Receiver)->AllowGsoPackets = 1;
    (*Receiver)->DisableIpVersion4Gso = 0;
    (*Receiver)->DisableIpVersion6Gso = 0;
    (*Receiver)->IpAlignOffset = 0;
    (*Receiver)->AlwaysPullup = 0;

    if (ParametersKey != NULL) {
        ULONG   ReceiverCalculateChecksums;
        ULONG   ReceiverAllowGsoPackets;
        ULONG   ReceiverDisableIpVersion4Gso;
        ULONG   ReceiverDisableIpVersion6Gso;
        ULONG   ReceiverIpAlignOffset;
        ULONG   ReceiverAlwaysPullup;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverCalculateChecksums",
                                         &ReceiverCalculateChecksums);
        if (NT_SUCCESS(status))
            (*Receiver)->CalculateChecksums = ReceiverCalculateChecksums;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverAllowGsoPackets",
                                         &ReceiverAllowGsoPackets);
        if (NT_SUCCESS(status))
            (*Receiver)->AllowGsoPackets = ReceiverAllowGsoPackets;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverDisableIpVersion4Gso",
                                         &ReceiverDisableIpVersion4Gso);
        if (NT_SUCCESS(status))
            (*Receiver)->DisableIpVersion4Gso = ReceiverDisableIpVersion4Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverDisableIpVersion6Gso",
                                         &ReceiverDisableIpVersion6Gso);
        if (NT_SUCCESS(status))
            (*Receiver)->DisableIpVersion6Gso = ReceiverDisableIpVersion6Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverIpAlignOffset",
                                         &ReceiverIpAlignOffset);
        if (NT_SUCCESS(status))
            (*Receiver)->IpAlignOffset = ReceiverIpAlignOffset;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverAlwaysPullup",
                                         &ReceiverAlwaysPullup);
        if (NT_SUCCESS(status))
            (*Receiver)->AlwaysPullup = ReceiverAlwaysPullup;
    }

    KeInitializeEvent(&(*Receiver)->Event, NotificationEvent, FALSE);

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Receiver)->DebugInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Receiver)->StoreInterface);

    FdoGetCacheInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Receiver)->CacheInterface);

    FdoGetGnttabInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Receiver)->GnttabInterface);

    FdoGetEvtchnInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Receiver)->EvtchnInterface);

    (*Receiver)->Frontend = Frontend;

    status = XENBUS_CACHE(Acquire, &(*Receiver)->CacheInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    MaxQueues = FrontendGetMaxQueues(Frontend);
    (*Receiver)->Ring = __ReceiverAllocate(sizeof (PXENVIF_RECEIVER_RING) *
                                           MaxQueues);

    status = STATUS_NO_MEMORY;
    if ((*Receiver)->Ring == NULL)
        goto fail3;

    Index = 0;
    while (Index < MaxQueues) {
        PXENVIF_RECEIVER_RING   Ring;

        status = __ReceiverRingInitialize(*Receiver, Index, &Ring);
        if (!NT_SUCCESS(status))
            goto fail4;

        (*Receiver)->Ring[Index] = Ring;
        Index++;
    }

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    while (--Index >= 0) {
        PXENVIF_RECEIVER_RING   Ring = (*Receiver)->Ring[Index];

        (*Receiver)->Ring[Index] = NULL;
        __ReceiverRingTeardown(Ring);
    }

    __ReceiverFree((*Receiver)->Ring);

    (*Receiver)->Ring = NULL;

fail3:
    Error("fail3\n");

    XENBUS_CACHE(Release, &(*Receiver)->CacheInterface);

fail2:
    Error("fail2\n");

    (*Receiver)->Frontend = NULL;

    RtlZeroMemory(&(*Receiver)->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&(*Receiver)->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    RtlZeroMemory(&(*Receiver)->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&(*Receiver)->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&(*Receiver)->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&(*Receiver)->Event, sizeof (KEVENT));

    (*Receiver)->CalculateChecksums = 0;
    (*Receiver)->AllowGsoPackets = 0;
    (*Receiver)->DisableIpVersion4Gso = 0;
    (*Receiver)->DisableIpVersion6Gso = 0;
    (*Receiver)->IpAlignOffset = 0;
    (*Receiver)->AlwaysPullup = 0;

    ASSERT(IsZeroMemory(*Receiver, sizeof (XENVIF_RECEIVER)));
    __ReceiverFree(*Receiver);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ReceiverConnect(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;
    NTSTATUS                status;

    Trace("====>\n");

    Frontend = Receiver->Frontend;

    status = XENBUS_DEBUG(Acquire, &Receiver->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Receiver->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_EVTCHN(Acquire, &Receiver->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_GNTTAB(Acquire, &Receiver->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    Index = 0;
    while (Index < (LONG)FrontendGetNumQueues(Frontend)) {
        PXENVIF_RECEIVER_RING   Ring = Receiver->Ring[Index];

        status = __ReceiverRingConnect(Ring);
        if (!NT_SUCCESS(status))
            goto fail5;

        Index++;
    }    

    status = XENBUS_DEBUG(Register,
                          &Receiver->DebugInterface,
                          __MODULE__ "|RECEIVER",
                          ReceiverDebugCallback,
                          Receiver,
                          &Receiver->DebugCallback);
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
        PXENVIF_RECEIVER_RING   Ring = Receiver->Ring[Index];

        __ReceiverRingDisconnect(Ring);
    }

    XENBUS_GNTTAB(Release, &Receiver->GnttabInterface);

fail4:
    Error("fail4\n");

    XENBUS_EVTCHN(Release, &Receiver->EvtchnInterface);

fail3:
    Error("fail3\n");

    XENBUS_STORE(Release, &Receiver->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Receiver->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__ReceiverSetGsoFeatureFlag(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend;
    NTSTATUS                        status;

    Frontend = Receiver->Frontend;

    (VOID) XENBUS_STORE(Remove,
                        &Receiver->StoreInterface,
                        Transaction,
                        FrontendGetPath(Frontend),
                        "feature-gso-tcpv4-prefix");

    status = XENBUS_STORE(Printf,
                          &Receiver->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "feature-gso-tcpv4",
                          "%u",
                          (Receiver->DisableIpVersion4Gso == 0) ? TRUE : FALSE);
    if (!NT_SUCCESS(status))
        goto fail1;

    (VOID) XENBUS_STORE(Remove,
                        &Receiver->StoreInterface,
                        Transaction,
                        FrontendGetPath(Frontend),
                        "feature-gso-tcpv6-prefix");

    status = XENBUS_STORE(Printf,
                          &Receiver->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "feature-gso-tcpv6",
                          "%u",
                          (Receiver->DisableIpVersion6Gso == 0) ? TRUE : FALSE);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__ReceiverSetChecksumFeatureFlag(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend;
    NTSTATUS                        status;

    Frontend = Receiver->Frontend;

    status = XENBUS_STORE(Printf,
                          &Receiver->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "feature-no-csum-offload",
                          "%u",
                          FALSE);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Printf,
                          &Receiver->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "feature-ipv6-csum-offload",
                          "%u",
                          TRUE);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ReceiverStoreWrite(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend;
    LONG                            Index;
    NTSTATUS                        status;

    Frontend = Receiver->Frontend;

    status = XENBUS_STORE(Printf,
                          &Receiver->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "request-rx-copy",
                          "%u",
                          TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Printf,
                          &Receiver->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "feature-sg",
                          "%u",
                          TRUE);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_STORE(Printf,
                          &Receiver->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "feature-rx-notify",
                          "%u",
                          TRUE);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = __ReceiverSetGsoFeatureFlag(Receiver, Transaction);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = __ReceiverSetChecksumFeatureFlag(Receiver, Transaction);
    if (!NT_SUCCESS(status))
        goto fail5;

    Index = 0;
    while (Index < (LONG)FrontendGetNumQueues(Frontend)) {
        PXENVIF_RECEIVER_RING   Ring = Receiver->Ring[Index];

        status = __ReceiverRingStoreWrite(Ring, Transaction);
        if (!NT_SUCCESS(status))
            goto fail6;

        Index++;
    }    

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ReceiverEnable(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;
    NTSTATUS                status;

    Trace("====>\n");

    Frontend = Receiver->Frontend;

    Index = 0;
    while (Index < (LONG)FrontendGetNumQueues(Frontend)) {
        PXENVIF_RECEIVER_RING   Ring = Receiver->Ring[Index];

        status = __ReceiverRingEnable(Ring);
        if (!NT_SUCCESS(status))
            goto fail1;

        Index++;
    }    

    Trace("<====\n");
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    while (--Index >= 0) {
        PXENVIF_RECEIVER_RING   Ring;

        Ring = Receiver->Ring[Index];
        if (Ring == NULL)
            break;

        __ReceiverRingDisable(Ring);
    }

    return status;
}

VOID
ReceiverDisable(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;

    Trace("====>\n");

    Frontend = Receiver->Frontend;

    Index = FrontendGetNumQueues(Frontend);
    while (--Index >= 0) {
        PXENVIF_RECEIVER_RING   Ring = Receiver->Ring[Index];

        __ReceiverRingDisable(Ring);
    }

    Trace("<====\n");
}

VOID
ReceiverDisconnect(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;

    Trace("=====>\n");

    Frontend = Receiver->Frontend;

    XENBUS_DEBUG(Deregister,
                 &Receiver->DebugInterface,
                 Receiver->DebugCallback);
    Receiver->DebugCallback = NULL;

    Index = FrontendGetNumQueues(Frontend);
    while (--Index >= 0) {
        PXENVIF_RECEIVER_RING   Ring = Receiver->Ring[Index];

        __ReceiverRingDisconnect(Ring);
    }

    XENBUS_GNTTAB(Release, &Receiver->GnttabInterface);

    XENBUS_EVTCHN(Release, &Receiver->EvtchnInterface);

    XENBUS_STORE(Release, &Receiver->StoreInterface);

    XENBUS_DEBUG(Release, &Receiver->DebugInterface);

    Trace("<====\n");
}

VOID
ReceiverTeardown(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;

    Frontend = Receiver->Frontend;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    KeFlushQueuedDpcs();

    ASSERT3U(Receiver->Returned, ==, Receiver->Loaned);
    Receiver->Loaned = 0;
    Receiver->Returned = 0;

    Index = FrontendGetMaxQueues(Frontend);
    while (--Index >= 0) {
        PXENVIF_RECEIVER_RING   Ring = Receiver->Ring[Index];

        Receiver->Ring[Index] = NULL;
        __ReceiverRingTeardown(Ring);
    }

    __ReceiverFree(Receiver->Ring);
    Receiver->Ring = NULL;

    XENBUS_CACHE(Release, &Receiver->CacheInterface);

    Receiver->Frontend = NULL;

    RtlZeroMemory(&Receiver->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&Receiver->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    RtlZeroMemory(&Receiver->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&Receiver->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Receiver->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Receiver->Event, sizeof (KEVENT));

    Receiver->CalculateChecksums = 0;
    Receiver->AllowGsoPackets = 0;
    Receiver->DisableIpVersion4Gso = 0;
    Receiver->DisableIpVersion6Gso = 0;
    Receiver->IpAlignOffset = 0;
    Receiver->AlwaysPullup = 0;

    ASSERT(IsZeroMemory(Receiver, sizeof (XENVIF_RECEIVER)));
    __ReceiverFree(Receiver);
}

VOID
ReceiverSetOffloadOptions(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  Options
    )
{
    PXENVIF_FRONTEND                Frontend;
    LONG                            Index;

    Frontend = Receiver->Frontend;

    if (Receiver->AllowGsoPackets == 0) {
        Warning("RECEIVER GSO DISALLOWED\n");
        Options.OffloadIpVersion4LargePacket = 0;
        Options.OffloadIpVersion6LargePacket = 0;
    }

    for (Index = 0;
         Index < (LONG)FrontendGetMaxQueues(Frontend);
         ++Index) {
        PXENVIF_RECEIVER_RING   Ring;

        Ring = Receiver->Ring[Index];
        if (Ring == NULL)
            break;

        __ReceiverRingSetOffloadOptions(Ring, Options);
    }    
}

VOID
ReceiverSetBackfillSize(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Size
    )
{
    PXENVIF_FRONTEND                Frontend;
    LONG                            Index;

    Frontend = Receiver->Frontend;

    ASSERT3U(Size, <, PAGE_SIZE);

    for (Index = 0;
         Index < (LONG)FrontendGetMaxQueues(Frontend);
         ++Index) {
        PXENVIF_RECEIVER_RING   Ring;

        Ring = Receiver->Ring[Index];
        if (Ring == NULL)
            break;

        __ReceiverRingSetBackfillSize(Ring, Size);
    }
}

VOID
ReceiverQueryRingSize(
    IN  PXENVIF_RECEIVER    Receiver,
    OUT PULONG              Size
    )
{
    UNREFERENCED_PARAMETER(Receiver);

    *Size = XENVIF_RECEIVER_RING_SIZE;
}

VOID
ReceiverReturnPacket(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  PVOID               Cookie
    )
{
    PXENVIF_RECEIVER_PACKET Packet = Cookie;
    PXENVIF_RECEIVER_RING   Ring;
    LONG                    Loaned;
    LONG                    Returned;

    Ring = Packet->Ring;

    __ReceiverRingReturnPacket(Ring, Packet, FALSE);

    KeMemoryBarrier();

    Returned = InterlockedIncrement(&Receiver->Returned);

    // Make sure Loaned is not sampled before Returned
    KeMemoryBarrier();

    Loaned = Receiver->Loaned;

    ASSERT3S(Loaned - Returned, >=, 0);

    KeSetEvent(&Receiver->Event, 0, FALSE);
}

#define XENVIF_RECEIVER_PACKET_WAIT_PERIOD 10

VOID
ReceiverWaitForPackets(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Loaned;
    LONG                    Returned;
    LARGE_INTEGER           Timeout;

    ASSERT3U(KeGetCurrentIrql(), <, DISPATCH_LEVEL);
    KeFlushQueuedDpcs();

    Frontend = Receiver->Frontend;

    Trace("%s: ====>\n", FrontendGetPath(Frontend));

    Returned = Receiver->Returned;
    Loaned = Receiver->Loaned;
    ASSERT3S(Loaned - Returned, >=, 0);

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(XENVIF_RECEIVER_PACKET_WAIT_PERIOD));

    while (Returned != Loaned) {
        Info("%s: (Loaned = %d Returned = %d)\n",
             FrontendGetPath(Frontend),
             Loaned,
             Returned);

        (VOID) KeWaitForSingleObject(&Receiver->Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     &Timeout);
        KeClearEvent(&Receiver->Event);

        Returned = Receiver->Returned;
        KeMemoryBarrier();

        ASSERT3S(Loaned, ==, Receiver->Loaned);
    }

    Info("%s: (Loaned = %d Returned = %d)\n",
         FrontendGetPath(Frontend),
         Loaned,
         Returned);

    Trace("%s: <====\n", FrontendGetPath(Frontend));
}

VOID
ReceiverTrigger(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Index
    )
{
    PXENVIF_RECEIVER_RING   Ring;

    Ring = Receiver->Ring[Index];

    __ReceiverRingTrigger(Ring, FALSE);
}

VOID
ReceiverSend(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Index
    )
{
    PXENVIF_RECEIVER_RING   Ring;

    Ring = Receiver->Ring[Index];

    __ReceiverRingSend(Ring, FALSE);
}

NTSTATUS
ReceiverSetHashAlgorithm(
    IN  PXENVIF_RECEIVER                Receiver,
    IN  XENVIF_PACKET_HASH_ALGORITHM    Algorithm
    )
{
    PXENVIF_FRONTEND                    Frontend;
    KIRQL                               Irql;
    LONG                                Index;
    NTSTATUS                            status;

    Frontend = Receiver->Frontend;

    status = FrontendSetHashAlgorithm(Frontend, Algorithm);
    if (!NT_SUCCESS(status))
        goto fail1;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    for (Index = 0;
         Index < (LONG)FrontendGetMaxQueues(Frontend);
         ++Index) {
        PXENVIF_RECEIVER_RING   Ring;

        Ring = Receiver->Ring[Index];
        if (Ring == NULL)
            break;

        __ReceiverRingAcquireLock(Ring);
        Ring->Hash.Algorithm = Algorithm;
        __ReceiverRingReleaseLock(Ring);
    }

    KeLowerIrql(Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ReceiverQueryHashCapabilities(
    IN  PXENVIF_RECEIVER    Receiver,
    OUT PULONG              Types
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Receiver->Frontend;

    status = FrontendQueryHashTypes(Frontend, Types);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ReceiverUpdateHashParameters(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Types,
    IN  PUCHAR              Key
    )
{
    PXENVIF_FRONTEND        Frontend;
    KIRQL                   Irql;
    LONG                    Index;
    NTSTATUS                status;

    Frontend = Receiver->Frontend;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    for (Index = 0;
         Index < (LONG)FrontendGetMaxQueues(Frontend);
         ++Index) {
        PXENVIF_RECEIVER_RING   Ring;

        Ring = Receiver->Ring[Index];
        if (Ring == NULL)
            break;

        __ReceiverRingAcquireLock(Ring);
        Ring->Hash.Types = Types;
        __ReceiverRingReleaseLock(Ring);
    }

    KeLowerIrql(Irql);

    status = FrontendSetHashTypes(Frontend, Types);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = FrontendSetHashKey(Frontend, Key);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ReceiverUpdateHashMapping(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  PPROCESSOR_NUMBER   ProcessorMapping,
    IN  ULONG               Size
    )
{
    PXENVIF_FRONTEND        Frontend;
    PULONG                  QueueMapping;
    ULONG                   NumQueues;
    ULONG                   Index;
    NTSTATUS                status;

    Frontend = Receiver->Frontend;

    QueueMapping = __ReceiverAllocate(sizeof (ULONG) * Size);

    status = STATUS_NO_MEMORY;
    if (QueueMapping == NULL)
        goto fail1;

    NumQueues = FrontendGetNumQueues(Frontend);

    status = STATUS_INVALID_PARAMETER;
    for (Index = 0; Index < Size; Index++) {
        QueueMapping[Index] = KeGetProcessorIndexFromNumber(&ProcessorMapping[Index]);

        if (QueueMapping[Index] >= NumQueues)
            goto fail2;
    }

    status = FrontendSetHashMapping(Frontend, QueueMapping, Size);
    if (!NT_SUCCESS(status))
        goto fail3;

    __ReceiverFree(QueueMapping);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    __ReceiverFree(QueueMapping);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}
