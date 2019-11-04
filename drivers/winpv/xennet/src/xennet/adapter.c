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

#define INITGUID 1

#include <ndis.h>
#include <stdlib.h>
#include <version.h>

#include <vif_interface.h>
#include <store_interface.h>
#include <suspend_interface.h>

#include "adapter.h"
#include "transmitter.h"
#include "receiver.h"
#include "util.h"
#include "dbg_print.h"
#include "assert.h"
#include "string.h"

#define MAXNAMELEN  128

typedef struct _PROPERTIES {
    int ipv4_csum;
    int tcpv4_csum;
    int udpv4_csum;
    int tcpv6_csum;
    int udpv6_csum;
    int need_csum_value;
    int lsov4;
    int lsov6;
    int lrov4;
    int lrov6;
    int rss;
} PROPERTIES, *PPROPERTIES;

typedef struct _XENNET_RSS {
    BOOLEAN Supported;
    BOOLEAN HashEnabled;
    BOOLEAN ScaleEnabled;
    ULONG   Types;
    UCHAR   Key[NDIS_RSS_HASH_SECRET_KEY_MAX_SIZE_REVISION_1];
    ULONG   KeySize;
    CCHAR   Table[NDIS_RSS_INDIRECTION_TABLE_MAX_SIZE_REVISION_1];
    ULONG   TableSize;
} XENNET_RSS, *PXENNET_RSS;

struct _XENNET_ADAPTER {
    PWCHAR                      Location;

    XENVIF_VIF_INTERFACE        VifInterface;
    XENBUS_STORE_INTERFACE      StoreInterface;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;

    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;

    ULONG                       MaximumFrameSize;
    ULONG                       CurrentLookahead;

    NDIS_HANDLE                 NdisAdapterHandle;
    NDIS_HANDLE                 NdisDmaHandle;
    NDIS_PNP_CAPABILITIES       Capabilities;
    NDIS_OFFLOAD                Offload;
    PROPERTIES                  Properties;
    XENNET_RSS                  Rss;
    NDIS_LINK_STATE             LinkState;

    PXENNET_RECEIVER            Receiver;
    PXENNET_TRANSMITTER         Transmitter;
    BOOLEAN                     Enabled;
};

static LONG AdapterCount;

static NDIS_OID XennetSupportedOids[] =
{
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_PHYSICAL_MEDIUM,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_GEN_VENDOR_ID,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
    OID_GEN_XMIT_ERROR,
    OID_GEN_RCV_ERROR,
    OID_GEN_RCV_CRC_ERROR,
    OID_GEN_RCV_NO_BUFFER,
    OID_GEN_TRANSMIT_QUEUE_LENGTH,
    OID_GEN_TRANSMIT_BUFFER_SPACE,
    OID_GEN_RECEIVE_BUFFER_SPACE,
    OID_GEN_STATISTICS,
    OID_GEN_DIRECTED_BYTES_XMIT,
    OID_GEN_DIRECTED_FRAMES_XMIT,
    OID_GEN_MULTICAST_BYTES_XMIT,
    OID_GEN_MULTICAST_FRAMES_XMIT,
    OID_GEN_BROADCAST_BYTES_XMIT,
    OID_GEN_BROADCAST_FRAMES_XMIT,
    OID_GEN_DIRECTED_BYTES_RCV,
    OID_GEN_DIRECTED_FRAMES_RCV,
    OID_GEN_MULTICAST_BYTES_RCV,
    OID_GEN_MULTICAST_FRAMES_RCV,
    OID_GEN_BROADCAST_BYTES_RCV,
    OID_GEN_BROADCAST_FRAMES_RCV,
    OID_GEN_INTERRUPT_MODERATION,
    OID_802_3_RCV_ERROR_ALIGNMENT,
    OID_802_3_XMIT_ONE_COLLISION,
    OID_802_3_XMIT_MORE_COLLISIONS,
    OID_OFFLOAD_ENCAPSULATION,
    OID_TCP_OFFLOAD_PARAMETERS,
    OID_PNP_CAPABILITIES,
    OID_PNP_QUERY_POWER,
    OID_PNP_SET_POWER,
    OID_GEN_RECEIVE_SCALE_PARAMETERS,
    OID_GEN_RECEIVE_HASH,
};

#define ADAPTER_POOL_TAG    'AteN'

__drv_functionClass(MINIPORT_PROCESS_SG_LIST)
static VOID
AdapterProcessSGList(
    IN PDEVICE_OBJECT       DeviceObject,
    IN PVOID                Reserved,
    IN PSCATTER_GATHER_LIST SGL,
    IN PVOID                Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(SGL);
    UNREFERENCED_PARAMETER(Context);

    ASSERT(FALSE);
}

__drv_functionClass(MINIPORT_ALLOCATE_SHARED_MEM_COMPLETE)
static VOID
AdapterAllocateComplete (
    IN NDIS_HANDLE              MiniportAdapterContext,
    IN PVOID                    VirtualAddress,
    IN PNDIS_PHYSICAL_ADDRESS   PhysicalAddress,
    IN ULONG                    Length,
    IN PVOID                    Context
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Context);

    ASSERT(FALSE);
}

static VOID
AdapterVifCallback(
    IN  PVOID                       Context,
    IN  XENVIF_VIF_CALLBACK_TYPE    Type,
    ...
    )
{
    PXENNET_ADAPTER     Adapter = Context;
    va_list             Arguments;

    va_start(Arguments, Type);

    switch (Type) {
    case XENVIF_TRANSMITTER_RETURN_PACKET: {
        PVOID                                       Cookie;
        PXENVIF_TRANSMITTER_PACKET_COMPLETION_INFO  Completion;

        Cookie = va_arg(Arguments, PVOID);
        Completion = va_arg(Arguments, PXENVIF_TRANSMITTER_PACKET_COMPLETION_INFO);

        TransmitterReturnPacket(Adapter->Transmitter,
                                Cookie,
                                Completion);
        break;
    }
    case XENVIF_RECEIVER_QUEUE_PACKET: {
        ULONG                           Index;
        PMDL                            Mdl;
        ULONG                           Offset;
        ULONG                           Length;
        XENVIF_PACKET_CHECKSUM_FLAGS    Flags;
        USHORT                          MaximumSegmentSize;
        USHORT                          TagControlInformation;
        PXENVIF_PACKET_INFO             Info;
        PXENVIF_PACKET_HASH             Hash;
        BOOLEAN                         More;
        PVOID                           Cookie;

        Index = va_arg(Arguments, ULONG);
        Mdl = va_arg(Arguments, PMDL);
        Offset = va_arg(Arguments, ULONG);
        Length = va_arg(Arguments, ULONG);
        Flags = va_arg(Arguments, XENVIF_PACKET_CHECKSUM_FLAGS);
        MaximumSegmentSize = va_arg(Arguments, USHORT);
        TagControlInformation = va_arg(Arguments, USHORT);
        Info = va_arg(Arguments, PXENVIF_PACKET_INFO);
        Hash = va_arg(Arguments, PXENVIF_PACKET_HASH);
        More = va_arg(Arguments, BOOLEAN);
        Cookie = va_arg(Arguments, PVOID);

        ReceiverQueuePacket(Adapter->Receiver,
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
    }
    case XENVIF_MAC_STATE_CHANGE: {
        AdapterMediaStateChange(Adapter);
        break;
    }
    }

    va_end(Arguments);
}

static VOID
DisplayOffload(
    IN  const CHAR      *Type,
    IN  PNDIS_OFFLOAD   Offload
    )
{
    Trace("%s:\n", Type);

    if (Offload->Checksum.IPv4Receive.IpChecksum)
        Trace("Checksum.IPv4Receive.IpChecksum ON\n");
    else
        Trace("Checksum.IPv4Receive.IpChecksum OFF\n");

    if (Offload->Checksum.IPv4Receive.TcpChecksum)
        Trace("Checksum.IPv4Receive.TcpChecksum ON\n");
    else
        Trace("Checksum.IPv4Receive.TcpChecksum OFF\n");

    if (Offload->Checksum.IPv4Receive.UdpChecksum)
        Trace("Checksum.IPv4Receive.UdpChecksum ON\n");
    else
        Trace("Checksum.IPv4Receive.UdpChecksum OFF\n");

    if (Offload->Checksum.IPv6Receive.TcpChecksum)
        Trace("Checksum.IPv6Receive.TcpChecksum ON\n");
    else
        Trace("Checksum.IPv6Receive.TcpChecksum OFF\n");

    if (Offload->Checksum.IPv6Receive.UdpChecksum)
        Trace("Checksum.IPv6Receive.UdpChecksum ON\n");
    else
        Trace("Checksum.IPv6Receive.UdpChecksum OFF\n");

    if (Offload->Checksum.IPv4Transmit.IpChecksum)
        Trace("Checksum.IPv4Transmit.IpChecksum ON\n");
    else
        Trace("Checksum.IPv4Transmit.IpChecksum OFF\n");

    if (Offload->Checksum.IPv4Transmit.TcpChecksum)
        Trace("Checksum.IPv4Transmit.TcpChecksum ON\n");
    else
        Trace("Checksum.IPv4Transmit.TcpChecksum OFF\n");

    if (Offload->Checksum.IPv4Transmit.UdpChecksum)
        Trace("Checksum.IPv4Transmit.UdpChecksum ON\n");
    else
        Trace("Checksum.IPv4Transmit.UdpChecksum OFF\n");

    if (Offload->Checksum.IPv6Transmit.TcpChecksum)
        Trace("Checksum.IPv6Transmit.TcpChecksum ON\n");
    else
        Trace("Checksum.IPv6Transmit.TcpChecksum OFF\n");

    if (Offload->Checksum.IPv6Transmit.UdpChecksum)
        Trace("Checksum.IPv6Transmit.UdpChecksum ON\n");
    else
        Trace("Checksum.IPv6Transmit.UdpChecksum OFF\n");

    if (Offload->LsoV2.IPv4.MaxOffLoadSize != 0)
        Trace("LsoV2.IPv4.MaxOffLoadSize = %u\n",
             Offload->LsoV2.IPv4.MaxOffLoadSize);
    else
        Trace("LsoV2.IPv4 OFF\n");

    if (Offload->LsoV2.IPv6.MaxOffLoadSize != 0)
        Trace("LsoV2.IPv6.MaxOffLoadSize = %u\n",
             Offload->LsoV2.IPv6.MaxOffLoadSize);
    else
        Trace("LsoV2.IPv6 OFF\n");
}

#define DISPLAY_OFFLOAD(_Offload) \
    DisplayOffload(#_Offload, &_Offload);

static VOID
AdapterIndicateOffloadChanged(
    IN  PXENNET_ADAPTER         Adapter
    )
{
    NDIS_STATUS_INDICATION      Status;
    NDIS_OFFLOAD                Current;
    PXENVIF_VIF_OFFLOAD_OPTIONS RxOptions;
    PXENVIF_VIF_OFFLOAD_OPTIONS TxOptions;

    RxOptions = ReceiverOffloadOptions(Adapter->Receiver);
    TxOptions = TransmitterOffloadOptions(Adapter->Transmitter);

    RtlZeroMemory(&Current, sizeof(Current));
    Current.Header.Type = NDIS_OBJECT_TYPE_OFFLOAD;
    Current.Header.Revision = NDIS_OFFLOAD_REVISION_2;
    Current.Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_2;

    Current.Checksum.IPv4Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (RxOptions->OffloadIpVersion4HeaderChecksum) {
        Current.Checksum.IPv4Receive.IpChecksum = 1;
        Current.Checksum.IPv4Receive.IpOptionsSupported = 1;
    }
    if (RxOptions->OffloadIpVersion4TcpChecksum) {
        Current.Checksum.IPv4Receive.TcpChecksum = 1;
        Current.Checksum.IPv4Receive.TcpOptionsSupported = 1;
    }
    if (RxOptions->OffloadIpVersion4UdpChecksum) {
        Current.Checksum.IPv4Receive.UdpChecksum = 1;
    }

    Current.Checksum.IPv6Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
    Current.Checksum.IPv6Receive.IpExtensionHeadersSupported = 1;

    if (RxOptions->OffloadIpVersion6TcpChecksum) {
        Current.Checksum.IPv6Receive.TcpChecksum = 1;
        Current.Checksum.IPv6Receive.TcpOptionsSupported = 1;
    }
    if (RxOptions->OffloadIpVersion6UdpChecksum) {
        Current.Checksum.IPv6Receive.UdpChecksum = 1;
    }

    XENVIF_VIF(ReceiverSetOffloadOptions,
               &Adapter->VifInterface,
               *RxOptions);

    Current.Checksum.IPv4Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (TxOptions->OffloadIpVersion4HeaderChecksum) {
        Current.Checksum.IPv4Transmit.IpChecksum = 1;
        Current.Checksum.IPv4Transmit.IpOptionsSupported = 1;
    }
    if (TxOptions->OffloadIpVersion4TcpChecksum) {
        Current.Checksum.IPv4Transmit.TcpChecksum = 1;
        Current.Checksum.IPv4Transmit.TcpOptionsSupported = 1;
    }
    if (TxOptions->OffloadIpVersion4UdpChecksum) {
        Current.Checksum.IPv4Transmit.UdpChecksum = 1;
    }

    Current.Checksum.IPv6Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
    Current.Checksum.IPv6Transmit.IpExtensionHeadersSupported = 1;

    if (TxOptions->OffloadIpVersion6TcpChecksum) {
        Current.Checksum.IPv6Transmit.TcpChecksum = 1;
        Current.Checksum.IPv6Transmit.TcpOptionsSupported = 1;
    }
    if (TxOptions->OffloadIpVersion6UdpChecksum) {
        Current.Checksum.IPv6Transmit.UdpChecksum = 1;
    }

    if (TxOptions->OffloadIpVersion4LargePacket) {
        XENVIF_VIF(TransmitterQueryLargePacketSize,
                   &Adapter->VifInterface,
                   4,
                   &Current.LsoV2.IPv4.MaxOffLoadSize);
        Current.LsoV2.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        Current.LsoV2.IPv4.MinSegmentCount = 2;
    }

    if (TxOptions->OffloadIpVersion6LargePacket) {
        XENVIF_VIF(TransmitterQueryLargePacketSize,
                   &Adapter->VifInterface,
                   6,
                   &Current.LsoV2.IPv6.MaxOffLoadSize);
        Current.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        Current.LsoV2.IPv6.MinSegmentCount = 2;
        Current.LsoV2.IPv6.IpExtensionHeadersSupported = 1;
        Current.LsoV2.IPv6.TcpOptionsSupported = 1;
    }

    DISPLAY_OFFLOAD(Current);

    Adapter->Offload = Current;

    RtlZeroMemory(&Status, sizeof(Status));
    Status.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    Status.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    Status.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;
    Status.StatusCode = NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG;
    Status.StatusBuffer = &Current;
    Status.StatusBufferSize = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_2;

    NdisMIndicateStatusEx(Adapter->NdisAdapterHandle, &Status);
}

static VOID
AdapterGetPacketFilter(
    IN  PXENNET_ADAPTER         Adapter,
    OUT PULONG                  PacketFilter
    )
{
    XENVIF_MAC_FILTER_LEVEL UnicastFilterLevel;
    XENVIF_MAC_FILTER_LEVEL MulticastFilterLevel;
    XENVIF_MAC_FILTER_LEVEL BroadcastFilterLevel;

    XENVIF_VIF(MacQueryFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_UNICAST,
               &UnicastFilterLevel);

    XENVIF_VIF(MacQueryFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_MULTICAST,
               &MulticastFilterLevel);

    XENVIF_VIF(MacQueryFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_BROADCAST,
               &BroadcastFilterLevel);

    *PacketFilter = 0;

    if (UnicastFilterLevel == XENVIF_MAC_FILTER_ALL) {
        ASSERT3U(MulticastFilterLevel, ==, XENVIF_MAC_FILTER_ALL);
        ASSERT3U(BroadcastFilterLevel, ==, XENVIF_MAC_FILTER_ALL);

        *PacketFilter |= NDIS_PACKET_TYPE_PROMISCUOUS;
        return;
    } else if (UnicastFilterLevel == XENVIF_MAC_FILTER_MATCHING) {
        *PacketFilter |= NDIS_PACKET_TYPE_DIRECTED;
    }

    if (MulticastFilterLevel == XENVIF_MAC_FILTER_ALL)
        *PacketFilter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
    else if (MulticastFilterLevel == XENVIF_MAC_FILTER_MATCHING)
        *PacketFilter |= NDIS_PACKET_TYPE_MULTICAST;

    if (BroadcastFilterLevel == XENVIF_MAC_FILTER_ALL)
        *PacketFilter |= NDIS_PACKET_TYPE_BROADCAST;
}

static NDIS_STATUS
AdapterSetPacketFilter(
    IN  PXENNET_ADAPTER         Adapter,
    IN  PULONG                  PacketFilter
    )
{
    XENVIF_MAC_FILTER_LEVEL UnicastFilterLevel;
    XENVIF_MAC_FILTER_LEVEL MulticastFilterLevel;
    XENVIF_MAC_FILTER_LEVEL BroadcastFilterLevel;

    if (*PacketFilter & ~XENNET_SUPPORTED_PACKET_FILTERS)
        return NDIS_STATUS_INVALID_PARAMETER;

    if (*PacketFilter & NDIS_PACKET_TYPE_PROMISCUOUS) {
        UnicastFilterLevel = XENVIF_MAC_FILTER_ALL;
        MulticastFilterLevel = XENVIF_MAC_FILTER_ALL;
        BroadcastFilterLevel = XENVIF_MAC_FILTER_ALL;
        goto done;
    }

    if (*PacketFilter & NDIS_PACKET_TYPE_DIRECTED)
        UnicastFilterLevel = XENVIF_MAC_FILTER_MATCHING;
    else
        UnicastFilterLevel = XENVIF_MAC_FILTER_NONE;

    if (*PacketFilter & NDIS_PACKET_TYPE_ALL_MULTICAST)
        MulticastFilterLevel = XENVIF_MAC_FILTER_ALL;
    else if (*PacketFilter & NDIS_PACKET_TYPE_MULTICAST)
        MulticastFilterLevel = XENVIF_MAC_FILTER_MATCHING;
    else
        MulticastFilterLevel = XENVIF_MAC_FILTER_NONE;

    if (*PacketFilter & NDIS_PACKET_TYPE_BROADCAST)
        BroadcastFilterLevel = XENVIF_MAC_FILTER_ALL;
    else
        BroadcastFilterLevel = XENVIF_MAC_FILTER_NONE;

done:
    XENVIF_VIF(MacSetFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_UNICAST,
               UnicastFilterLevel);

    XENVIF_VIF(MacSetFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_MULTICAST,
               MulticastFilterLevel);

    XENVIF_VIF(MacSetFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_BROADCAST,
               BroadcastFilterLevel);

    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
AdapterGetOffloadEncapsulation(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_OFFLOAD_ENCAPSULATION Offload
    )
{
    XENVIF_VIF_OFFLOAD_OPTIONS  Options;
    PXENVIF_VIF_OFFLOAD_OPTIONS TxOptions;
    PXENVIF_VIF_OFFLOAD_OPTIONS RxOptions;

    if (Offload->IPv4.Enabled == NDIS_OFFLOAD_SET_ON &&
        Offload->IPv4.EncapsulationType != NDIS_ENCAPSULATION_IEEE_802_3)
        goto invalid_parameter;

    if (Offload->IPv6.Enabled == NDIS_OFFLOAD_SET_ON &&
        Offload->IPv6.EncapsulationType != NDIS_ENCAPSULATION_IEEE_802_3)
        goto invalid_parameter;

    XENVIF_VIF(TransmitterQueryOffloadOptions,
               &Adapter->VifInterface,
               &Options);

    TxOptions = TransmitterOffloadOptions(Adapter->Transmitter);
    TxOptions->Value = 0;
    TxOptions->OffloadTagManipulation = 1;

    if (Adapter->Properties.lsov4 && Options.OffloadIpVersion4LargePacket)
        TxOptions->OffloadIpVersion4LargePacket = 1;
    if (Adapter->Properties.lsov6 && Options.OffloadIpVersion6LargePacket)
        TxOptions->OffloadIpVersion6LargePacket = 1;
    if ((Adapter->Properties.ipv4_csum & 1) && Options.OffloadIpVersion4HeaderChecksum)
        TxOptions->OffloadIpVersion4HeaderChecksum = 1;
    if ((Adapter->Properties.tcpv4_csum & 1) && Options.OffloadIpVersion4TcpChecksum)
        TxOptions->OffloadIpVersion4TcpChecksum = 1;
    if ((Adapter->Properties.udpv4_csum & 1) && Options.OffloadIpVersion4UdpChecksum)
        TxOptions->OffloadIpVersion4UdpChecksum = 1;
    if ((Adapter->Properties.tcpv6_csum & 1) && Options.OffloadIpVersion6TcpChecksum)
        TxOptions->OffloadIpVersion6TcpChecksum = 1;
    if ((Adapter->Properties.udpv6_csum & 1) && Options.OffloadIpVersion6UdpChecksum)
        TxOptions->OffloadIpVersion6UdpChecksum = 1;

    RxOptions = ReceiverOffloadOptions(Adapter->Receiver);

    RxOptions->Value = 0;
    RxOptions->OffloadTagManipulation = 1;

    if (Adapter->Properties.need_csum_value)
        RxOptions->NeedChecksumValue = 1;
    if (Adapter->Properties.lrov4)
        RxOptions->OffloadIpVersion4LargePacket = 1;
    if (Adapter->Properties.lrov4)
        RxOptions->NeedLargePacketSplit = 1;
    if (Adapter->Properties.lrov6)
        RxOptions->OffloadIpVersion6LargePacket = 1;
    if (Adapter->Properties.lrov6)
        RxOptions->NeedLargePacketSplit = 1;
    if (Adapter->Properties.ipv4_csum & 2)
        RxOptions->OffloadIpVersion4HeaderChecksum = 1;
    if (Adapter->Properties.tcpv4_csum & 2)
        RxOptions->OffloadIpVersion4TcpChecksum = 1;
    if (Adapter->Properties.udpv4_csum & 2)
        RxOptions->OffloadIpVersion4UdpChecksum = 1;
    if (Adapter->Properties.tcpv6_csum & 2)
        RxOptions->OffloadIpVersion6TcpChecksum = 1;
    if (Adapter->Properties.udpv6_csum & 2)
        RxOptions->OffloadIpVersion6UdpChecksum = 1;

    AdapterIndicateOffloadChanged(Adapter);
    return NDIS_STATUS_SUCCESS;

invalid_parameter:
    return NDIS_STATUS_INVALID_PARAMETER;
}

#define NO_CHANGE(x)    ((x) == NDIS_OFFLOAD_PARAMETERS_NO_CHANGE)
#define RX_ENABLED(x)   ((x) == NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED ||            \
                         (x) == NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED)
#define TX_ENABLED(x)   ((x) == NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED ||            \
                         (x) == NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED)
#define CHANGE(x, y)    (((x) == (y)) ? 0 : (((x) = (y)), 1))

static NDIS_STATUS
AdapterGetTcpOffloadParameters(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_OFFLOAD_PARAMETERS    Offload
    )
{
    XENVIF_VIF_OFFLOAD_OPTIONS      Options;
    PXENVIF_VIF_OFFLOAD_OPTIONS     TxOptions;
    PXENVIF_VIF_OFFLOAD_OPTIONS     RxOptions;
    BOOLEAN                         Changed;

    XENVIF_VIF(TransmitterQueryOffloadOptions,
               &Adapter->VifInterface,
               &Options);

    if (!NO_CHANGE(Offload->IPsecV1))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->LsoV1))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->TcpConnectionIPv4))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->TcpConnectionIPv6))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->LsoV2IPv4) &&
        !(Options.OffloadIpVersion4LargePacket))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->LsoV2IPv6) &&
        !(Options.OffloadIpVersion6LargePacket))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->IPsecV2))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->IPsecV2IPv4))
        goto invalid_parameter;

    Changed = FALSE;
    TxOptions = TransmitterOffloadOptions(Adapter->Transmitter);
    RxOptions = ReceiverOffloadOptions(Adapter->Receiver);

    if (Offload->LsoV2IPv4 == NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED) {
        Changed |= CHANGE(TxOptions->OffloadIpVersion4LargePacket, 1);
    } else if (Offload->LsoV2IPv4 == NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED) {
        Changed |= CHANGE(TxOptions->OffloadIpVersion4LargePacket, 0);
    }

    if (Offload->LsoV2IPv6 == NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED) {
        Changed |= CHANGE(TxOptions->OffloadIpVersion6LargePacket, 1);
    } else if (Offload->LsoV2IPv6 == NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED) {
        Changed |= CHANGE(TxOptions->OffloadIpVersion6LargePacket, 0);
    }

    Changed |= CHANGE(TxOptions->OffloadIpVersion4HeaderChecksum, TX_ENABLED(Offload->IPv4Checksum));
    Changed |= CHANGE(TxOptions->OffloadIpVersion4TcpChecksum, TX_ENABLED(Offload->TCPIPv4Checksum));
    Changed |= CHANGE(TxOptions->OffloadIpVersion4UdpChecksum, TX_ENABLED(Offload->UDPIPv4Checksum));
    Changed |= CHANGE(TxOptions->OffloadIpVersion6TcpChecksum, TX_ENABLED(Offload->TCPIPv6Checksum));
    Changed |= CHANGE(TxOptions->OffloadIpVersion6UdpChecksum, TX_ENABLED(Offload->UDPIPv6Checksum));

    Changed |= CHANGE(RxOptions->OffloadIpVersion4HeaderChecksum, RX_ENABLED(Offload->IPv4Checksum));
    Changed |= CHANGE(RxOptions->OffloadIpVersion4TcpChecksum, RX_ENABLED(Offload->TCPIPv4Checksum));
    Changed |= CHANGE(RxOptions->OffloadIpVersion4UdpChecksum, RX_ENABLED(Offload->UDPIPv4Checksum));
    Changed |= CHANGE(RxOptions->OffloadIpVersion6TcpChecksum, RX_ENABLED(Offload->TCPIPv6Checksum));
    Changed |= CHANGE(RxOptions->OffloadIpVersion6UdpChecksum, RX_ENABLED(Offload->UDPIPv6Checksum));

    AdapterIndicateOffloadChanged(Adapter);
    return NDIS_STATUS_SUCCESS;

invalid_parameter:
    return NDIS_STATUS_INVALID_PARAMETER;
}

#undef NO_CHANGE
#undef RX_ENABLED
#undef TX_ENABLED
#undef CHANGE

static VOID
AdapterDisableRSSHash(
    IN  PXENNET_ADAPTER Adapter
    )
{
    Adapter->Rss.ScaleEnabled = FALSE;
    Adapter->Rss.HashEnabled = FALSE;

    (VOID) XENVIF_VIF(ReceiverSetHashAlgorithm,
                      &Adapter->VifInterface,
                      XENVIF_PACKET_HASH_ALGORITHM_NONE);
}

static NDIS_STATUS
AdapterUpdateRSSTable(
    IN  PXENNET_ADAPTER Adapter,
    IN  PCCHAR          Table,
    IN  ULONG           TableSize
    )
{
    PROCESSOR_NUMBER    Mapping[NDIS_RSS_INDIRECTION_TABLE_MAX_SIZE_REVISION_1];
    ULONG               Index;
    NTSTATUS            status;

    if (TableSize == 0) {
        AdapterDisableRSSHash(Adapter);
        return NDIS_STATUS_SUCCESS;
    }

    if (TableSize > sizeof (Adapter->Rss.Table))
        return NDIS_STATUS_INVALID_DATA;

    RtlZeroMemory(Adapter->Rss.Table, sizeof (Adapter->Rss.Table)) ;
    RtlCopyMemory(Adapter->Rss.Table, Table, TableSize);
    Adapter->Rss.TableSize = TableSize;

    RtlZeroMemory(Mapping, sizeof (Mapping));
    for (Index = 0; Index < TableSize; Index++) {
        Mapping[Index].Group = 0;
        Mapping[Index].Number = Table[Index];
    }

    status = XENVIF_VIF(UpdateHashMapping,
                        &Adapter->VifInterface,
                        Mapping,
                        TableSize);

    return (NT_SUCCESS(status)) ? NDIS_STATUS_SUCCESS : NDIS_STATUS_INVALID_DATA;
}

static NDIS_STATUS
AdapterUpdateRSSKey(
    IN  PXENNET_ADAPTER Adapter,
    IN  PUCHAR          Key,
    IN  ULONG           KeySize
    )
{
    NTSTATUS            status;

    if (KeySize == 0) {
        AdapterDisableRSSHash(Adapter);
        return NDIS_STATUS_SUCCESS;
    }

    if (KeySize > sizeof (Adapter->Rss.Key))
        return NDIS_STATUS_INVALID_DATA;

    RtlZeroMemory(Adapter->Rss.Key, sizeof (Adapter->Rss.Key));
    RtlCopyMemory(Adapter->Rss.Key, Key, KeySize);
    Adapter->Rss.KeySize = KeySize;

    status = XENVIF_VIF(ReceiverUpdateHashParameters,
                        &Adapter->VifInterface,
                        Adapter->Rss.Types,
                        Adapter->Rss.Key);

    return (NT_SUCCESS(status)) ? NDIS_STATUS_SUCCESS : NDIS_STATUS_INVALID_DATA;
}

static NDIS_STATUS
AdapterUpdateRSSHash(
    IN  PXENNET_ADAPTER Adapter,
    IN  ULONG           Information
    )
{
    ULONG               HashType = NDIS_RSS_HASH_TYPE_FROM_HASH_INFO(Information);
    ULONG               HashFunc = NDIS_RSS_HASH_FUNC_FROM_HASH_INFO(Information);
    NTSTATUS            status;

    if (HashFunc == 0) {
        AdapterDisableRSSHash(Adapter);
        return NDIS_STATUS_SUCCESS;
    }

    if (HashFunc != NdisHashFunctionToeplitz)
        return NDIS_STATUS_FAILURE;

    if (HashType == 0)
        return NDIS_STATUS_FAILURE;

    if (HashType & ~(NDIS_HASH_TCP_IPV4 |
                     NDIS_HASH_IPV4 |
                     NDIS_HASH_TCP_IPV6 |
                     NDIS_HASH_IPV6))
        return NDIS_STATUS_FAILURE;

    status = XENVIF_VIF(ReceiverSetHashAlgorithm,
                        &Adapter->VifInterface,
                        XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ);
    if (!NT_SUCCESS(status))
        return NDIS_STATUS_FAILURE;

    Adapter->Rss.Types = 0;

    if (HashType & NDIS_HASH_TCP_IPV4)
        Adapter->Rss.Types |= 1 << XENVIF_PACKET_HASH_TYPE_IPV4_TCP;

    if (HashType & NDIS_HASH_IPV4)
        Adapter->Rss.Types |= 1 << XENVIF_PACKET_HASH_TYPE_IPV4;

    if (HashType & NDIS_HASH_TCP_IPV6)
        Adapter->Rss.Types |= 1 << XENVIF_PACKET_HASH_TYPE_IPV6_TCP;

    if (HashType & NDIS_HASH_IPV6)
        Adapter->Rss.Types |= 1 << XENVIF_PACKET_HASH_TYPE_IPV6;

    status = XENVIF_VIF(ReceiverUpdateHashParameters,
                        &Adapter->VifInterface,
                        Adapter->Rss.Types,
                        Adapter->Rss.Key);

    return (NT_SUCCESS(status)) ? NDIS_STATUS_SUCCESS : NDIS_STATUS_INVALID_DATA;
}

static VOID
DisplayRss(
    IN  PXENNET_RSS Rss
    )
{
    Trace("HashEnabled: %s\n", (Rss->HashEnabled) ? "TRUE" : "FALSE");
    Trace("ScaleEnabled: %s\n", (Rss->ScaleEnabled) ? "TRUE" : "FALSE");

    if (Rss->Types != 0) {
        Trace("Types:\n");
        if (Rss->Types & 1 << XENVIF_PACKET_HASH_TYPE_IPV4)
            Trace("- IPv4\n");
        if (Rss->Types & 1 << XENVIF_PACKET_HASH_TYPE_IPV4_TCP)
            Trace("- IPv4 + TCP\n");
        if (Rss->Types & 1 << XENVIF_PACKET_HASH_TYPE_IPV6)
            Trace("- IPv6\n");
        if (Rss->Types & 1 << XENVIF_PACKET_HASH_TYPE_IPV6_TCP)
            Trace("- IPv6 + TCP\n");
    }

    if (Rss->KeySize != 0) {
        ULONG   Index;

        Trace("Key:\n");

        for (Index = 0; Index < Rss->KeySize; ) {
            CHAR    Buffer[80];
            STRING  String;
            ULONG   Count;
            ULONG   Column;

            String.Buffer = Buffer;
            String.MaximumLength = sizeof (Buffer);
            String.Length = 0;

            Count = 8;
            if (Index + Count >= Rss->KeySize)
                Count = Rss->KeySize - Index;

            (VOID) StringPrintf(&String, "[%2u - %2u]: ",
                                Index,
                                Index + Count - 1);

            String.Buffer += String.Length;
            String.MaximumLength -= String.Length;
            String.Length = 0;

            for (Column = 0; Column < Count; Column++, Index++) {
                (VOID) StringPrintf(&String, "%02x ",
                                    Rss->Key[Index]);

                String.Buffer += String.Length;
                String.MaximumLength -= String.Length;
                String.Length = 0;
            }

            Trace("%s\n", Buffer);
        }
    }

    if (Rss->TableSize != 0) {
        ULONG   Index;

        Trace("Table:\n");

        for (Index = 0; Index < Rss->TableSize; ) {
            CHAR    Buffer[80];
            STRING  String;
            ULONG   Count;
            ULONG   Column;

            String.Buffer = Buffer;
            String.MaximumLength = sizeof (Buffer);
            String.Length = 0;

            Count = 8;
            if (Index + Count >= Rss->TableSize)
                Count = Rss->TableSize - Index;

            (VOID) StringPrintf(&String, "[%2u - %2u]: ",
                                Index,
                                Index + Count - 1);

            String.Buffer += String.Length;
            String.MaximumLength -= String.Length;
            String.Length = 0;

            for (Column = 0; Column < Count; Column++, Index++) {
                (VOID) StringPrintf(&String, "%02x ",
                                    Rss->Table[Index]);

                String.Buffer += String.Length;
                String.MaximumLength -= String.Length;
                String.Length = 0;
            }

            Trace("%s\n", Buffer);
        }
    }
}

static NDIS_STATUS
AdapterGetReceiveScaleParameters(
    IN  PXENNET_ADAPTER                 Adapter,
    IN  PNDIS_RECEIVE_SCALE_PARAMETERS  Parameters
    )
{
    NDIS_STATUS                         ndisStatus;

    ASSERT3U(Parameters->Header.Type, ==, NDIS_OBJECT_TYPE_RSS_PARAMETERS);
    ASSERT3U(Parameters->Header.Revision, ==, NDIS_RECEIVE_SCALE_PARAMETERS_REVISION_1);
    ASSERT3U(Parameters->Header.Size, >=, NDIS_SIZEOF_RECEIVE_SCALE_PARAMETERS_REVISION_1);

    if (!Adapter->Rss.Supported)
        return NDIS_STATUS_NOT_SUPPORTED;

    if (!Adapter->Properties.rss)
        return NDIS_STATUS_NOT_SUPPORTED;

    if (Adapter->Rss.HashEnabled)
        return NDIS_STATUS_NOT_SUPPORTED;

    if (!(Parameters->Flags & NDIS_RSS_PARAM_FLAG_DISABLE_RSS)) {
        Adapter->Rss.ScaleEnabled = TRUE;
    } else {
        AdapterDisableRSSHash(Adapter);
        return NDIS_STATUS_SUCCESS;
    }

    if (!(Parameters->Flags & NDIS_RSS_PARAM_FLAG_HASH_INFO_UNCHANGED)) {
        ndisStatus = AdapterUpdateRSSHash(Adapter, Parameters->HashInformation);
        if (ndisStatus != NDIS_STATUS_SUCCESS)
            goto fail;
    }

    if (!(Parameters->Flags & NDIS_RSS_PARAM_FLAG_HASH_KEY_UNCHANGED)) {
        ndisStatus = AdapterUpdateRSSKey(Adapter,
                                         (PUCHAR)Parameters + Parameters->HashSecretKeyOffset,
                                         Parameters->HashSecretKeySize);
        if (ndisStatus != NDIS_STATUS_SUCCESS)
            goto fail;
    }

    if (!(Parameters->Flags & NDIS_RSS_PARAM_FLAG_ITABLE_UNCHANGED)) {
        ndisStatus = AdapterUpdateRSSTable(Adapter,
                                           (PCCHAR)Parameters + Parameters->IndirectionTableOffset,
                                           Parameters->IndirectionTableSize);
        if (ndisStatus != NDIS_STATUS_SUCCESS)
            goto fail;
    }

    DisplayRss(&Adapter->Rss);

    return NDIS_STATUS_SUCCESS;

fail:
    AdapterDisableRSSHash(Adapter);
    return ndisStatus;
}

static NDIS_STATUS
AdapterGetReceiveHashParameters(
    IN  PXENNET_ADAPTER                 Adapter,
    IN  PNDIS_RECEIVE_HASH_PARAMETERS   Parameters
    )
{
    NDIS_STATUS                         ndisStatus;

    ASSERT3U(Parameters->Header.Type, ==, NDIS_OBJECT_TYPE_DEFAULT);
    ASSERT3U(Parameters->Header.Revision, ==, NDIS_RECEIVE_HASH_PARAMETERS_REVISION_1);
    ASSERT3U(Parameters->Header.Size, >=, NDIS_SIZEOF_RECEIVE_HASH_PARAMETERS_REVISION_1);

    if (!Adapter->Rss.Supported)
        return NDIS_STATUS_NOT_SUPPORTED;

    if (Adapter->Rss.ScaleEnabled)
        return NDIS_STATUS_NOT_SUPPORTED;

    if (Parameters->Flags & NDIS_RECEIVE_HASH_FLAG_ENABLE_HASH) {
        Adapter->Rss.HashEnabled = TRUE;
    } else {
        AdapterDisableRSSHash(Adapter);
        return NDIS_STATUS_SUCCESS;
    }

    if (!(Parameters->Flags & NDIS_RECEIVE_HASH_FLAG_HASH_INFO_UNCHANGED)) {
        ndisStatus = AdapterUpdateRSSHash(Adapter, Parameters->HashInformation);
        if (ndisStatus != NDIS_STATUS_SUCCESS)
            goto fail;
    }

    if (!(Parameters->Flags & NDIS_RECEIVE_HASH_FLAG_HASH_KEY_UNCHANGED)) {
        ndisStatus = AdapterUpdateRSSKey(Adapter,
                                         (PUCHAR)Parameters + Parameters->HashSecretKeyOffset,
                                         Parameters->HashSecretKeySize);
        if (ndisStatus != NDIS_STATUS_SUCCESS)
            goto fail;
    }

    DisplayRss(&Adapter->Rss);

    return NDIS_STATUS_SUCCESS;

fail:
    AdapterDisableRSSHash(Adapter);
    return ndisStatus;
}

static NDIS_STATUS
AdapterQueryGeneralStatistics(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_STATISTICS_INFO   Info,
    IN  ULONG               BufferLength,
    IN OUT PULONG           BytesWritten
    )
{
    ULONGLONG   Value;

    if (BufferLength < sizeof(NDIS_STATISTICS_INFO))
        goto fail1;

    RtlZeroMemory(Info, sizeof(NDIS_STATISTICS_INFO));
    Info->Header.Revision = NDIS_OBJECT_REVISION_1;
    Info->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    Info->Header.Size = sizeof(NDIS_STATISTICS_INFO);

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_BACKEND_ERRORS,
                      &Value);
    Info->ifInErrors = Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_FRONTEND_ERRORS,
                      &Value);
    Info->ifInErrors += Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_PACKETS_DROPPED,
                      &Value);
    Info->ifInDiscards = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_UNICAST_OCTETS,
                      &Value);
    Info->ifHCInOctets = Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_MULTICAST_OCTETS,
                      &Value);
    Info->ifHCInOctets += Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_BROADCAST_OCTETS,
                      &Value);
    Info->ifHCInOctets += Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_UNICAST_OCTETS,
                      &Value);
    Info->ifHCInUcastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_UNICAST_PACKETS,
                      &Value);
    Info->ifHCInUcastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_MULTICAST_OCTETS,
                      &Value);
    Info->ifHCInMulticastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_MULTICAST_PACKETS,
                      &Value);
    Info->ifHCInMulticastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_BROADCAST_OCTETS,
                      &Value);
    Info->ifHCInBroadcastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_BROADCAST_PACKETS,
                      &Value);
    Info->ifHCInBroadcastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_BACKEND_ERRORS,
                      &Value);
    Info->ifOutErrors = Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_FRONTEND_ERRORS,
                      &Value);
    Info->ifOutErrors += Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_UNICAST_OCTETS,
                      &Value);
    Info->ifHCOutOctets = Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_MULTICAST_OCTETS,
                      &Value);
    Info->ifHCOutOctets += Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_BROADCAST_OCTETS,
                      &Value);
    Info->ifHCOutOctets += Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_UNICAST_OCTETS,
                      &Value);
    Info->ifHCOutUcastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_UNICAST_PACKETS,
                      &Value);
    Info->ifHCOutUcastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_MULTICAST_OCTETS,
                      &Value);
    Info->ifHCOutMulticastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_MULTICAST_PACKETS,
                      &Value);
    Info->ifHCOutMulticastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_BROADCAST_OCTETS,
                      &Value);
    Info->ifHCOutBroadcastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_BROADCAST_PACKETS,
                      &Value);
    Info->ifHCOutBroadcastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS;
    Info->ifOutDiscards = 0;

    *BytesWritten = sizeof(NDIS_STATISTICS_INFO);
    return NDIS_STATUS_SUCCESS;

fail1:
    *BytesWritten = 0;
    return NDIS_STATUS_BUFFER_TOO_SHORT;
}

static NDIS_STATUS
AdapterQueryMulticastList(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PVOID               Buffer,
    IN  ULONG               BufferLength,
    IN OUT PULONG           BytesNeeded,
    IN OUT PULONG           BytesWritten
    )
{
    ULONG       Count;
    NDIS_STATUS ndisStatus;
    NTSTATUS    status;

    XENVIF_VIF(MacQueryMulticastAddresses,
               &Adapter->VifInterface,
               NULL,
               &Count);
    *BytesNeeded = Count * ETHERNET_ADDRESS_LENGTH;

    ndisStatus = NDIS_STATUS_INVALID_LENGTH;
    if (BufferLength < *BytesNeeded)
        goto fail1;

    status = XENVIF_VIF(MacQueryMulticastAddresses,
                        &Adapter->VifInterface,
                        Buffer,
                        &Count);
    ndisStatus = NDIS_STATUS_FAILURE;
    if (!NT_SUCCESS(status))
        goto fail2;

    *BytesWritten = Count * ETHERNET_ADDRESS_LENGTH;
    return NDIS_STATUS_SUCCESS;

fail2:
fail1:
    *BytesWritten = 0;
    return ndisStatus;
}

static FORCEINLINE NDIS_STATUS
AdapterSetMulticastAddresses(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PETHERNET_ADDRESS   Address,
    IN  ULONG               Count
    )
{
    NTSTATUS        status;

    status = XENVIF_VIF(MacSetMulticastAddresses,
                        &Adapter->VifInterface,
                        Address,
                        Count);
    if (!NT_SUCCESS(status))
        return NDIS_STATUS_INVALID_DATA;

    return NDIS_STATUS_SUCCESS;
}

static FORCEINLINE VOID
AdapterGetXmitOk(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PULONGLONG          Buffer
    )
{
    ULONGLONG   Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_UNICAST_PACKETS,
                &Value);

    *Buffer = (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_MULTICAST_PACKETS,
                &Value);

    *Buffer += (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_BROADCAST_PACKETS,
                &Value);

    *Buffer += (ULONG)Value;
}

static FORCEINLINE VOID
AdapterGetRcvOk(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PULONGLONG          Buffer
    )
{
    ULONGLONG   Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_UNICAST_PACKETS,
                &Value);

    *Buffer = (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_MULTICAST_PACKETS,
                &Value);

    *Buffer += (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_BROADCAST_PACKETS,
                &Value);

    *Buffer += (ULONG)Value;
}

static NDIS_STATUS
AdapterGetXmitError(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PULONG              Buffer
    )
{
    ULONGLONG   Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_BACKEND_ERRORS,
                &Value);

    *Buffer = (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_FRONTEND_ERRORS,
                &Value);

    *Buffer += (ULONG)Value;

    return NDIS_STATUS_SUCCESS;
}

static FORCEINLINE NDIS_STATUS
AdapterGetRcvError(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PULONG              Buffer
    )
{
    ULONGLONG   Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_BACKEND_ERRORS,
                &Value);

    *Buffer = (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_FRONTEND_ERRORS,
                &Value);

    *Buffer += (ULONG)Value;

    return NDIS_STATUS_SUCCESS;
}

static FORCEINLINE NDIS_STATUS
AdapterInterruptModeration(
    IN  PXENNET_ADAPTER                         Adapter,
    IN  PNDIS_INTERRUPT_MODERATION_PARAMETERS   Params,
    IN  ULONG                                   BufferLength,
    IN OUT PULONG                               BytesWritten
    )
{
    UNREFERENCED_PARAMETER(Adapter);

    if (BufferLength < NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1)
        goto fail1;

    Params->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    Params->Header.Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
    Params->Header.Size = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;

    Params->Flags = 0;
    Params->InterruptModeration = NdisInterruptModerationNotSupported;

    *BytesWritten = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
    return NDIS_STATUS_SUCCESS;

fail1:
    *BytesWritten = 0;
    return NDIS_STATUS_BUFFER_TOO_SHORT;
}

static FORCEINLINE NDIS_STATUS
AdapterReceiveHash(
    IN  PXENNET_ADAPTER                 Adapter,
    IN  PNDIS_RECEIVE_HASH_PARAMETERS   Params,
    IN  ULONG                           BufferLength,
    IN OUT PULONG                       BytesWritten
    )
{
    ULONG                               HashType;
    ULONG                               HashFunc;

    if (BufferLength < NDIS_SIZEOF_RECEIVE_HASH_PARAMETERS_REVISION_1 +
                       sizeof (Adapter->Rss.Key))
        goto fail1;

    Params->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    Params->Header.Revision = NDIS_RECEIVE_HASH_PARAMETERS_REVISION_1;
    Params->Header.Size = NDIS_SIZEOF_RECEIVE_HASH_PARAMETERS_REVISION_1;

    Params->Flags = (Adapter->Rss.HashEnabled) ? NDIS_RECEIVE_HASH_FLAG_ENABLE_HASH : 0;

    HashFunc = NdisHashFunctionToeplitz;
    HashType = 0;

    if (Adapter->Rss.Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV4_TCP))
        HashType |= NDIS_HASH_TCP_IPV4;

    if (Adapter->Rss.Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV4))
        HashType |= NDIS_HASH_IPV4;

    if (Adapter->Rss.Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV6_TCP))
        HashType |= NDIS_HASH_TCP_IPV6;

    if (Adapter->Rss.Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV6))
        HashType |= NDIS_HASH_IPV6;

    Params->HashInformation = NDIS_RSS_HASH_INFO_FROM_TYPE_AND_FUNC(HashType, HashFunc);
    Params->HashSecretKeySize = (USHORT)Adapter->Rss.KeySize;
    Params->HashSecretKeyOffset = NDIS_SIZEOF_RECEIVE_HASH_PARAMETERS_REVISION_1;

    RtlCopyMemory((PUCHAR)Params + Params->HashSecretKeyOffset,
                  Adapter->Rss.Key,
                  Params->HashSecretKeySize);

    *BytesWritten = NDIS_SIZEOF_RECEIVE_HASH_PARAMETERS_REVISION_1 +
                    Adapter->Rss.KeySize;
    return NDIS_STATUS_SUCCESS;

fail1:
    *BytesWritten = 0;
    return NDIS_STATUS_BUFFER_TOO_SHORT;
}

NDIS_HANDLE
AdapterGetHandle(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return Adapter->NdisAdapterHandle;
}

PXENVIF_VIF_INTERFACE
AdapterGetVifInterface(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return &Adapter->VifInterface;
}

PXENNET_TRANSMITTER
AdapterGetTransmitter(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return Adapter->Transmitter;
}

PXENNET_RECEIVER
AdapterGetReceiver(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return Adapter->Receiver;
}

PWCHAR
AdapterGetLocation(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return Adapter->Location;
}

static FORCEINLINE PVOID
__AdapterAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, ADAPTER_POOL_TAG);
}

static FORCEINLINE VOID
__AdapterFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, ADAPTER_POOL_TAG);
}

static FORCEINLINE PANSI_STRING
__AdapterMultiSzToUpcaseAnsi(
    IN  PCHAR       Buffer
    )
{
    PANSI_STRING    Ansi;
    LONG            Index;
    LONG            Count;
    NTSTATUS        status;

    Index = 0;
    Count = 0;
    for (;;) {
        if (Buffer[Index] == '\0') {
            Count++;
            Index++;

            // Check for double NUL
            if (Buffer[Index] == '\0')
                break;
        } else {
            Buffer[Index] = __toupper(Buffer[Index]);
            Index++;
        }
    }

    Ansi = __AdapterAllocate(sizeof (ANSI_STRING) * (Count + 1));

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG   Length;

        Length = (ULONG)strlen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1);
        Ansi[Index].Buffer = __AdapterAllocate(Ansi[Index].MaximumLength);

        status = STATUS_NO_MEMORY;
        if (Ansi[Index].Buffer == NULL)
            goto fail2;

        RtlCopyMemory(Ansi[Index].Buffer, Buffer, Length);
        Ansi[Index].Length = (USHORT)Length;

        Buffer += Length + 1;
    }

    return Ansi;

fail2:
    Error("fail2\n");

    while (--Index >= 0)
        __AdapterFree(Ansi[Index].Buffer);

    __AdapterFree(Ansi);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static FORCEINLINE VOID
__AdapterFreeAnsi(
    IN  PANSI_STRING    Ansi
    )
{
    ULONG               Index;

    for (Index = 0; Ansi[Index].Buffer != NULL; Index++)
        __AdapterFree(Ansi[Index].Buffer);

    __AdapterFree(Ansi);
}

static FORCEINLINE BOOLEAN
__AdapterMatchDistribution(
    IN  PXENNET_ADAPTER Adapter,
    IN  PCHAR           Buffer
    )
{
    PCHAR               Vendor;
    PCHAR               Product;
    PCHAR               Context;
    const CHAR          *Text;
    BOOLEAN             Match;
    ULONG               Index;
    NTSTATUS            status;

    UNREFERENCED_PARAMETER(Adapter);

    status = STATUS_INVALID_PARAMETER;

    Vendor = __strtok_r(Buffer, " ", &Context);
    if (Vendor == NULL)
        goto fail1;

    Product = __strtok_r(NULL, " ", &Context);
    if (Product == NULL)
        goto fail2;

    Match = TRUE;

    Text = VENDOR_NAME_STR;

    for (Index = 0; Text[Index] != 0; Index++) {
        if (!isalnum((UCHAR)Text[Index])) {
            if (Vendor[Index] != '_') {
                Match = FALSE;
                break;
            }
        } else {
            if (Vendor[Index] != Text[Index]) {
                Match = FALSE;
                break;
            }
        }
    }

    Text = "XENNET";

    if (_stricmp(Product, Text) != 0)
        Match = FALSE;

    return Match;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return FALSE;
}

static FORCEINLINE VOID
__AdapterClearDistribution(
    IN  PXENNET_ADAPTER Adapter
    )
{
    PCHAR               Buffer;
    PANSI_STRING        Distributions;
    ULONG               Index;
    NTSTATUS            status;

    Trace("====>\n");

    status = XENBUS_STORE(Directory,
                          &Adapter->StoreInterface,
                          NULL,
                          NULL,
                          "drivers",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Distributions = __AdapterMultiSzToUpcaseAnsi(Buffer);

        XENBUS_STORE(Free,
                     &Adapter->StoreInterface,
                     Buffer);
    } else {
        Distributions = NULL;
    }

    if (Distributions == NULL)
        goto done;

    for (Index = 0; Distributions[Index].Buffer != NULL; Index++) {
        PANSI_STRING    Distribution = &Distributions[Index];

        status = XENBUS_STORE(Read,
                              &Adapter->StoreInterface,
                              NULL,
                              "drivers",
                              Distribution->Buffer,
                              &Buffer);
        if (!NT_SUCCESS(status))
            continue;

        if (__AdapterMatchDistribution(Adapter, Buffer))
            (VOID) XENBUS_STORE(Remove,
                                &Adapter->StoreInterface,
                                NULL,
                                "drivers",
                                Distribution->Buffer);

        XENBUS_STORE(Free,
                     &Adapter->StoreInterface,
                     Buffer);
    }

    __AdapterFreeAnsi(Distributions);

done:
    Trace("<====\n");
}

#define MAXIMUM_INDEX   255

static FORCEINLINE NTSTATUS
__AdapterSetDistribution(
    IN  PXENNET_ADAPTER Adapter
    )
{
    ULONG               Index;
    CHAR                Distribution[MAXNAMELEN];
    CHAR                Vendor[MAXNAMELEN];
    STRING              String;
    const CHAR          *Product;
    NTSTATUS            status;

    Trace("====>\n");

    Index = 0;
    while (Index <= MAXIMUM_INDEX) {
        PCHAR   Buffer;

        String.Buffer = Distribution;
        String.MaximumLength = sizeof (Distribution);
        String.Length = 0;

        status = StringPrintf(&String,
                              "%u",
                              Index);
        ASSERT(NT_SUCCESS(status));

        status = XENBUS_STORE(Read,
                              &Adapter->StoreInterface,
                              NULL,
                              "drivers",
                              Distribution,
                              &Buffer);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_OBJECT_NAME_NOT_FOUND)
                goto update;

            goto fail1;
        }

        XENBUS_STORE(Free,
                     &Adapter->StoreInterface,
                     Buffer);

        Index++;
    }

    status = STATUS_UNSUCCESSFUL;
    goto fail2;

update:
    String.Buffer = Vendor;
    String.MaximumLength = sizeof (Vendor);
    String.Length = 0;

    status = StringPrintf(&String,
                          "%s",
                          VENDOR_NAME_STR);
    ASSERT(NT_SUCCESS(status));

    for (Index  = 0; Vendor[Index] != '\0'; Index++)
        if (!isalnum((UCHAR)Vendor[Index]))
            Vendor[Index] = '_';

    Product = "XENNET";

#if DBG
#define ATTRIBUTES   "(DEBUG)"
#else
#define ATTRIBUTES   ""
#endif

    (VOID) XENBUS_STORE(Printf,
                        &Adapter->StoreInterface,
                        NULL,
                        "drivers",
                        Distribution,
                        "%s %s %u.%u.%u.%u %s",
                        Vendor,
                        Product,
                        MAJOR_VERSION,
                        MINOR_VERSION,
                        MICRO_VERSION,
                        BUILD_NUMBER,
                        ATTRIBUTES
                        );

#undef  ATTRIBUTES

    Trace("<====\n");
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static DECLSPEC_NOINLINE VOID
AdapterSuspendCallbackLate(
    IN  PVOID       Argument
    )
{
    PXENNET_ADAPTER Adapter = Argument;
    LONG            Count;

    (VOID) InterlockedDecrement(&AdapterCount);

    Count = InterlockedIncrement(&AdapterCount);
    ASSERT(Count != 0);

    if (Count == 1)
        (VOID) __AdapterSetDistribution(Adapter);
}

static NTSTATUS
AdapterSetDistribution(
    IN  PXENNET_ADAPTER Adapter
    )
{
    LONG                Count;
    NTSTATUS            status;

    Trace("====>\n");

    Count = InterlockedIncrement(&AdapterCount);
    ASSERT(Count != 0);

    if (Count == 1)
        (VOID) __AdapterSetDistribution(Adapter);

    status = XENBUS_SUSPEND(Register,
                            &Adapter->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            AdapterSuspendCallbackLate,
                            Adapter,
                            &Adapter->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail1;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    Count = InterlockedDecrement(&AdapterCount);

    if (Count == 0)
        __AdapterClearDistribution(Adapter);

    return status;
}

static VOID
AdapterClearDistribution(
    IN  PXENNET_ADAPTER Adapter
    )
{
    LONG                Count;

    Trace("====>\n");

    XENBUS_SUSPEND(Deregister,
                   &Adapter->SuspendInterface,
                   Adapter->SuspendCallbackLate);
    Adapter->SuspendCallbackLate = NULL;

    Count = InterlockedDecrement(&AdapterCount);

    if (Count == 0)
        __AdapterClearDistribution(Adapter);

    Trace("<====\n");
}

NDIS_STATUS
AdapterEnable(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    NTSTATUS                status;

    ASSERT(!Adapter->Enabled);

    status = XENBUS_STORE(Acquire,
                          &Adapter->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_SUSPEND(Acquire,
                            &Adapter->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = AdapterSetDistribution(Adapter);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENVIF_VIF(Enable,
                        &Adapter->VifInterface,
                        AdapterVifCallback,
                        Adapter);
    if (!NT_SUCCESS(status))
        goto fail4;

    ReceiverEnable(Adapter->Receiver);

    AdapterMediaStateChange(Adapter);

    Adapter->Enabled = TRUE;

    return NDIS_STATUS_SUCCESS;

fail4:
    AdapterClearDistribution(Adapter);

fail3:
    XENBUS_SUSPEND(Release, &Adapter->SuspendInterface);

fail2:
    XENBUS_STORE(Release, &Adapter->StoreInterface);

fail1:
    return NDIS_STATUS_FAILURE;
}

VOID
AdapterDisable(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    ASSERT(Adapter->Enabled);
    Adapter->Enabled = FALSE;

    ReceiverDisable(Adapter->Receiver);

    XENVIF_VIF(Disable,
               &Adapter->VifInterface);

    AdapterMediaStateChange(Adapter);

    AdapterClearDistribution(Adapter);

    XENBUS_SUSPEND(Release, &Adapter->SuspendInterface);
    XENBUS_STORE(Release, &Adapter->StoreInterface);
}

static VOID
DisplayLinkState(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_LINK_STATE    LinkState
    )
{
    if (LinkState->MediaConnectState == MediaConnectStateUnknown) {
        Info("%ws: LINK: STATE UNKNOWN\n", Adapter->Location);
    } else if (LinkState->MediaConnectState == MediaConnectStateDisconnected) {
        Info("%ws: LINK: DOWN\n", Adapter->Location);
    } else {
        if (LinkState->MediaDuplexState == MediaDuplexStateHalf)
            Info("%ws: LINK: UP: SPEED=%I64u DUPLEX=HALF\n",
                 Adapter->Location,
                 LinkState->RcvLinkSpeed);
        else if (LinkState->MediaDuplexState == MediaDuplexStateFull)
            Info("%ws: LINK: UP: SPEED=%I64u DUPLEX=FULL\n",
                 Adapter->Location,
                 LinkState->RcvLinkSpeed);
        else
            Info("%ws: LINK: UP: SPEED=%I64u DUPLEX=UNKNOWN\n",
                 Adapter->Location,
                 LinkState->RcvLinkSpeed);
    }
}

VOID
AdapterMediaStateChange(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    NDIS_LINK_STATE         LinkState;
    NDIS_STATUS_INDICATION  StatusIndication;

    RtlZeroMemory(&LinkState, sizeof(LinkState));
    LinkState.Header.Revision = NDIS_LINK_STATE_REVISION_1;
    LinkState.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    LinkState.Header.Size = NDIS_SIZEOF_LINK_STATE_REVISION_1;

    XENVIF_VIF(MacQueryState,
               &Adapter->VifInterface,
               &LinkState.MediaConnectState,
               &LinkState.RcvLinkSpeed,
               &LinkState.MediaDuplexState);

    LinkState.XmitLinkSpeed = LinkState.RcvLinkSpeed;

    if (!RtlEqualMemory(&Adapter->LinkState,
                       &LinkState,
                       sizeof (LinkState)))
        DisplayLinkState(Adapter, &LinkState);

    Adapter->LinkState = LinkState;

    RtlZeroMemory(&StatusIndication, sizeof(StatusIndication));
    StatusIndication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    StatusIndication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    StatusIndication.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;

    StatusIndication.SourceHandle = Adapter->NdisAdapterHandle;
    StatusIndication.StatusCode = NDIS_STATUS_LINK_STATE;
    StatusIndication.StatusBuffer = &LinkState;
    StatusIndication.StatusBufferSize = sizeof (NDIS_LINK_STATE);

    NdisMIndicateStatusEx(Adapter->NdisAdapterHandle, &StatusIndication);
}

NDIS_STATUS
AdapterSetInformation(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_OID_REQUEST   Request
    )
{
    PVOID                   Buffer;
    ULONG                   BufferLength;
    ULONG                   BytesNeeded;
    ULONG                   BytesRead;
    BOOLEAN                 Warn;
    NDIS_STATUS             ndisStatus;

    Buffer = Request->DATA.SET_INFORMATION.InformationBuffer;
    BufferLength = Request->DATA.SET_INFORMATION.InformationBufferLength;
    BytesNeeded = BytesRead = 0;
    Warn = TRUE;
    ndisStatus = NDIS_STATUS_SUCCESS;

    switch (Request->DATA.SET_INFORMATION.Oid) {
    case OID_PNP_SET_POWER:
        BytesNeeded = sizeof(NDIS_DEVICE_POWER_STATE);
        if (BufferLength >= BytesNeeded) {
            PNDIS_DEVICE_POWER_STATE PowerState;

            PowerState = (PNDIS_DEVICE_POWER_STATE)Buffer;
            switch (*PowerState) {
            case NdisDeviceStateD0:
                Info("%ws: SET_POWER: D0\n",
                     Adapter->Location);
                break;

            case NdisDeviceStateD1:
                Info("%ws: SET_POWER: D1\n",
                     Adapter->Location);
                break;

            case NdisDeviceStateD2:
                Info("%ws: SET_POWER: D2\n",
                     Adapter->Location);
                break;

            case NdisDeviceStateD3:
                Info("%ws: SET_POWER: D3\n",
                     Adapter->Location);
                break;
            }
        }
        // do nothing
        break;

    case OID_GEN_CURRENT_LOOKAHEAD:
        BytesNeeded = sizeof(ULONG);
        Adapter->CurrentLookahead = Adapter->MaximumFrameSize;
        if (BufferLength == BytesNeeded) {
            Adapter->CurrentLookahead = *(PULONG)Buffer;
            BytesRead = sizeof(ULONG);
        }
        break;

    case OID_GEN_CURRENT_PACKET_FILTER:
        BytesNeeded = sizeof(ULONG);
        if (BufferLength == BytesNeeded) {
            ndisStatus = AdapterSetPacketFilter(Adapter,
                                                (PULONG)Buffer);
            BytesRead = sizeof(ULONG);
        }
        break;

    case OID_802_3_MULTICAST_LIST:
        BytesNeeded = ETHERNET_ADDRESS_LENGTH;
        if (BufferLength % ETHERNET_ADDRESS_LENGTH == 0) {
            ndisStatus = AdapterSetMulticastAddresses(Adapter,
                                                      Buffer,
                                                      BufferLength / ETHERNET_ADDRESS_LENGTH);
            if (ndisStatus == NDIS_STATUS_SUCCESS)
                BytesRead = BufferLength;
        } else {
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
        }
        break;

    case OID_OFFLOAD_ENCAPSULATION:
        BytesNeeded = NDIS_SIZEOF_OFFLOAD_ENCAPSULATION_REVISION_1;
        if (BufferLength >= BytesNeeded) {
            ndisStatus = AdapterGetOffloadEncapsulation(Adapter,
                                                        (PNDIS_OFFLOAD_ENCAPSULATION)Buffer);
            if (ndisStatus == NDIS_STATUS_SUCCESS)
                BytesRead = NDIS_SIZEOF_OFFLOAD_ENCAPSULATION_REVISION_1;
        } else {
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
        }
        break;

    case OID_TCP_OFFLOAD_PARAMETERS:
        BytesNeeded = NDIS_OFFLOAD_PARAMETERS_REVISION_2;
        if (BufferLength >= BytesNeeded) {
            ndisStatus = AdapterGetTcpOffloadParameters(Adapter,
                                                        (PNDIS_OFFLOAD_PARAMETERS)Buffer);
            if (ndisStatus == NDIS_STATUS_SUCCESS)
                BytesRead = NDIS_OFFLOAD_PARAMETERS_REVISION_2;
        } else {
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
        }
        break;

    case OID_GEN_RECEIVE_SCALE_PARAMETERS:
        BytesNeeded = NDIS_SIZEOF_RECEIVE_SCALE_PARAMETERS_REVISION_1;
        if (BufferLength >= BytesNeeded) {
            ndisStatus = AdapterGetReceiveScaleParameters(Adapter,
                                                          (PNDIS_RECEIVE_SCALE_PARAMETERS)Buffer);
            if (ndisStatus == NDIS_STATUS_SUCCESS)
                BytesRead = sizeof(NDIS_RECEIVE_SCALE_PARAMETERS);
        } else {
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
        }
        break;

    case OID_GEN_RECEIVE_HASH:
        BytesNeeded = NDIS_SIZEOF_RECEIVE_HASH_PARAMETERS_REVISION_1;
        if (BufferLength >= BytesNeeded) {
            ndisStatus = AdapterGetReceiveHashParameters(Adapter,
                                                         (PNDIS_RECEIVE_HASH_PARAMETERS)Buffer);
            if (ndisStatus == NDIS_STATUS_SUCCESS)
                BytesRead = sizeof(NDIS_RECEIVE_HASH_PARAMETERS);
        } else {
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
        }
        break;

    case OID_GEN_INTERRUPT_MODERATION:
    case OID_GEN_MACHINE_NAME:
    case OID_GEN_NETWORK_LAYER_ADDRESSES:
        Warn = FALSE;
        /*FALLTHRU*/
    default:
        if (Warn)
            Warning("UNSUPPORTED OID %08x\n", Request->DATA.QUERY_INFORMATION.Oid);

        ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
        break;
    }

    Request->DATA.SET_INFORMATION.BytesNeeded = BytesNeeded;
    if (ndisStatus == NDIS_STATUS_SUCCESS)
        Request->DATA.SET_INFORMATION.BytesRead = BytesRead;

    return ndisStatus;
}

static FORCEINLINE NDIS_STATUS
__CopyBuffer(
    IN  PVOID   Destination,
    IN  ULONG   DestinationLength,
    IN  PVOID   Source,
    IN  ULONG   SourceLength,
    OUT PULONG  CopyLength
    )
{
    *CopyLength = __min(SourceLength, DestinationLength);
    RtlCopyMemory(Destination, Source, *CopyLength);

    return (DestinationLength >= SourceLength) ?
           NDIS_STATUS_SUCCESS :
           NDIS_STATUS_BUFFER_TOO_SHORT;
}

static FORCEINLINE NDIS_STATUS
__SetUlong(
    IN  PVOID   Destination,
    IN  ULONG   DestinationLength,
    IN  ULONG   Source,
    OUT PULONG  CopyLength
    )
{
    return __CopyBuffer(Destination,
                        DestinationLength & ~3,
                        &Source,
                        sizeof (ULONG),
                        CopyLength);
}

static FORCEINLINE NDIS_STATUS
__SetUlong64(
    IN  PVOID   Destination,
    IN  ULONG   DestinationLength,
    IN  ULONG64 Source,
    OUT PULONG  CopyLength
    )
{
    NDIS_STATUS ndisStatus;

    ndisStatus =  __CopyBuffer(Destination,
                               DestinationLength & ~3,
                               &Source,
                               sizeof (ULONG64),
                               CopyLength);
    if (DestinationLength >= 4)
        ndisStatus = NDIS_STATUS_SUCCESS;

    return ndisStatus;
}

NDIS_STATUS
AdapterQueryInformation(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_OID_REQUEST   Request
    )
{
    PVOID                   Buffer;
    ULONG                   BufferLength;
    ULONG                   BytesNeeded;
    ULONG                   BytesWritten;
    ULONG                   Value32;
    ULONGLONG               Value64;
    ETHERNET_ADDRESS        EthernetAddress;
    BOOLEAN                 Warn;
    NDIS_STATUS             ndisStatus;

    Buffer = Request->DATA.QUERY_INFORMATION.InformationBuffer;
    BufferLength = Request->DATA.QUERY_INFORMATION.InformationBufferLength;
    BytesNeeded = BytesWritten = 0;
    Warn = TRUE;
    ndisStatus = NDIS_STATUS_SUCCESS;

    switch (Request->DATA.QUERY_INFORMATION.Oid) {
    case OID_PNP_CAPABILITIES:
        BytesNeeded = sizeof(Adapter->Capabilities);
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  &Adapter->Capabilities,
                                  BytesNeeded,
                                  &BytesWritten);
        break;

    case OID_PNP_QUERY_POWER:
        BytesNeeded = sizeof(NDIS_DEVICE_POWER_STATE);

        if (BufferLength >= BytesNeeded) {
            PNDIS_DEVICE_POWER_STATE PowerState;

            PowerState = (PNDIS_DEVICE_POWER_STATE)Buffer;
            switch (*PowerState) {
            case NdisDeviceStateD0:
                Info("%ws: QUERY_POWER: D0\n",
                     Adapter->Location);
                break;

            case NdisDeviceStateD1:
                Info("%ws: QUERY_POWER: D1\n",
                     Adapter->Location);
                break;

            case NdisDeviceStateD2:
                Info("%ws: QUERY_POWER: D2\n",
                     Adapter->Location);
                break;

            case NdisDeviceStateD3:
                Info("%ws: QUERY_POWER: D3\n",
                     Adapter->Location);
                break;
            }
        }

        BytesWritten = 0;
        // do nothing
        break;

    case OID_GEN_SUPPORTED_LIST:
        BytesNeeded = sizeof(XennetSupportedOids);
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  &XennetSupportedOids[0],
                                  BytesNeeded,
                                  &BytesWritten);
        break;

    case OID_GEN_HARDWARE_STATUS:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                NdisHardwareStatusReady,
                                &BytesWritten);
        break;

    case OID_GEN_MEDIA_SUPPORTED:
    case OID_GEN_MEDIA_IN_USE:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                XENNET_MEDIA_TYPE,
                                &BytesWritten);
        break;

    case OID_GEN_MAXIMUM_LOOKAHEAD:
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Adapter->MaximumFrameSize,
                                &BytesWritten);
        break;

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
    case OID_GEN_RECEIVE_BUFFER_SPACE:
        XENVIF_VIF(TransmitterQueryRingSize,
                    &Adapter->VifInterface,
                    (PULONG)&Value32);
        Value32 *= Adapter->MaximumFrameSize;
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_VENDOR_DESCRIPTION:
        BytesNeeded = (ULONG)strlen(VENDOR_NAME_STR) + 1;
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  VENDOR_NAME_STR,
                                  BytesNeeded,
                                  &BytesWritten);
        break;

    case OID_GEN_VENDOR_DRIVER_VERSION:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (MAJOR_VERSION << 16) |
                                MINOR_VERSION,
                                &BytesWritten);
        break;

    case OID_GEN_DRIVER_VERSION:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (NDIS_MINIPORT_MAJOR_VERSION << 8) |
                                NDIS_MINIPORT_MINOR_VERSION,
                                &BytesWritten);
        break;

    case OID_GEN_MAC_OPTIONS:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                XENNET_MAC_OPTIONS,
                                &BytesWritten);
        break;

    case OID_GEN_STATISTICS:
        BytesNeeded = sizeof(NDIS_STATISTICS_INFO);
        ndisStatus = AdapterQueryGeneralStatistics(Adapter,
                                                   (PNDIS_STATISTICS_INFO)Buffer,
                                                   BufferLength,
                                                   &BytesWritten);
        break;

    case OID_802_3_MULTICAST_LIST:
        ndisStatus = AdapterQueryMulticastList(Adapter,
                                               Buffer,
                                               BufferLength,
                                               &BytesNeeded,
                                               &BytesWritten);
        break;

    case OID_802_3_PERMANENT_ADDRESS:
        XENVIF_VIF(MacQueryPermanentAddress,
                    &Adapter->VifInterface,
                    &EthernetAddress);
        BytesNeeded = sizeof(ETHERNET_ADDRESS);
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  &EthernetAddress,
                                  BytesNeeded,
                                  &BytesWritten);
        break;

    case OID_802_3_CURRENT_ADDRESS:
        XENVIF_VIF(MacQueryCurrentAddress,
                    &Adapter->VifInterface,
                    &EthernetAddress);
        BytesNeeded = sizeof(ETHERNET_ADDRESS);
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  &EthernetAddress,
                                  BytesNeeded,
                                  &BytesWritten);
        break;

    case OID_GEN_MAXIMUM_FRAME_SIZE:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Adapter->MaximumFrameSize -
                                    sizeof(ETHERNET_TAGGED_HEADER),
                                &BytesWritten);
        break;

    case OID_GEN_MAXIMUM_TOTAL_SIZE:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Adapter->MaximumFrameSize -
                                    sizeof(ETHERNET_TAGGED_HEADER) +
                                    sizeof (ETHERNET_UNTAGGED_HEADER),
                                &BytesWritten);
        break;

    case OID_GEN_CURRENT_LOOKAHEAD:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Adapter->CurrentLookahead,
                                &BytesWritten);
        break;

    case OID_GEN_VENDOR_ID:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                0x5853,
                                &BytesWritten);
        break;

    case OID_GEN_MEDIA_CONNECT_STATUS:
        XENVIF_VIF(MacQueryState,
                    &Adapter->VifInterface,
                    (PNET_IF_MEDIA_CONNECT_STATE)&Value32,
                    NULL,
                    NULL);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_MAXIMUM_SEND_PACKETS:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                16,
                                &BytesWritten);
        break;

    case OID_GEN_CURRENT_PACKET_FILTER:
        AdapterGetPacketFilter(Adapter, &Value32);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_XMIT_OK:
        AdapterGetXmitOk(Adapter, &Value64);
        BytesNeeded = sizeof(ULONG64);
        ndisStatus = __SetUlong64(Buffer,
                                  BufferLength,
                                  Value64,
                                  &BytesWritten);
        break;

    case OID_GEN_RCV_OK:
        AdapterGetRcvOk(Adapter, &Value64);
        BytesNeeded = sizeof(ULONG64);
        ndisStatus = __SetUlong64(Buffer,
                                  BufferLength,
                                  Value64,
                                  &BytesWritten);
        break;

    case OID_GEN_XMIT_ERROR:
        AdapterGetXmitError(Adapter, &Value32);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_RCV_ERROR:
        AdapterGetRcvError(Adapter, &Value32);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_RCV_NO_BUFFER:
    case OID_GEN_TRANSMIT_QUEUE_LENGTH:
    case OID_GEN_RCV_CRC_ERROR:
    case OID_802_3_RCV_ERROR_ALIGNMENT:
    case OID_802_3_XMIT_ONE_COLLISION:
    case OID_802_3_XMIT_MORE_COLLISIONS:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                0,
                                &BytesWritten);
        break;

    case OID_802_3_MAXIMUM_LIST_SIZE:
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                32,
                                &BytesWritten);
        break;

    case OID_GEN_DIRECTED_BYTES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_UNICAST_OCTETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_DIRECTED_FRAMES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_UNICAST_PACKETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_MULTICAST_BYTES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_MULTICAST_OCTETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_MULTICAST_FRAMES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_MULTICAST_PACKETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_BROADCAST_BYTES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_BROADCAST_OCTETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_BROADCAST_FRAMES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_BROADCAST_PACKETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_DIRECTED_BYTES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_UNICAST_OCTETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_DIRECTED_FRAMES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_UNICAST_PACKETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_MULTICAST_BYTES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_MULTICAST_OCTETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_MULTICAST_FRAMES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_MULTICAST_PACKETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_BROADCAST_BYTES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_BROADCAST_OCTETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_BROADCAST_FRAMES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_BROADCAST_PACKETS,
                   &Value64);
        BytesNeeded = sizeof(ULONG);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_INTERRUPT_MODERATION:
        BytesNeeded = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
        ndisStatus = AdapterInterruptModeration(Adapter,
                                                (PNDIS_INTERRUPT_MODERATION_PARAMETERS)Buffer,
                                                BufferLength,
                                                &BytesWritten);
        break;

    case OID_GEN_RECEIVE_HASH:
        BytesNeeded = NDIS_SIZEOF_RECEIVE_HASH_PARAMETERS_REVISION_1 +
                      Adapter->Rss.KeySize;
        ndisStatus = AdapterReceiveHash(Adapter,
                                        (PNDIS_RECEIVE_HASH_PARAMETERS)Buffer,
                                        BufferLength,
                                        &BytesWritten);
        break;

    case OID_IP4_OFFLOAD_STATS:
    case OID_IP6_OFFLOAD_STATS:
    case OID_GEN_SUPPORTED_GUIDS:
        // We don't handle these since NDIS 6.0 is supposed to do this for us
    case OID_GEN_MAC_ADDRESS:
    case OID_GEN_MAX_LINK_SPEED:
        // ignore these common unwanted OIDs
	case OID_GEN_INIT_TIME_MS:
	case OID_GEN_RESET_COUNTS:
	case OID_GEN_MEDIA_SENSE_COUNTS:
        Warn = FALSE;
        /*FALLTHRU*/
    default:
        if (Warn)
            Warning("UNSUPPORTED OID %08x\n", Request->DATA.QUERY_INFORMATION.Oid);

        ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
        break;
    }

    Request->DATA.QUERY_INFORMATION.BytesWritten = BytesWritten;
    Request->DATA.QUERY_INFORMATION.BytesNeeded = BytesNeeded;

    return ndisStatus;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
__QueryInterface(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  const GUID      *Guid,
    IN  ULONG           Version,
    OUT PINTERFACE      Interface,
    IN  ULONG           Size,
    IN  BOOLEAN         Optional
    )
{
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(StatusBlock));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       DeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = Guid;
    StackLocation->Parameters.QueryInterface.Size = (USHORT)Size;
    StackLocation->Parameters.QueryInterface.Version = (USHORT)Version;
    StackLocation->Parameters.QueryInterface.Interface = Interface;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(DeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_NOT_SUPPORTED && Optional)
            goto done;

        goto fail2;
    }

done:
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#pragma prefast(push)
#pragma prefast(disable:6102)

static NTSTATUS
__QueryLocationInformation(
    IN  PDEVICE_OBJECT  DeviceObject,
    OUT PWCHAR          *Location
    )
{
    ULONG               Size;
    NTSTATUS            status;

    status = IoGetDeviceProperty(DeviceObject,
                                 DevicePropertyLocationInformation,
                                 0,
                                 NULL,
                                 &Size);
    if (!NT_SUCCESS(status) &&
        status != STATUS_BUFFER_TOO_SMALL)
        goto fail1;

    Size += sizeof (WCHAR);

    *Location = __AdapterAllocate(Size);

    status = STATUS_NO_MEMORY;
    if (*Location == NULL)
        goto fail2;

    status = IoGetDeviceProperty(DeviceObject,
                                 DevicePropertyLocationInformation,
                                 Size,
                                 *Location,
                                 &Size);
    if (!NT_SUCCESS(status))
        goto fail3;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    __AdapterFree(*Location);

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n");

    return status;
}

#define READ_PROPERTY(field, name, defaultval, handle)  \
    do {                                                \
        NDIS_STATUS                     _Status;        \
        NDIS_STRING                     _Value;         \
        PNDIS_CONFIGURATION_PARAMETER   _Data;          \
        RtlInitUnicodeString(&_Value, name);            \
        NdisReadConfiguration(&_Status, &_Data, handle, \
                        &_Value, NdisParameterInteger); \
        if (_Status == NDIS_STATUS_SUCCESS)             \
            field = _Data->ParameterData.IntegerData;   \
        else                                            \
            field = defaultval;                         \
                                                        \
        Trace("%ws = %d\n", name, field);               \
    } while (FALSE);

static NDIS_STATUS
AdapterGetAdvancedSettings(
    IN  PXENNET_ADAPTER Adapter
    )
{
    NDIS_CONFIGURATION_OBJECT   Config;
    NDIS_HANDLE                 Handle;
    NDIS_STATUS                 ndisStatus;

    RtlZeroMemory(&Config, sizeof(Config));
    Config.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    Config.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    Config.Header.Size = NDIS_SIZEOF_CONFIGURATION_OBJECT_REVISION_1;
    Config.NdisHandle = Adapter->NdisAdapterHandle;
    Config.Flags = 0;

    ndisStatus = NdisOpenConfigurationEx(&Config, &Handle);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail1;

    READ_PROPERTY(Adapter->Properties.ipv4_csum, L"*IPChecksumOffloadIPv4", 3, Handle);
    READ_PROPERTY(Adapter->Properties.tcpv4_csum, L"*TCPChecksumOffloadIPv4", 3, Handle);
    READ_PROPERTY(Adapter->Properties.udpv4_csum, L"*UDPChecksumOffloadIPv4", 3, Handle);
    READ_PROPERTY(Adapter->Properties.tcpv6_csum, L"*TCPChecksumOffloadIPv6", 3, Handle);
    READ_PROPERTY(Adapter->Properties.udpv6_csum, L"*UDPChecksumOffloadIPv6", 3, Handle);
    READ_PROPERTY(Adapter->Properties.lsov4, L"*LSOv2IPv4", 1, Handle);
    READ_PROPERTY(Adapter->Properties.lsov6, L"*LSOv2IPv6", 1, Handle);
    READ_PROPERTY(Adapter->Properties.lrov4, L"LROIPv4", 1, Handle);
    READ_PROPERTY(Adapter->Properties.lrov6, L"LROIPv6", 1, Handle);
    READ_PROPERTY(Adapter->Properties.need_csum_value, L"NeedChecksumValue", 1, Handle);
    READ_PROPERTY(Adapter->Properties.rss, L"*RSS", 1, Handle);

    NdisCloseConfiguration(Handle);

    return NDIS_STATUS_SUCCESS;

fail1:
    return NDIS_STATUS_FAILURE;
}

#undef READ_PROPERTY

#pragma prefast(pop)

static NDIS_STATUS
AdapterSetRegistrationAttributes(
    IN  PXENNET_ADAPTER Adapter
    )
{
    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES   Attribs;
    NDIS_STATUS                                     ndisStatus;

    RtlZeroMemory(&Attribs, sizeof(Attribs));
    Attribs.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
    Attribs.Header.Revision = NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
    Attribs.Header.Size = NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
    Attribs.MiniportAdapterContext = (NDIS_HANDLE)Adapter;
    Attribs.AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_BUS_MASTER |
                             NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND;
    Attribs.CheckForHangTimeInSeconds = 0;
    Attribs.InterfaceType = XENNET_INTERFACE_TYPE;

    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&Attribs);

    return ndisStatus;
}

static NDIS_STATUS
AdapterSetGeneralAttributes(
    IN  PXENNET_ADAPTER Adapter
    )
{
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES    Attribs;
    ULONG                                       Types;
    NDIS_RECEIVE_SCALE_CAPABILITIES             Rss;
    NDIS_STATUS                                 ndisStatus;
    NTSTATUS                                    status;

    RtlZeroMemory(&Attribs, sizeof(Attribs));
    Attribs.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
    Attribs.Header.Revision = NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
    Attribs.Header.Size = NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
    Attribs.MediaType = XENNET_MEDIA_TYPE;

    XENVIF_VIF(MacQueryMaximumFrameSize,
               &Adapter->VifInterface,
               (PULONG)&Adapter->MaximumFrameSize);

    Attribs.MtuSize = Adapter->MaximumFrameSize - sizeof (ETHERNET_TAGGED_HEADER);
    Attribs.MaxXmitLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    Attribs.MaxRcvLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    Attribs.XmitLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    Attribs.RcvLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    Attribs.MediaConnectState = MediaConnectStateConnected;
    Attribs.MediaDuplexState = MediaDuplexStateFull;
    Attribs.LookaheadSize = Adapter->MaximumFrameSize;
    Attribs.PowerManagementCapabilities = &Adapter->Capabilities;
    Attribs.MacOptions = XENNET_MAC_OPTIONS;
    Attribs.SupportedPacketFilters = XENNET_SUPPORTED_PACKET_FILTERS;
    Attribs.MaxMulticastListSize = 32;
    Attribs.MacAddressLength = ETHERNET_ADDRESS_LENGTH;

    XENVIF_VIF(MacQueryPermanentAddress,
               &Adapter->VifInterface,
               (PETHERNET_ADDRESS)&Attribs.PermanentMacAddress);
    XENVIF_VIF(MacQueryCurrentAddress,
               &Adapter->VifInterface,
               (PETHERNET_ADDRESS)&Attribs.CurrentMacAddress);

    Attribs.PhysicalMediumType = NdisPhysicalMedium802_3;
    Attribs.AccessType = NET_IF_ACCESS_BROADCAST;
    Attribs.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
    Attribs.ConnectionType = NET_IF_CONNECTION_DEDICATED;
    Attribs.IfType = IF_TYPE_ETHERNET_CSMACD;
    Attribs.IfConnectorPresent = TRUE;
    Attribs.SupportedStatistics = NDIS_STATISTICS_XMIT_OK_SUPPORTED |
                                  NDIS_STATISTICS_XMIT_ERROR_SUPPORTED |
                                  NDIS_STATISTICS_DIRECTED_BYTES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_DIRECTED_FRAMES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_MULTICAST_BYTES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_MULTICAST_FRAMES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_BROADCAST_BYTES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_BROADCAST_FRAMES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_RCV_OK_SUPPORTED |
                                  NDIS_STATISTICS_RCV_ERROR_SUPPORTED |
                                  NDIS_STATISTICS_DIRECTED_BYTES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_DIRECTED_FRAMES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_MULTICAST_BYTES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_MULTICAST_FRAMES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_BROADCAST_BYTES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_BROADCAST_FRAMES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_GEN_STATISTICS_SUPPORTED;
                      
    Attribs.SupportedOidList = XennetSupportedOids;
    Attribs.SupportedOidListLength = sizeof(XennetSupportedOids);

    Attribs.RecvScaleCapabilities = NULL;

    if (!Adapter->Properties.rss) {
        Info("%ws: RSS DISABLED\n",
             Adapter->Location);
        goto done;
    }

    status = XENVIF_VIF(ReceiverSetHashAlgorithm,
                        &Adapter->VifInterface,
                        XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ);
    if (!NT_SUCCESS(status))
        goto done;

    status = XENVIF_VIF(ReceiverQueryHashCapabilities,
                        &Adapter->VifInterface,
                        &Types);
    if (!NT_SUCCESS(status))
        goto done;

    RtlZeroMemory(&Rss, sizeof(Rss));
    Rss.Header.Type = NDIS_OBJECT_TYPE_RSS_CAPABILITIES;
    Rss.Header.Revision = NDIS_RECEIVE_SCALE_CAPABILITIES_REVISION_1;
    Rss.Header.Size = NDIS_SIZEOF_RECEIVE_SCALE_CAPABILITIES_REVISION_1;

    Rss.CapabilitiesFlags = NDIS_RSS_CAPS_MESSAGE_SIGNALED_INTERRUPTS |
                            NDIS_RSS_CAPS_CLASSIFICATION_AT_ISR |
                            NDIS_RSS_CAPS_CLASSIFICATION_AT_DPC |
                            NdisHashFunctionToeplitz;

    if (Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV4_TCP))
        Rss.CapabilitiesFlags |= NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV4;

    if (Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV6_TCP))
        Rss.CapabilitiesFlags |= NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6;

    XENVIF_VIF(QueryRingCount,
               &Adapter->VifInterface,
               &Rss.NumberOfReceiveQueues);
    Rss.NumberOfInterruptMessages = Rss.NumberOfReceiveQueues;

    Info("%ws: RSS ENABLED (%u QUEUES)\n",
         Adapter->Location,
         Rss.NumberOfReceiveQueues);

    Adapter->Rss.Supported = TRUE;
    Attribs.RecvScaleCapabilities = &Rss;

done:
    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&Attribs);

    return ndisStatus;
}

static NDIS_STATUS
AdapterSetOffloadAttributes(
    IN  PXENNET_ADAPTER Adapter
    )
{
    NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES    Attribs;
    XENVIF_VIF_OFFLOAD_OPTIONS                  Options;
    PXENVIF_VIF_OFFLOAD_OPTIONS                 RxOptions;
    PXENVIF_VIF_OFFLOAD_OPTIONS                 TxOptions;
    NDIS_OFFLOAD                                Default;
    NDIS_OFFLOAD                                Supported;
    NDIS_STATUS                                 ndisStatus;

    TxOptions = TransmitterOffloadOptions(Adapter->Transmitter);
    RxOptions = ReceiverOffloadOptions(Adapter->Receiver);

    TxOptions->Value = 0;
    TxOptions->OffloadTagManipulation = 1;

    RxOptions->Value = 0;
    RxOptions->OffloadTagManipulation = 1;

    if (Adapter->Properties.need_csum_value)
        RxOptions->NeedChecksumValue = 1;

    if (Adapter->Properties.lrov4) {
        RxOptions->OffloadIpVersion4LargePacket = 1;
        RxOptions->NeedLargePacketSplit = 1;
    }

    if (Adapter->Properties.lrov6) {
        RxOptions->OffloadIpVersion6LargePacket = 1;
        RxOptions->NeedLargePacketSplit = 1;
    }

    XENVIF_VIF(ReceiverSetOffloadOptions,
               &Adapter->VifInterface,
               *RxOptions);

    XENVIF_VIF(TransmitterQueryOffloadOptions,
               &Adapter->VifInterface,
               &Options);

    RtlZeroMemory(&Supported, sizeof(Supported));
    Supported.Header.Type = NDIS_OBJECT_TYPE_OFFLOAD;
    Supported.Header.Revision = NDIS_OFFLOAD_REVISION_2;
    Supported.Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_2;

    Supported.Checksum.IPv4Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    Supported.Checksum.IPv4Receive.IpChecksum = 1;
    Supported.Checksum.IPv4Receive.IpOptionsSupported = 1;

    Supported.Checksum.IPv4Receive.TcpChecksum = 1;
    Supported.Checksum.IPv4Receive.TcpOptionsSupported = 1;

    Supported.Checksum.IPv4Receive.UdpChecksum = 1;

    Supported.Checksum.IPv6Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    Supported.Checksum.IPv6Receive.IpExtensionHeadersSupported = 1;

    Supported.Checksum.IPv6Receive.TcpChecksum = 1;
    Supported.Checksum.IPv6Receive.TcpOptionsSupported = 1;

    Supported.Checksum.IPv6Receive.UdpChecksum = 1;

    Supported.Checksum.IPv4Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (Options.OffloadIpVersion4HeaderChecksum) {
        Supported.Checksum.IPv4Transmit.IpChecksum = 1;
        Supported.Checksum.IPv4Transmit.IpOptionsSupported = 1;
    }

    if (Options.OffloadIpVersion4TcpChecksum) {
        Supported.Checksum.IPv4Transmit.TcpChecksum = 1;
        Supported.Checksum.IPv4Transmit.TcpOptionsSupported = 1;
    }

    if (Options.OffloadIpVersion4UdpChecksum)
        Supported.Checksum.IPv4Transmit.UdpChecksum = 1;

    Supported.Checksum.IPv6Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    Supported.Checksum.IPv6Transmit.IpExtensionHeadersSupported = 1;

    if (Options.OffloadIpVersion6TcpChecksum) {
        Supported.Checksum.IPv6Transmit.TcpChecksum = 1;
        Supported.Checksum.IPv6Transmit.TcpOptionsSupported = 1;
    }

    if (Options.OffloadIpVersion6UdpChecksum)
        Supported.Checksum.IPv6Transmit.UdpChecksum = 1;

    if (Options.OffloadIpVersion4LargePacket) {
        XENVIF_VIF(TransmitterQueryLargePacketSize,
                   &Adapter->VifInterface,
                   4,
                   &Supported.LsoV2.IPv4.MaxOffLoadSize);
        Supported.LsoV2.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        Supported.LsoV2.IPv4.MinSegmentCount = 2;
    }

    if (Options.OffloadIpVersion6LargePacket) {
        XENVIF_VIF(TransmitterQueryLargePacketSize,
                   &Adapter->VifInterface,
                   6,
                   &Supported.LsoV2.IPv6.MaxOffLoadSize);
        Supported.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        Supported.LsoV2.IPv6.MinSegmentCount = 2;
        Supported.LsoV2.IPv6.IpExtensionHeadersSupported = 1;
        Supported.LsoV2.IPv6.TcpOptionsSupported = 1;
    }

    DISPLAY_OFFLOAD(Supported);

    Default = Supported;

    if (!(Adapter->Properties.ipv4_csum & 2))
        Default.Checksum.IPv4Receive.IpChecksum = 0;

    if (!(Adapter->Properties.tcpv4_csum & 2))
        Default.Checksum.IPv4Receive.TcpChecksum = 0;

    if (!(Adapter->Properties.udpv4_csum & 2))
        Default.Checksum.IPv4Receive.UdpChecksum = 0;

    if (!(Adapter->Properties.tcpv6_csum & 2))
        Default.Checksum.IPv6Receive.TcpChecksum = 0;

    if (!(Adapter->Properties.udpv6_csum & 2))
        Default.Checksum.IPv6Receive.UdpChecksum = 0;

    if (!(Adapter->Properties.ipv4_csum & 1))
        Default.Checksum.IPv4Transmit.IpChecksum = 0;

    if (!(Adapter->Properties.tcpv4_csum & 1))
        Default.Checksum.IPv4Transmit.TcpChecksum = 0;

    if (!(Adapter->Properties.udpv4_csum & 1))
        Default.Checksum.IPv4Transmit.UdpChecksum = 0;

    if (!(Adapter->Properties.tcpv6_csum & 1))
        Default.Checksum.IPv6Transmit.TcpChecksum = 0;

    if (!(Adapter->Properties.udpv6_csum & 1))
        Default.Checksum.IPv6Transmit.UdpChecksum = 0;

    if (!(Adapter->Properties.lsov4)) {
        Default.LsoV2.IPv4.MaxOffLoadSize = 0;
        Default.LsoV2.IPv4.MinSegmentCount = 0;
    }

    if (!(Adapter->Properties.lsov6)) {
        Default.LsoV2.IPv6.MaxOffLoadSize = 0;
        Default.LsoV2.IPv6.MinSegmentCount = 0;
    }

    DISPLAY_OFFLOAD(Default);

    Adapter->Offload = Default;

    RtlZeroMemory(&Attribs, sizeof(Attribs));
    Attribs.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES;
    Attribs.Header.Revision = NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1;
    Attribs.Header.Size = NDIS_SIZEOF_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1;
    Attribs.DefaultOffloadConfiguration = &Default;
    Attribs.HardwareOffloadCapabilities = &Supported;

    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&Attribs);
    return ndisStatus;
}

NDIS_STATUS
AdapterInitialize(
    IN  NDIS_HANDLE         Handle,
    OUT PXENNET_ADAPTER     *Adapter
    )
{
    NDIS_STATUS             ndisStatus;
    NTSTATUS                status;
    PDEVICE_OBJECT          DeviceObject;
    NDIS_SG_DMA_DESCRIPTION Dma;

    *Adapter = __AdapterAllocate(sizeof (XENNET_ADAPTER));

    ndisStatus = NDIS_STATUS_RESOURCES;
    if (*Adapter == NULL)
        goto fail1;

    RtlZeroMemory(*Adapter, sizeof (XENNET_ADAPTER));

    NdisMGetDeviceProperty(Handle,
                           &DeviceObject,
                           NULL,
                           NULL,
                           NULL,
                           NULL);

    status = __QueryLocationInformation(DeviceObject,
                                        &(*Adapter)->Location);

    ndisStatus = NDIS_STATUS_FAILURE;
    if (!NT_SUCCESS(status))
        goto fail2;

    status = __QueryInterface(DeviceObject,
                              &GUID_XENVIF_VIF_INTERFACE,
                              XENVIF_VIF_INTERFACE_VERSION_MAX,
                              (PINTERFACE)&(*Adapter)->VifInterface,
                              sizeof(XENVIF_VIF_INTERFACE),
                              FALSE);

    if (!NT_SUCCESS(status))
        goto fail3;

    status = __QueryInterface(DeviceObject,
                              &GUID_XENBUS_STORE_INTERFACE,
                              XENBUS_STORE_INTERFACE_VERSION_MAX,
                              (PINTERFACE)&(*Adapter)->StoreInterface,
                              sizeof(XENBUS_STORE_INTERFACE),
                              FALSE);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = __QueryInterface(DeviceObject,
                              &GUID_XENBUS_SUSPEND_INTERFACE,
                              XENBUS_SUSPEND_INTERFACE_VERSION_MAX,
                              (PINTERFACE)&(*Adapter)->SuspendInterface,
                              sizeof(XENBUS_SUSPEND_INTERFACE),
                              FALSE);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENVIF_VIF(Acquire,
                        &(*Adapter)->VifInterface);
    if (!NT_SUCCESS(status))
        goto fail6;

    (*Adapter)->NdisAdapterHandle = Handle;

    ndisStatus = TransmitterInitialize(*Adapter, &(*Adapter)->Transmitter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail7;

    ndisStatus = ReceiverInitialize(*Adapter, &(*Adapter)->Receiver);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail8;

    ndisStatus = AdapterGetAdvancedSettings(*Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail9;

    ndisStatus = AdapterSetRegistrationAttributes(*Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail10;

    ndisStatus = AdapterSetGeneralAttributes(*Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail11;

    ndisStatus = AdapterSetOffloadAttributes(*Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail12;

    RtlZeroMemory(&Dma, sizeof(Dma));
    Dma.Header.Type = NDIS_OBJECT_TYPE_SG_DMA_DESCRIPTION;
    Dma.Header.Revision = NDIS_SG_DMA_DESCRIPTION_REVISION_1;
    Dma.Header.Size = NDIS_SIZEOF_SG_DMA_DESCRIPTION_REVISION_1;
    Dma.Flags = NDIS_SG_DMA_64_BIT_ADDRESS;
    Dma.MaximumPhysicalMapping = 65536;
    Dma.ProcessSGListHandler = AdapterProcessSGList;
    Dma.SharedMemAllocateCompleteHandler = AdapterAllocateComplete;

    ndisStatus = NdisMRegisterScatterGatherDma((*Adapter)->NdisAdapterHandle,
                                               &Dma,
                                               &(*Adapter)->NdisDmaHandle);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        (*Adapter)->NdisDmaHandle = NULL;

    return NDIS_STATUS_SUCCESS;

fail12:
fail11:
fail10:
fail9:
    ReceiverTeardown((*Adapter)->Receiver);
    (*Adapter)->Receiver = NULL;

fail8:
    TransmitterTeardown((*Adapter)->Transmitter);
    (*Adapter)->Transmitter = NULL;

fail7:
    (*Adapter)->NdisAdapterHandle = NULL;

    XENVIF_VIF(Release, &(*Adapter)->VifInterface);

fail6:
    RtlZeroMemory(&(*Adapter)->SuspendInterface, sizeof(XENBUS_SUSPEND_INTERFACE));

fail5:
    RtlZeroMemory(&(*Adapter)->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));

fail4:
    RtlZeroMemory(&(*Adapter)->VifInterface, sizeof(XENVIF_VIF_INTERFACE));

fail3:
    __AdapterFree((*Adapter)->Location);

fail2:
    __AdapterFree(*Adapter);

fail1:
    return ndisStatus;
}

VOID
AdapterTeardown(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    TransmitterTeardown(Adapter->Transmitter);
    Adapter->Transmitter = NULL;

    ReceiverTeardown(Adapter->Receiver);
    Adapter->Receiver = NULL;

    if (Adapter->NdisDmaHandle != NULL)
        NdisMDeregisterScatterGatherDma(Adapter->NdisDmaHandle);
    Adapter->NdisDmaHandle = NULL;

    XENVIF_VIF(Release, &Adapter->VifInterface);

    RtlZeroMemory(&Adapter->SuspendInterface, sizeof(XENBUS_SUSPEND_INTERFACE));
    RtlZeroMemory(&Adapter->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));
    RtlZeroMemory(&Adapter->VifInterface, sizeof(XENVIF_VIF_INTERFACE));

    __AdapterFree(Adapter->Location);

    __AdapterFree(Adapter);
}
