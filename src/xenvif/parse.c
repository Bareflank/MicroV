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
#include <ethernet.h>
#include <tcpip.h>
#include <llc.h>
#include <ipx.h>

#include <vif_interface.h>

#include "parse.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

static FORCEINLINE NTSTATUS
__ParseTcpHeader(
    IN      PUCHAR                      StartVa,
    IN      ULONG                       Offset,
    IN      XENVIF_PARSE_PULLUP         Pullup,
    IN      PVOID                       Argument,
    IN OUT  PXENVIF_PACKET_PAYLOAD      Payload,
    OUT     PXENVIF_PACKET_INFO         Info
    )
{
    PTCP_HEADER                         Header;

    Info->TcpHeader.Offset = Offset;

    if (!Pullup(Argument,
                StartVa + Offset,
                Payload,
                sizeof (TCP_HEADER)))
        goto fail1;

    Header = (PTCP_HEADER)(StartVa + Offset);
    Offset += sizeof (TCP_HEADER);

    Info->TcpHeader.Length = Offset - Info->TcpHeader.Offset;

    // Check for malformned header
    if (TCP_HEADER_LENGTH(Header) < Info->TcpHeader.Length)
        goto fail2;

    if (TCP_HEADER_LENGTH(Header) > Info->TcpHeader.Length) {
        ULONG Extra;

        Info->TcpOptions.Offset = Offset;

        Extra = TCP_HEADER_LENGTH(Header) - Info->TcpHeader.Length;

        if (!Pullup(Argument,
                    StartVa + Offset,
                    Payload,
                    Extra))
            goto fail3;

        Offset += Extra;

        Info->TcpOptions.Length = Offset - Info->TcpOptions.Offset;
    }

    Info->Length += Info->TcpHeader.Length + Info->TcpOptions.Length;

    return STATUS_SUCCESS;

fail3:
    Info->TcpOptions.Offset = 0;

fail2:
    Info->TcpHeader.Length = 0;

fail1:
    Info->TcpHeader.Offset = 0;

    return STATUS_UNSUCCESSFUL;
}

static FORCEINLINE NTSTATUS
__ParseUdpHeader(
    IN      PUCHAR                      StartVa,
    IN      ULONG                       Offset,
    IN      XENVIF_PARSE_PULLUP         Pullup,
    IN      PVOID                       Argument,
    IN OUT  PXENVIF_PACKET_PAYLOAD      Payload,
    OUT     PXENVIF_PACKET_INFO         Info
    )
{
    Info->UdpHeader.Offset = Offset;

    if (!Pullup(Argument,
                StartVa + Offset,
                Payload,
                sizeof (UDP_HEADER)))
        goto fail1;

    Offset += sizeof (UDP_HEADER);

    Info->UdpHeader.Length = Offset - Info->UdpHeader.Offset;

    Info->Length += Info->UdpHeader.Length;

    return STATUS_SUCCESS;

fail1:
    Info->UdpHeader.Offset = 0;

    return STATUS_UNSUCCESSFUL;
}

static FORCEINLINE NTSTATUS
__ParseIpVersion4Header(
    IN      PUCHAR                      StartVa,
    IN      ULONG                       Offset,
    IN      XENVIF_PARSE_PULLUP         Pullup,
    IN      PVOID                       Argument,
    IN OUT  PXENVIF_PACKET_PAYLOAD      Payload,
    OUT     PXENVIF_PACKET_INFO         Info
    )
{
    PIPV4_HEADER                        Header;
    USHORT                              PacketLength;
    USHORT                              FragmentOffsetAndFlags;
    NTSTATUS                            status;

    Info->IpHeader.Offset = Offset;

    if (!Pullup(Argument, StartVa + Offset, Payload, sizeof (IPV4_HEADER)))
        goto fail1;

    Header = (PIPV4_HEADER)(StartVa + Offset);
    Offset += sizeof (IPV4_HEADER);

    Info->IpHeader.Length = Offset - Info->IpHeader.Offset;

    if (Header->Version != 4)
        goto fail2;

    PacketLength = NTOHS(Header->PacketLength);
    if (PacketLength > Info->IpHeader.Length + Payload->Length)
        goto fail3;

    if (IPV4_HEADER_LENGTH(Header) < Info->IpHeader.Length)
        goto fail4;

    if (IPV4_HEADER_LENGTH(Header) > Info->IpHeader.Length) {
        ULONG Extra;

        Info->IpOptions.Offset = Offset;

        Extra = IPV4_HEADER_LENGTH(Header) - Info->IpHeader.Length;

        if (!Pullup(Argument,
                    StartVa + Offset,
                    Payload,
                    Extra))
            goto fail5;

        Offset += Extra;

        Info->IpOptions.Length = Offset - Info->IpOptions.Offset;
    }

    Info->Length += Info->IpHeader.Length + Info->IpOptions.Length;

    FragmentOffsetAndFlags = NTOHS(Header->FragmentOffsetAndFlags);
    Info->IsAFragment = IPV4_IS_A_FRAGMENT(FragmentOffsetAndFlags) ? TRUE : FALSE;
    
    status = STATUS_SUCCESS;
    if (Info->IsAFragment)
        goto done;

    switch (Header->Protocol) {
    case IPPROTO_TCP:
        status = __ParseTcpHeader(StartVa,
                                  Offset,
                                  Pullup,
                                  Argument,
                                  Payload,
                                  Info);
        break;

    case IPPROTO_UDP:
        status = __ParseUdpHeader(StartVa,
                                  Offset,
                                  Pullup,
                                  Argument,
                                  Payload,
                                  Info);
        break;

    default:
        status = STATUS_SUCCESS;
        break;
    }

done:
    return status;

fail5:
    Info->IpOptions.Offset = 0;

fail4:
fail3:
fail2:
    Info->IpHeader.Length = 0;

fail1:
    Info->IpHeader.Offset = 0;

    return STATUS_UNSUCCESSFUL;
}

static FORCEINLINE NTSTATUS
__ParseIpVersion6Header(
    IN      PUCHAR                      StartVa,
    IN      ULONG                       Offset,
    IN      XENVIF_PARSE_PULLUP         Pullup,
    IN      PVOID                       Argument,
    IN OUT  PXENVIF_PACKET_PAYLOAD      Payload,
    OUT     PXENVIF_PACKET_INFO         Info
    )
{
    PIPV6_HEADER                        Header;
    USHORT                              PayloadLength;
    UCHAR                               NextHeader;
    ULONG                               Count;
    BOOLEAN                             Finished;
    NTSTATUS                            status;

    Info->IpHeader.Offset = Offset;

    if (!Pullup(Argument,
                StartVa + Offset,
                Payload,
                sizeof (IPV6_HEADER)))
        goto fail1;

    Header = (PIPV6_HEADER)(StartVa + Offset);
    Offset += sizeof (IPV6_HEADER);

    Info->IpHeader.Length = Offset - Info->IpHeader.Offset;

    if (Header->Version != 6)
        goto fail2;

    PayloadLength = NTOHS(Header->PayloadLength);
    if (PayloadLength > Payload->Length)
        goto fail3;

    Info->IpOptions.Offset = Offset;

    NextHeader = Header->NextHeader;
    Count = 0;
    Finished = FALSE;

    while (!Finished && Count < 100) {
        switch (NextHeader) {
        case IPPROTO_FRAGMENT: {
            PIPV6_FRAGMENT_HEADER   Fragment;
            USHORT                  FragmentOffsetAndFlags;

            if (!Pullup(Argument,
                        StartVa + Offset,
                        Payload,
                        sizeof (IPV6_FRAGMENT_HEADER)))
                goto fail4;

            Fragment = (PIPV6_FRAGMENT_HEADER)(StartVa + Offset);
            Offset += sizeof (IPV6_FRAGMENT_HEADER);

            FragmentOffsetAndFlags = NTOHS(Fragment->OffsetAndFlags);
            Info->IsAFragment = IPV6_IS_A_FRAGMENT(FragmentOffsetAndFlags) ? TRUE : FALSE;

            NextHeader = Fragment->NextHeader;
            break;
        }
        case IPPROTO_AH: {
            PIP_AUTHENTICATION_HEADER   Authentication;
            ULONG                       Extra;

            if (!Pullup(Argument,
                        StartVa + Offset,
                        Payload,
                        sizeof (IP_AUTHENTICATION_HEADER)))
                goto fail4;

            Authentication = (PIP_AUTHENTICATION_HEADER)(StartVa + Offset);
            Offset += sizeof (IP_AUTHENTICATION_HEADER);

            Extra = ((ULONG)(Authentication->Length + 2) << 2) -
                    ((ULONG)sizeof (IP_AUTHENTICATION_HEADER));

            if (!Pullup(Argument,
                        StartVa + Offset,
                        Payload,
                        Extra))
                goto fail5;

            Offset += Extra;

            NextHeader = Authentication->NextHeader;
            break;
        }
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING: {
            PIPV6_OPTION_HEADER Option;
            ULONG               Extra;

            if (!Pullup(Argument,
                        StartVa + Offset,
                        Payload,
                        sizeof (IPV6_OPTION_HEADER)))
                goto fail4;

            Option = (PIPV6_OPTION_HEADER)(StartVa + Offset);
            Offset += sizeof (IPV6_OPTION_HEADER);

            Extra = ((ULONG)(Option->Length + 1) << 3) -
                    ((ULONG)sizeof (IPV6_OPTION_HEADER));

            if (!Pullup(Argument,
                        StartVa + Offset,
                        Payload,
                        Extra))
                goto fail5;

            Offset += Extra;

            NextHeader = Option->NextHeader;
            break;
        }
        default:
            Finished = TRUE;
            break;
        }

        Count++;
    }

    if (!Finished)
        goto fail6;

    Info->IpOptions.Length = (ULONG)(Offset - Info->IpOptions.Offset);
    if (Info->IpOptions.Length == 0)
        Info->IpOptions.Offset = 0;

    Info->Length += Info->IpHeader.Length + Info->IpOptions.Length;

    status = STATUS_SUCCESS;
    if (Info->IsAFragment)
        goto done;
    
    switch (NextHeader) {
    case IPPROTO_TCP:
        status = __ParseTcpHeader(StartVa,
                                  Offset,
                                  Pullup,
                                  Argument,
                                  Payload,
                                  Info);
        break;

    case IPPROTO_UDP:
        status = __ParseUdpHeader(StartVa,
                                  Offset,
                                  Pullup,
                                  Argument,
                                  Payload,
                                  Info);
        break;

    default:
        status = STATUS_SUCCESS;
        break;
    }

done:
    return status;

fail6:
fail5:
fail4:
    Info->IpOptions.Offset = 0;

fail3:
fail2:
    Info->IpHeader.Length = 0;

fail1:
    Info->IpHeader.Offset = 0;

    return STATUS_UNSUCCESSFUL;
}

static FORCEINLINE NTSTATUS
__ParseLLCSnapHeader(
    IN      PUCHAR                      StartVa,
    IN      ULONG                       Offset,
    IN      XENVIF_PARSE_PULLUP         Pullup,
    IN      PVOID                       Argument,
    IN OUT  PXENVIF_PACKET_PAYLOAD      Payload,
    OUT     PXENVIF_PACKET_INFO         Info
    )
{
    PLLC_SNAP_HEADER                    Header;

    Info->LLCSnapHeader.Offset = Offset;

    if (!Pullup(Argument,
                StartVa + Offset,
                Payload,
                sizeof (LLC_U_HEADER)))
        goto fail1;

    Header = (PLLC_SNAP_HEADER)(StartVa + Offset);
    Offset += sizeof (LLC_U_HEADER);

    if ((Header->DestinationSAP & LLC_SAP_MASK) == 0xAA &&
        (Header->SourceSAP & LLC_SAP_MASK) == 0xAA &&
        Header->Control == LLC_U_FRAME) {
        ULONG Extra;

        Extra = sizeof (LLC_SNAP_HEADER) - sizeof (LLC_U_HEADER);

        if (!Pullup(Argument,
                    StartVa + Offset,
                    Payload,
                    Extra))
            goto fail2;

        Offset += Extra;
    }

    Info->LLCSnapHeader.Length = Offset - Info->LLCSnapHeader.Offset;

    Info->Length += Info->LLCSnapHeader.Length;

    return STATUS_SUCCESS;

fail2:
fail1:
    Info->LLCSnapHeader.Offset = 0;

    return STATUS_UNSUCCESSFUL;
}

static FORCEINLINE NTSTATUS
__ParseEthernetHeader(
    IN      PUCHAR                      StartVa,
    IN      ULONG                       Offset,
    IN      XENVIF_PARSE_PULLUP         Pullup,
    IN      PVOID                       Argument,
    IN OUT  PXENVIF_PACKET_PAYLOAD      Payload,
    OUT     PXENVIF_PACKET_INFO         Info
    )
{
    PETHERNET_HEADER                    Header;
    USHORT                              TypeOrLength;
    BOOLEAN                             IsLLC;
    NTSTATUS                            status;

    Info->EthernetHeader.Offset = Offset;

    if (!Pullup(Argument,
                StartVa + Offset,
                Payload,
                sizeof (ETHERNET_UNTAGGED_HEADER)))
        goto fail1;

    Header = (PETHERNET_HEADER)(StartVa + Offset);
    Offset += sizeof (ETHERNET_UNTAGGED_HEADER);

    IsLLC = FALSE;

    TypeOrLength = NTOHS(Header->Untagged.TypeOrLength);
    if (TypeOrLength == ETHERTYPE_TPID) {
        ULONG Extra;

        Extra = sizeof (ETHERNET_TAGGED_HEADER) -
                sizeof (ETHERNET_UNTAGGED_HEADER);

        if (!Pullup(Argument,
                    StartVa + Offset,
                    Payload,
                    Extra))
            goto fail2;

        Offset += Extra;

        TypeOrLength = NTOHS(Header->Tagged.TypeOrLength);
    }

    if (TypeOrLength <= ETHERNET_MTU)
        IsLLC = TRUE;

    Info->EthernetHeader.Length = Offset - Info->EthernetHeader.Offset;
    Info->Length += Info->EthernetHeader.Length;

    if (IsLLC) {
        status = __ParseLLCSnapHeader(StartVa,
                                      Offset,
                                      Pullup,
                                      Argument,
                                      Payload,
                                      Info);
    } else {
        switch (TypeOrLength) {
        case ETHERTYPE_IPV4:
            status = __ParseIpVersion4Header(StartVa,
                                             Offset,
                                             Pullup,
                                             Argument,
                                             Payload,
                                             Info);
            break;

        case ETHERTYPE_IPV6:
            status = __ParseIpVersion6Header(StartVa,
                                             Offset,
                                             Pullup,
                                             Argument,
                                             Payload,
                                             Info);
            break;

        default:
            status = STATUS_SUCCESS;
            break;
        }
    }

    return status;

fail2:
fail1:
    Info->EthernetHeader.Offset = 0;

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
ParsePacket(
    IN      PUCHAR                      StartVa,
    IN      XENVIF_PARSE_PULLUP         Pullup,
    IN      PVOID                       Argument,
    IN OUT  PXENVIF_PACKET_PAYLOAD      Payload,
    OUT     PXENVIF_PACKET_INFO         Info
    )
{
    ASSERT(IsZeroMemory(Info, sizeof (XENVIF_PACKET_INFO)));

    return __ParseEthernetHeader(StartVa,
                                 0,
                                 Pullup,
                                 Argument,
                                 Payload,
                                 Info);
}
