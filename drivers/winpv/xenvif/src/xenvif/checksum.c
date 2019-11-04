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
#include <tcpip.h>

#include <vif_interface.h>

#include "checksum.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

static FORCEINLINE VOID
__AccumulateChecksum(
    IN OUT  PULONG  Accumulator,
    IN      PUCHAR  BaseVa,
    IN      ULONG   ByteCount
    )
{
    ULONG           Current;

    Current = *Accumulator;

    while (ByteCount > 1) {
        Current += *((PUSHORT)BaseVa);
        if (Current & (1 << 31))
            Current = (Current & 0xFFFF) + (Current >> 16);
        BaseVa += 2;
        ByteCount -= 2;
    }

    if (ByteCount != 0)
        Current += (USHORT)*BaseVa;

    while ((Current >> 16) != 0)
        Current = (Current & 0xFFFF) + (Current >> 16);

    *Accumulator = Current;
}

VOID
AccumulateChecksum(
    IN OUT  PULONG  Accumulator,
    IN      PVOID   BaseVa,
    IN      ULONG   ByteCount
    )
{
    __AccumulateChecksum(Accumulator, BaseVa, ByteCount);
}

BOOLEAN
ChecksumVerify(
    IN  USHORT  Calculated,
    IN  USHORT  Embedded
    )
{
    ULONG       Accumulator = ~Calculated;

    // 
    // MSVC extends Calculated to ULONG prior to inverting it
    // so we must explicitly zero out the upper half
    //
    Accumulator &= 0xFFFF;

    // See RFC 1624, section 5
    __AccumulateChecksum(&Accumulator, (PUCHAR)&Embedded, sizeof (USHORT));

    return (Accumulator == 0xFFFF) ? TRUE : FALSE;
}

static FORCEINLINE USHORT
__ChecksumIpVersion4PseudoHeader(
    IN  PIPV4_ADDRESS   SourceAddress,
    IN  PIPV4_ADDRESS   DestinationAddress,
    IN  USHORT          Length,
    IN  UCHAR           Protocol
    )
{
    IPV4_PSEUDO_HEADER  Header;
    ULONG               Accumulator;

    RtlZeroMemory(&Header, sizeof (IPV4_PSEUDO_HEADER));

    Header.SourceAddress = *SourceAddress;
    Header.DestinationAddress = *DestinationAddress;
    Header.Length = HTONS(Length);
    Header.Protocol = Protocol;

    Accumulator = 0;
    __AccumulateChecksum(&Accumulator, (PUCHAR)&Header, sizeof (IPV4_PSEUDO_HEADER));

    // As-per RFC1624, Accumulator should never be 0.
    ASSERT(Accumulator != 0);

    return (USHORT)Accumulator;
}

USHORT
ChecksumIpVersion4PseudoHeader(
    IN  PIPV4_ADDRESS   SourceAddress,
    IN  PIPV4_ADDRESS   DestinationAddress,
    IN  USHORT          Length,
    IN  UCHAR           Protocol
    )
{
    return __ChecksumIpVersion4PseudoHeader(SourceAddress,
                                            DestinationAddress,
                                            Length,
                                            Protocol);
}

static FORCEINLINE USHORT
__ChecksumIpVersion6PseudoHeader(
    IN  PIPV6_ADDRESS   SourceAddress,
    IN  PIPV6_ADDRESS   DestinationAddress,
    IN  USHORT          Length,
    IN  UCHAR           Protocol
    )
{
    IPV6_PSEUDO_HEADER  Header;
    ULONG               Accumulator;

    RtlZeroMemory(&Header, sizeof (IPV6_PSEUDO_HEADER));

    Header.SourceAddress = *SourceAddress;
    Header.DestinationAddress = *DestinationAddress;
    Header.Length = HTONS(Length);
    Header.NextHeader = Protocol;

    Accumulator = 0;
    __AccumulateChecksum(&Accumulator, (PUCHAR)&Header, sizeof (IPV6_PSEUDO_HEADER));

    // As-per RFC1624, Accumulator should never be 0.
    ASSERT(Accumulator != 0);

    return (USHORT)Accumulator;
}

USHORT
ChecksumIpVersion6PseudoHeader(
    IN  PIPV6_ADDRESS   SourceAddress,
    IN  PIPV6_ADDRESS   DestinationAddress,
    IN  USHORT          Length,
    IN  UCHAR           Protocol
    )
{
    return __ChecksumIpVersion6PseudoHeader(SourceAddress,
                                            DestinationAddress,
                                            Length,
                                            Protocol);
}

USHORT
ChecksumPseudoHeader(
    IN  PUCHAR              StartVa,
    IN  PXENVIF_PACKET_INFO Info
    )
{
    PIP_HEADER              Header;
    UCHAR                   Protocol;
    USHORT                  Checksum;

    ASSERT(Info->IpHeader.Length != 0);
    Header = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

    if (Info->TcpHeader.Length != 0) {
        Protocol = IPPROTO_TCP;
    } else {
        ASSERT(Info->UdpHeader.Length != 0);
        Protocol = IPPROTO_UDP;
    }

    if (Header->Version == 4) {
        USHORT              Length;

        Length = NTOHS(Header->Version4.PacketLength) -
                 sizeof (IPV4_HEADER) -
                 (USHORT)Info->IpOptions.Length;

        Checksum = __ChecksumIpVersion4PseudoHeader(&Header->Version4.SourceAddress,
                                                    &Header->Version4.DestinationAddress,
                                                    Length,
                                                    Protocol);
    } else {
        USHORT              Length;

        ASSERT3U(Header->Version, ==, 6);

        Length = NTOHS(Header->Version6.PayloadLength) -
                 (USHORT)Info->IpOptions.Length;

        Checksum = __ChecksumIpVersion6PseudoHeader(&Header->Version6.SourceAddress,
                                                    &Header->Version6.DestinationAddress,
                                                    Length,
                                                    Protocol);
    }

    return Checksum;
}

USHORT
ChecksumIpVersion4Header(
    IN  PUCHAR              StartVa,
    IN  PXENVIF_PACKET_INFO Info
    )
{
    ULONG                   Accumulator;
    PIPV4_HEADER            Header;
    USHORT                  Saved;

    ASSERT(Info->IpHeader.Length != 0);
    Header = (PIPV4_HEADER)(StartVa + Info->IpHeader.Offset);

    ASSERT3U(Header->Version, ==, 4);

    Saved = Header->Checksum;
    Header->Checksum = 0;

    Accumulator = 0;
    __AccumulateChecksum(&Accumulator,
                         StartVa + Info->IpHeader.Offset,
                         Info->IpHeader.Length);

    Header->Checksum = Saved;

    if (Info->IpOptions.Length != 0)
        __AccumulateChecksum(&Accumulator,
                             StartVa + Info->IpOptions.Offset,
                             Info->IpOptions.Length);

    // As-per RFC1624, Accumulator should never be 0.
    ASSERT(Accumulator != 0);

    return (USHORT)~Accumulator;
}

USHORT
ChecksumTcpPacket(
    IN  PUCHAR                  StartVa,
    IN  PXENVIF_PACKET_INFO     Info,
    IN  USHORT                  PseudoHeaderChecksum,
    IN  PXENVIF_PACKET_PAYLOAD  Payload
    )
{
    ULONG                       Accumulator;
    PIP_HEADER                  IpHeader;
    PTCP_HEADER                 TcpHeader;
    USHORT                      Saved;
    PMDL                        Mdl;
    ULONG                       Offset;
    ULONG                       Length;

    ASSERT(Info->IpHeader.Length != 0);
    IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

    ASSERT(Info->TcpHeader.Length != 0);
    TcpHeader = (PTCP_HEADER)(StartVa + Info->TcpHeader.Offset);

    Saved = TcpHeader->Checksum;
    TcpHeader->Checksum = 0;

    Accumulator = PseudoHeaderChecksum;
    __AccumulateChecksum(&Accumulator,
                         StartVa + Info->TcpHeader.Offset,
                         Info->TcpHeader.Length);

    TcpHeader->Checksum = Saved;

    if (Info->TcpOptions.Length != 0)
        __AccumulateChecksum(&Accumulator,
                             StartVa + Info->TcpOptions.Offset,
                             Info->TcpOptions.Length);

    Mdl = Payload->Mdl;
    Offset = Payload->Offset;

    if (IpHeader->Version == 4) {
        PIPV4_HEADER    Version4 = &IpHeader->Version4;
        
        Length = NTOHS(Version4->PacketLength) -
                 Info->IpHeader.Length -
                 Info->IpOptions.Length;
    } else {
        PIPV6_HEADER    Version6 = &IpHeader->Version6;

        Length = NTOHS(Version6->PayloadLength) -
                 Info->IpOptions.Length;
    }

    Length -= Info->TcpHeader.Length;
    Length -= Info->TcpOptions.Length;
    Length = __min(Length, Payload->Length);

    while (Length != 0) {
        PUCHAR  BaseVa;
        ULONG   ByteCount;

        ASSERT(Mdl != NULL);

        BaseVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        BaseVa += Offset;

        ByteCount = Mdl->ByteCount;
        ASSERT3U(Offset, <=, ByteCount);
        ByteCount -= Offset;
        ByteCount = __min(ByteCount, Length);

        __AccumulateChecksum(&Accumulator, BaseVa, ByteCount);

        Length -= ByteCount;

        Mdl = Mdl->Next;
        Offset = 0;
    }

    // As-per RFC1624, Accumulator should never be 0.
    ASSERT(Accumulator != 0);

    return (USHORT)~Accumulator;
}

USHORT
ChecksumUdpPacket(
    IN  PUCHAR                  StartVa,
    IN  PXENVIF_PACKET_INFO     Info,
    IN  USHORT                  PseudoHeaderChecksum,
    IN  PXENVIF_PACKET_PAYLOAD  Payload
    )
{
    ULONG                       Accumulator;
    PIP_HEADER                  IpHeader;
    PUDP_HEADER                 UdpHeader;
    USHORT                      Saved;
    PMDL                        Mdl;
    ULONG                       Offset;
    ULONG                       Length;

    ASSERT(Info->IpHeader.Length != 0);
    IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

    ASSERT(Info->UdpHeader.Length != 0);
    UdpHeader = (PUDP_HEADER)(StartVa + Info->UdpHeader.Offset);

    Saved = UdpHeader->Checksum;
    UdpHeader->Checksum = 0;

    Accumulator = PseudoHeaderChecksum;
    __AccumulateChecksum(&Accumulator,
                         StartVa + Info->UdpHeader.Offset,
                         Info->UdpHeader.Length);

    UdpHeader->Checksum = Saved;

    Mdl = Payload->Mdl;
    Offset = Payload->Offset;

    if (IpHeader->Version == 4) {
        PIPV4_HEADER    Version4 = &IpHeader->Version4;
        
        Length = NTOHS(Version4->PacketLength) -
                 sizeof (IPV4_HEADER) -
                 (USHORT)Info->IpOptions.Length;
    } else {
        PIPV6_HEADER    Version6 = &IpHeader->Version6;

        Length = NTOHS(Version6->PayloadLength) -
                 (USHORT)Info->IpOptions.Length;
    }

    Length -= Info->UdpHeader.Length;
    Length = __min(Length, Payload->Length);

    while (Length != 0) {
        PUCHAR  BaseVa;
        ULONG   ByteCount;

        ASSERT(Mdl != NULL);

        BaseVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        BaseVa += Offset;

        ByteCount = Mdl->ByteCount;
        ASSERT3U(Offset, <=, ByteCount);
        ByteCount -= Offset;
        ByteCount = __min(ByteCount, Length);

        __AccumulateChecksum(&Accumulator, BaseVa, ByteCount);

        Length -= ByteCount;

        Mdl = Mdl->Next;
        Offset = 0;
    }

    // As-per RFC1624, Accumulator should never be 0.
    ASSERT(Accumulator != 0);

    return (USHORT)~Accumulator;
}
