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

#ifndef _XENVIF_CHECKSUM_H
#define _XENVIF_CHECKSUM_H

#include "parse.h"

extern VOID
AccumulateChecksum(
    IN OUT  PULONG  Accumulator,
    IN      PVOID   MappedSystemVa,
    IN      ULONG   ByteCount
    );

extern USHORT
ChecksumIpVersion4Header(
    IN  PUCHAR              StartVa,
    IN  PXENVIF_PACKET_INFO Info
    );

extern USHORT
ChecksumIpVersion4PseudoHeader(
    IN  PIPV4_ADDRESS   SourceAddress,
    IN  PIPV4_ADDRESS   DestinationAddress,
    IN  USHORT          Length,
    IN  UCHAR           Protocol
    );

extern USHORT
ChecksumIpVersion6PseudoHeader(
    IN  PIPV6_ADDRESS   SourceAddress,
    IN  PIPV6_ADDRESS   DestinationAddress,
    IN  USHORT          Length,
    IN  UCHAR           Protocol
    );

extern USHORT
ChecksumPseudoHeader(
    IN  PUCHAR              StartVa,
    IN  PXENVIF_PACKET_INFO Info
    );

extern USHORT
ChecksumTcpPacket(
    IN  PUCHAR                  StartVa,
    IN  PXENVIF_PACKET_INFO     Info,
    IN  USHORT                  PseudoHeaderChecksum,
    IN  PXENVIF_PACKET_PAYLOAD  Payload
    );

extern USHORT
ChecksumUdpPacket(
    IN  PUCHAR                  StartVa,
    IN  PXENVIF_PACKET_INFO     Info,
    IN  USHORT                  PseudoHeaderChecksum,
    IN  PXENVIF_PACKET_PAYLOAD  Payload
    );

extern BOOLEAN
ChecksumVerify(
    IN  USHORT  Calculated,
    IN  USHORT  Embedded
    );

#endif  // _XENVIF_CHECKSUM_H
