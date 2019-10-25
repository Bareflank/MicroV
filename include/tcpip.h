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

#include <ws2def.h>

#include "ethernet.h"

#ifndef _TCPIP_H
#define _TCPIP_H

#pragma warning(push)
#pragma warning(disable:4214) // nonstandard extension used : bit field types other than int
#pragma warning(disable:4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable:4200) // nonstandard extension used : zero-sized array in struct/union

#pragma pack(push, 1)

// TCP/IP data structures
//
// NOTE: Fields are in network byte order

// IPv4

typedef struct _IPV4_ADDRESS {
    union {
        ULONG   Dword[1];
        UCHAR   Byte[4];
    };
} IPV4_ADDRESS, *PIPV4_ADDRESS;

#define IPV4_ADDRESS_LENGTH (sizeof (IPV4_ADDRESS))

typedef struct _IPV4_HEADER {
    UCHAR           HeaderLength:4;
    UCHAR           Version:4;
    UCHAR           TypeOfService;
    USHORT          PacketLength;
    USHORT          PacketID;
    USHORT          FragmentOffsetAndFlags;

#define IPV4_FRAGMENT_OFFSET(_FragmentOffsetAndFlags)   \
        ((_FragmentOffsetAndFlags) & 0x1fff)
#define IPV4_DONT_FRAGMENT(_FragmentOffsetAndFlags)     \
        ((_FragmentOffsetAndFlags) & 0x4000)
#define IPV4_MORE_FRAGMENTS(_FragmentOffsetAndFlags)    \
        ((_FragmentOffsetAndFlags) & 0x2000)
#define IPV4_IS_A_FRAGMENT(_FragmentOffsetAndFlags)     \
        ((_FragmentOffsetAndFlags) & 0x3fff)

    UCHAR           TimeToLive;
    UCHAR           Protocol;
    USHORT          Checksum;
    IPV4_ADDRESS    SourceAddress;
    IPV4_ADDRESS    DestinationAddress;
} IPV4_HEADER, *PIPV4_HEADER;

#define IPV4_HEADER_LENGTH(_Header) \
        (((ULONG)((_Header)->HeaderLength)) << 2)

#define MAXIMUM_IPV4_HEADER_LENGTH \
        (0xF << 2)

// IPv6

typedef struct _IPV6_ADDRESS {
    union {
        ULONG   Dword[4];
        USHORT  Word[8];
        UCHAR   Byte[16];
    };
} IPV6_ADDRESS, *PIPV6_ADDRESS;

#define IPV6_ADDRESS_LENGTH (sizeof (IPV6_ADDRESS))

#define IS_IPV6_UNSPECIFIED_ADDRESS(_Address)   \
        (((_Address)->Byte[0] == 0) &&          \
         ((_Address)->Byte[1] == 0) &&          \
         ((_Address)->Byte[2] == 0) &&          \
         ((_Address)->Byte[3] == 0) &&          \
         ((_Address)->Byte[4] == 0) &&          \
         ((_Address)->Byte[5] == 0) &&          \
         ((_Address)->Byte[6] == 0) &&          \
         ((_Address)->Byte[7] == 0) &&          \
         ((_Address)->Byte[8] == 0) &&          \
         ((_Address)->Byte[9] == 0) &&          \
         ((_Address)->Byte[10] == 0) &&         \
         ((_Address)->Byte[11] == 0) &&         \
         ((_Address)->Byte[12] == 0) &&         \
         ((_Address)->Byte[13] == 0) &&         \
         ((_Address)->Byte[14] == 0) &&         \
         ((_Address)->Byte[15] == 0))

typedef struct _IPV6_HEADER {
    union {
      struct {
        UCHAR       __Pad:4;
        UCHAR       Version:4;
      };
      ULONG         VCF;
    };
    USHORT          PayloadLength;
    UCHAR           NextHeader;
    UCHAR           HopLimit;
    IPV6_ADDRESS    SourceAddress;
    IPV6_ADDRESS    DestinationAddress;
} IPV6_HEADER, *PIPV6_HEADER;

#define IPV6_HEADER_LENGTH(_Header) \
        (ULONG)(sizeof (IPV6_HEADER))

#define MAXIMUM_IPV6_HEADER_LENGTH \
        (ULONG)(sizeof (IPV6_HEADER))

// There is no defined maximum for an IPv6 options
// sequence but 256 is a reasonable maximum for
// header plus options.
#define MAXIMUM_IPV6_OPTIONS_LENGTH \
        (ULONG)(256 - sizeof (IPV6_HEADER))

// IP

typedef union _IP_ADDRESS {
    IPV4_ADDRESS    Version4;
    IPV6_ADDRESS    Version6;
} IP_ADDRESS, *PIP_ADDRESS;

typedef union _IP_HEADER {
    struct {
        UCHAR   __Pad:4;
        UCHAR   Version:4;
    };
    IPV4_HEADER Version4;
    IPV6_HEADER Version6;
} IP_HEADER, *PIP_HEADER;
  
#define IP_HEADER_LENGTH(_Header)                   \
        (((_Header)->Version == 4) ?                \
        IPV4_HEADER_LENGTH(&(_Header)->Version4) :  \
        IPV6_HEADER_LENGTH(&(_Header)->Version6))

// Options

typedef struct _IPV6_OPTION_HEADER {
    UCHAR   NextHeader;
    UCHAR   Length;
} IPV6_OPTION_HEADER, *PIPV6_OPTION_HEADER;

#define IPV6_OPTION_HEADER_LENGTH(_Header)  \
        (ULONG)(sizeof (IPV6_OPTION_HEADER) + (_Header)->PayloadLength)

typedef struct _IPV6_FRAGMENT_HEADER {
    UCHAR   NextHeader;
    UCHAR   Reserved;
    USHORT  OffsetAndFlags;
    ULONG   ID;
} IPV6_FRAGMENT_HEADER, *PIPV6_FRAGMENT_HEADER;

#define IPV6_FRAGMENT_OFFSET(_FragmentOffsetAndFlags)   \
        ((_FragmentOffsetAndFlags) & 0xfff8)
#define IPV6_MORE_FRAGMENTS(_FragmentOffsetAndFlags)    \
        ((_FragmentOffsetAndFlags) & 0x0001)
#define IPV6_IS_A_FRAGMENT(_FragmentOffsetAndFlags)     \
        ((_FragmentOffsetAndFlags) & 0xfff9)

// TCP

typedef struct _TCP_HEADER {
    USHORT  SourcePort;
    USHORT  DestinationPort;
    ULONG   Seq;
    ULONG   Ack;
    UCHAR   Reserved:4;
    UCHAR   HeaderLength:4;
    UCHAR   Flags;

#define	TCP_FIN   0x01
#define	TCP_SYN   0x02
#define	TCP_RST   0x04
#define	TCP_PSH   0x08
#define	TCP_ACK   0x10
#define	TCP_URG   0x20
#define	TCP_ECE   0x40
#define	TCP_CWR   0x80

    USHORT  Window;
    USHORT  Checksum;
    USHORT  UrgentPointer;
} TCP_HEADER, *PTCP_HEADER;

#define TCP_HEADER_LENGTH(_Header)  \
        (((ULONG)((_Header)->HeaderLength)) << 2)

#define MAXIMUM_TCP_HEADER_LENGTH \
        (0xF << 2)

#define TCPOPT_NOP          1
#define TCPOPT_TIMESTAMP    8
#define TCPOLEN_TIMESTAMP   10

// UDP

typedef struct _UDP_HEADER {
    USHORT  SourcePort;
    USHORT  DestinationPort;
    USHORT  PacketLength;
    USHORT  Checksum;
} UDP_HEADER, *PUDP_HEADER;

#define UDP_HEADER_LENGTH(_Header)  \
        (ULONG)(sizeof (UDP_HEADER))

// ICMPV6

typedef struct _ICMPV6_HEADER {
    UCHAR   Type;
    UCHAR   Code;
    USHORT  Checksum;
    ULONG   Data;
} ICMPV6_HEADER, *PICMPV6_HEADER;

#define ICMPV6_TYPE_RS  133
#define ICMPV6_TYPE_RA  134
#define ICMPV6_TYPE_NS  135
#define ICMPV6_TYPE_NA  136

// AH

typedef struct _IP_AUTHENTICATION_HEADER {
    UCHAR   NextHeader;
    UCHAR   Length;
    USHORT  Reserved;
    ULONG   Spi;
    ULONG   Seq;
    UCHAR   Icv[0];
} IP_AUTHENTICATION_HEADER, *PIP_AUTHENTICATION_HEADER;

// Checksum

typedef struct _IPV4_PSEUDO_HEADER {
    IPV4_ADDRESS    SourceAddress;
    IPV4_ADDRESS    DestinationAddress;
    UCHAR           Zero;
    UCHAR           Protocol;   // TCP or UDP
    USHORT          Length;     // Including TCP/UDP header
} IPV4_PSEUDO_HEADER, *PIPV4_PSEUDO_HEADER;

typedef struct _IPV6_PSEUDO_HEADER {
    IPV6_ADDRESS    SourceAddress;
    IPV6_ADDRESS    DestinationAddress;
    USHORT          Length;     // Including TCP/UDP header
    UCHAR           Zero[3];
    UCHAR           NextHeader; // TCP or UDP
} IPV6_PSEUDO_HEADER, *PIPV6_PSEUDO_HEADER;

typedef union _PSEUDO_HEADER {
    IPV4_PSEUDO_HEADER  Version4;
    IPV6_PSEUDO_HEADER  Version6;
} PSEUDO_HEADER, *PPSEUDO_HEADER;

// ARP

typedef struct _ARP_HEADER {
    USHORT  HardwareType;

#define HARDWARE_ETHER  1

    USHORT  ProtocolType;

#define PROTOCOL_IPV4   ETHERTYPE_IPV4

    UCHAR   HardwareAddressLength;
    UCHAR   ProtocolAddressLength;
    USHORT  Operation;

#define ARP_REQUEST     1
#define ARP_REPLY       2
#define RARP_REQUEST    3
#define RARP_REPLY      4

} ARP_HEADER, *PARP_HEADER;

#define ARP_HEADER_LENGTH(_Header)  \
        (ULONG)(sizeof (ARP_HEADER))

#pragma pack(pop)

#pragma warning(pop)

#endif  //_TCPIP_H
