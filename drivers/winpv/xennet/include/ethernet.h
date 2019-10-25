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

#ifndef _ETHERNET_H_
#define _ETHERNET_H_

#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used : nameless struct/union

#pragma pack(push, 1)

// Ethernet data structures
//
// NOTE: Fields are in network byte order

#define ETHERNET_MTU            1500
#define ETHERNET_MIN            60
#define ETHERNET_MAX            1514

typedef struct _ETHERNET_ADDRESS {
    UCHAR   Byte[6];
} ETHERNET_ADDRESS, *PETHERNET_ADDRESS;

#define ETHERNET_ADDRESS_LENGTH (sizeof (ETHERNET_ADDRESS))

typedef enum _ETHERNET_ADDRESS_TYPE {
    ETHERNET_ADDRESS_TYPE_INVALID = 0,
    ETHERNET_ADDRESS_UNICAST,
    ETHERNET_ADDRESS_MULTICAST,
    ETHERNET_ADDRESS_BROADCAST,
    ETHERNET_ADDRESS_TYPE_COUNT
} ETHERNET_ADDRESS_TYPE, *PETHERNET_ADDRESS_TYPE;

#define GET_ETHERNET_ADDRESS_TYPE(_Address)                 \
        (((_Address)->Byte[0] & 0x01) ?                     \
            (((((_Address)->Byte[0] & ~0x03) == 0xFC) &&    \
              (((_Address)->Byte[1]        ) == 0xFF) &&    \
              (((_Address)->Byte[2]        ) == 0xFF) &&    \
              (((_Address)->Byte[3]        ) == 0xFF) &&    \
              (((_Address)->Byte[4]        ) == 0xFF) &&    \
              (((_Address)->Byte[5]        ) == 0xFF)       \
             ) ?                                            \
                ETHERNET_ADDRESS_BROADCAST :                \
                ETHERNET_ADDRESS_MULTICAST                  \
            ) :                                             \
            ETHERNET_ADDRESS_UNICAST                        \
        )

typedef struct _ETHERNET_UNTAGGED_HEADER {
    ETHERNET_ADDRESS    DestinationAddress;
    ETHERNET_ADDRESS    SourceAddress;
    USHORT              TypeOrLength;

#define ETHERTYPE_IPV4      0x0800
#define ETHERTYPE_IPV6      0x86DD
#define ETHERTYPE_ARP       0x0806
#define ETHERTYPE_RARP      0x0835
#define ETHERTYPE_TPID      0x8100
#define ETHERTYPE_LOOPBACK  0x9000

} ETHERNET_UNTAGGED_HEADER, *PETHERNET_UNTAGGED_HEADER;

typedef struct _ETHERNET_TAG {
    USHORT  ProtocolID;    // == ETHERTYPE_TPID
    USHORT  ControlInformation;

#define PACK_TAG_CONTROL_INFORMATION(_ControlInformation, _UserPriority, _CanonicalFormatId, _VlanId)   \
        do {                                                                                            \
            (_ControlInformation) = (USHORT)(_VlanId) & 0x0FFF;                                         \
            (_ControlInformation) |= (USHORT)((_CanonicalFormatId) << 12) & 0x1000;                     \
            (_ControlInformation) |= (USHORT)((_UserPriority) << 13) & 0xE000;                          \
        } while (FALSE)

#define UNPACK_TAG_CONTROL_INFORMATION(_ControlInformation, _UserPriority, _CanonicalFormatId, _VlanId) \
        do {                                                                                            \
            (_VlanId) = (_ControlInformation) & 0xFFF;                                                  \
            (_CanonicalFormatId) = ((_ControlInformation) & 0x1000) >> 12;                              \
            (_UserPriority) = ((_ControlInformation) & 0xE000) >> 13;                                   \
        } while (FALSE)

} ETHERNET_TAG, *PETHERNET_TAG;

typedef struct _ETHERNET_TAGGED_HEADER {
  ETHERNET_ADDRESS  DestinationAddress;
  ETHERNET_ADDRESS  SourceAddress;
  ETHERNET_TAG      Tag;
  USHORT            TypeOrLength;
} ETHERNET_TAGGED_HEADER, *PETHERNET_TAGGED_HEADER;

typedef union _ETHERNET_HEADER {
    ETHERNET_UNTAGGED_HEADER    Untagged;
    ETHERNET_TAGGED_HEADER      Tagged;
} ETHERNET_HEADER, *PETHERNET_HEADER;

#define ETHERNET_HEADER_IS_TAGGED(_Header)                          \
        ((_Header)->Untagged.TypeOrLength == NTOHS(ETHERTYPE_TPID))

#define ETHERNET_HEADER_LENGTH(_Header)         \
        ETHERNET_HEADER_IS_TAGGED(_Header) ?    \
        sizeof (ETHERNET_TAGGED_HEADER) :       \
        sizeof (ETHERNET_UNTAGGEDHEADER))

#pragma pack(pop)

#pragma warning(pop)

#endif  // _ETHERNET_H
