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

/*! \file vif_interface.h
    \brief XENVIF VIF Interface

    This interface provides access to the PV network frontend
*/

#ifndef _XENVIF_VIF_INTERFACE_H
#define _XENVIF_VIF_INTERFACE_H

#ifndef _WINDLL

#include <ifdef.h>
#include <ethernet.h>

/*! \enum _XENVIF_PACKET_HASH_ALGORITHM
    \brief Hash algorithm
*/
typedef enum _XENVIF_PACKET_HASH_ALGORITHM {
    /*! None (value should be ignored) */
    XENVIF_PACKET_HASH_ALGORITHM_NONE = 0,
    /*! Unspecified hash (value can be used) */
    XENVIF_PACKET_HASH_ALGORITHM_UNSPECIFIED,
    /*! Toeplitz hash */
    XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ
} XENVIF_PACKET_HASH_ALGORITHM, *PXENVIF_PACKET_HASH_ALGORITHM;

typedef enum _XENVIF_PACKET_HASH_TYPE {
    /*! None (value should be ignored) */
    XENVIF_PACKET_HASH_TYPE_NONE = 0,
    /*! IPv4 header only */
    XENVIF_PACKET_HASH_TYPE_IPV4,
    /*! IPv4 and TCP headers */
    XENVIF_PACKET_HASH_TYPE_IPV4_TCP,
    /*! IPv6 header only */
    XENVIF_PACKET_HASH_TYPE_IPV6,
    /*! IPv6 and TCP headers */
    XENVIF_PACKET_HASH_TYPE_IPV6_TCP
} XENVIF_PACKET_HASH_TYPE, *PXENVIF_PACKET_HASH_TYPE;

struct _XENVIF_PACKET_HASH_V1 {
    /*! Hash algorithm used to calculate value */
    XENVIF_PACKET_HASH_ALGORITHM    Algorithm;
    /*! Calculated value */
    ULONG                           Value;
};

/*! \struct _XENVIF_PACKET_HASH_V2
    \brief Hash information
*/
struct _XENVIF_PACKET_HASH_V2 {
    /*! Hash algorithm used to calculate value */
    XENVIF_PACKET_HASH_ALGORITHM    Algorithm;
    /*! Scope of hash */
    XENVIF_PACKET_HASH_TYPE         Type;
    /*! Calculated value */
    ULONG                           Value;
};

typedef struct _XENVIF_PACKET_HASH_V2 XENVIF_PACKET_HASH, *PXENVIF_PACKET_HASH;

/*! \struct _XENVIF_PACKET_HEADER_V1
    \brief Packet header information
*/
struct  _XENVIF_PACKET_HEADER_V1 {
    /*! Offset from beginning of packet */
    ULONG   Offset;
    /*! Length of header (0 indicates a header is not present) */
    ULONG   Length;
};

struct _XENVIF_PACKET_INFO_V1 {
    ULONG                           Length;
    USHORT                          TagControlInformation;
    BOOLEAN                         IsAFragment;
    struct _XENVIF_PACKET_HEADER_V1 EthernetHeader;
    struct _XENVIF_PACKET_HEADER_V1 LLCSnapHeader;
    struct _XENVIF_PACKET_HEADER_V1 IpHeader;
    struct _XENVIF_PACKET_HEADER_V1 IpOptions;
    struct _XENVIF_PACKET_HEADER_V1 TcpHeader;
    struct _XENVIF_PACKET_HEADER_V1 TcpOptions;
    struct _XENVIF_PACKET_HEADER_V1 UdpHeader;
};

/*! \struct _XENVIF_PACKET_INFO_V2
    \brief Packet information
*/
struct _XENVIF_PACKET_INFO_V2 {
    /*! Total length of all headers */
    ULONG                           Length;
    /*! TRUE if the packet is an IP fragment */
    BOOLEAN                         IsAFragment;
    /*! Ethernet header (stripped of any VLAN tag) */
    struct _XENVIF_PACKET_HEADER_V1 EthernetHeader;
    /*! LLC header (used for IPX or 802.3 IP) */
    struct _XENVIF_PACKET_HEADER_V1 LLCSnapHeader;
    /*! IP header (v4 or v6) */
    struct _XENVIF_PACKET_HEADER_V1 IpHeader;
    /*! IP options (v4 or v6) */
    struct _XENVIF_PACKET_HEADER_V1 IpOptions;
    /*! TCP header */
    struct _XENVIF_PACKET_HEADER_V1 TcpHeader;
    /*! TCP options */
    struct _XENVIF_PACKET_HEADER_V1 TcpOptions;
    /*! UDP header */
    struct _XENVIF_PACKET_HEADER_V1 UdpHeader;
};

typedef struct _XENVIF_PACKET_INFO_V2   XENVIF_PACKET_INFO, *PXENVIF_PACKET_INFO;

#pragma warning(push)
#pragma warning(disable:4214)   // nonstandard extension used : bit field types other than int
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

/*! \struct _XENVIF_PACKET_CHECKSUM_FLAGS_V1
    \brief Packet checksum flags
*/
struct _XENVIF_PACKET_CHECKSUM_FLAGS_V1 {
    union {
        struct {
            /*! IPv4 header checksum validation succeeded */
            ULONG   IpChecksumSucceeded:1;
            /*! IPv4 header checksum validation failed */
            ULONG   IpChecksumFailed:1;
            /*! IPv4 header checksum is present */
            ULONG   IpChecksumPresent:1;
            /*! TCP checksum validation succeeded */
            ULONG   TcpChecksumSucceeded:1;
            /*! TCP checksum validation failed */
            ULONG   TcpChecksumFailed:1;
            /*! TCP checksum is present */
            ULONG   TcpChecksumPresent:1;
            /*! UDP checksum validation succeeded */
            ULONG   UdpChecksumSucceeded:1;
            /*! UDP checksum validation failed */
            ULONG   UdpChecksumFailed:1;
            /*! UDP checksum is present */
            ULONG   UdpChecksumPresent:1;
            ULONG   Reserved:23;
        };
        /*! Raw representation */
        ULONG   Value;
    };
};

typedef struct _XENVIF_PACKET_CHECKSUM_FLAGS_V1 XENVIF_PACKET_CHECKSUM_FLAGS, *PXENVIF_PACKET_CHECKSUM_FLAGS;

#pragma warning(pop)

struct _XENVIF_RECEIVER_PACKET_V1 {
    LIST_ENTRY                              ListEntry;
    struct _XENVIF_PACKET_INFO_V1           *Info;
    ULONG                                   Offset;
    ULONG                                   Length;
    struct _XENVIF_PACKET_CHECKSUM_FLAGS_V1 Flags;
    USHORT                                  MaximumSegmentSize;
    PVOID                                   Cookie;
    MDL                                     Mdl;
    PFN_NUMBER                              __Pfn;
};

#pragma warning(push)
#pragma warning(disable:4214)   // nonstandard extension used : bit field types other than int
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

/*! \struct _XENVIF_VIF_OFFLOAD_OPTIONS_V1
    \brief Offload options
*/
struct _XENVIF_VIF_OFFLOAD_OPTIONS_V1 {
    union {
        struct {
            /*! Insert/strip VLAN tags */
            USHORT  OffloadTagManipulation:1;
            /*! Segment/coalesce IPv4 packets containing TCP large segments */ 
            USHORT  OffloadIpVersion4LargePacket:1;
            /*! Calculate/validate IPv4 header checksum */
            USHORT  OffloadIpVersion4HeaderChecksum:1;
            /*! Calculate/validate IPv4 TCP checksum */
            USHORT  OffloadIpVersion4TcpChecksum:1;
            /*! Calculate/validate IPv4 UDP checksum */
            USHORT  OffloadIpVersion4UdpChecksum:1;
            /*! Segment/coalesce IPv6 packets containing TCP large segments */ 
            USHORT  OffloadIpVersion6LargePacket:1;
            /*! Calculate/validate IPv6 TCP checksum */
            USHORT  OffloadIpVersion6TcpChecksum:1;
            /*! Calculate/validate IPv6 UDP checksum */
            USHORT  OffloadIpVersion6UdpChecksum:1;
            /*! Force calculation of any missing checksums on receive side */
            USHORT  NeedChecksumValue:1;
            /*! Force segmentation of packets containing TCP large segments on receive side */
            USHORT  NeedLargePacketSplit:1;
            USHORT  Reserved:6;
        };

        /*! Raw representation */
        USHORT  Value;
    };
};

typedef struct _XENVIF_VIF_OFFLOAD_OPTIONS_V1 XENVIF_VIF_OFFLOAD_OPTIONS, *PXENVIF_VIF_OFFLOAD_OPTIONS;

#pragma warning(pop)

#pragma pack(push, 1) 

struct _XENVIF_TRANSMITTER_PACKET_SEND_INFO_V1 {
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
    USHORT                      MaximumSegmentSize;
    USHORT                      TagControlInformation;
};

/*! \enum _XENVIF_TRANSMITTER_PACKET_STATUS
    \brief Transmit-side packet status
*/
typedef enum _XENVIF_TRANSMITTER_PACKET_STATUS {
    /*! Packet has been successfully processed by the backend */
    XENVIF_TRANSMITTER_PACKET_OK = 2,
    /*! Packet was dropped */
    XENVIF_TRANSMITTER_PACKET_DROPPED,
    /*! There was a problem handling the packet */
    XENVIF_TRANSMITTER_PACKET_ERROR
} XENVIF_TRANSMITTER_PACKET_STATUS, *PXENVIF_TRANSMITTER_PACKET_STATUS;

/*! \struct _XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO_V1
    \brief Packet information passed from provider to subsriber on
    transmit side packet return

    To fit into the reserved space in NDIS_PACKET and NET_BUFFER structures
    this structure must be at most the size of 3 pointer types.
*/
struct _XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO_V1 {
    /*! Ethernet address type (see \ref _ETHERNET_ADDRESS_TYPE) */
    UCHAR   Type;
    /*! Send status (see \ref _XENVIF_TRANSMITTER_PACKET_STATUS) */
    UCHAR   Status;
    /*! Total length of the sent packet */
    USHORT  PacketLength;
    /*! Length of packet payload after recognized headers are removed */
    USHORT  PayloadLength;
};

typedef struct _XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO_V1 XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO, *PXENVIF_TRANSMITTER_PACKET_COMPLETION_INFO;

#pragma pack(pop) 

struct _XENVIF_TRANSMITTER_PACKET_V2 {
    LIST_ENTRY                                              ListEntry;
    PVOID                                                   Cookie;
    ULONG                                                   Value;
    struct _XENVIF_TRANSMITTER_PACKET_SEND_INFO_V1          Send;
    struct _XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO_V1    Completion;
    PMDL                                                    Mdl;
    ULONG                                                   Offset;
    ULONG                                                   Length;
};

/*! \enum _XENVIF_VIF_STATISTIC
    \brief Interface statistics
*/
typedef enum _XENVIF_VIF_STATISTIC {
    /*! RFC 2863 ifOutDiscards */
    XENVIF_TRANSMITTER_PACKETS_DROPPED = 0,
    /*! Backend component of RFC 2863 ifOutErrors */
    XENVIF_TRANSMITTER_BACKEND_ERRORS,
    /*! Frontend component of RFC 2863 ifOutErrors */
    XENVIF_TRANSMITTER_FRONTEND_ERRORS,
    /*! RFC 2863 ifOutUcastPkts */
    XENVIF_TRANSMITTER_UNICAST_PACKETS,
    /*! Total number of octets in ifOutUcastPkts */
    XENVIF_TRANSMITTER_UNICAST_OCTETS,
    /*! RFC 2863 ifOutMulticastPkts */
    XENVIF_TRANSMITTER_MULTICAST_PACKETS,
    /*! Total number of octets in ifOutMulticastPkts */
    XENVIF_TRANSMITTER_MULTICAST_OCTETS,
    /*! RFC 2863 ifOutBroadcastPkts */
    XENVIF_TRANSMITTER_BROADCAST_PACKETS,
    /*! Total number of octets in ifOutBroadcastPkts */
    XENVIF_TRANSMITTER_BROADCAST_OCTETS,
    /*! RFC 2863 ifInDiscards */
    XENVIF_RECEIVER_PACKETS_DROPPED,
    /*! Backend component of RFC 2863 ifInErrors */
    XENVIF_RECEIVER_BACKEND_ERRORS,
    /*! Frontend component of RFC 2863 ifInErrors */
    XENVIF_RECEIVER_FRONTEND_ERRORS,
    /*! RFC 2863 ifInUcastPkts */
    XENVIF_RECEIVER_UNICAST_PACKETS,
    /*! Total number of octets in ifInUcastPkts */
    XENVIF_RECEIVER_UNICAST_OCTETS,
    /*! RFC 2863 ifInMulticastPkts */
    XENVIF_RECEIVER_MULTICAST_PACKETS,
    /*! Total number of octets in ifInMulticastPkts */
    XENVIF_RECEIVER_MULTICAST_OCTETS,
    /*! RFC 2863 ifInBroadcastPkts */
    XENVIF_RECEIVER_BROADCAST_PACKETS,
    /*! Total number of octets in ifInBroadcastPkts */
    XENVIF_RECEIVER_BROADCAST_OCTETS,
    XENVIF_VIF_STATISTIC_COUNT
} XENVIF_VIF_STATISTIC, *PXENVIF_VIF_STATISTIC;

/*! \enum _XENVIF_MAC_FILTER_LEVEL
    \brief Filter level applied to packets
*/
typedef enum _XENVIF_MAC_FILTER_LEVEL {
    /*! Don't filter out any packets */
    XENVIF_MAC_FILTER_NONE = 0,
    /*! Filter out all packets except those with a matching destination address */
    XENVIF_MAC_FILTER_MATCHING = 1,
    /*! Filter out all packets */
    XENVIF_MAC_FILTER_ALL = 2
} XENVIF_MAC_FILTER_LEVEL, *PXENVIF_MAC_FILTER_LEVEL;

/*! \enum _XENVIF_VIF_CALLBACK_TYPE
    \brief Type of callback (see \ref XENVIF_VIF_CALLBACK)
*/
typedef enum _XENVIF_VIF_CALLBACK_TYPE {
    /*! Return a transmit side packet to the subscriber */
    XENVIF_TRANSMITTER_RETURN_PACKET = 0,
    /*! Queue a receive side packet at the subscriber */
    XENVIF_RECEIVER_QUEUE_PACKET,
    /*! Notify the subscriber of a MAC (link) state has change */
    XENVIF_MAC_STATE_CHANGE
} XENVIF_VIF_CALLBACK_TYPE, *PXENVIF_VIF_CALLBACK_TYPE;

/*! \typedef XENVIF_VIF_ACQUIRE
    \brief Acquire a reference to the VIF interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENVIF_VIF_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENVIF_VIF_RELEASE
    \brief Release a reference to the VIF interface

    \param Interface The interface header
*/  
typedef VOID
(*XENVIF_VIF_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENVIF_VIF_CALLBACK
    \brief Provider to subscriber callback function

    \param Argument An optional context argument passed to the callback
    \param Type The callback type
    \param ... Additional paramaters required by \a Type

    \b XENVIF_TRANSMITTER_RETURN_PACKET:
    \param Cookie Cookie supplied to XENVIF_TRANSMITTER_QUEUE_PACKET
    \param Completion Packet completion information

    \b XENVIF_RECEIVER_QUEUE_PACKET:
    \param Index The index of the queue on which the packet was received
    \param Mdl The initial MDL of the packet
    \param Offset The offset of the packet data in the initial MDL
    \param Length The total length of the packet
    \param Flags Packet checksum flags
    \param MaximumSegmentSize The TCP MSS (used only if OffloadOptions.OffloadIpVersion[4|6]LargePacket is set)
    \param TagControlInformation The VLAN TCI (used only if OffloadOptions.OffloadTagManipulation is set)
    \param Info Header information for the packet
    \param Hash Hash information for the packet
    \param More A flag to indicate whether more packets will be queued for the same CPU
    \param Cookie Cookie that should be passed to XENVIF_RECEIVER_RETURN_PACKET method

    \b XENVIF_MAC_STATE_CHANGE:
    No additional arguments
*/
typedef VOID
(*XENVIF_VIF_CALLBACK)(
    IN  PVOID                       Argument OPTIONAL,
    IN  XENVIF_VIF_CALLBACK_TYPE    Type,
    ...
    );

/*! \typedef XENVIF_VIF_ENABLE
    \brief Enable the VIF interface

    All packets queued for transmit will be rejected and no packets will
    be queued for receive until this method completes. 

    \param Interface The interface header
    \param Callback The subscriber's callback function
    \param Argument An optional context argument passed to the callback
*/
typedef NTSTATUS
(*XENVIF_VIF_ENABLE)(
    IN  PINTERFACE          Interface,
    IN  XENVIF_VIF_CALLBACK Callback,
    IN  PVOID               Argument OPTIONAL
    );

/*! \typedef XENVIF_VIF_DISABLE
    \brief Disable the VIF interface

    This method will not complete until any packets queued for receive
    have been returned. Any packets queued for transmit may be aborted.

    \param Interface The interface header
*/
typedef VOID
(*XENVIF_VIF_DISABLE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENVIF_VIF_QUERY_STATISTIC
    \brief Query the value of an interface statistic

    Interface statistics are 64-bits wide and zero based. They are
    zeroed when the vif device object is created. They are not
    zeroed by this call or by any vif state change (e.g. reconnection
    across migration).

    \param Interface The interface header
    \param Index The index of the statistic in \ref _XENVIF_VIF_STATISTIC
    \param Value Buffer to receive the value of the statistic
*/
typedef NTSTATUS
(*XENVIF_VIF_QUERY_STATISTIC)(
    IN  PINTERFACE              Interface,
    IN  XENVIF_VIF_STATISTIC    Index,
    OUT PULONGLONG              Value
    );

/*! \typedef XENVIF_VIF_QUERY_RING_COUNT
    \brief Query the number of shared rings between frontend
    and backend

    \param Interface The interface header
    \param Count Buffer to receive the count
*/
typedef VOID
(*XENVIF_VIF_QUERY_RING_COUNT)(
    IN  PINTERFACE  Interface,
    OUT PULONG      Count
    );

/*! \typedef XENVIF_VIF_UPDATE_HASH_MAPPING
    \brief Update the mapping of hash to transmitter/receiver ring

    The default mapping is hash % number-of-rings

    \param Interface The interface header
    \param Mapping The mapping table
    \param Size The size of the mapping table
*/
typedef NTSTATUS
(*XENVIF_VIF_UPDATE_HASH_MAPPING)(
    IN  PINTERFACE          Interface,
    IN  PPROCESSOR_NUMBER   Mapping,
    IN  ULONG               Size
    );

typedef VOID
(*XENVIF_VIF_RECEIVER_RETURN_PACKETS_V1)(
    IN  PINTERFACE  Interface,
    IN  PLIST_ENTRY List
    );

/*! \typedef XENVIF_VIF_RECEIVER_RETURN_PACKET
    \brief Return packets queued for receive by \ref XENVIF_VIF_CALLBACK
    (Type = \ref XENVIF_RECEIVER_QUEUE_PACKET)

    \param Interface The interface header
    \param Cookie Cookie passed to XENVIF_RECEIVER_QUEUE_PACKET callback
*/
typedef VOID
(*XENVIF_VIF_RECEIVER_RETURN_PACKET)(
    IN  PINTERFACE  Interface,
    IN  PVOID       Cookie
    );

typedef NTSTATUS
(*XENVIF_VIF_TRANSMITTER_GET_PACKET_HEADERS_V2)(
    IN  PINTERFACE                              Interface,
    IN  struct _XENVIF_TRANSMITTER_PACKET_V2    *Packet,
    OUT PVOID                                   Headers,
    OUT PXENVIF_PACKET_INFO                     Info
    );

typedef NTSTATUS
(*XENVIF_VIF_TRANSMITTER_QUEUE_PACKETS_V2)(
    IN  PINTERFACE  Interface,
    IN  PLIST_ENTRY List
    );

typedef VOID
(*XENVIF_VIF_TRANSMITTER_QUEUE_PACKET_V4)(
    IN  PINTERFACE                  Interface,
    IN  PMDL                        Mdl,
    IN  ULONG                       Offset,
    IN  ULONG                       Length,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions,
    IN  USHORT                      MaximumSegmentSize,
    IN  USHORT                      TagControlInformation,
    IN  PXENVIF_PACKET_HASH         Hash,
    IN  PVOID                       Cookie
    );

typedef NTSTATUS
(*XENVIF_VIF_TRANSMITTER_QUEUE_PACKET_V5)(
    IN  PINTERFACE                  Interface,
    IN  PMDL                        Mdl,
    IN  ULONG                       Offset,
    IN  ULONG                       Length,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions,
    IN  USHORT                      MaximumSegmentSize,
    IN  USHORT                      TagControlInformation,
    IN  PXENVIF_PACKET_HASH         Hash,
    IN  PVOID                       Cookie
    );

/*! \typedef XENVIF_VIF_TRANSMITTER_QUEUE_PACKET
    \brief Queue a packet at the provider's transmit side

    \param Interface The interface header
    \param Mdl The initial MDL of the packet
    \param Offset The offset of the packet data in the initial MDL
    \param Length The total length of the packet
    \param OffloadOptions The requested offload options for this packet
    \param MaximumSegmentSize The TCP MSS (used only if OffloadOptions.OffloadIpVersion[4|6]LargePacket is set)
    \param TagControlInformation The VLAN TCI (used only if OffloadOptions.OffloadTagManipulation is set)
    \param Hash Hash information for the packet
    \param More A flag to indicate whether there will more packets queued with the same value of Hash
    \param Cookie A cookie specified by the caller that will be passed to the XENVIF_TRANSMITTER_RETURN_PACKET callback
*/
typedef NTSTATUS
(*XENVIF_VIF_TRANSMITTER_QUEUE_PACKET)(
    IN  PINTERFACE                  Interface,
    IN  PMDL                        Mdl,
    IN  ULONG                       Offset,
    IN  ULONG                       Length,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions,
    IN  USHORT                      MaximumSegmentSize,
    IN  USHORT                      TagControlInformation,
    IN  PXENVIF_PACKET_HASH         Hash,
    IN  BOOLEAN                     More,
    IN  PVOID                       Cookie
    );

/*! \typedef XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS
    \brief Query the available set of transmit side offload options

    \param Interface The interface header
    \param Options Buffer to receive the avilable options
    (see \ref _XENVIF_VIF_OFFLOAD_OPTIONS_V1)
*/
typedef VOID
(*XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS)(
    IN  PINTERFACE                  Interface,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS Options
    );

/*! \typedef XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS
    \brief Set the required set of receive side offload options

    \param Interface The interface header
    \param Options The required options
    (see \ref _XENVIF_VIF_OFFLOAD_OPTIONS_V1)
*/
typedef VOID
(*XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS)(
    IN  PINTERFACE                  Interface,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  Options
    );

/*! \typedef XENVIF_VIF_RECEIVER_SET_BACKFILL_SIZE
    \brief Set the required receive backfill size (free space before
    packet payload).

    \param Interface The interface header
    \param Size The required size
*/
typedef VOID
(*XENVIF_VIF_RECEIVER_SET_BACKFILL_SIZE)(
    IN  PINTERFACE  Interface,
    IN  ULONG       Size
    );

/*! \typedef XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE
    \brief Query the maximum size of packet containing a TCP large segment
    that can be handled by the transmit side

    \param Interface The interface header
    \param Version The IP version (4 or 6)
    \param Size Buffer to receive the maximum packet size
*/ 
typedef VOID
(*XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE)(
    IN  PINTERFACE  Interface,
    IN  UCHAR       Version,
    OUT PULONG      Size
    );

/*! \typedef XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE
    \brief Query the maximum number of transmit side packets that can
    be queued in each shared ring between frontend and backend

    \param Interface The interface header
    \param Size Buffer to receive the maximum number of packets
*/
typedef VOID
(*XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE)(
    IN  PINTERFACE  Interface,
    OUT PULONG      Size
    );

/*! \typedef XENVIF_VIF_RECEIVER_QUERY_RING_SIZE
    \brief Query the maximum number of receive side packets that can
    be queued in each shared ring between backend and frontend

    \param Interface The interface header
    \param Size Buffer to receive the maximum number of packets
*/
typedef VOID
(*XENVIF_VIF_RECEIVER_QUERY_RING_SIZE)(
    IN  PINTERFACE  Interface,
    OUT PULONG      Size
    );

/*! \typedef XENVIF_VIF_RECEIVER_SET_HASH_ALGORITHM
    \brief Select a hash alorithm

    \param Interface The interface header
    \param Algorithm The algorithm to enable (or
    XENVIF_PACKET_HASH_ALGORITHM_NONE to disable hashing)
*/
typedef NTSTATUS
(*XENVIF_VIF_RECEIVER_SET_HASH_ALGORITHM)(
    IN  PINTERFACE                      Interface,
    IN  XENVIF_PACKET_HASH_ALGORITHM    Algorithm
    );

/*! \typedef XENVIF_VIF_RECEIVER_QUERY_HASH_CAPABILITIES
    \brief Query any algorithm-specific capabilities.

    \param Interface The interface header
    \param ... Additional capabilities reported by the selected algorithm

    \b XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ:
    \param Types Mask of hash types supported
*/
typedef NTSTATUS
(*XENVIF_VIF_RECEIVER_QUERY_HASH_CAPABILITIES)(
    IN  PINTERFACE  Interface,
    ...
    );

/*! \typedef XENVIF_VIF_RECEIVER_UPDATE_HASH_PARAMETERS
    \brief Set parameters of currently selected algorithm.

    \param Interface The interface header
    \param ... Additional parameters required by the selected algorithm

    \b XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ:
    \param Types Mask of hash types enabled
    \param Key Pointer to a 40-byte array containing the hash key
*/
typedef NTSTATUS
(*XENVIF_VIF_RECEIVER_UPDATE_HASH_PARAMETERS)(
    IN  PINTERFACE  Interface,
    ...
    );

#define XENVIF_VIF_HASH_KEY_SIZE    40

/*! \typedef XENVIF_VIF_MAC_QUERY_STATE
    \brief Query the current MAC (link) state

    \param Interface The interface header
    \param MediaConnectState Buffer to receive the current connection state
    \param LinkSpeed Buffer to receive the current link speed in Gbps
    \param MediaDuplexState Buffer to receive the current duplex state
*/
typedef VOID
(*XENVIF_VIF_MAC_QUERY_STATE)(
    IN  PINTERFACE                  Interface,
    OUT PNET_IF_MEDIA_CONNECT_STATE MediaConnectState OPTIONAL,
    OUT PULONG64                    LinkSpeed OPTIONAL,
    OUT PNET_IF_MEDIA_DUPLEX_STATE  MediaDuplexState OPTIONAL
    );

/*! \typedef XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE
    \brief Query the maximum MAC (i.e. on the wire) frame size (not
    including CRC)

    \param Interface The interface header
    \param Size Buffer to receive the maximum frame size
*/
typedef VOID
(*XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE)(
    IN  PINTERFACE  Interface,
    OUT PULONG      Size
    );

/*! \typedef XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS
    \brief Query the permanent MAC address (set by the toolstack)

    \param Interface The interface header
    \param Address Buffer to receive the permanent address
*/
typedef VOID
(*XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS)(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    );

/*! \typedef XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS
    \brief Query the current MAC address (may be set by the guest)

    The guest OS may override the MAC address using the registry. If this
    is not done then the current address will be identical to the
    permanent address.

    \param Interface The interface header
    \param Address Buffer to receive the current address
*/
typedef VOID
(*XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS)(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    );

/*! \typedef XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES
    \brief Query the current set of active multicast addresses

    \param Interface The interface header
    \param Address An optional buffer to receive the set of addresses
    \param Count A buffer to receive the number of active addresses

    Call this method with \a Address set to NULL to get the \a Count,
    which can then be used to allocate a buffer of suitable size to receive
    the array of addresses.
*/
typedef NTSTATUS
(*XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES)(
    IN      PINTERFACE          Interface,
    OUT     PETHERNET_ADDRESS   Address OPTIONAL,
    IN OUT  PULONG              Count
    );

/*! \typedef XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES
    \brief Update the set of active multicast addresses

    \param Interface The interface header
    \param Address An optional buffer containing the set of addresses
    \param Count The number of addresses in the buffer

    The \a Address buffer may only by NULL if \a Count is zero, in which
    case the set of active multicast addresses will be cleared.
*/
typedef NTSTATUS
(*XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES)(
    IN  PINTERFACE          Interface,
    IN  PETHERNET_ADDRESS   Address OPTIONAL,
    IN  ULONG               Count
    );

/*! \typedef XENVIF_VIF_MAC_SET_FILTER_LEVEL
    \brief Set a filter level for a given type of packet

    \param Interface The interface header
    \param Type The destination address type of the packet
    (see \ref _ETHERNET_ADDRESS_TYPE)
    \param Level The new filter level (see \ref _XENVIF_MAC_FILTER_LEVEL)
*/
typedef NTSTATUS
(*XENVIF_VIF_MAC_SET_FILTER_LEVEL)(
    IN  PINTERFACE              Interface,
    IN  ETHERNET_ADDRESS_TYPE   Type,
    IN  XENVIF_MAC_FILTER_LEVEL Level
    );

/*! \typedef XENVIF_VIF_MAC_QUERY_FILTER_LEVEL
    \brief Query the current filter level for a given type of packet

    \param Interface The interface header
    \param Type The destination address type of the packet
    (see \ref _ETHERNET_ADDRESS_TYPE)
    \param Level Buffer to receive the filter level (see \ref _XENVIF_MAC_FILTER_LEVEL)
*/
typedef NTSTATUS
(*XENVIF_VIF_MAC_QUERY_FILTER_LEVEL)(
    IN  PINTERFACE                  Interface,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    OUT PXENVIF_MAC_FILTER_LEVEL    Level
    );

// {76F279CD-CA11-418B-92E8-C57F77DE0E2E}
DEFINE_GUID(GUID_XENVIF_VIF_INTERFACE, 
0x76f279cd, 0xca11, 0x418b, 0x92, 0xe8, 0xc5, 0x7f, 0x77, 0xde, 0xe, 0x2e);

/*! \struct _XENVIF_VIF_INTERFACE_V2
    \brief VIF interface version 2
    \ingroup interfaces
*/
struct _XENVIF_VIF_INTERFACE_V2 {
    INTERFACE                                       Interface;
    XENVIF_VIF_ACQUIRE                              Acquire;
    XENVIF_VIF_RELEASE                              Release;
    XENVIF_VIF_ENABLE                               Enable;
    XENVIF_VIF_DISABLE                              Disable;
    XENVIF_VIF_QUERY_STATISTIC                      QueryStatistic;
    XENVIF_VIF_RECEIVER_RETURN_PACKETS_V1           ReceiverReturnPacketsVersion1;
    XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS         ReceiverSetOffloadOptions;
    XENVIF_VIF_RECEIVER_QUERY_RING_SIZE             ReceiverQueryRingSize;
    XENVIF_VIF_TRANSMITTER_GET_PACKET_HEADERS_V2    TransmitterGetPacketHeadersVersion2;
    XENVIF_VIF_TRANSMITTER_QUEUE_PACKETS_V2         TransmitterQueuePacketsVersion2;
    XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS    TransmitterQueryOffloadOptions;
    XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE  TransmitterQueryLargePacketSize;
    XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE          TransmitterQueryRingSize;
    XENVIF_VIF_MAC_QUERY_STATE                      MacQueryState;
    XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE         MacQueryMaximumFrameSize;
    XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS          MacQueryPermanentAddress;
    XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS            MacQueryCurrentAddress;
    XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES        MacQueryMulticastAddresses;
    XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES          MacSetMulticastAddresses;
    XENVIF_VIF_MAC_SET_FILTER_LEVEL                 MacSetFilterLevel;
    XENVIF_VIF_MAC_QUERY_FILTER_LEVEL               MacQueryFilterLevel;
};

/*! \struct _XENVIF_VIF_INTERFACE_V3
    \brief VIF interface version 3
    \ingroup interfaces
*/
struct _XENVIF_VIF_INTERFACE_V3 {
    INTERFACE                                       Interface;
    XENVIF_VIF_ACQUIRE                              Acquire;
    XENVIF_VIF_RELEASE                              Release;
    XENVIF_VIF_ENABLE                               Enable;
    XENVIF_VIF_DISABLE                              Disable;
    XENVIF_VIF_QUERY_STATISTIC                      QueryStatistic;
    XENVIF_VIF_RECEIVER_RETURN_PACKETS_V1           ReceiverReturnPacketsVersion1;
    XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS         ReceiverSetOffloadOptions;
    XENVIF_VIF_RECEIVER_SET_BACKFILL_SIZE           ReceiverSetBackfillSize;
    XENVIF_VIF_RECEIVER_QUERY_RING_SIZE             ReceiverQueryRingSize;
    XENVIF_VIF_TRANSMITTER_GET_PACKET_HEADERS_V2    TransmitterGetPacketHeadersVersion2;
    XENVIF_VIF_TRANSMITTER_QUEUE_PACKETS_V2         TransmitterQueuePacketsVersion2;
    XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS    TransmitterQueryOffloadOptions;
    XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE  TransmitterQueryLargePacketSize;
    XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE          TransmitterQueryRingSize;
    XENVIF_VIF_MAC_QUERY_STATE                      MacQueryState;
    XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE         MacQueryMaximumFrameSize;
    XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS          MacQueryPermanentAddress;
    XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS            MacQueryCurrentAddress;
    XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES        MacQueryMulticastAddresses;
    XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES          MacSetMulticastAddresses;
    XENVIF_VIF_MAC_SET_FILTER_LEVEL                 MacSetFilterLevel;
    XENVIF_VIF_MAC_QUERY_FILTER_LEVEL               MacQueryFilterLevel;
};

/*! \struct _XENVIF_VIF_INTERFACE_V4
    \brief VIF interface version 4
    \ingroup interfaces
*/
struct _XENVIF_VIF_INTERFACE_V4 {
    INTERFACE                                       Interface;
    XENVIF_VIF_ACQUIRE                              Acquire;
    XENVIF_VIF_RELEASE                              Release;
    XENVIF_VIF_ENABLE                               Enable;
    XENVIF_VIF_DISABLE                              Disable;
    XENVIF_VIF_QUERY_STATISTIC                      QueryStatistic;
    XENVIF_VIF_RECEIVER_RETURN_PACKET               ReceiverReturnPacket;
    XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS         ReceiverSetOffloadOptions;
    XENVIF_VIF_RECEIVER_SET_BACKFILL_SIZE           ReceiverSetBackfillSize;
    XENVIF_VIF_RECEIVER_QUERY_RING_SIZE             ReceiverQueryRingSize;
    XENVIF_VIF_TRANSMITTER_QUEUE_PACKET_V4          TransmitterQueuePacketVersion4;
    XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS    TransmitterQueryOffloadOptions;
    XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE  TransmitterQueryLargePacketSize;
    XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE          TransmitterQueryRingSize;
    XENVIF_VIF_MAC_QUERY_STATE                      MacQueryState;
    XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE         MacQueryMaximumFrameSize;
    XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS          MacQueryPermanentAddress;
    XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS            MacQueryCurrentAddress;
    XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES        MacQueryMulticastAddresses;
    XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES          MacSetMulticastAddresses;
    XENVIF_VIF_MAC_SET_FILTER_LEVEL                 MacSetFilterLevel;
    XENVIF_VIF_MAC_QUERY_FILTER_LEVEL               MacQueryFilterLevel;
};

/*! \struct _XENVIF_VIF_INTERFACE_V5
    \brief VIF interface version 5
    \ingroup interfaces
*/
struct _XENVIF_VIF_INTERFACE_V5 {
    INTERFACE                                       Interface;
    XENVIF_VIF_ACQUIRE                              Acquire;
    XENVIF_VIF_RELEASE                              Release;
    XENVIF_VIF_ENABLE                               Enable;
    XENVIF_VIF_DISABLE                              Disable;
    XENVIF_VIF_QUERY_STATISTIC                      QueryStatistic;
    XENVIF_VIF_RECEIVER_RETURN_PACKET               ReceiverReturnPacket;
    XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS         ReceiverSetOffloadOptions;
    XENVIF_VIF_RECEIVER_SET_BACKFILL_SIZE           ReceiverSetBackfillSize;
    XENVIF_VIF_RECEIVER_QUERY_RING_SIZE             ReceiverQueryRingSize;
    XENVIF_VIF_TRANSMITTER_QUEUE_PACKET_V5          TransmitterQueuePacket;
    XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS    TransmitterQueryOffloadOptions;
    XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE  TransmitterQueryLargePacketSize;
    XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE          TransmitterQueryRingSize;
    XENVIF_VIF_MAC_QUERY_STATE                      MacQueryState;
    XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE         MacQueryMaximumFrameSize;
    XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS          MacQueryPermanentAddress;
    XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS            MacQueryCurrentAddress;
    XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES        MacQueryMulticastAddresses;
    XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES          MacSetMulticastAddresses;
    XENVIF_VIF_MAC_SET_FILTER_LEVEL                 MacSetFilterLevel;
    XENVIF_VIF_MAC_QUERY_FILTER_LEVEL               MacQueryFilterLevel;
};

/*! \struct _XENVIF_VIF_INTERFACE_V6
    \brief VIF interface version 6
    \ingroup interfaces
*/
struct _XENVIF_VIF_INTERFACE_V6 {
    INTERFACE                                       Interface;
    XENVIF_VIF_ACQUIRE                              Acquire;
    XENVIF_VIF_RELEASE                              Release;
    XENVIF_VIF_ENABLE                               Enable;
    XENVIF_VIF_DISABLE                              Disable;
    XENVIF_VIF_QUERY_STATISTIC                      QueryStatistic;
    XENVIF_VIF_QUERY_RING_COUNT                     QueryRingCount;
    XENVIF_VIF_UPDATE_HASH_MAPPING                  UpdateHashMapping;
    XENVIF_VIF_RECEIVER_RETURN_PACKET               ReceiverReturnPacket;
    XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS         ReceiverSetOffloadOptions;
    XENVIF_VIF_RECEIVER_SET_BACKFILL_SIZE           ReceiverSetBackfillSize;
    XENVIF_VIF_RECEIVER_QUERY_RING_SIZE             ReceiverQueryRingSize;
    XENVIF_VIF_RECEIVER_SET_HASH_ALGORITHM          ReceiverSetHashAlgorithm;
    XENVIF_VIF_RECEIVER_QUERY_HASH_CAPABILITIES     ReceiverQueryHashCapabilities;
    XENVIF_VIF_RECEIVER_UPDATE_HASH_PARAMETERS      ReceiverUpdateHashParameters;
    XENVIF_VIF_TRANSMITTER_QUEUE_PACKET_V5          TransmitterQueuePacket;
    XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS    TransmitterQueryOffloadOptions;
    XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE  TransmitterQueryLargePacketSize;
    XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE          TransmitterQueryRingSize;
    XENVIF_VIF_MAC_QUERY_STATE                      MacQueryState;
    XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE         MacQueryMaximumFrameSize;
    XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS          MacQueryPermanentAddress;
    XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS            MacQueryCurrentAddress;
    XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES        MacQueryMulticastAddresses;
    XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES          MacSetMulticastAddresses;
    XENVIF_VIF_MAC_SET_FILTER_LEVEL                 MacSetFilterLevel;
    XENVIF_VIF_MAC_QUERY_FILTER_LEVEL               MacQueryFilterLevel;
};

/*! \struct _XENVIF_VIF_INTERFACE_V7
    \brief VIF interface version 7
    \ingroup interfaces
*/
struct _XENVIF_VIF_INTERFACE_V7 {
    INTERFACE                                       Interface;
    XENVIF_VIF_ACQUIRE                              Acquire;
    XENVIF_VIF_RELEASE                              Release;
    XENVIF_VIF_ENABLE                               Enable;
    XENVIF_VIF_DISABLE                              Disable;
    XENVIF_VIF_QUERY_STATISTIC                      QueryStatistic;
    XENVIF_VIF_QUERY_RING_COUNT                     QueryRingCount;
    XENVIF_VIF_UPDATE_HASH_MAPPING                  UpdateHashMapping;
    XENVIF_VIF_RECEIVER_RETURN_PACKET               ReceiverReturnPacket;
    XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS         ReceiverSetOffloadOptions;
    XENVIF_VIF_RECEIVER_SET_BACKFILL_SIZE           ReceiverSetBackfillSize;
    XENVIF_VIF_RECEIVER_QUERY_RING_SIZE             ReceiverQueryRingSize;
    XENVIF_VIF_RECEIVER_SET_HASH_ALGORITHM          ReceiverSetHashAlgorithm;
    XENVIF_VIF_RECEIVER_QUERY_HASH_CAPABILITIES     ReceiverQueryHashCapabilities;
    XENVIF_VIF_RECEIVER_UPDATE_HASH_PARAMETERS      ReceiverUpdateHashParameters;
    XENVIF_VIF_TRANSMITTER_QUEUE_PACKET             TransmitterQueuePacket;
    XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS    TransmitterQueryOffloadOptions;
    XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE  TransmitterQueryLargePacketSize;
    XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE          TransmitterQueryRingSize;
    XENVIF_VIF_MAC_QUERY_STATE                      MacQueryState;
    XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE         MacQueryMaximumFrameSize;
    XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS          MacQueryPermanentAddress;
    XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS            MacQueryCurrentAddress;
    XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES        MacQueryMulticastAddresses;
    XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES          MacSetMulticastAddresses;
    XENVIF_VIF_MAC_SET_FILTER_LEVEL                 MacSetFilterLevel;
    XENVIF_VIF_MAC_QUERY_FILTER_LEVEL               MacQueryFilterLevel;
};

/*! \struct _XENVIF_VIF_INTERFACE_V8
    \brief VIF interface version 8
    \ingroup interfaces
*/
struct _XENVIF_VIF_INTERFACE_V8 {
    INTERFACE                                       Interface;
    XENVIF_VIF_ACQUIRE                              Acquire;
    XENVIF_VIF_RELEASE                              Release;
    XENVIF_VIF_ENABLE                               Enable;
    XENVIF_VIF_DISABLE                              Disable;
    XENVIF_VIF_QUERY_STATISTIC                      QueryStatistic;
    XENVIF_VIF_QUERY_RING_COUNT                     QueryRingCount;
    XENVIF_VIF_UPDATE_HASH_MAPPING                  UpdateHashMapping;
    XENVIF_VIF_RECEIVER_RETURN_PACKET               ReceiverReturnPacket;
    XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS         ReceiverSetOffloadOptions;
    XENVIF_VIF_RECEIVER_SET_BACKFILL_SIZE           ReceiverSetBackfillSize;
    XENVIF_VIF_RECEIVER_QUERY_RING_SIZE             ReceiverQueryRingSize;
    XENVIF_VIF_RECEIVER_SET_HASH_ALGORITHM          ReceiverSetHashAlgorithm;
    XENVIF_VIF_RECEIVER_QUERY_HASH_CAPABILITIES     ReceiverQueryHashCapabilities;
    XENVIF_VIF_RECEIVER_UPDATE_HASH_PARAMETERS      ReceiverUpdateHashParameters;
    XENVIF_VIF_TRANSMITTER_QUEUE_PACKET             TransmitterQueuePacket;
    XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS    TransmitterQueryOffloadOptions;
    XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE  TransmitterQueryLargePacketSize;
    XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE          TransmitterQueryRingSize;
    XENVIF_VIF_MAC_QUERY_STATE                      MacQueryState;
    XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE         MacQueryMaximumFrameSize;
    XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS          MacQueryPermanentAddress;
    XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS            MacQueryCurrentAddress;
    XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES        MacQueryMulticastAddresses;
    XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES          MacSetMulticastAddresses;
    XENVIF_VIF_MAC_SET_FILTER_LEVEL                 MacSetFilterLevel;
    XENVIF_VIF_MAC_QUERY_FILTER_LEVEL               MacQueryFilterLevel;
};

typedef struct _XENVIF_VIF_INTERFACE_V8 XENVIF_VIF_INTERFACE, *PXENVIF_VIF_INTERFACE;

/*! \def XENVIF_VIF
    \brief Macro at assist in method invocation
*/
#define XENVIF_VIF(_Method, _Interface, ...)    \
    (_Interface)-> ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENVIF_VIF_INTERFACE_VERSION_MIN    2
#define XENVIF_VIF_INTERFACE_VERSION_MAX    8

#endif  // _XENVIF_INTERFACE_H
