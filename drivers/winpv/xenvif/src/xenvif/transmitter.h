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

#ifndef _XENVIF_TRANSMITTER_H
#define _XENVIF_TRANSMITTER_H

#include <ntddk.h>
#include <netioapi.h>

#include <vif_interface.h>
#include <tcpip.h>

#include "frontend.h"

typedef struct _XENVIF_TRANSMITTER XENVIF_TRANSMITTER, *PXENVIF_TRANSMITTER;

extern NTSTATUS
TransmitterInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_TRANSMITTER *Transmitter
    );

extern NTSTATUS
TransmitterConnect(
    IN  PXENVIF_TRANSMITTER Transmitter
    );

extern NTSTATUS
TransmitterStoreWrite(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    );

extern NTSTATUS
TransmitterEnable(
    IN  PXENVIF_TRANSMITTER Transmitter
    );

extern VOID
TransmitterDisable(
    IN  PXENVIF_TRANSMITTER Transmitter
    );

extern VOID
TransmitterDisconnect(
    IN  PXENVIF_TRANSMITTER Transmitter
    );

extern VOID
TransmitterTeardown(
    IN  PXENVIF_TRANSMITTER Transmitter
    );

extern VOID
TransmitterNotify(
    IN  PXENVIF_TRANSMITTER Transmitter,
    IN  ULONG               Index
    );

extern VOID
TransmitterAbortPackets(
    IN  PXENVIF_TRANSMITTER Transmitter
    );

extern VOID
TransmitterQueueArp(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  PIPV4_ADDRESS           Address
    );

extern VOID
TransmitterQueueNeighbourAdvertisement(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  PIPV6_ADDRESS           Address
    );

extern VOID
TransmitterQueueMulticastControl(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  PETHERNET_ADDRESS       Address,
    IN  BOOLEAN                 Add
    );

extern VOID
TransmitterQueryRingSize(
    IN  PXENVIF_TRANSMITTER Transmitter,
    OUT PULONG              Size
    );

extern NTSTATUS
TransmitterQueuePacket(
    IN  PXENVIF_TRANSMITTER         Transmitter,
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

extern VOID
TransmitterQueryOffloadOptions(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS Options
    );

extern VOID
TransmitterQueryLargePacketSize(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  UCHAR                   Version,
    OUT PULONG                  Size
    );

BOOLEAN
TransmitterHasMulticastControl(
    IN  PXENVIF_TRANSMITTER Transmitter
    );

NTSTATUS
TransmitterRequestMulticastControl(
    IN  PXENVIF_TRANSMITTER Transmitter,
    IN  BOOLEAN             Enabled
    );

#endif  // _XENVIF_TRANSMITTER_H
