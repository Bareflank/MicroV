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

#ifndef _XENVIF_RECEIVER_H
#define _XENVIF_RECEIVER_H

#include <ntddk.h>
#include <ifdef.h>
#include <vif_interface.h>

#include "frontend.h"

typedef struct _XENVIF_RECEIVER XENVIF_RECEIVER, *PXENVIF_RECEIVER;

extern NTSTATUS
ReceiverInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_RECEIVER    *Receiver
    );

extern NTSTATUS
ReceiverConnect(
    IN  PXENVIF_RECEIVER    Receiver
    );

extern NTSTATUS
ReceiverStoreWrite(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    );

extern NTSTATUS
ReceiverEnable(
    IN  PXENVIF_RECEIVER    Receiver
    );

extern VOID
ReceiverDisable(
    IN  PXENVIF_RECEIVER    Receiver
    );

extern VOID
ReceiverDisconnect(
    IN  PXENVIF_RECEIVER    Receiver
    );

extern VOID
ReceiverTeardown(
    IN  PXENVIF_RECEIVER    Receiver
    );

extern VOID
ReceiverWaitForPackets(
    IN  PXENVIF_RECEIVER    Receiver
    );

extern VOID
ReceiverQueryRingSize(
    IN  PXENVIF_RECEIVER    Receiver,
    OUT PULONG              Size
    );

extern VOID
ReceiverSetOffloadOptions(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  Options
    );

extern VOID
ReceiverSetBackfillSize(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Size
    );

extern VOID
ReceiverReturnPacket(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  PVOID               Cookie
    );

extern VOID
ReceiverTrigger(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Index
    );

extern VOID
ReceiverSend(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Index
    );

NTSTATUS
ReceiverSetHashAlgorithm(
    IN  PXENVIF_RECEIVER                Receiver,
    IN  XENVIF_PACKET_HASH_ALGORITHM    Algorithm
    );

NTSTATUS
ReceiverQueryHashCapabilities(
    IN  PXENVIF_RECEIVER    Receiver,
    OUT PULONG              Types
    );

NTSTATUS
ReceiverUpdateHashParameters(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Types,
    IN  PUCHAR              Key
    );

NTSTATUS
ReceiverUpdateHashMapping(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  PPROCESSOR_NUMBER   ProcessorMapping,
    IN  ULONG               Order
    );

#endif  // _XENVIF_RECEIVER_H
