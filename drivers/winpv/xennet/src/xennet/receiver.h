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

#ifndef _XENNET_RECEIVER_H_
#define _XENNET_RECEIVER_H_

#include <ndis.h>

typedef struct _XENNET_RECEIVER XENNET_RECEIVER, *PXENNET_RECEIVER;

#include "adapter.h"
extern NDIS_STATUS
ReceiverInitialize(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PXENNET_RECEIVER    *Receiver
    );

extern VOID
ReceiverTeardown(
    IN  PXENNET_RECEIVER    Receiver
    );

extern VOID
ReceiverReturnNetBufferLists(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  ULONG               ReturnFlags
    );

extern VOID
ReceiverQueuePacket(
    IN  PXENNET_RECEIVER                Receiver,
    IN  ULONG                           Index,
    IN  PMDL                            Mdl,
    IN  ULONG                           Offset,
    IN  ULONG                           Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS    Flags,
    IN  USHORT                          MaximumSegmentSize,
    IN  USHORT                          TagControlInformation,
    IN  PXENVIF_PACKET_INFO             Info,
    IN  PXENVIF_PACKET_HASH             Hash,
    IN  BOOLEAN                         More,
    IN  PVOID                           Cookie
    );

extern PXENVIF_VIF_OFFLOAD_OPTIONS
ReceiverOffloadOptions(
    IN  PXENNET_RECEIVER    Receiver
    );

extern VOID
ReceiverEnable(
    IN  PXENNET_RECEIVER    Receiver
    );

extern VOID
ReceiverDisable(
    IN  PXENNET_RECEIVER    Receiver
    );

#endif // _XENNET_RECEIVER_H_
