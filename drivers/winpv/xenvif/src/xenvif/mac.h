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

#ifndef _XENVIF_MAC_H
#define _XENVIF_MAC_H

#include <ntddk.h>
#include <ethernet.h>
#include <vif_interface.h>

#include "frontend.h"

typedef struct _XENVIF_MAC XENVIF_MAC, *PXENVIF_MAC;

extern NTSTATUS
MacInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_MAC         *Mac
    );

extern NTSTATUS
MacConnect(
    IN  PXENVIF_MAC Mac
    );

extern NTSTATUS
MacEnable(
    IN  PXENVIF_MAC Mac
    );

extern VOID
MacDisable(
    IN  PXENVIF_MAC Mac
    );

extern VOID
MacDisconnect(
    IN  PXENVIF_MAC Mac
    );

extern VOID
MacTeardown(
    IN  PXENVIF_MAC Mac
    );

extern VOID
MacQueryMaximumFrameSize(
    IN  PXENVIF_MAC Mac,
    OUT PULONG      Size
    );

extern VOID
MacQueryPermanentAddress(
    IN  PXENVIF_MAC         Mac,
    OUT PETHERNET_ADDRESS   Address                   
    );

extern VOID
MacQueryCurrentAddress(
    IN  PXENVIF_MAC         Mac,
    OUT PETHERNET_ADDRESS   Address                   
    );

extern VOID
MacQueryBroadcastAddress(
    IN  PXENVIF_MAC         Mac,
    OUT PETHERNET_ADDRESS   Address                   
    );

extern NTSTATUS
MacAddMulticastAddress(
    IN      PXENVIF_MAC         Mac,
    OUT     PETHERNET_ADDRESS   Address
    );

extern NTSTATUS
MacRemoveMulticastAddress(
    IN      PXENVIF_MAC         Mac,
    OUT     PETHERNET_ADDRESS   Address
    );

extern NTSTATUS
MacQueryMulticastAddresses(
    IN      PXENVIF_MAC         Mac,
    OUT     PETHERNET_ADDRESS   Address OPTIONAL,
    IN OUT  PULONG              Count
    );

extern NTSTATUS
MacSetFilterLevel(
    IN  PXENVIF_MAC             Mac,
    IN  ETHERNET_ADDRESS_TYPE   Type,
    IN  XENVIF_MAC_FILTER_LEVEL Level
    );

extern NTSTATUS
MacQueryFilterLevel(
    IN  PXENVIF_MAC                 Mac,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    OUT PXENVIF_MAC_FILTER_LEVEL    Level
    );

extern VOID
MacQueryState(
    IN  PXENVIF_MAC                 Mac,
    OUT PNET_IF_MEDIA_CONNECT_STATE MediaConnectState OPTIONAL,
    OUT PULONG64                    LinkSpeed OPTIONAL,
    OUT PNET_IF_MEDIA_DUPLEX_STATE  MediaDuplexState OPTIONAL
    );

extern BOOLEAN
MacApplyFilters(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   DestinationAddress
    );

#endif  // _XENVIF_MAC_H
