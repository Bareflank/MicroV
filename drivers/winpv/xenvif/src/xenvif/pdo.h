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

#ifndef _XENVIF_PDO_H
#define _XENVIF_PDO_H

#include <ntddk.h>
#include <ifdef.h>
#include <ethernet.h>

#include "driver.h"
#include "types.h"

extern VOID
PdoSetDevicePnpState(
    IN  PXENVIF_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    );

extern DEVICE_PNP_STATE
PdoGetDevicePnpState(
    IN  PXENVIF_PDO Pdo
    );

extern VOID
PdoSetMissing(
    IN  PXENVIF_PDO Pdo,
    IN  const CHAR  *Reason
    );

extern BOOLEAN
PdoIsMissing(
    IN  PXENVIF_PDO Pdo
    );

extern VOID
PdoRequestEject(
    IN  PXENVIF_PDO Pdo
    );

extern BOOLEAN
PdoIsEjectRequested(
    IN  PXENVIF_PDO Pdo
    );

extern PCHAR
PdoGetName(
    IN  PXENVIF_PDO Pdo
    );

extern PXENVIF_FDO
PdoGetFdo(
    IN  PXENVIF_PDO Pdo
    );

extern PDEVICE_OBJECT
PdoGetDeviceObject(
    IN  PXENVIF_PDO Pdo
    );

#include "vif.h"

extern PXENVIF_VIF_CONTEXT
PdoGetVifContext(
    IN  PXENVIF_PDO Pdo
    );

extern PDMA_ADAPTER
PdoGetDmaAdapter(
    IN  PXENVIF_PDO         Pdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    );

extern BOOLEAN
PdoTranslateBusAddress(
    IN      PXENVIF_PDO         Pdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    );

extern ULONG
PdoSetBusData(
    IN  PXENVIF_PDO     Pdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    );

extern ULONG
PdoGetBusData(
    IN  PXENVIF_PDO     Pdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    );

extern PETHERNET_ADDRESS
PdoGetPermanentAddress(
    IN  PXENVIF_PDO Pdo
    );

extern PETHERNET_ADDRESS
PdoGetCurrentAddress(
    IN  PXENVIF_PDO Pdo
    );

extern NTSTATUS
PdoCreate(
    IN  PXENVIF_FDO Fdo,
    IN  ULONG       Number,
    IN  PCHAR       Address
    );

extern NTSTATUS
PdoResume(
    IN  PXENVIF_PDO Pdo
    );

extern VOID
PdoSuspend(
    IN  PXENVIF_PDO Pdo
    );

extern VOID
PdoDestroy(
    IN  PXENVIF_PDO Pdo
    );

#include "frontend.h"

extern PXENVIF_FRONTEND
PdoGetFrontend(
    IN  PXENVIF_PDO Pdo
    );

extern PXENBUS_EVTCHN_INTERFACE
PdoGetEvtchnInterface(
    IN  PXENVIF_PDO     Pdo
    );

extern PXENBUS_DEBUG_INTERFACE
PdoGetDebugInterface(
    IN  PXENVIF_PDO     Pdo
    );

extern PXENBUS_STORE_INTERFACE
PdoGetStoreInterface(
    IN  PXENVIF_PDO     Pdo
    );

extern PXENBUS_CACHE_INTERFACE
PdoGetCacheInterface(
    IN  PXENVIF_PDO     Pdo
    );

extern PXENBUS_GNTTAB_INTERFACE
PdoGetGnttabInterface(
    IN  PXENVIF_PDO     Pdo
    );

extern PXENBUS_SUSPEND_INTERFACE
PdoGetSuspendInterface(
    IN  PXENVIF_PDO     Pdo
    );

#include "vif.h"

extern PXENVIF_VIF_INTERFACE
PdoGetVifInterface(
    IN  PXENVIF_PDO Pdo
    );

extern NTSTATUS
PdoDispatch(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    );

#endif  // _XENVIF_PDO_H
