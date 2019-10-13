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

#ifndef _XENBUS_PDO_H
#define _XENBUS_PDO_H

#include <ntddk.h>

#include "driver.h"
#include "types.h"

extern VOID
PdoSetDevicePnpState(
    IN  PXENBUS_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    );

extern DEVICE_PNP_STATE
PdoGetDevicePnpState(
    IN  PXENBUS_PDO Pdo
    );

extern BOOLEAN
PdoIsMissing(
    IN  PXENBUS_PDO Pdo
    );

extern VOID
PdoSetMissing(
    IN  PXENBUS_PDO Pdo,
    IN  const CHAR  *Reason
    );

extern PCHAR
PdoGetName(
    IN  PXENBUS_PDO Pdo
    );

extern PDEVICE_OBJECT
PdoGetDeviceObject(
    IN  PXENBUS_PDO Pdo
    );

extern PXENBUS_FDO
PdoGetFdo(
    IN  PXENBUS_PDO Pdo
    );

extern PDMA_ADAPTER
PdoGetDmaAdapter(
    IN  PXENBUS_PDO         Pdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    );

extern BOOLEAN
PdoTranslateBusAddress(
    IN      PXENBUS_PDO         Pdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    );

extern ULONG
PdoSetBusData(
    IN  PXENBUS_PDO Pdo,
    IN  ULONG       DataType,
    IN  PVOID       Buffer,
    IN  ULONG       Offset,
    IN  ULONG       Length
    );

extern ULONG
PdoGetBusData(
    IN  PXENBUS_PDO Pdo,
    IN  ULONG       DataType,
    IN  PVOID       Buffer,
    IN  ULONG       Offset,
    IN  ULONG       Length
    );

extern NTSTATUS
PdoCreate(
    IN  PXENBUS_FDO     Fdo,
    IN  PANSI_STRING    Name
    );

extern VOID
PdoResume(
    IN  PXENBUS_PDO Pdo
    );

extern VOID
PdoSuspend(
    IN  PXENBUS_PDO Pdo
    );

extern VOID
PdoDestroy(
    IN  PXENBUS_PDO Pdo
    );

extern NTSTATUS
PdoDispatch(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    );

#endif  // _XENBUS_PDO_H
