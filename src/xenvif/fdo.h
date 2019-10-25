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

#ifndef _XENVIF_FDO_H
#define _XENVIF_FDO_H

#include <ntddk.h>
#include <debug_interface.h>
#include <suspend_interface.h>
#include <evtchn_interface.h>
#include <store_interface.h>
#include <range_set_interface.h>
#include <cache_interface.h>
#include <gnttab_interface.h>
#include <unplug_interface.h>

#include "driver.h"
#include "types.h"

extern PCHAR
FdoGetVendorName(
    IN  PXENVIF_FDO Fdo
    );

extern PCHAR
FdoGetName(
    IN  PXENVIF_FDO Fdo
    );

extern NTSTATUS
FdoAddPhysicalDeviceObject(
    IN  PXENVIF_FDO     Fdo,
    IN  PXENVIF_PDO     Pdo
    );

extern VOID
FdoRemovePhysicalDeviceObject(
    IN  PXENVIF_FDO     Fdo,
    IN  PXENVIF_PDO     Pdo
    );

extern VOID
FdoAcquireMutex(
    IN  PXENVIF_FDO     Fdo
    );

extern VOID
FdoReleaseMutex(
    IN  PXENVIF_FDO     Fdo
    );

extern PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    IN  PXENVIF_FDO Fdo
    );

extern PDMA_ADAPTER
FdoGetDmaAdapter(
    IN  PXENVIF_FDO         Fdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    );

extern BOOLEAN
FdoTranslateBusAddress(
    IN      PXENVIF_FDO         Fdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    );

extern ULONG
FdoSetBusData(
    IN  PXENVIF_FDO     Fdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    );

extern ULONG
FdoGetBusData(
    IN  PXENVIF_FDO     Fdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    );

extern NTSTATUS
FdoDelegateIrp(
    IN  PXENVIF_FDO    Fdo,
    IN  PIRP            Irp
    );

extern NTSTATUS
FdoDispatch(
    IN  PXENVIF_FDO    Fdo,
    IN  PIRP            Irp
    );

#define DECLARE_FDO_GET_INTERFACE(_Interface, _Type)    \
extern VOID                                             \
FdoGet ## _Interface ## Interface(                      \
    IN  PXENVIF_FDO Fdo,                                \
    OUT _Type       _Interface ## Interface             \
    );

DECLARE_FDO_GET_INTERFACE(Debug, PXENBUS_DEBUG_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Suspend, PXENBUS_SUSPEND_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Evtchn, PXENBUS_EVTCHN_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Store, PXENBUS_STORE_INTERFACE)
DECLARE_FDO_GET_INTERFACE(RangeSet, PXENBUS_RANGE_SET_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Cache, PXENBUS_CACHE_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Gnttab, PXENBUS_GNTTAB_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Unplug, PXENBUS_UNPLUG_INTERFACE)

extern NTSTATUS
FdoCreate(
    IN  PDEVICE_OBJECT  PhysicalDeviceObject
    );

extern VOID
FdoDestroy(
    IN  PXENVIF_FDO    Fdo
    );

#endif  // _XENVIF_FDO_H
