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

#ifndef _XENBUS_FDO_H
#define _XENBUS_FDO_H

#include <ntddk.h>

#include "driver.h"
#include "types.h"

typedef struct _XENBUS_INTERRUPT XENBUS_INTERRUPT, *PXENBUS_INTERRUPT;

extern NTSTATUS
FdoCreate(
    IN  PDEVICE_OBJECT  PhysicalDeviceObject
    );

extern VOID
FdoDestroy(
    IN  PXENBUS_FDO Fdo
    );

extern NTSTATUS
FdoDelegateIrp(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    );

extern VOID
FdoAddPhysicalDeviceObject(
    IN  PXENBUS_FDO Fdo,
    IN  PXENBUS_PDO Pdo
    );

extern VOID
FdoRemovePhysicalDeviceObject(
    IN  PXENBUS_FDO Fdo,
    IN  PXENBUS_PDO Pdo
    );

extern VOID
FdoAcquireMutex(
    IN  PXENBUS_FDO Fdo
    );

extern VOID
FdoReleaseMutex(
    IN  PXENBUS_FDO Fdo
    );

extern PDEVICE_OBJECT
FdoGetDeviceObject(
    IN  PXENBUS_FDO Fdo
    );

extern PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    IN  PXENBUS_FDO Fdo
    );

extern PDMA_ADAPTER
FdoGetDmaAdapter(
    IN  PXENBUS_FDO         Fdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    );

extern BOOLEAN
FdoTranslateBusAddress(
    IN      PXENBUS_FDO         Fdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    );

extern ULONG
FdoSetBusData(
    IN  PXENBUS_FDO     Fdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    );

extern ULONG
FdoGetBusData(
    IN  PXENBUS_FDO     Fdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    );

extern PCHAR
FdoGetVendorName(
    IN  PXENBUS_FDO Fdo
    );

extern PCHAR
FdoGetName(
    IN  PXENBUS_FDO Fdo
    );

extern NTSTATUS
FdoAllocateHole(
    IN  PXENBUS_FDO         Fdo,
    IN  ULONG               Count,
    OUT PVOID               *VirtualAddress OPTIONAL,
    OUT PPHYSICAL_ADDRESS   PhysicalAddress
    );

extern VOID
FdoFreeHole(
    IN  PXENBUS_FDO         Fdo,
    IN  PHYSICAL_ADDRESS    PhysicalAddress,
    IN  ULONG               Count
    );

// Disable erroneous SAL warnings around use of interrupt locks
#pragma warning(disable:28230)
#pragma warning(disable:28285)

extern
_IRQL_requires_max_(HIGH_LEVEL)
_IRQL_saves_
_IRQL_raises_(HIGH_LEVEL)
KIRQL
FdoAcquireInterruptLock(
    IN  PXENBUS_FDO         Fdo,
    IN  PXENBUS_INTERRUPT   Interrupt
    );

extern
_IRQL_requires_(HIGH_LEVEL)
VOID
FdoReleaseInterruptLock(
    IN  PXENBUS_FDO                 Fdo,
    IN  PXENBUS_INTERRUPT           Interrupt,
    IN  __drv_restoresIRQL KIRQL    Irql
    );

extern PXENBUS_INTERRUPT
FdoAllocateInterrupt(
    IN  PXENBUS_FDO         Fdo,
    IN  KINTERRUPT_MODE     InterruptMode,
    IN  USHORT              Group,
    IN  UCHAR               Number,
    IN  KSERVICE_ROUTINE    Callback,
    IN  PVOID               Argument OPTIONAL
    );

extern UCHAR
FdoGetInterruptVector(
    IN  PXENBUS_FDO         Fdo,
    IN  PXENBUS_INTERRUPT   Interrupt
    );

extern ULONG
FdoGetInterruptLine(
    IN  PXENBUS_FDO         Fdo,
    IN  PXENBUS_INTERRUPT   Interrupt
    );

extern VOID
FdoFreeInterrupt(
    IN  PXENBUS_FDO         Fdo,
    IN  PXENBUS_INTERRUPT   Interrupt
    );

#include "suspend.h"

extern PXENBUS_SUSPEND_CONTEXT
FdoGetSuspendContext(
    IN  PXENBUS_FDO Fdo
    );

#include "shared_info.h"

extern PXENBUS_SHARED_INFO_CONTEXT
FdoGetSharedInfoContext(
    IN  PXENBUS_FDO Fdo
    );

#include "evtchn.h"

extern PXENBUS_EVTCHN_CONTEXT
FdoGetEvtchnContext(
    IN  PXENBUS_FDO Fdo
    );

#include "debug.h"

extern PXENBUS_DEBUG_CONTEXT
FdoGetDebugContext(
    IN  PXENBUS_FDO Fdo
    );

#include "store.h"

extern PXENBUS_STORE_CONTEXT
FdoGetStoreContext(
    IN  PXENBUS_FDO Fdo
    );

#include "range_set.h"

extern PXENBUS_RANGE_SET_CONTEXT
FdoGetRangeSetContext(
    IN  PXENBUS_FDO Fdo
    );

#include "cache.h"

extern PXENBUS_CACHE_CONTEXT
FdoGetCacheContext(
    IN  PXENBUS_FDO Fdo
    );

#include "gnttab.h"

extern PXENBUS_GNTTAB_CONTEXT
FdoGetGnttabContext(
    IN  PXENBUS_FDO Fdo
    );

#include "unplug.h"

extern PXENBUS_UNPLUG_CONTEXT
FdoGetUnplugContext(
    IN  PXENBUS_FDO Fdo
    );

#include "console.h"

extern PXENBUS_CONSOLE_CONTEXT
FdoGetConsoleContext(
    IN  PXENBUS_FDO Fdo
    );

extern NTSTATUS
FdoDispatch(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    );

#endif  // _XENBUS_FDO_H
