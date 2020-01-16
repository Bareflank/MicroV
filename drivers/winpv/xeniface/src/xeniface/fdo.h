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

#ifndef _XENIFACE_FDO_H
#define _XENIFACE_FDO_H

#include <ntifs.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <suspend_interface.h>
#include <shared_info_interface.h>

#include "driver.h"
#include "types.h"

#include "thread.h"
#include "mutex.h"

typedef enum _FDO_RESOURCE_TYPE {
    MEMORY_RESOURCE = 0,
    INTERRUPT_RESOURCE,
    RESOURCE_COUNT
} FDO_RESOURCE_TYPE, *PFDO_RESOURCE_TYPE;

typedef struct _FDO_RESOURCE {
    CM_PARTIAL_RESOURCE_DESCRIPTOR Raw;
    CM_PARTIAL_RESOURCE_DESCRIPTOR Translated;
} FDO_RESOURCE, *PFDO_RESOURCE;


typedef struct _XENIFACE_FDO {
    struct _XENIFACE_DX             *Dx;
    PDEVICE_OBJECT                  LowerDeviceObject;
    PDEVICE_OBJECT                  PhysicalDeviceObject;
    DEVICE_CAPABILITIES             LowerDeviceCapabilities;
    ULONG                           Usage[DeviceUsageTypeDumpFile + 1];
    BOOLEAN                         NotDisableable;

    PXENIFACE_THREAD                SystemPowerThread;
    PIRP                            SystemPowerIrp;
    PXENIFACE_THREAD                DevicePowerThread;
    PIRP                            DevicePowerIrp;

    XENIFACE_MUTEX                  Mutex;
    ULONG                           References;

    FDO_RESOURCE                    Resource[RESOURCE_COUNT];

    XENBUS_STORE_INTERFACE          StoreInterface;
    XENBUS_SUSPEND_INTERFACE        SuspendInterface;
    XENBUS_SHARED_INFO_INTERFACE    SharedInfoInterface;
    XENBUS_EVTCHN_INTERFACE         EvtchnInterface;
    XENBUS_GNTTAB_INTERFACE         GnttabInterface;
    PXENBUS_SUSPEND_CALLBACK        SuspendCallbackLate;

    BOOLEAN                         InterfacesAcquired;

    KSPIN_LOCK                      StoreWatchLock;
    LIST_ENTRY                      StoreWatchList;

    KSPIN_LOCK                      EvtchnLock;
    LIST_ENTRY                      EvtchnList;

    KSPIN_LOCK                      SuspendLock;
    LIST_ENTRY                      SuspendList;

    KSPIN_LOCK                      GnttabCacheLock;

    IO_CSQ                          IrpQueue;
    KSPIN_LOCK                      IrpQueueLock;
    LIST_ENTRY                      IrpList;

    PXENBUS_GNTTAB_CACHE            GnttabCache;

    #define MAX_SESSIONS    (65536)

    int                             WmiReady;

    USHORT                          Sessions;
    XENIFACE_MUTEX                  SessionLock;
    LIST_ENTRY                      SessionHead;

    PXENIFACE_THREAD                registryThread;
    KEVENT                          registryWriteEvent;

    UNICODE_STRING                  SuggestedInstanceName;

    UNICODE_STRING                  InterfaceName;

} XENIFACE_FDO, *PXENIFACE_FDO;


extern PCHAR
FdoGetName(
    IN  PXENIFACE_FDO Fdo
    );

extern NTSTATUS
FdoCreate(
    IN  PDEVICE_OBJECT  PhysicalDeviceObject
    );

extern VOID
FdoDestroy(
    IN  PXENIFACE_FDO    Fdo
    );

extern VOID
FdoAcquireMutex(
    IN  PXENIFACE_FDO     Fdo
    );

extern VOID
FdoReleaseMutex(
    IN  PXENIFACE_FDO     Fdo
    );

extern PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    IN  PXENIFACE_FDO Fdo
    );

extern VOID
FdoReap(
    IN  PXENIFACE_FDO Fdo
    );

extern NTSTATUS
FdoDelegateIrp(
    IN  PXENIFACE_FDO    Fdo,
    IN  PIRP            Irp
    );


extern PXENBUS_STORE_INTERFACE
FdoGetStoreInterface(
    IN  PXENIFACE_FDO     Fdo
    );


extern PXENBUS_SUSPEND_INTERFACE
FdoGetSuspendInterface(
    IN  PXENIFACE_FDO     Fdo
    );


extern NTSTATUS
FdoDispatch(
    IN  PXENIFACE_FDO    Fdo,
    IN  PIRP            Irp
    );

#endif  // _XENIFACE_FDO_H
