/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source 1and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the23 
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

#define INITGUID 1

#include <ntddk.h>
#include <procgrp.h>
#include <wdmguid.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <xen.h>

#include <version.h>

#include "names.h"
#include "registry.h"
#include "fdo.h"
#include "pdo.h"
#include "thread.h"
#include "high.h"
#include "mutex.h"
#include "shared_info.h"
#include "evtchn.h"
#include "debug.h"
#include "store.h"
#include "console.h"
#include "cache.h"
#include "gnttab.h"
#include "suspend.h"
#include "sync.h"
#include "balloon.h"
#include "driver.h"
#include "range_set.h"
#include "unplug.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define XENBUS_FDO_TAG 'ODF'

#define MAXNAMELEN  128

struct _XENBUS_INTERRUPT {
    PXENBUS_FDO         Fdo;
    LIST_ENTRY          ListEntry;
    KINTERRUPT_MODE     InterruptMode;
    PKINTERRUPT         InterruptObject;
    PROCESSOR_NUMBER    ProcNumber;
    UCHAR               Vector;
    ULONG               Line;
    PKSERVICE_ROUTINE   Callback;
    PVOID               Argument;
};

struct _XENBUS_FDO {
    PXENBUS_DX                      Dx;
    PDEVICE_OBJECT                  LowerDeviceObject;
    PDEVICE_OBJECT                  PhysicalDeviceObject;
    DEVICE_CAPABILITIES             LowerDeviceCapabilities;
    PBUS_INTERFACE_STANDARD         LowerBusInterface;
    ULONG                           Usage[DeviceUsageTypeDumpFile + 1];
    BOOLEAN                         NotDisableable;

    PXENBUS_THREAD                  SystemPowerThread;
    PIRP                            SystemPowerIrp;
    PXENBUS_THREAD                  DevicePowerThread;
    PIRP                            DevicePowerIrp;

    CHAR                            VendorName[MAXNAMELEN];

    MUTEX                           Mutex;
    LIST_ENTRY                      List;
    ULONG                           References;

    PXENBUS_THREAD                  ScanThread;
    KEVENT                          ScanEvent;
    PXENBUS_STORE_WATCH             ScanWatch;

    PXENBUS_THREAD                  SuspendThread;
    KEVENT                          SuspendEvent;
    PXENBUS_STORE_WATCH             SuspendWatch;

    PXENBUS_THREAD                  BalloonThread;
    KEVENT                          BalloonEvent;
    PXENBUS_STORE_WATCH             BalloonWatch;
    MUTEX                           BalloonSuspendMutex;

    PCM_PARTIAL_RESOURCE_LIST       RawResourceList;
    PCM_PARTIAL_RESOURCE_LIST       TranslatedResourceList;

    BOOLEAN                         Active;

    PXENBUS_SUSPEND_CONTEXT         SuspendContext;
    PXENBUS_SHARED_INFO_CONTEXT     SharedInfoContext;
    PXENBUS_EVTCHN_CONTEXT          EvtchnContext;
    PXENBUS_DEBUG_CONTEXT           DebugContext;
    PXENBUS_STORE_CONTEXT           StoreContext;
    PXENBUS_CONSOLE_CONTEXT         ConsoleContext;
    PXENBUS_RANGE_SET_CONTEXT       RangeSetContext;
    PXENBUS_CACHE_CONTEXT           CacheContext;
    PXENBUS_GNTTAB_CONTEXT          GnttabContext;
    PXENBUS_UNPLUG_CONTEXT          UnplugContext;
    PXENBUS_BALLOON_CONTEXT         BalloonContext;

    XENBUS_DEBUG_INTERFACE          DebugInterface;
    XENBUS_SUSPEND_INTERFACE        SuspendInterface;
    XENBUS_EVTCHN_INTERFACE         EvtchnInterface;
    XENBUS_STORE_INTERFACE          StoreInterface;
    XENBUS_CONSOLE_INTERFACE        ConsoleInterface;
    XENBUS_RANGE_SET_INTERFACE      RangeSetInterface;
    XENBUS_BALLOON_INTERFACE        BalloonInterface;

    PUCHAR                          Buffer;
    PMDL                            Mdl;
    PXENBUS_RANGE_SET               RangeSet;
    LIST_ENTRY                      InterruptList;

    PXENBUS_EVTCHN_CHANNEL          Channel;
    PXENBUS_SUSPEND_CALLBACK        SuspendCallbackLate;
    PLOG_DISPOSITION                LogDisposition;
};

static FORCEINLINE PVOID
__FdoAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_FDO_TAG);
}

static FORCEINLINE VOID
__FdoFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_FDO_TAG);
}

static FORCEINLINE VOID
__FdoSetDevicePnpState(
    IN  PXENBUS_FDO         Fdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENBUS_DX              Dx = Fdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

static FORCEINLINE VOID
__FdoRestoreDevicePnpState(
    IN  PXENBUS_FDO         Fdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENBUS_DX              Dx = Fdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__FdoGetDevicePnpState(
    IN  PXENBUS_FDO Fdo
    )
{
    PXENBUS_DX      Dx = Fdo->Dx;

    return Dx->DevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__FdoGetPreviousDevicePnpState(
    IN  PXENBUS_FDO Fdo
    )
{
    PXENBUS_DX      Dx = Fdo->Dx;

    return Dx->PreviousDevicePnpState;
}

static FORCEINLINE VOID
__FdoSetDevicePowerState(
    IN  PXENBUS_FDO         Fdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXENBUS_DX              Dx = Fdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__FdoGetDevicePowerState(
    IN  PXENBUS_FDO Fdo
    )
{
    PXENBUS_DX      Dx = Fdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__FdoSetSystemPowerState(
    IN  PXENBUS_FDO         Fdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXENBUS_DX              Dx = Fdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__FdoGetSystemPowerState(
    IN  PXENBUS_FDO Fdo
    )
{
    PXENBUS_DX      Dx = Fdo->Dx;

    return Dx->SystemPowerState;
}

static FORCEINLINE PDEVICE_OBJECT
__FdoGetDeviceObject(
    IN  PXENBUS_FDO Fdo
    )
{
    PXENBUS_DX      Dx = Fdo->Dx;

    return Dx->DeviceObject;
}

PDEVICE_OBJECT
FdoGetDeviceObject(
    IN  PXENBUS_FDO Fdo
    )
{
    return __FdoGetDeviceObject(Fdo);
}

static FORCEINLINE PDEVICE_OBJECT
__FdoGetPhysicalDeviceObject(
    IN  PXENBUS_FDO Fdo
    )
{
    return Fdo->PhysicalDeviceObject;
}

PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    IN  PXENBUS_FDO Fdo
    )
{
    return __FdoGetPhysicalDeviceObject(Fdo);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
FdoAcquireLowerBusInterface(
    IN  PXENBUS_FDO         Fdo
    )
{
    PBUS_INTERFACE_STANDARD BusInterface;
    KEVENT                  Event;
    IO_STATUS_BLOCK         StatusBlock;
    PIRP                    Irp;
    PIO_STACK_LOCATION      StackLocation;
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    BusInterface = __FdoAllocate(sizeof (BUS_INTERFACE_STANDARD));

    status = STATUS_NO_MEMORY;
    if (BusInterface == NULL)
        goto fail1;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail2;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = &GUID_BUS_INTERFACE_STANDARD;
    StackLocation->Parameters.QueryInterface.Size = sizeof (BUS_INTERFACE_STANDARD);
    StackLocation->Parameters.QueryInterface.Version = 1;
    StackLocation->Parameters.QueryInterface.Interface = (PINTERFACE)BusInterface;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_INVALID_PARAMETER;
    if (BusInterface->Version != 1)
        goto fail4;

    Fdo->LowerBusInterface = BusInterface;

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    __FdoFree(BusInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
FdoReleaseLowerBusInterface(
    IN  PXENBUS_FDO         Fdo
    )
{
    PBUS_INTERFACE_STANDARD BusInterface;

    BusInterface = Fdo->LowerBusInterface;

    if (BusInterface == NULL)
        return;

    Fdo->LowerBusInterface = NULL;

    BusInterface->InterfaceDereference(BusInterface->Context);

    __FdoFree(BusInterface);
}

PDMA_ADAPTER
FdoGetDmaAdapter(
    IN  PXENBUS_FDO         Fdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    )
{
    PBUS_INTERFACE_STANDARD BusInterface;

    BusInterface = Fdo->LowerBusInterface;
    ASSERT(BusInterface != NULL);

    return BusInterface->GetDmaAdapter(BusInterface->Context,
                                       DeviceDescriptor,
                                       NumberOfMapRegisters);
}

BOOLEAN
FdoTranslateBusAddress(
    IN      PXENBUS_FDO         Fdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    )
{
    PBUS_INTERFACE_STANDARD     BusInterface;

    BusInterface = Fdo->LowerBusInterface;
    ASSERT(BusInterface != NULL);

    return BusInterface->TranslateBusAddress(BusInterface->Context,
                                             BusAddress,
                                             Length,
                                             AddressSpace,
                                             TranslatedAddress);
}

ULONG
FdoSetBusData(
    IN  PXENBUS_FDO         Fdo,
    IN  ULONG               DataType,
    IN  PVOID               Buffer,
    IN  ULONG               Offset,
    IN  ULONG               Length
    )
{
    PBUS_INTERFACE_STANDARD BusInterface;

    BusInterface = Fdo->LowerBusInterface;
    ASSERT(BusInterface != NULL);

    return BusInterface->SetBusData(BusInterface->Context,
                                    DataType,
                                    Buffer,
                                    Offset,
                                    Length);
}

ULONG
FdoGetBusData(
    IN  PXENBUS_FDO         Fdo,
    IN  ULONG               DataType,
    IN  PVOID               Buffer,
    IN  ULONG               Offset,
    IN  ULONG               Length
    )
{
    PBUS_INTERFACE_STANDARD BusInterface;

    BusInterface = Fdo->LowerBusInterface;
    ASSERT(BusInterface != NULL);

    return BusInterface->GetBusData(BusInterface->Context,
                                    DataType,
                                    Buffer,
                                    Offset,
                                    Length);
}

static FORCEINLINE NTSTATUS
__FdoSetVendorName(
    IN  PXENBUS_FDO Fdo,
    IN  USHORT      VendorID,
    IN  USHORT      DeviceID
    )
{
    NTSTATUS        status;

    status = STATUS_NOT_SUPPORTED;
    if (VendorID != 'XS')
        goto fail1;

    status = RtlStringCbPrintfA(Fdo->VendorName,
                                MAXNAMELEN,
                                "%s%04X",
                                VENDOR_PREFIX_STR,
                                DeviceID);
    ASSERT(NT_SUCCESS(status));

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE PCHAR
__FdoGetVendorName(
    IN  PXENBUS_FDO Fdo
    )
{
    return Fdo->VendorName;
}

PCHAR
FdoGetVendorName(
    IN  PXENBUS_FDO Fdo
    )
{
    return __FdoGetVendorName(Fdo);
}

static FORCEINLINE VOID
__FdoSetName(
    IN  PXENBUS_FDO Fdo
    )
{
    PXENBUS_DX      Dx = Fdo->Dx;
    NTSTATUS        status;

    status = RtlStringCbPrintfA(Dx->Name,
                                MAXNAMELEN,
                                "%s XENBUS",
                                __FdoGetVendorName(Fdo));
    ASSERT(NT_SUCCESS(status));
}

static FORCEINLINE PCHAR
__FdoGetName(
    IN  PXENBUS_FDO Fdo
    )
{
    PXENBUS_DX      Dx = Fdo->Dx;

    return Dx->Name;
}

PCHAR
FdoGetName(
    IN  PXENBUS_FDO Fdo
    )
{
    return __FdoGetName(Fdo);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
FdoQueryId(
    IN  PXENBUS_FDO         Fdo,
    IN  BUS_QUERY_ID_TYPE   Type,
    OUT PCHAR               *Id
    )
{
    KEVENT                  Event;
    IO_STATUS_BLOCK         StatusBlock;
    PIRP                    Irp;
    PIO_STACK_LOCATION      StackLocation;
    PWCHAR                  Buffer;
    ULONG                   Length;
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_ID;

    StackLocation->Parameters.QueryId.IdType = Type;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    Buffer = (PWCHAR)StatusBlock.Information;
    Length = (ULONG)(wcslen(Buffer) + 1) * sizeof (CHAR);

    *Id = __AllocatePoolWithTag(PagedPool, Length, 'SUB');

    status = STATUS_NO_MEMORY;
    if (*Id == NULL)
        goto fail3;

    status = RtlStringCbPrintfA(*Id, Length, "%ws", Buffer);
    ASSERT(NT_SUCCESS(status));

    ExFreePool(Buffer);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ExFreePool((PVOID)StatusBlock.Information);

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
FdoQueryDeviceText(
    IN  PXENBUS_FDO         Fdo,
    IN  DEVICE_TEXT_TYPE    Type,
    OUT PCHAR               *Text
    )
{
    KEVENT                  Event;
    IO_STATUS_BLOCK         StatusBlock;
    PIRP                    Irp;
    PIO_STACK_LOCATION      StackLocation;
    PWCHAR                  Buffer;
    ULONG                   Length;
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_DEVICE_TEXT;

    StackLocation->Parameters.QueryDeviceText.DeviceTextType = Type;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    Buffer = (PWCHAR)StatusBlock.Information;
    Length = (ULONG)(wcslen(Buffer) + 1) * sizeof (CHAR);

    *Text = __AllocatePoolWithTag(PagedPool, Length, 'SUB');

    status = STATUS_NO_MEMORY;
    if (*Text == NULL)
        goto fail3;

    status = RtlStringCbPrintfA(*Text, Length, "%ws", Buffer);
    ASSERT(NT_SUCCESS(status));

    ExFreePool(Buffer);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ExFreePool((PVOID)StatusBlock.Information);

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
FdoSetActive(
    IN  PXENBUS_FDO Fdo
    )
{
    PCHAR           DeviceID;
    PCHAR           InstanceID;
    PCHAR           ActiveDeviceID;
    PCHAR           LocationInformation;
    NTSTATUS        status;

    status = FdoQueryId(Fdo,
                        BusQueryDeviceID,
                        &DeviceID);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = FdoQueryId(Fdo,
                        BusQueryInstanceID,
                        &InstanceID);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = FdoQueryDeviceText(Fdo,
                                DeviceTextLocationInformation,
                                &LocationInformation);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = DriverGetActive("DeviceID", &ActiveDeviceID);
    if (NT_SUCCESS(status)) {
        Fdo->Active = (_stricmp(DeviceID, ActiveDeviceID) == 0) ? TRUE : FALSE;

        if (Fdo->Active)
            (VOID) DriverUpdateActive(DeviceID, InstanceID, LocationInformation);

        ExFreePool(ActiveDeviceID);
    } else {
        status = DriverSetActive(DeviceID, InstanceID, LocationInformation);
        if (NT_SUCCESS(status))
            Fdo->Active = TRUE;
    }

    ExFreePool(LocationInformation);
    ExFreePool(InstanceID);
    ExFreePool(DeviceID);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ExFreePool(InstanceID);

fail2:
    Error("fail2\n");

    ExFreePool(DeviceID);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
FdoClearActive(
    IN  PXENBUS_FDO Fdo
    )
{
    (VOID) DriverClearActive();

    Fdo->Active = FALSE;
}

static FORCEINLINE BOOLEAN
__FdoIsActive(
    IN  PXENBUS_FDO Fdo
    )
{
    return Fdo->Active;
}

static NTSTATUS
FdoSetFriendlyName(
    IN  PXENBUS_FDO Fdo,
    IN  USHORT      DeviceID
    )
{
    HANDLE          SoftwareKey;
    HANDLE          HardwareKey;
    PANSI_STRING    DriverDesc;
    CHAR            Buffer[MAXNAMELEN];
    ANSI_STRING     FriendlyName[2];
    NTSTATUS        status;

    status = RegistryOpenSoftwareKey(__FdoGetPhysicalDeviceObject(Fdo),
                                     KEY_READ,
                                     &SoftwareKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryOpenHardwareKey(__FdoGetPhysicalDeviceObject(Fdo),
                                     KEY_ALL_ACCESS,
                                     &HardwareKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryQuerySzValue(SoftwareKey,
                                  "DriverDesc",
                                  NULL,
                                  &DriverDesc);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RtlStringCbPrintfA(Buffer,
                                MAXNAMELEN,
                                "%Z (%04X)",
                                &DriverDesc[0],
                                DeviceID
                                );
    if (!NT_SUCCESS(status))
        goto fail4;

    RtlZeroMemory(FriendlyName, sizeof (ANSI_STRING) * 2);
    RtlInitAnsiString(&FriendlyName[0], Buffer);

    status = RegistryUpdateSzValue(HardwareKey,
                                   "FriendlyName",
                                   REG_SZ,
                                   FriendlyName);
    if (!NT_SUCCESS(status))
        goto fail5;

    Info("%Z\n", &FriendlyName[0]);

    RegistryFreeSzValue(DriverDesc);

    RegistryCloseKey(HardwareKey);

    RegistryCloseKey(SoftwareKey);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

    RegistryFreeSzValue(DriverDesc);

fail3:
    Error("fail3\n");

    RegistryCloseKey(HardwareKey);

fail2:
    Error("fail2\n");

    RegistryCloseKey(SoftwareKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define DEFINE_FDO_GET_CONTEXT(_Interface, _Type)               \
static FORCEINLINE _Type                                        \
__FdoGet ## _Interface ## Context(                              \
    IN  PXENBUS_FDO Fdo                                         \
    )                                                           \
{                                                               \
    return Fdo-> ## _Interface ## Context;                      \
}                                                               \
                                                                \
_Type                                                           \
FdoGet ## _Interface ## Context(                                \
    IN  PXENBUS_FDO Fdo                                         \
    )                                                           \
{                                                               \
    return __FdoGet ## _Interface ## Context(Fdo);              \
}

DEFINE_FDO_GET_CONTEXT(Suspend, PXENBUS_SUSPEND_CONTEXT)
DEFINE_FDO_GET_CONTEXT(SharedInfo, PXENBUS_SHARED_INFO_CONTEXT)
DEFINE_FDO_GET_CONTEXT(Evtchn, PXENBUS_EVTCHN_CONTEXT)
DEFINE_FDO_GET_CONTEXT(Debug, PXENBUS_DEBUG_CONTEXT)
DEFINE_FDO_GET_CONTEXT(Store, PXENBUS_STORE_CONTEXT)
DEFINE_FDO_GET_CONTEXT(Console, PXENBUS_CONSOLE_CONTEXT)
DEFINE_FDO_GET_CONTEXT(RangeSet, PXENBUS_RANGE_SET_CONTEXT)
DEFINE_FDO_GET_CONTEXT(Cache, PXENBUS_CACHE_CONTEXT)
DEFINE_FDO_GET_CONTEXT(Gnttab, PXENBUS_GNTTAB_CONTEXT)
DEFINE_FDO_GET_CONTEXT(Unplug, PXENBUS_UNPLUG_CONTEXT)
DEFINE_FDO_GET_CONTEXT(Balloon, PXENBUS_BALLOON_CONTEXT)

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoDelegateIrpCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PKEVENT             Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
FdoDelegateIrp(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PDEVICE_OBJECT      DeviceObject;
    PIO_STACK_LOCATION  StackLocation;
    PIRP                SubIrp;
    KEVENT              Event;
    PIO_STACK_LOCATION  SubStackLocation;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    // Find the top of the FDO stack and hold a reference
    DeviceObject = IoGetAttachedDeviceReference(Fdo->Dx->DeviceObject);

    // Get a new IRP for the FDO stack
    SubIrp = IoAllocateIrp(DeviceObject->StackSize, FALSE);

    status = STATUS_NO_MEMORY;
    if (SubIrp == NULL)
        goto done;

    // Copy in the information from the original IRP
    SubStackLocation = IoGetNextIrpStackLocation(SubIrp);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    RtlCopyMemory(SubStackLocation, StackLocation,
                  FIELD_OFFSET(IO_STACK_LOCATION, CompletionRoutine));
    SubStackLocation->Control = 0;

    IoSetCompletionRoutine(SubIrp,
                           FdoDelegateIrpCompletion,
                           &Event,
                           TRUE,
                           TRUE,
                           TRUE);

    // Default completion status
    SubIrp->IoStatus.Status = Irp->IoStatus.Status;

    status = IoCallDriver(DeviceObject, SubIrp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = SubIrp->IoStatus.Status;
    } else {
        ASSERT3U(status, ==, SubIrp->IoStatus.Status);
    }

    IoFreeIrp(SubIrp);

done:
    ObDereferenceObject(DeviceObject);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoForwardIrpSynchronouslyCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PKEVENT             Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
FdoForwardIrpSynchronously(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    )
{
    KEVENT          Event;
    NTSTATUS        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           FdoForwardIrpSynchronouslyCompletion,
                           &Event,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = Irp->IoStatus.Status;
    } else {
        ASSERT3U(status, ==, Irp->IoStatus.Status);
    }

    return status;
}

VOID
FdoAddPhysicalDeviceObject(
    IN  PXENBUS_FDO     Fdo,
    IN  PXENBUS_PDO     Pdo
    )
{
    PDEVICE_OBJECT      DeviceObject;
    PXENBUS_DX          Dx;

    DeviceObject = PdoGetDeviceObject(Pdo);
    Dx = (PXENBUS_DX)DeviceObject->DeviceExtension;
    ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

    InsertTailList(&Fdo->List, &Dx->ListEntry);
    ASSERT3U(Fdo->References, !=, 0);
    Fdo->References++;

    if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0)
        PdoResume(Pdo);
}

VOID
FdoRemovePhysicalDeviceObject(
    IN  PXENBUS_FDO     Fdo,
    IN  PXENBUS_PDO     Pdo
    )
{
    PDEVICE_OBJECT      DeviceObject;
    PXENBUS_DX          Dx;

    DeviceObject = PdoGetDeviceObject(Pdo);
    Dx = (PXENBUS_DX)DeviceObject->DeviceExtension;
    ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

    if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0)
        PdoSuspend(Pdo);

    RemoveEntryList(&Dx->ListEntry);
    ASSERT3U(Fdo->References, !=, 0);
    --Fdo->References;

    if (Fdo->ScanThread)
        ThreadWake(Fdo->ScanThread);
}

static FORCEINLINE VOID
__FdoAcquireMutex(
    IN  PXENBUS_FDO     Fdo
    )
{
    AcquireMutex(&Fdo->Mutex);
}

VOID
FdoAcquireMutex(
    IN  PXENBUS_FDO     Fdo
    )
{
    __FdoAcquireMutex(Fdo);
}

static FORCEINLINE VOID
__FdoReleaseMutex(
    IN  PXENBUS_FDO     Fdo
    )
{
    ReleaseMutex(&Fdo->Mutex);
}

VOID
FdoReleaseMutex(
    IN  PXENBUS_FDO     Fdo
    )
{
    __FdoReleaseMutex(Fdo);

    if (Fdo->References == 0) {
        DriverAcquireMutex();
        FdoDestroy(Fdo);
        DriverReleaseMutex();
    }
}

static BOOLEAN
FdoEnumerate(
    IN  PXENBUS_FDO     Fdo,
    IN  PANSI_STRING    Classes
    )
{
    BOOLEAN             NeedInvalidate;
    HANDLE              ParametersKey;
    ULONG               Enumerate;
    PLIST_ENTRY         ListEntry;
    ULONG               Index;
    NTSTATUS            status;

    Trace("====>\n");

    NeedInvalidate = FALSE;

    ParametersKey = DriverGetParametersKey();

    status = RegistryQueryDwordValue(ParametersKey,
                                     "Enumerate",
                                     &Enumerate);
    if (!NT_SUCCESS(status))
        Enumerate = 1;

    if (Enumerate == 0)
        goto done;

    __FdoAcquireMutex(Fdo);

    ListEntry = Fdo->List.Flink;
    while (ListEntry != &Fdo->List) {
        PLIST_ENTRY     Next = ListEntry->Flink;
        PXENBUS_DX      Dx = CONTAINING_RECORD(ListEntry, XENBUS_DX, ListEntry);
        PXENBUS_PDO     Pdo = Dx->Pdo;

        if (!PdoIsMissing(Pdo) && PdoGetDevicePnpState(Pdo) != Deleted) {
            PCHAR           Name;
            BOOLEAN         Missing;

            Name = PdoGetName(Pdo);
            Missing = TRUE;

            // If the PDO already exists and its name is in the class list
            // then we don't want to remove it.
            for (Index = 0; Classes[Index].Buffer != NULL; Index++) {
                PANSI_STRING Class = &Classes[Index];

                if (Class->Length == 0)
                    continue;

                if (strcmp(Name, Class->Buffer) == 0) {
                    Missing = FALSE;
                    Class->Length = 0;  // avoid duplication
                    break;
                }
            }

            if (Missing) {
                PdoSetMissing(Pdo, "device disappeared");

                // If the PDO has not yet been enumerated then we can
                // go ahead and mark it as deleted, otherwise we need
                // to notify PnP manager and wait for the REMOVE_DEVICE
                // IRP.
                if (PdoGetDevicePnpState(Pdo) == Present) {
                    PdoSetDevicePnpState(Pdo, Deleted);
                    PdoDestroy(Pdo);
                } else {
                    NeedInvalidate = TRUE;
                }
            }
        }

        ListEntry = Next;
    }

    // Walk the class list and create PDOs for any new classes
    for (Index = 0; Classes[Index].Buffer != NULL; Index++) {
        PANSI_STRING Class = &Classes[Index];

        if (Class->Length != 0) {
            status = PdoCreate(Fdo, Class);
            if (NT_SUCCESS(status))
                NeedInvalidate = TRUE;
        }
    }

    __FdoReleaseMutex(Fdo);

done:
    Trace("<====\n");

    return NeedInvalidate;
}

static PANSI_STRING
FdoMultiSzToUpcaseAnsi(
    IN  PCHAR       Buffer
    )
{
    PANSI_STRING    Ansi;
    LONG            Index;
    LONG            Count;
    NTSTATUS        status;

    Index = 0;
    Count = 0;
    for (;;) {
        if (Buffer[Index] == '\0') {
            Count++;
            Index++;

            // Check for double NUL
            if (Buffer[Index] == '\0')
                break;
        } else {
            Buffer[Index] = __toupper(Buffer[Index]);
            Index++;
        }
    }

    Ansi = __FdoAllocate(sizeof (ANSI_STRING) * (Count + 1));

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG   Length;

        Length = (ULONG)strlen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1);
        Ansi[Index].Buffer = __FdoAllocate(Ansi[Index].MaximumLength);

        status = STATUS_NO_MEMORY;
        if (Ansi[Index].Buffer == NULL)
            goto fail2;

        RtlCopyMemory(Ansi[Index].Buffer, Buffer, Length);
        Ansi[Index].Length = (USHORT)Length;

        Buffer += Length + 1;
    }

    return Ansi;

fail2:
    Error("fail2\n");

    while (--Index >= 0)
        __FdoFree(Ansi[Index].Buffer);

    __FdoFree(Ansi);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static VOID
FdoFreeAnsi(
    IN  PANSI_STRING    Ansi
    )
{
    ULONG               Index;

    for (Index = 0; Ansi[Index].Buffer != NULL; Index++)
        __FdoFree(Ansi[Index].Buffer);
        
    __FdoFree(Ansi);
}

static PANSI_STRING
FdoCombineAnsi(
    IN  PANSI_STRING    AnsiA,
    IN  PANSI_STRING    AnsiB
    )
{
    LONG                Count;
    ULONG               Index;
    PANSI_STRING        Ansi;
    NTSTATUS            status;

    Count = 0;

    for (Index = 0;
         AnsiA != NULL && AnsiA[Index].Buffer != NULL; 
         Index++)
        Count++;

    for (Index = 0;
         AnsiB != NULL && AnsiB[Index].Buffer != NULL; 
         Index++)
        Count++;

    Ansi = __FdoAllocate(sizeof (ANSI_STRING) * (Count + 1));

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    Count = 0;

    for (Index = 0;
         AnsiA != NULL && AnsiA[Index].Buffer != NULL; 
         Index++) {
        USHORT  Length;

        Length = AnsiA[Index].MaximumLength;

        Ansi[Count].MaximumLength = Length;
        Ansi[Count].Buffer = __FdoAllocate(Length);

        status = STATUS_NO_MEMORY;
        if (Ansi[Count].Buffer == NULL)
            goto fail2;

        RtlCopyMemory(Ansi[Count].Buffer, AnsiA[Index].Buffer, Length);
        Ansi[Count].Length = AnsiA[Index].Length;

        Count++;
    }

    for (Index = 0;
         AnsiB != NULL && AnsiB[Index].Buffer != NULL; 
         Index++) {
        USHORT  Length;

        Length = AnsiB[Index].MaximumLength;

        Ansi[Count].MaximumLength = Length;
        Ansi[Count].Buffer = __FdoAllocate(Length);

        status = STATUS_NO_MEMORY;
        if (Ansi[Count].Buffer == NULL)
            goto fail3;

        RtlCopyMemory(Ansi[Count].Buffer, AnsiB[Index].Buffer, Length);
        Ansi[Count].Length = AnsiB[Index].Length;

        Count++;
    }

    return Ansi;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    while (--Count >= 0) 
        __FdoFree(Ansi[Count].Buffer);

    __FdoFree(Ansi);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static NTSTATUS
FdoScan(
    IN  PXENBUS_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENBUS_FDO         Fdo = Context;
    PKEVENT             Event;
    HANDLE              ParametersKey;
    NTSTATUS            status;

    Info("====>\n");

    Event = ThreadGetEvent(Self);

    ParametersKey = DriverGetParametersKey();

    for (;;) {
        PCHAR                   Buffer;
        PANSI_STRING            StoreClasses;
        PANSI_STRING            SyntheticClasses;
        PANSI_STRING            SupportedClasses;
        PANSI_STRING            Classes;
        ULONG                   Index;
        BOOLEAN                 NeedInvalidate;

        Trace("waiting...\n");

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        Trace("awake\n");

        if (ThreadIsAlerted(Self))
            break;

        // It is not safe to use interfaces before this point
        if (__FdoGetDevicePnpState(Fdo) != Started)
            goto loop;

        status = XENBUS_STORE(Directory,
                              &Fdo->StoreInterface,
                              NULL,
                              NULL,
                              "device",
                              &Buffer);
        if (NT_SUCCESS(status)) {
            StoreClasses = FdoMultiSzToUpcaseAnsi(Buffer);

            XENBUS_STORE(Free,
                         &Fdo->StoreInterface,
                         Buffer);
        } else {
            StoreClasses = NULL;
        }

        status = RegistryQuerySzValue(ParametersKey,
                                      "SyntheticClasses",
                                      NULL,
                                      &SyntheticClasses);
        if (!NT_SUCCESS(status))
            SyntheticClasses = NULL;

        Classes = FdoCombineAnsi(StoreClasses, SyntheticClasses);

        if (StoreClasses != NULL)
            FdoFreeAnsi(StoreClasses);

        if (SyntheticClasses != NULL)
            RegistryFreeSzValue(SyntheticClasses);

        if (Classes == NULL)
            goto loop;

        if (ParametersKey != NULL) {
            status = RegistryQuerySzValue(ParametersKey,
                                          "SupportedClasses",
                                          NULL,
                                          &SupportedClasses);
            if (!NT_SUCCESS(status))
                SupportedClasses = NULL;
        } else {
            SupportedClasses = NULL;
        }

        // NULL out anything in the Classes list that not in the
        // SupportedClasses list    
        for (Index = 0; Classes[Index].Buffer != NULL; Index++) {
            PANSI_STRING    Class = &Classes[Index];
            ULONG           Entry;
            BOOLEAN         Supported;

            Supported = FALSE;

            for (Entry = 0;
                 SupportedClasses != NULL && SupportedClasses[Entry].Buffer != NULL;
                 Entry++) {
                if (strncmp(Class->Buffer,
                            SupportedClasses[Entry].Buffer,
                            Class->Length) == 0) {
                    Supported = TRUE;
                    break;
                }
            }

            if (!Supported)
                Class->Length = 0;
        }

        if (SupportedClasses != NULL)
            RegistryFreeSzValue(SupportedClasses);

        NeedInvalidate = FdoEnumerate(Fdo, Classes);

        FdoFreeAnsi(Classes);

        if (NeedInvalidate) {
            NeedInvalidate = FALSE;
            IoInvalidateDeviceRelations(__FdoGetPhysicalDeviceObject(Fdo), 
                                        BusRelations);
        }

loop:
        KeSetEvent(&Fdo->ScanEvent, IO_NO_INCREMENT, FALSE);
    }

    KeSetEvent(&Fdo->ScanEvent, IO_NO_INCREMENT, FALSE);

    Info("<====\n");
    return STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__FdoSuspendSetActive(
    IN  PXENBUS_FDO     Fdo
    )
{
    if (!TryAcquireMutex(&Fdo->BalloonSuspendMutex))
        goto fail1;

    Trace("<===>\n");

    return STATUS_SUCCESS;

fail1:
    return STATUS_UNSUCCESSFUL;
}

static FORCEINLINE VOID
__FdoSuspendClearActive(
    IN  PXENBUS_FDO     Fdo
    )
{
    ReleaseMutex(&Fdo->BalloonSuspendMutex);

    Trace("<===>\n");

    //
    // We may have missed initiating a balloon
    // whilst suspending/resuming.
    //
    if (Fdo->BalloonInterface.Interface.Context != NULL)
        ThreadWake(Fdo->BalloonThread);
}

static NTSTATUS
FdoSuspend(
    IN  PXENBUS_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENBUS_FDO         Fdo = Context;
    GROUP_AFFINITY      Affinity;
    PKEVENT             Event;

    Info("====>\n");

    // We really want to know what CPU this thread will run on
    Affinity.Group = 0;
    Affinity.Mask = (KAFFINITY)1;
    KeSetSystemGroupAffinityThread(&Affinity, NULL);

    (VOID) KeSetPriorityThread(KeGetCurrentThread(),
                               LOW_PRIORITY);

    Event = ThreadGetEvent(Self);

    for (;;) {
        PCHAR       Buffer;
        BOOLEAN     Suspend;
        NTSTATUS    status;

        Trace("waiting...\n");

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        Trace("awake\n");

        if (ThreadIsAlerted(Self))
            break;

        // It is not safe to use interfaces before this point
        if (__FdoGetDevicePowerState(Fdo) != PowerDeviceD0)
            goto loop;

        status = XENBUS_STORE(Read,
                              &Fdo->StoreInterface,
                              NULL,
                              "control",
                              "shutdown",
                              &Buffer);
        if (NT_SUCCESS(status)) {
            Suspend = (strcmp(Buffer, "suspend") == 0) ? TRUE : FALSE;
                
            XENBUS_STORE(Free,
                         &Fdo->StoreInterface,
                         Buffer);
        } else {
            Suspend = FALSE;
        }

        if (!Suspend) {
            Trace("nothing to do\n");
            goto loop;
        }

        status = __FdoSuspendSetActive(Fdo);
        if (!NT_SUCCESS(status))
            goto loop;

        (VOID) XENBUS_STORE(Printf,
                            &Fdo->StoreInterface,
                            NULL,
                            "control",
                            "shutdown",
                            "");

        (VOID) XENBUS_SUSPEND(Trigger, &Fdo->SuspendInterface);

        __FdoSuspendClearActive(Fdo);

        KeFlushQueuedDpcs();

loop:
        KeSetEvent(&Fdo->SuspendEvent, IO_NO_INCREMENT, FALSE);
    }

    KeSetEvent(&Fdo->SuspendEvent, IO_NO_INCREMENT, FALSE);

    Info("<====\n");
    return STATUS_SUCCESS;
}

#define TIME_US(_us)            ((_us) * 10ll)
#define TIME_MS(_ms)            (TIME_US((_ms) * 1000ll))
#define TIME_S(_s)              (TIME_MS((_s) * 1000ll))
#define TIME_RELATIVE(_t)       (-(_t))

static FORCEINLINE NTSTATUS
__FdoBalloonSetActive(
    IN  PXENBUS_FDO         Fdo
    )
{
    if (!TryAcquireMutex(&Fdo->BalloonSuspendMutex))
        goto fail1;

    Trace("<===>\n");

    (VOID) XENBUS_STORE(Printf,
                        &Fdo->StoreInterface,
                        NULL,
                        "control",
                        "balloon-active",
                        "%u",
                        1);

    return STATUS_SUCCESS;

fail1:
    return STATUS_UNSUCCESSFUL;
}

static FORCEINLINE VOID
__FdoBalloonClearActive(
    IN  PXENBUS_FDO     Fdo
    )
{
    (VOID) XENBUS_STORE(Printf,
                        &Fdo->StoreInterface,
                        NULL,
                        "control",
                        "balloon-active",
                        "%u",
                        0);

    ReleaseMutex(&Fdo->BalloonSuspendMutex);

    Trace("<===>\n");

    //
    // We may have missed initiating a suspend
    // whilst the balloon was active.
    //
    ThreadWake(Fdo->SuspendThread);
}

#define XENBUS_BALLOON_RETRY_PERIOD 1

static NTSTATUS
FdoBalloon(
    IN  PXENBUS_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENBUS_FDO         Fdo = Context;
    PKEVENT             Event;
    LARGE_INTEGER       Timeout;
    ULONGLONG           StaticMax;
    BOOLEAN             Initialized;
    BOOLEAN             Active;
    NTSTATUS            status;

    Info("====>\n");

    Event = ThreadGetEvent(Self);

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(XENBUS_BALLOON_RETRY_PERIOD));

    StaticMax = 0;
    Initialized = FALSE;
    Active = FALSE;

    for (;;) {
        PCHAR                   Buffer;
        ULONGLONG               Target;
        ULONGLONG               Size;

        Trace("waiting%s...\n", (Active) ? " (Active)" : "");

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     (Active) ?
                                     &Timeout :
                                     NULL);
        KeClearEvent(Event);
        
        Trace("awake\n");

        if (ThreadIsAlerted(Self))
            break;

        // It is not safe to use interfaces before this point
        if (__FdoGetDevicePowerState(Fdo) != PowerDeviceD0) {
            if (Active) {
                Active = FALSE;

                __FdoBalloonClearActive(Fdo);
            }

            goto loop;
        }

        if (!Initialized) {
            ULONGLONG   VideoRAM;

            ASSERT(!Active);

            status = XENBUS_STORE(Read,
                                  &Fdo->StoreInterface,
                                  NULL,
                                  "memory",
                                  "static-max",
                                  &Buffer);
            if (!NT_SUCCESS(status))
                goto loop;

            StaticMax = _strtoui64(Buffer, NULL, 10);

            XENBUS_STORE(Free,
                         &Fdo->StoreInterface,
                         Buffer);

            if (StaticMax == 0)
                goto loop;

            status = XENBUS_STORE(Read,
                                  &Fdo->StoreInterface,
                                  NULL,
                                  "memory",
                                  "videoram",
                                  &Buffer);
            if (NT_SUCCESS(status)) {
                VideoRAM = _strtoui64(Buffer, NULL, 10);

                XENBUS_STORE(Free,
                             &Fdo->StoreInterface,
                             Buffer);
            } else {
                VideoRAM = 0;
            }

            if (StaticMax < VideoRAM)
                goto loop;

            StaticMax -= VideoRAM;
            StaticMax /= 4;   // We need the value in pages

            Initialized = TRUE;
        }

        ASSERT(Initialized);

        status = XENBUS_STORE(Read,
                              &Fdo->StoreInterface,
                              NULL,
                              "memory",
                              "target",
                              &Buffer);
        if (!NT_SUCCESS(status))
            goto loop;

        Target = _strtoui64(Buffer, NULL, 10) / 4;

        XENBUS_STORE(Free,
                     &Fdo->StoreInterface,
                     Buffer);

        if (Target > StaticMax)
            Target = StaticMax;

        Size = StaticMax - Target;

        if (XENBUS_BALLOON(GetSize,
                           &Fdo->BalloonInterface) == Size) {
            Trace("nothing to do\n");
            goto loop;
        }

        if (!Active) {
            status = __FdoBalloonSetActive(Fdo);
            if (!NT_SUCCESS(status))
                goto loop;

            Active = TRUE;
        }

        status = XENBUS_BALLOON(Adjust,
                                &Fdo->BalloonInterface,
                                Size);
        if (!NT_SUCCESS(status))
            goto loop;

        ASSERT(Active);
        Active = FALSE;

        __FdoBalloonClearActive(Fdo);

loop:
        if (!Active)
            KeSetEvent(&Fdo->BalloonEvent, IO_NO_INCREMENT, FALSE);
    }

    ASSERT3U(XENBUS_BALLOON(GetSize,
                            &Fdo->BalloonInterface), ==, 0);

    KeSetEvent(&Fdo->BalloonEvent, IO_NO_INCREMENT, FALSE);

    Info("<====\n");
    return STATUS_SUCCESS;
}

static VOID
FdoDumpIoResourceDescriptor(
    IN  PXENBUS_FDO             Fdo,
    IN  PIO_RESOURCE_DESCRIPTOR Descriptor
    )
{
    Trace("%s: %s\n",
          __FdoGetName(Fdo),
          ResourceDescriptorTypeName(Descriptor->Type));

    if (Descriptor->Option == 0)
        Trace("Required\n");
    else if (Descriptor->Option == IO_RESOURCE_ALTERNATIVE)
        Trace("Alternative\n");
    else if (Descriptor->Option == IO_RESOURCE_PREFERRED)
        Trace("Preferred\n");
    else if (Descriptor->Option == (IO_RESOURCE_ALTERNATIVE | IO_RESOURCE_PREFERRED))
        Trace("Preferred Alternative\n");

    Trace("ShareDisposition = %s Flags = %04x\n",
          ResourceDescriptorShareDispositionName(Descriptor->ShareDisposition),
          Descriptor->Flags);

    switch (Descriptor->Type) {
    case CmResourceTypeMemory:
        Trace("Length = %08x Alignment = %08x\n MinimumAddress = %08x.%08x MaximumAddress = %08x.%08x\n",
              Descriptor->u.Memory.Length,
              Descriptor->u.Memory.Alignment,
              Descriptor->u.Memory.MinimumAddress.HighPart,
              Descriptor->u.Memory.MinimumAddress.LowPart,
              Descriptor->u.Memory.MaximumAddress.HighPart,
              Descriptor->u.Memory.MaximumAddress.LowPart);
        break;

    case CmResourceTypeInterrupt:
        Trace("MinimumVector = %08x MaximumVector = %08x AffinityPolicy = %s PriorityPolicy = %s Group = %u TargettedProcessors = %p\n",
              Descriptor->u.Interrupt.MinimumVector,
              Descriptor->u.Interrupt.MaximumVector,
              IrqDevicePolicyName(Descriptor->u.Interrupt.AffinityPolicy),
              IrqPriorityName(Descriptor->u.Interrupt.PriorityPolicy),
              Descriptor->u.Interrupt.Group,
              (PVOID)Descriptor->u.Interrupt.TargetedProcessors);
        break;

    default:
        break;
    }
}

static VOID
FdoDumpIoResourceList(
    IN  PXENBUS_FDO         Fdo,
    IN  PIO_RESOURCE_LIST   List
    )
{
    ULONG                   Index;

    for (Index = 0; Index < List->Count; Index++) {
        PIO_RESOURCE_DESCRIPTOR Descriptor = &List->Descriptors[Index];

        Trace("%s: %d\n",
              __FdoGetName(Fdo),
              Index);

        FdoDumpIoResourceDescriptor(Fdo, Descriptor);
    }
}

static NTSTATUS
FdoFilterResourceRequirements(
    IN  PXENBUS_FDO                 Fdo,
    IN  PIRP                        Irp
    )
{
    PIO_RESOURCE_REQUIREMENTS_LIST  Old;
    ULONG                           Size;
    PIO_RESOURCE_REQUIREMENTS_LIST  New;
    IO_RESOURCE_DESCRIPTOR          Interrupt;
    PIO_RESOURCE_LIST               List;
    ULONG                           Index;
    ULONG                           Count;
    NTSTATUS                        status;

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (!__FdoIsActive(Fdo))
        goto not_active;

    Old = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
    ASSERT3U(Old->AlternativeLists, ==, 1);

    Count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    Size = Old->ListSize +
        (sizeof (IO_RESOURCE_DESCRIPTOR) * Count);

    New = __AllocatePoolWithTag(PagedPool, Size, 'SUB');

    status = STATUS_NO_MEMORY;
    if (New == NULL)
        goto fail2;

    RtlCopyMemory(New, Old, Old->ListSize);
    New->ListSize = Size;

    List = &New->List[0];

    for (Index = 0; Index < List->Count; Index++) {
        PIO_RESOURCE_DESCRIPTOR Descriptor = &List->Descriptors[Index];

        if (Descriptor->Type != CmResourceTypeInterrupt)
            continue;

        Descriptor->Flags |= CM_RESOURCE_INTERRUPT_POLICY_INCLUDED;
        Descriptor->u.Interrupt.AffinityPolicy = IrqPolicySpecifiedProcessors;
        Descriptor->u.Interrupt.Group = 0;
        Descriptor->u.Interrupt.TargetedProcessors = (KAFFINITY)1;
    }

    RtlZeroMemory(&Interrupt, sizeof (IO_RESOURCE_DESCRIPTOR));
    Interrupt.Option = 0; // Required
    Interrupt.Type = CmResourceTypeInterrupt;
    Interrupt.ShareDisposition = CmResourceShareDeviceExclusive;
    Interrupt.Flags = CM_RESOURCE_INTERRUPT_LATCHED |
                      CM_RESOURCE_INTERRUPT_MESSAGE |
                      CM_RESOURCE_INTERRUPT_POLICY_INCLUDED;

    Interrupt.u.Interrupt.MinimumVector = CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN;
    Interrupt.u.Interrupt.MaximumVector = CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN;
    Interrupt.u.Interrupt.AffinityPolicy = IrqPolicySpecifiedProcessors;
    Interrupt.u.Interrupt.PriorityPolicy = IrqPriorityUndefined;

    for (Index = 0; Index < Count; Index++) {
        PROCESSOR_NUMBER    ProcNumber;

        status = KeGetProcessorNumberFromIndex(Index, &ProcNumber);
        ASSERT(NT_SUCCESS(status));

        if (RtlIsNtDdiVersionAvailable(NTDDI_WIN7))
            Interrupt.u.Interrupt.Group = ProcNumber.Group;

        Interrupt.u.Interrupt.TargetedProcessors = (KAFFINITY)1 << ProcNumber.Number;
        List->Descriptors[List->Count++] = Interrupt;
    }

    FdoDumpIoResourceList(Fdo, List);

    Irp->IoStatus.Information = (ULONG_PTR)New;
    status = STATUS_SUCCESS;

    ExFreePool(Old);

not_active:
    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static VOID
FdoDumpCmPartialResourceDescriptor(
    IN  PXENBUS_FDO                     Fdo,
    IN  BOOLEAN                         Translated,
    IN  PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor
    )
{
    Trace("%s: %s: %s SharedDisposition=%s Flags=%04x\n",
          __FdoGetName(Fdo),
          (Translated) ? "TRANSLATED" : "RAW",
          ResourceDescriptorTypeName(Descriptor->Type),
          ResourceDescriptorShareDispositionName(Descriptor->ShareDisposition),
          Descriptor->Flags);
    
    switch (Descriptor->Type) {
    case CmResourceTypeMemory:
        Trace("%s: %s: Start = %08x.%08x Length = %08x\n",
              __FdoGetName(Fdo),
              (Translated) ? "TRANSLATED" : "RAW",
              Descriptor->u.Memory.Start.HighPart,
              Descriptor->u.Memory.Start.LowPart,
              Descriptor->u.Memory.Length);
        break;

    case CmResourceTypeInterrupt:
        if (Descriptor->Flags & CM_RESOURCE_INTERRUPT_MESSAGE) {
            if (Translated)
                Trace("%s: TRANSLATED: Level = %08x Vector = %08x Affinity = %p\n",
                      __FdoGetName(Fdo),
                      Descriptor->u.MessageInterrupt.Translated.Level,
                      Descriptor->u.MessageInterrupt.Translated.Vector,
                      (PVOID)Descriptor->u.MessageInterrupt.Translated.Affinity);
            else
                Trace("%s: RAW: MessageCount = %08x Vector = %08x Affinity = %p\n",
                      __FdoGetName(Fdo),
                      Descriptor->u.MessageInterrupt.Raw.MessageCount,
                      Descriptor->u.MessageInterrupt.Raw.Vector,
                      (PVOID)Descriptor->u.MessageInterrupt.Raw.Affinity);
        } else {
            Trace("%s: %s: Level = %08x Vector = %08x Affinity = %p\n",
                  __FdoGetName(Fdo),
                  (Translated) ? "TRANSLATED" : "RAW",
                  Descriptor->u.Interrupt.Level,
                  Descriptor->u.Interrupt.Vector,
                  (PVOID)Descriptor->u.Interrupt.Affinity);
        }
        break;
    default:
        break;
    }
}

static VOID
FdoDumpCmPartialResourceList(
    IN  PXENBUS_FDO                 Fdo,
    IN  BOOLEAN                     Translated,
    IN  PCM_PARTIAL_RESOURCE_LIST   List
    )
{
    ULONG                           Index;

    Trace("%s: %s: Version = %d Revision = %d Count = %d\n",
          __FdoGetName(Fdo),
          (Translated) ? "TRANSLATED" : "RAW",
          List->Version,
          List->Revision,
          List->Count);

    for (Index = 0; Index < List->Count; Index++) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor = &List->PartialDescriptors[Index];

        Trace("%s: %s: %d\n",
              __FdoGetName(Fdo),
              (Translated) ? "TRANSLATED" : "RAW",
              Index);

        FdoDumpCmPartialResourceDescriptor(Fdo, Translated, Descriptor);
    }
}

static VOID
FdoDumpCmFullResourceDescriptor(
    IN  PXENBUS_FDO                     Fdo,
    IN  BOOLEAN                         Translated,
    IN  PCM_FULL_RESOURCE_DESCRIPTOR    Descriptor
    )
{
    Trace("%s: %s: InterfaceType = %s BusNumber = %d\n",
          __FdoGetName(Fdo),
          (Translated) ? "TRANSLATED" : "RAW",
          InterfaceTypeName(Descriptor->InterfaceType),
          Descriptor->BusNumber);

    FdoDumpCmPartialResourceList(Fdo, Translated, &Descriptor->PartialResourceList);
}

static VOID
FdoDumpCmResourceList(
    IN  PXENBUS_FDO         Fdo,
    IN  BOOLEAN             Translated,
    IN  PCM_RESOURCE_LIST   List
    )
{
    FdoDumpCmFullResourceDescriptor(Fdo, Translated, &List->List[0]);
}

_IRQL_requires_max_(HIGH_LEVEL)
_IRQL_saves_
_IRQL_raises_(HIGH_LEVEL)
KIRQL
FdoAcquireInterruptLock(
    IN  PXENBUS_FDO         Fdo,
    IN  PXENBUS_INTERRUPT   Interrupt
    )
{
    UNREFERENCED_PARAMETER(Fdo);

    return KeAcquireInterruptSpinLock(Interrupt->InterruptObject);
}

_IRQL_requires_(HIGH_LEVEL)
VOID
FdoReleaseInterruptLock(
    IN  PXENBUS_FDO                 Fdo,
    IN  PXENBUS_INTERRUPT           Interrupt,
    IN  __drv_restoresIRQL KIRQL    Irql
    )
{
    UNREFERENCED_PARAMETER(Fdo);

    KeReleaseInterruptSpinLock(Interrupt->InterruptObject, Irql);
}

static
_Function_class_(KSERVICE_ROUTINE)
__drv_requiresIRQL(HIGH_LEVEL)
BOOLEAN
FdoInterruptCallback(
    IN  PKINTERRUPT             InterruptObject,
    IN  PVOID                   Context
    )
{
    PXENBUS_INTERRUPT           Interrupt = Context;

    if (Interrupt->Callback == NULL)
        return FALSE;

    return Interrupt->Callback(InterruptObject,
                               Interrupt->Argument);
}

static NTSTATUS
FdoConnectInterrupt(
    IN  PXENBUS_FDO                     Fdo,
    IN  PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw,
    IN  PCM_PARTIAL_RESOURCE_DESCRIPTOR Translated,
    OUT PXENBUS_INTERRUPT               *Interrupt
    )
{
    IO_CONNECT_INTERRUPT_PARAMETERS     Connect;
    BOOLEAN                             Found;
    ULONG                               Number;
    NTSTATUS                            status;

    Trace("====>\n");

    *Interrupt = __FdoAllocate(sizeof (XENBUS_INTERRUPT));

    status = STATUS_NO_MEMORY;
    if (*Interrupt == NULL)
        goto fail1;

    (*Interrupt)->Fdo = Fdo;
    (*Interrupt)->InterruptMode = (Translated->Flags & CM_RESOURCE_INTERRUPT_LATCHED) ?
                                  Latched :
                                  LevelSensitive;

    if (~Translated->Flags & CM_RESOURCE_INTERRUPT_MESSAGE)
        (*Interrupt)->Line = Raw->u.Interrupt.Vector;

    RtlZeroMemory(&Connect, sizeof (IO_CONNECT_INTERRUPT_PARAMETERS));
    Connect.FullySpecified.PhysicalDeviceObject = __FdoGetPhysicalDeviceObject(Fdo);
    Connect.FullySpecified.ShareVector = (BOOLEAN)(Translated->ShareDisposition == CmResourceShareShared);
    Connect.FullySpecified.InterruptMode = (*Interrupt)->InterruptMode;
    Connect.FullySpecified.InterruptObject = &(*Interrupt)->InterruptObject;
    Connect.FullySpecified.ServiceRoutine = FdoInterruptCallback;
    Connect.FullySpecified.ServiceContext = *Interrupt;

    if (Translated->Flags & CM_RESOURCE_INTERRUPT_MESSAGE) {
        Connect.FullySpecified.Vector = Translated->u.MessageInterrupt.Translated.Vector;
        Connect.FullySpecified.Irql = (KIRQL)Translated->u.MessageInterrupt.Translated.Level;
        Connect.FullySpecified.SynchronizeIrql = (KIRQL)Translated->u.MessageInterrupt.Translated.Level;
        Connect.FullySpecified.Group = Translated->u.MessageInterrupt.Translated.Group;
        Connect.FullySpecified.ProcessorEnableMask = Translated->u.MessageInterrupt.Translated.Affinity;
    } else {
        Connect.FullySpecified.Vector = Translated->u.Interrupt.Vector;
        Connect.FullySpecified.Irql = (KIRQL)Translated->u.Interrupt.Level;
        Connect.FullySpecified.SynchronizeIrql = (KIRQL)Translated->u.Interrupt.Level;
        Connect.FullySpecified.Group = Translated->u.Interrupt.Group;
        Connect.FullySpecified.ProcessorEnableMask = Translated->u.Interrupt.Affinity;
    }

    Connect.Version = (Connect.FullySpecified.Group != 0) ?
                      CONNECT_FULLY_SPECIFIED_GROUP :
                      CONNECT_FULLY_SPECIFIED;

    status = IoConnectInterruptEx(&Connect);
    if (!NT_SUCCESS(status))
        goto fail2;

    (*Interrupt)->Vector = (UCHAR)Connect.FullySpecified.Vector;

    (*Interrupt)->ProcNumber.Group = Connect.FullySpecified.Group;

#if defined(__i386__)
    Found = _BitScanReverse(&Number, Connect.FullySpecified.ProcessorEnableMask);
#elif defined(__x86_64__)
    Found = _BitScanReverse64(&Number, Connect.FullySpecified.ProcessorEnableMask);
#else
#error 'Unrecognised architecture'
#endif
    ASSERT(Found);

    (*Interrupt)->ProcNumber.Number = (UCHAR)Number;

    Info("%p: %s %s CPU %u:%u VECTOR %02x\n",
         (*Interrupt)->InterruptObject,
         ResourceDescriptorShareDispositionName(Translated->ShareDisposition),
         InterruptModeName((*Interrupt)->InterruptMode),
         (*Interrupt)->ProcNumber.Group,
         (*Interrupt)->ProcNumber.Number,
         (*Interrupt)->Vector);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __FdoFree(*Interrupt);
    *Interrupt = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
FdoDisconnectInterrupt(
    IN  PXENBUS_FDO                     Fdo,
    IN  PXENBUS_INTERRUPT               Interrupt
    )
{
    IO_DISCONNECT_INTERRUPT_PARAMETERS  Disconnect;

    UNREFERENCED_PARAMETER(Fdo);

    Trace("====>\n");

    Info("%p: CPU %u:%u VECTOR %02x\n",
         Interrupt->InterruptObject,
         Interrupt->ProcNumber.Group,
         Interrupt->ProcNumber.Number,
         Interrupt->Vector);

    RtlZeroMemory(&Interrupt->ProcNumber, sizeof (PROCESSOR_NUMBER));
    Interrupt->Vector = 0;

    RtlZeroMemory(&Disconnect, sizeof (IO_DISCONNECT_INTERRUPT_PARAMETERS));
    Disconnect.Version = CONNECT_FULLY_SPECIFIED;
    Disconnect.ConnectionContext.InterruptObject = Interrupt->InterruptObject;

    IoDisconnectInterruptEx(&Disconnect);

    Interrupt->Line = 0;
    Interrupt->InterruptObject = NULL;
    Interrupt->InterruptMode = 0;
    Interrupt->Fdo = NULL;

    ASSERT(IsZeroMemory(Interrupt, sizeof (XENBUS_INTERRUPT)));
    __FdoFree(Interrupt);

    Trace("<====\n");
}

static NTSTATUS
FdoCreateInterrupt(
    IN  PXENBUS_FDO     Fdo
    )
{
    ULONG               Index;
    PXENBUS_INTERRUPT   Interrupt;
    NTSTATUS            status;

    InitializeListHead(&Fdo->InterruptList);

    for (Index = 0; Index < Fdo->TranslatedResourceList->Count; Index++) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw = &Fdo->RawResourceList->PartialDescriptors[Index];
        PCM_PARTIAL_RESOURCE_DESCRIPTOR Translated = &Fdo->TranslatedResourceList->PartialDescriptors[Index];

        if (Translated->Type != CmResourceTypeInterrupt)
            continue;

        status = FdoConnectInterrupt(Fdo, Raw, Translated, &Interrupt);
        if (!NT_SUCCESS(status))
            goto fail1;

        InsertTailList(&Fdo->InterruptList, &Interrupt->ListEntry);
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    while (!IsListEmpty(&Fdo->InterruptList)) {
        PLIST_ENTRY ListEntry;

        ListEntry = RemoveHeadList(&Fdo->InterruptList);
        ASSERT(ListEntry != &Fdo->InterruptList);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Interrupt = CONTAINING_RECORD(ListEntry, XENBUS_INTERRUPT, ListEntry);

        FdoDisconnectInterrupt(Fdo, Interrupt);
    }

    RtlZeroMemory(&Fdo->InterruptList, sizeof (LIST_ENTRY));

    return status;
}

PXENBUS_INTERRUPT
FdoAllocateInterrupt(
    IN  PXENBUS_FDO         Fdo,
    IN  KINTERRUPT_MODE     InterruptMode,
    IN  USHORT              Group,
    IN  UCHAR               Number,
    IN  KSERVICE_ROUTINE    Callback,
    IN  PVOID               Argument OPTIONAL
    )
{
    PLIST_ENTRY             ListEntry;
    PXENBUS_INTERRUPT       Interrupt;
    KIRQL                   Irql;

    for (ListEntry = Fdo->InterruptList.Flink;
         ListEntry != &Fdo->InterruptList;
         ListEntry = ListEntry->Flink) {
        Interrupt = CONTAINING_RECORD(ListEntry, XENBUS_INTERRUPT, ListEntry);

        if (Interrupt->Callback == NULL &&
            Interrupt->InterruptMode == InterruptMode &&
            Interrupt->ProcNumber.Group == Group &&
            Interrupt->ProcNumber.Number == Number)
            goto found;
    }

    goto fail1;

found:
    Irql = FdoAcquireInterruptLock(Fdo, Interrupt);
    Interrupt->Callback = Callback;
    Interrupt->Argument = Argument;
    FdoReleaseInterruptLock(Fdo, Interrupt, Irql);

    return Interrupt;

fail1:
    return NULL;
}

UCHAR
FdoGetInterruptVector(
    IN  PXENBUS_FDO         Fdo,
    IN  PXENBUS_INTERRUPT   Interrupt
    )
{
    UNREFERENCED_PARAMETER(Fdo);

    return Interrupt->Vector;
}

ULONG
FdoGetInterruptLine(
    IN  PXENBUS_FDO         Fdo,
    IN  PXENBUS_INTERRUPT   Interrupt
    )
{
    UNREFERENCED_PARAMETER(Fdo);

    return Interrupt->Line;
}

VOID
FdoFreeInterrupt(
    IN  PXENBUS_FDO         Fdo,
    IN  PXENBUS_INTERRUPT   Interrupt
    )
{
    KIRQL                   Irql;

    Irql = FdoAcquireInterruptLock(Fdo, Interrupt);
    Interrupt->Callback = NULL;
    Interrupt->Argument = NULL;
    FdoReleaseInterruptLock(Fdo, Interrupt, Irql);
}

static VOID
FdoDestroyInterrupt(
    IN  PXENBUS_FDO     Fdo
    )
{
    while (!IsListEmpty(&Fdo->InterruptList)) {
        PLIST_ENTRY         ListEntry;
        PXENBUS_INTERRUPT   Interrupt;

        ListEntry = RemoveHeadList(&Fdo->InterruptList);
        ASSERT(ListEntry != &Fdo->InterruptList);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Interrupt = CONTAINING_RECORD(ListEntry, XENBUS_INTERRUPT, ListEntry);

#pragma warning(push)
#pragma warning(disable:4054)   // 'type cast' : from function pointer to data pointer
        ASSERT3P(Interrupt->Callback, ==, NULL);
#pragma warning(pop)

        ASSERT3P(Interrupt->Argument, ==, NULL);

        FdoDisconnectInterrupt(Fdo, Interrupt);
    }

    RtlZeroMemory(&Fdo->InterruptList, sizeof (LIST_ENTRY));
}

static
_Function_class_(KSERVICE_ROUTINE)
_IRQL_requires_(HIGH_LEVEL)
_IRQL_requires_same_
BOOLEAN
FdoEvtchnCallback(
    IN  PKINTERRUPT         InterruptObject,
    IN  PVOID               Argument
    )
{
    PXENBUS_FDO             Fdo = Argument;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Fdo != NULL);

    XENBUS_DEBUG(Trigger, &Fdo->DebugInterface, NULL);

    return TRUE;
}

static FORCEINLINE BOOLEAN
__FdoMatchDistribution(
    IN  PXENBUS_FDO Fdo,
    IN  PCHAR       Buffer
    )
{
    PCHAR           Vendor;
    PCHAR           Product;
    PCHAR           Context;
    const CHAR      *Text;
    BOOLEAN         Match;
    ULONG           Index;
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Fdo);

    status = STATUS_INVALID_PARAMETER;

    Vendor = __strtok_r(Buffer, " ", &Context);
    if (Vendor == NULL)
        goto fail1;

    Product = __strtok_r(NULL, " ", &Context);
    if (Product == NULL)
        goto fail2;

    Match = TRUE;

    Text = VENDOR_NAME_STR;

    for (Index = 0; Text[Index] != 0; Index++) {
        if (!isalnum((UCHAR)Text[Index])) {
            if (Vendor[Index] != '_') {
                Match = FALSE;
                break;
            }
        } else {
            if (Vendor[Index] != Text[Index]) {
                Match = FALSE;
                break;
            }
        }
    }

    Text = "XENBUS";

    if (_stricmp(Product, Text) != 0)
        Match = FALSE;

    return Match;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return FALSE;
}

static VOID
FdoClearDistribution(
    IN  PXENBUS_FDO Fdo
    )
{
    PCHAR           Buffer;
    PANSI_STRING    Distributions;
    ULONG           Index;
    NTSTATUS        status;

    Trace("====>\n");

    status = XENBUS_STORE(Directory,
                          &Fdo->StoreInterface,
                          NULL,
                          NULL,
                          "drivers",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Distributions = FdoMultiSzToUpcaseAnsi(Buffer);

        XENBUS_STORE(Free,
                     &Fdo->StoreInterface,
                     Buffer);
    } else {
        Distributions = NULL;
    }

    if (Distributions == NULL)
        goto done;

    for (Index = 0; Distributions[Index].Buffer != NULL; Index++) {
        PANSI_STRING    Distribution = &Distributions[Index];

        status = XENBUS_STORE(Read,
                              &Fdo->StoreInterface,
                              NULL,
                              "drivers",
                              Distribution->Buffer,
                              &Buffer);
        if (!NT_SUCCESS(status))
            continue;

        if (__FdoMatchDistribution(Fdo, Buffer))
            (VOID) XENBUS_STORE(Remove,
                                &Fdo->StoreInterface,
                                NULL,
                                "drivers",
                                Distribution->Buffer);

        XENBUS_STORE(Free,
                     &Fdo->StoreInterface,
                     Buffer);
    }

    FdoFreeAnsi(Distributions);

done:
    Trace("<====\n");
}

#define MAXIMUM_INDEX   255

static NTSTATUS
FdoSetDistribution(
    IN  PXENBUS_FDO Fdo
    )
{
    ULONG           Index;
    CHAR            Distribution[MAXNAMELEN];
    CHAR            Vendor[MAXNAMELEN];
    const CHAR      *Product;
    NTSTATUS        status;

    Trace("====>\n");

    Index = 0;
    while (Index <= MAXIMUM_INDEX) {
        PCHAR   Buffer;

        status = RtlStringCbPrintfA(Distribution,
                                    MAXNAMELEN,
                                    "%u",
                                    Index);
        ASSERT(NT_SUCCESS(status));

        status = XENBUS_STORE(Read,
                              &Fdo->StoreInterface,
                              NULL,
                              "drivers",
                              Distribution,
                              &Buffer);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_OBJECT_NAME_NOT_FOUND)
                goto update;

            goto fail1;
        }

        XENBUS_STORE(Free,
                     &Fdo->StoreInterface,
                     Buffer);

        Index++;
    }

    status = STATUS_UNSUCCESSFUL;
    goto fail2;

update:
    status = RtlStringCbPrintfA(Vendor,
                                MAXNAMELEN,
                                "%s",
                                VENDOR_NAME_STR);
    ASSERT(NT_SUCCESS(status));

    for (Index  = 0; Vendor[Index] != '\0'; Index++)
        if (!isalnum((UCHAR)Vendor[Index]))
            Vendor[Index] = '_';

    Product = "XENBUS";

#if DBG
#define ATTRIBUTES   "(DEBUG)"
#else
#define ATTRIBUTES   ""
#endif

    (VOID) XENBUS_STORE(Printf,
                        &Fdo->StoreInterface,
                        NULL,
                        "drivers",
                        Distribution,
                        "%s %s %u.%u.%u.%u %s",
                        Vendor,
                        Product,
                        MAJOR_VERSION,
                        MINOR_VERSION,
                        MICRO_VERSION,
                        BUILD_NUMBER,
                        ATTRIBUTES
                        );

#undef  ATTRIBUTES

    Trace("<====\n");
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define FDO_OUT_BUFFER_SIZE 1024

CHAR FdoOutBuffer[FDO_OUT_BUFFER_SIZE];

static VOID
FdoOutputBuffer(
    IN  PVOID   Argument,
    IN  PCHAR   Buffer,
    IN  ULONG   Length
    )
{
    PXENBUS_FDO Fdo = Argument;
    ULONG       Index;
    PCHAR       Cursor;

    Cursor = FdoOutBuffer;
    for (Index = 0; Index < Length; Index++) {
        if (Cursor - FdoOutBuffer >= FDO_OUT_BUFFER_SIZE)
            break;

        *Cursor++ = Buffer[Index];

        if (Buffer[Index] != '\n')
            continue;

        if (Cursor - FdoOutBuffer >= FDO_OUT_BUFFER_SIZE)
            break;

        *(Cursor - 1) = '\r';
        *Cursor++ = '\n';
    }

    (VOID) XENBUS_CONSOLE(Write,
                          &Fdo->ConsoleInterface,
                          FdoOutBuffer,
                          (ULONG)(Cursor - FdoOutBuffer));
}

static FORCEINLINE NTSTATUS
__FdoD3ToD0(
    IN  PXENBUS_FDO Fdo
    )
{
    NTSTATUS        status;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    (VOID) FdoSetDistribution(Fdo);

    Fdo->Channel = XENBUS_EVTCHN(Open,
                                 &Fdo->EvtchnInterface,
                                 XENBUS_EVTCHN_TYPE_VIRQ,
                                 FdoEvtchnCallback,
                                 Fdo,
                                 VIRQ_DEBUG);

    status = STATUS_UNSUCCESSFUL;
    if (Fdo->Channel == NULL)
        goto fail1;

    (VOID) XENBUS_EVTCHN(Unmask,
                         &Fdo->EvtchnInterface,
                         Fdo->Channel,
                         FALSE,
                         TRUE);

    status = LogAddDisposition(DriverGetConsoleLogLevel(),
                               FdoOutputBuffer,
                               Fdo,
                               &Fdo->LogDisposition);
    ASSERT(NT_SUCCESS(status));

    status = XENBUS_STORE(WatchAdd,
                          &Fdo->StoreInterface,
                          NULL,
                          "device",
                          ThreadGetEvent(Fdo->ScanThread),
                          &Fdo->ScanWatch);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_STORE(WatchAdd,
                          &Fdo->StoreInterface,
                          "control",
                          "shutdown",
                          ThreadGetEvent(Fdo->SuspendThread),
                          &Fdo->SuspendWatch);
    if (!NT_SUCCESS(status))
        goto fail3;

    (VOID) XENBUS_STORE(Printf,
                        &Fdo->StoreInterface,
                        NULL,
                        "control",
                        "feature-suspend",
                        "%u",
                        1);

    if (Fdo->BalloonInterface.Interface.Context != NULL) {
        status = XENBUS_STORE(WatchAdd,
                              &Fdo->StoreInterface,
                              "memory",
                              "target",
                              ThreadGetEvent(Fdo->BalloonThread),
                              &Fdo->BalloonWatch);
        if (!NT_SUCCESS(status))
            goto fail4;

        (VOID) XENBUS_STORE(Printf,
                            &Fdo->StoreInterface,
                            NULL,
                            "control",
                            "feature-balloon",
                            "%u",
                            1);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    (VOID) XENBUS_STORE(Remove,
                        &Fdo->StoreInterface,
                        NULL,
                        "control",
                        "feature-suspend");

    (VOID) XENBUS_STORE(WatchRemove,
                        &Fdo->StoreInterface,
                        Fdo->SuspendWatch);
    Fdo->SuspendWatch = NULL;

fail3:
    Error("fail3\n");

    (VOID) XENBUS_STORE(WatchRemove,
                        &Fdo->StoreInterface,
                        Fdo->ScanWatch);
    Fdo->ScanWatch = NULL;

fail2:
    Error("fail2\n");

    LogRemoveDisposition(Fdo->LogDisposition);
    Fdo->LogDisposition = NULL;

    XENBUS_EVTCHN(Close,
                  &Fdo->EvtchnInterface,
                  Fdo->Channel);
    Fdo->Channel = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__FdoD0ToD3(
    IN  PXENBUS_FDO Fdo
    )
{
    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    if (Fdo->BalloonInterface.Interface.Context != NULL) {
        (VOID) XENBUS_STORE(Remove,
                            &Fdo->StoreInterface,
                            NULL,
                            "control",
                            "feature-balloon");

        (VOID) XENBUS_STORE(WatchRemove,
                            &Fdo->StoreInterface,
                            Fdo->BalloonWatch);
        Fdo->BalloonWatch = NULL;
    }

    (VOID) XENBUS_STORE(Remove,
                        &Fdo->StoreInterface,
                        NULL,
                        "control",
                        "feature-suspend");

    (VOID) XENBUS_STORE(WatchRemove,
                        &Fdo->StoreInterface,
                        Fdo->SuspendWatch);
    Fdo->SuspendWatch = NULL;

    (VOID) XENBUS_STORE(WatchRemove,
                        &Fdo->StoreInterface,
                        Fdo->ScanWatch);
    Fdo->ScanWatch = NULL;

    LogRemoveDisposition(Fdo->LogDisposition);
    Fdo->LogDisposition = NULL;

    XENBUS_EVTCHN(Close,
                  &Fdo->EvtchnInterface,
                  Fdo->Channel);
    Fdo->Channel = NULL;

    FdoClearDistribution(Fdo);

    Trace("<====\n");
}

static VOID
FdoSuspendCallbackLate(
    IN  PVOID   Argument
    )
{
    PXENBUS_FDO Fdo = Argument;
    NTSTATUS    status;

    __FdoD0ToD3(Fdo);

    status = __FdoD3ToD0(Fdo);
    ASSERT(NT_SUCCESS(status));
}

static NTSTATUS
FdoCreateHole(
    IN  PXENBUS_FDO Fdo
    )
{
    PMDL            Mdl;
    PFN_NUMBER      Pfn;
    LONGLONG        Start;
    ULONG           Count;
    NTSTATUS        status;

    status = XENBUS_RANGE_SET(Create,
                              &Fdo->RangeSetInterface,
                              "hole",
                              &Fdo->RangeSet);
    if (!NT_SUCCESS(status))
        goto fail1;

    Mdl = Fdo->Mdl;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    Start = Pfn;
    Count = BYTES_TO_PAGES(Mdl->ByteCount);

    status = XENBUS_RANGE_SET(Put,
                              &Fdo->RangeSetInterface,
                              Fdo->RangeSet,
                              Start,
                              Count);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_UNSUCCESSFUL;
    if (MemoryDecreaseReservation(PAGE_ORDER_2M, 1, &Pfn) != 1)
        goto fail3;

    Trace("%08x - %08x\n", Start, Start + Count - 1);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    XENBUS_RANGE_SET(Get,
                     &Fdo->RangeSetInterface,
                     Fdo->RangeSet,
                     Start,
                     Count);

fail2:
    Error("fail2\n");

    XENBUS_RANGE_SET(Destroy,
                     &Fdo->RangeSetInterface,
                     Fdo->RangeSet);
    Fdo->RangeSet = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
FdoAllocateHole(
    IN  PXENBUS_FDO         Fdo,
    IN  ULONG               Count,
    OUT PVOID               *VirtualAddress OPTIONAL,
    OUT PPHYSICAL_ADDRESS   PhysicalAddress
    )
{
    LONGLONG                Start;
    NTSTATUS                status;

    status = XENBUS_RANGE_SET(Pop,
                              &Fdo->RangeSetInterface,
                              Fdo->RangeSet,
                              Count,
                              &Start);
    if (!NT_SUCCESS(status))
        goto fail1;

    Trace("%08x - %08x\n", Start, Start + Count - 1);

    if (VirtualAddress != NULL) {
        PUCHAR  StartVa = Fdo->Buffer;
        PMDL    Mdl = Fdo->Mdl;
        ULONG   Index;
        ULONG   ByteOffset;

        Index = (ULONG)((PFN_NUMBER)Start - MmGetMdlPfnArray(Mdl)[0]);
        ByteOffset = Index * PAGE_SIZE;
        ASSERT3U(ByteOffset, <=, Mdl->ByteCount);

        *VirtualAddress = StartVa + ByteOffset;
    }

    PhysicalAddress->QuadPart = Start << PAGE_SHIFT;

    return STATUS_SUCCESS;;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
FdoFreeHole(
    IN  PXENBUS_FDO         Fdo,
    IN  PHYSICAL_ADDRESS    PhysicalAddress,
    IN  ULONG               Count
    )
{
    LONGLONG                Start;
    NTSTATUS                status;

    ASSERT3U(PhysicalAddress.QuadPart & (PAGE_SIZE - 1), ==, 0);
    Start = PhysicalAddress.QuadPart >> PAGE_SHIFT;

    Trace("%08x - %08x\n", Start, Start + Count - 1);

    status = XENBUS_RANGE_SET(Put,
                              &Fdo->RangeSetInterface,
                              Fdo->RangeSet,
                              Start,
                              Count);
    ASSERT(NT_SUCCESS(status));
}

static VOID
FdoDestroyHole(
    IN  PXENBUS_FDO Fdo
    )
{
    PMDL            Mdl;
    PFN_NUMBER      Pfn;
    LONGLONG        Start;
    ULONG           Count;
    ULONG           Index;
    NTSTATUS        status;

    Mdl = Fdo->Mdl;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    Start = Pfn;
    Count = BYTES_TO_PAGES(Mdl->ByteCount);

    Trace("%08x - %08x\n", Start, Start + Count - 1);

    ASSERT3U(Count & ((1u << PAGE_ORDER_2M) - 1), ==, 0);
    if (MemoryPopulatePhysmap(PAGE_ORDER_2M, 1, &Pfn) == 1)
        goto done;

    for (Index = 0; Index < Count; Index++) {
        if (MemoryPopulatePhysmap(PAGE_ORDER_4K, 1, &Pfn) != 1)
            BUG("FAILED TO RE-POPULATE HOLE");

        Pfn++;
    }

done:
    status = XENBUS_RANGE_SET(Get,
                              &Fdo->RangeSetInterface,
                              Fdo->RangeSet,
                              Start,
                              Count);
    ASSERT(NT_SUCCESS(status));

    XENBUS_RANGE_SET(Destroy,
                     &Fdo->RangeSetInterface,
                     Fdo->RangeSet);
    Fdo->RangeSet = NULL;
}

// This function must not touch pageable code or data
static NTSTATUS
FdoD3ToD0(
    IN  PXENBUS_FDO             Fdo
    )
{
    POWER_STATE                 PowerState;
    KIRQL                       Irql;
    PLIST_ENTRY                 ListEntry;
    NTSTATUS                    status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetDevicePowerState(Fdo), ==, PowerDeviceD3);

    Trace("====>\n");

    if (!__FdoIsActive(Fdo))
        goto not_active;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    status = XENBUS_DEBUG(Acquire, &Fdo->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_SUSPEND(Acquire, &Fdo->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_RANGE_SET(Acquire, &Fdo->RangeSetInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    // Subsequent interfaces require use of BAR space
    status = FdoCreateHole(Fdo);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_EVTCHN(Acquire, &Fdo->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_STORE(Acquire, &Fdo->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = XENBUS_CONSOLE(Acquire, &Fdo->ConsoleInterface);
    if (!NT_SUCCESS(status))
        goto fail7;

    if (Fdo->BalloonInterface.Interface.Context != NULL) {
        status = XENBUS_BALLOON(Acquire, &Fdo->BalloonInterface);
        if (!NT_SUCCESS(status))
            goto fail8;
    }

    status = __FdoD3ToD0(Fdo);
    if (!NT_SUCCESS(status))
        goto fail9;

    status = XENBUS_SUSPEND(Register,
                            &Fdo->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            FdoSuspendCallbackLate,
                            Fdo,
                            &Fdo->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail10;

    KeLowerIrql(Irql);

not_active:
    __FdoSetDevicePowerState(Fdo, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(Fdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    __FdoAcquireMutex(Fdo);

    for (ListEntry = Fdo->List.Flink;
         ListEntry != &Fdo->List;
         ListEntry = ListEntry->Flink) {
        PXENBUS_DX  Dx = CONTAINING_RECORD(ListEntry, XENBUS_DX, ListEntry);
        PXENBUS_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        PdoResume(Pdo);
    }

    __FdoReleaseMutex(Fdo);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail10:
    Error("fail10\n");

    __FdoD0ToD3(Fdo);

fail9:
    Error("fail9\n");

    if (Fdo->BalloonInterface.Interface.Context != NULL)
        XENBUS_BALLOON(Release, &Fdo->BalloonInterface);

fail8:
    Error("fail8\n");

    XENBUS_CONSOLE(Release, &Fdo->ConsoleInterface);

fail7:
    Error("fail7\n");

    XENBUS_STORE(Release, &Fdo->StoreInterface);

fail6:
    Error("fail6\n");

    XENBUS_EVTCHN(Release, &Fdo->EvtchnInterface);

fail5:
    Error("fail5\n");

    FdoDestroyHole(Fdo);

fail4:
    Error("fail4\n");

    XENBUS_RANGE_SET(Release, &Fdo->RangeSetInterface);

fail3:
    Error("fail3\n");

    XENBUS_SUSPEND(Release, &Fdo->SuspendInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Fdo->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    KeLowerIrql(Irql);

    return status;
}

// This function must not touch pageable code or data
static VOID
FdoD0ToD3(
    IN  PXENBUS_FDO Fdo
    )
{
    POWER_STATE     PowerState;
    PLIST_ENTRY     ListEntry;
    KIRQL           Irql;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetDevicePowerState(Fdo), ==, PowerDeviceD0);

    Trace("====>\n");

    __FdoAcquireMutex(Fdo);

    for (ListEntry = Fdo->List.Flink;
         ListEntry != &Fdo->List;
         ListEntry = ListEntry->Flink) {
        PXENBUS_DX  Dx = CONTAINING_RECORD(ListEntry, XENBUS_DX, ListEntry);
        PXENBUS_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (PdoGetDevicePnpState(Pdo) == Deleted ||
            PdoIsMissing(Pdo))
            continue;

        PdoSuspend(Pdo);
    }

    __FdoReleaseMutex(Fdo);

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(Fdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    __FdoSetDevicePowerState(Fdo, PowerDeviceD3);

    if (!__FdoIsActive(Fdo))
        goto not_active;

    if (Fdo->BalloonInterface.Interface.Context != NULL) {
        Trace("waiting for balloon thread...\n");

        KeClearEvent(&Fdo->BalloonEvent);
        ThreadWake(Fdo->BalloonThread);

        (VOID) KeWaitForSingleObject(&Fdo->BalloonEvent,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);

        Trace("done\n");
    }

    Trace("waiting for suspend thread...\n");

    KeClearEvent(&Fdo->SuspendEvent);
    ThreadWake(Fdo->SuspendThread);

    (VOID) KeWaitForSingleObject(&Fdo->SuspendEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    Trace("done\n");

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    XENBUS_SUSPEND(Deregister,
                   &Fdo->SuspendInterface,
                   Fdo->SuspendCallbackLate);
    Fdo->SuspendCallbackLate = NULL;

    __FdoD0ToD3(Fdo);

    if (Fdo->BalloonInterface.Interface.Context != NULL)
        XENBUS_BALLOON(Release, &Fdo->BalloonInterface);

    XENBUS_CONSOLE(Release, &Fdo->ConsoleInterface);

    XENBUS_STORE(Release, &Fdo->StoreInterface);

    XENBUS_EVTCHN(Release, &Fdo->EvtchnInterface);

    FdoDestroyHole(Fdo);

    XENBUS_RANGE_SET(Release, &Fdo->RangeSetInterface);

    XENBUS_SUSPEND(Release, &Fdo->SuspendInterface);

    XENBUS_DEBUG(Release, &Fdo->DebugInterface);

    KeLowerIrql(Irql);

not_active:
    Trace("<====\n");
}

// This function must not touch pageable code or data
static VOID
FdoS4ToS3(
    IN  PXENBUS_FDO Fdo
    )
{
    KIRQL           Irql;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetSystemPowerState(Fdo), ==, PowerSystemHibernate);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    if (!__FdoIsActive(Fdo))
        goto not_active;

    LogResume();

    HypercallPopulate();

    UnplugDevices();

not_active:
    KeLowerIrql(Irql);

    __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);

    Trace("<====\n");
}

// This function must not touch pageable code or data
static VOID
FdoS3ToS4(
    IN  PXENBUS_FDO Fdo
    )
{
    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetSystemPowerState(Fdo), ==, PowerSystemSleeping3);

    if (!__FdoIsActive(Fdo))
        goto not_active;

    BUG_ON(SuspendGetReferences(Fdo->SuspendContext) != 0);
    BUG_ON(SharedInfoGetReferences(Fdo->SharedInfoContext) != 0);
    BUG_ON(EvtchnGetReferences(Fdo->EvtchnContext) != 0);
    BUG_ON(StoreGetReferences(Fdo->StoreContext) != 0);
    BUG_ON(ConsoleGetReferences(Fdo->ConsoleContext) != 0);
    BUG_ON(GnttabGetReferences(Fdo->GnttabContext) != 0);
    BUG_ON(BalloonGetReferences(Fdo->BalloonContext) != 0);

not_active:
    __FdoSetSystemPowerState(Fdo, PowerSystemHibernate);

    Trace("<====\n");
}

static VOID
FdoFilterCmPartialResourceList(
    IN  PXENBUS_FDO                 Fdo,
    IN  PCM_PARTIAL_RESOURCE_LIST   List
    )
{
    ULONG                           Index;

    UNREFERENCED_PARAMETER(Fdo);

    for (Index = 0; Index < List->Count; Index++) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor = &List->PartialDescriptors[Index];

        //
        // These are additional resources that XENBUS requested, so they must
        // be filtered out before the underlying PCI bus driver sees them. Happily
        // it appears that swapping the type to DevicePrivate causes PCI.SYS to ignore
        // them.
        //
        if (Descriptor->Type == CmResourceTypeInterrupt &&
            (Descriptor->Flags & CM_RESOURCE_INTERRUPT_MESSAGE))
            Descriptor->Type = CmResourceTypeDevicePrivate;
    }
}

#define BALLOON_WARN_TIMEOUT        10
#define BALLOON_BUGCHECK_TIMEOUT    1200

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
FdoStartDevice(
    IN  PXENBUS_FDO                 Fdo,
    IN  PIRP                        Irp
    )
{
    PIO_STACK_LOCATION              StackLocation;
    PCM_RESOURCE_LIST               ResourceList;
    PCM_FULL_RESOURCE_DESCRIPTOR    Descriptor;
    ULONG                           Size;
    NTSTATUS                        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    // Raw

    ResourceList = StackLocation->Parameters.StartDevice.AllocatedResources;
    FdoDumpCmResourceList(Fdo, FALSE, ResourceList);

    ASSERT3U(ResourceList->Count, ==, 1);
    Descriptor = &ResourceList->List[0];

    ASSERT3U(Descriptor->InterfaceType, ==, PCIBus);
    ASSERT3U(Descriptor->BusNumber, ==, 0);

    Size = FIELD_OFFSET(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors) +
           (Descriptor->PartialResourceList.Count) * sizeof (CM_PARTIAL_RESOURCE_DESCRIPTOR);

    Fdo->RawResourceList = __FdoAllocate(Size);

    status = STATUS_NO_MEMORY;
    if (Fdo->RawResourceList == NULL)
        goto fail1;

    RtlCopyMemory(Fdo->RawResourceList, &Descriptor->PartialResourceList, Size);

    FdoFilterCmPartialResourceList(Fdo, &Descriptor->PartialResourceList);

    // Translated

    ResourceList = StackLocation->Parameters.StartDevice.AllocatedResourcesTranslated;
    FdoDumpCmResourceList(Fdo, TRUE, ResourceList);

    ASSERT3U(ResourceList->Count, ==, 1);
    Descriptor = &ResourceList->List[0];

    ASSERT3U(Descriptor->InterfaceType, ==, PCIBus);
    ASSERT3U(Descriptor->BusNumber, ==, 0);

    Size = FIELD_OFFSET(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors) +
           (Descriptor->PartialResourceList.Count) * sizeof (CM_PARTIAL_RESOURCE_DESCRIPTOR);

    Fdo->TranslatedResourceList = __FdoAllocate(Size);

    status = STATUS_NO_MEMORY;
    if (Fdo->TranslatedResourceList == NULL)
        goto fail2;

    RtlCopyMemory(Fdo->TranslatedResourceList, &Descriptor->PartialResourceList, Size);

    FdoFilterCmPartialResourceList(Fdo, &Descriptor->PartialResourceList);

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail3;

    if (!__FdoIsActive(Fdo))
        goto not_active;

    status = FdoCreateInterrupt(Fdo);
    if (!NT_SUCCESS(status))
        goto fail4;

    KeInitializeEvent(&Fdo->ScanEvent, NotificationEvent, FALSE);

    status = ThreadCreate(FdoScan, Fdo, &Fdo->ScanThread);
    if (!NT_SUCCESS(status))
        goto fail5;

    InitializeMutex(&Fdo->BalloonSuspendMutex);

    KeInitializeEvent(&Fdo->SuspendEvent, NotificationEvent, FALSE);

    status = ThreadCreate(FdoSuspend, Fdo, &Fdo->SuspendThread);
    if (!NT_SUCCESS(status))
        goto fail6;

    if (Fdo->BalloonInterface.Interface.Context != NULL) {
        KeInitializeEvent(&Fdo->BalloonEvent, NotificationEvent, FALSE);

        status = ThreadCreate(FdoBalloon, Fdo, &Fdo->BalloonThread);
        if (!NT_SUCCESS(status))
            goto fail7;
    }

not_active:
    status = FdoD3ToD0(Fdo);
    if (!NT_SUCCESS(status))
        goto fail8;

    if (Fdo->BalloonInterface.Interface.Context != NULL) {
        LARGE_INTEGER   Timeout;

        ASSERT(__FdoIsActive(Fdo));

        //
        // Balloon inflation should complete within a reasonable
        // time (otherwise the target is probably unreasonable).
        //
        Timeout.QuadPart = TIME_RELATIVE(TIME_S(BALLOON_WARN_TIMEOUT));

        status = KeWaitForSingleObject(&Fdo->BalloonEvent,
                                        Executive,
                                        KernelMode,
                                        FALSE,
                                        &Timeout);
        if (status == STATUS_TIMEOUT) {
            Warning("waiting for balloon\n");

            //
            // If inflation does not complete after a lengthy timeout
            // then it is unlikely that it ever will. In this case we
            // cause a bugcheck.
            //
            Timeout.QuadPart = TIME_RELATIVE(TIME_S((BALLOON_BUGCHECK_TIMEOUT - BALLOON_WARN_TIMEOUT)));

            status = KeWaitForSingleObject(&Fdo->BalloonEvent,
                                            Executive,
                                            KernelMode,
                                            FALSE,
                                            &Timeout);
            if (status == STATUS_TIMEOUT)
                BUG("BALLOON INFLATION TIMEOUT\n");
        }
    }

    __FdoSetDevicePnpState(Fdo, Started);

    if (__FdoIsActive(Fdo))
        ThreadWake(Fdo->ScanThread);

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail8:
    Error("fail8\n");

    if (!__FdoIsActive(Fdo))
        goto fail4;
    
    if (Fdo->BalloonInterface.Interface.Context != NULL) {
        ThreadAlert(Fdo->BalloonThread);
        ThreadJoin(Fdo->BalloonThread);
        Fdo->BalloonThread = NULL;
    }

fail7:
    Error("fail7\n");

    if (Fdo->BalloonInterface.Interface.Context != NULL)
        RtlZeroMemory(&Fdo->BalloonEvent, sizeof (KEVENT));

    ThreadAlert(Fdo->SuspendThread);
    ThreadJoin(Fdo->SuspendThread);
    Fdo->SuspendThread = NULL;

fail6:
    Error("fail6\n");

    RtlZeroMemory(&Fdo->SuspendEvent, sizeof (KEVENT));

    RtlZeroMemory(&Fdo->BalloonSuspendMutex, sizeof (MUTEX));

    ThreadAlert(Fdo->ScanThread);
    ThreadJoin(Fdo->ScanThread);
    Fdo->ScanThread = NULL;

fail5:
    Error("fail5\n");

    RtlZeroMemory(&Fdo->ScanEvent, sizeof (KEVENT));

    FdoDestroyInterrupt(Fdo);

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    __FdoFree(Fdo->TranslatedResourceList);
    Fdo->TranslatedResourceList = NULL;

fail2:
    Error("fail2\n");

    __FdoFree(Fdo->RawResourceList);
    Fdo->RawResourceList = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoQueryStopDevice(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    status = STATUS_UNSUCCESSFUL;
    if (Fdo->BalloonInterface.Interface.Context != NULL &&
        XENBUS_BALLOON(GetSize,
                       &Fdo->BalloonInterface) != 0)
        goto fail1;

    __FdoSetDevicePnpState(Fdo, StopPending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoCancelStopDevice(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    Irp->IoStatus.Status = STATUS_SUCCESS;

    __FdoRestoreDevicePnpState(Fdo, StopPending);

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static NTSTATUS
FdoStopDevice(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0)
        FdoD0ToD3(Fdo);

    if (!__FdoIsActive(Fdo))
        goto not_active;

    if (Fdo->BalloonInterface.Interface.Context != NULL) {
        ThreadAlert(Fdo->BalloonThread);
        ThreadJoin(Fdo->BalloonThread);
        Fdo->BalloonThread = NULL;

        RtlZeroMemory(&Fdo->BalloonEvent, sizeof (KEVENT));
    }

    ThreadAlert(Fdo->SuspendThread);
    ThreadJoin(Fdo->SuspendThread);
    Fdo->SuspendThread = NULL;

    RtlZeroMemory(&Fdo->SuspendEvent, sizeof (KEVENT));

    RtlZeroMemory(&Fdo->BalloonSuspendMutex, sizeof (MUTEX));

    ThreadAlert(Fdo->ScanThread);
    ThreadJoin(Fdo->ScanThread);
    Fdo->ScanThread = NULL;

    RtlZeroMemory(&Fdo->ScanEvent, sizeof (KEVENT));

    FdoDestroyInterrupt(Fdo);

not_active:
    __FdoFree(Fdo->TranslatedResourceList);
    Fdo->TranslatedResourceList = NULL;

    __FdoFree(Fdo->RawResourceList);
    Fdo->RawResourceList = NULL;

    __FdoSetDevicePnpState(Fdo, Stopped);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static NTSTATUS
FdoQueryRemoveDevice(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    status = STATUS_UNSUCCESSFUL;
    if (Fdo->BalloonInterface.Interface.Context != NULL &&
        XENBUS_BALLOON(GetSize,
                       &Fdo->BalloonInterface) != 0)
        goto fail1;

    __FdoSetDevicePnpState(Fdo, RemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoCancelRemoveDevice(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __FdoRestoreDevicePnpState(Fdo, RemovePending);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static NTSTATUS
FdoSurpriseRemoval(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    )
{
    PLIST_ENTRY     ListEntry;
    NTSTATUS        status;

    __FdoSetDevicePnpState(Fdo, SurpriseRemovePending);

    __FdoAcquireMutex(Fdo);

    for (ListEntry = Fdo->List.Flink;
         ListEntry != &Fdo->List;
         ListEntry = ListEntry->Flink) {
        PXENBUS_DX  Dx = CONTAINING_RECORD(ListEntry, XENBUS_DX, ListEntry);
        PXENBUS_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (!PdoIsMissing(Pdo))
            PdoSetMissing(Pdo, "FDO surprise removed");
    }

    __FdoReleaseMutex(Fdo);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
FdoRemoveDevice(
    IN  PXENBUS_FDO                     Fdo,
    IN  PIRP                            Irp
    )
{
    PLIST_ENTRY                         ListEntry;
    NTSTATUS                            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    if (__FdoGetPreviousDevicePnpState(Fdo) != Started)
        goto done;

    if (__FdoIsActive(Fdo)) {
        Trace("waiting for scan thread...\n");

        KeClearEvent(&Fdo->ScanEvent);
        ThreadWake(Fdo->ScanThread);

        (VOID) KeWaitForSingleObject(&Fdo->ScanEvent,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);

        Trace("done\n");
    }

    __FdoAcquireMutex(Fdo);

    ListEntry = Fdo->List.Flink;
    while (ListEntry != &Fdo->List) {
        PLIST_ENTRY Flink = ListEntry->Flink;
        PXENBUS_DX  Dx = CONTAINING_RECORD(ListEntry, XENBUS_DX, ListEntry);
        PXENBUS_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (!PdoIsMissing(Pdo))
            PdoSetMissing(Pdo, "FDO removed");

        if (PdoGetDevicePnpState(Pdo) != SurpriseRemovePending)
            PdoSetDevicePnpState(Pdo, Deleted);

        if (PdoGetDevicePnpState(Pdo) == Deleted)
            PdoDestroy(Pdo);

        ListEntry = Flink;
    }

    __FdoReleaseMutex(Fdo);

    if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0)
        FdoD0ToD3(Fdo);

    if (!__FdoIsActive(Fdo))
        goto not_active;

    if (Fdo->BalloonInterface.Interface.Context != NULL) {
        ThreadAlert(Fdo->BalloonThread);
        ThreadJoin(Fdo->BalloonThread);
        Fdo->BalloonThread = NULL;

        RtlZeroMemory(&Fdo->BalloonEvent, sizeof (KEVENT));
    }

    ThreadAlert(Fdo->SuspendThread);
    ThreadJoin(Fdo->SuspendThread);
    Fdo->SuspendThread = NULL;

    RtlZeroMemory(&Fdo->SuspendEvent, sizeof (KEVENT));

    RtlZeroMemory(&Fdo->BalloonSuspendMutex, sizeof (MUTEX));

    ThreadAlert(Fdo->ScanThread);
    ThreadJoin(Fdo->ScanThread);
    Fdo->ScanThread = NULL;

    RtlZeroMemory(&Fdo->ScanEvent, sizeof (KEVENT));

    FdoDestroyInterrupt(Fdo);

not_active:
    __FdoFree(Fdo->TranslatedResourceList);
    Fdo->TranslatedResourceList = NULL;

    __FdoFree(Fdo->RawResourceList);
    Fdo->RawResourceList = NULL;

done:
    __FdoSetDevicePnpState(Fdo, Deleted);

    // We must release our reference before the PDO is destroyed
    FdoReleaseLowerBusInterface(Fdo);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    __FdoAcquireMutex(Fdo);
    ASSERT3U(Fdo->References, !=, 0);
    --Fdo->References;
    __FdoReleaseMutex(Fdo);

    if (Fdo->References == 0) {
        DriverAcquireMutex();
        FdoDestroy(Fdo);
        DriverReleaseMutex();
    }

    return status;
}

#define SCAN_PAUSE  10

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
FdoQueryDeviceRelations(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    ULONG               Size;
    PDEVICE_RELATIONS   Relations;
    ULONG               Count;
    PLIST_ENTRY         ListEntry;
    BOOLEAN             Warned;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    status = Irp->IoStatus.Status;

    if (StackLocation->Parameters.QueryDeviceRelations.Type != BusRelations) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    Warned = FALSE;

    for (;;) {
        LARGE_INTEGER   Timeout;

        if (!__FdoIsActive(Fdo))
            break;

        Timeout.QuadPart = TIME_RELATIVE(TIME_S(SCAN_PAUSE));

        status = KeWaitForSingleObject(&Fdo->ScanEvent,
                                       Executive,
                                       KernelMode,
                                       FALSE,
                                       &Timeout);
        if (status != STATUS_TIMEOUT)
            break;

        if (!Warned) {
            Warning("waiting for device enumeration\n");
            Warned = TRUE;
        }
    }

    __FdoAcquireMutex(Fdo);

    Count = 0;
    for (ListEntry = Fdo->List.Flink;
         ListEntry != &Fdo->List;
         ListEntry = ListEntry->Flink)
        Count++;

    Size = FIELD_OFFSET(DEVICE_RELATIONS, Objects) + (sizeof (PDEVICE_OBJECT) * __max(Count, 1));

    Relations = __AllocatePoolWithTag(PagedPool, Size, 'SUB');

    status = STATUS_NO_MEMORY;
    if (Relations == NULL)
        goto fail1;

    for (ListEntry = Fdo->List.Flink;
         ListEntry != &Fdo->List;
         ListEntry = ListEntry->Flink) {
        PXENBUS_DX  Dx = CONTAINING_RECORD(ListEntry, XENBUS_DX, ListEntry);
        PXENBUS_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (PdoIsMissing(Pdo))
            continue;

        if (PdoGetDevicePnpState(Pdo) == Present)
            PdoSetDevicePnpState(Pdo, Enumerated);

        ObReferenceObject(Dx->DeviceObject);
        Relations->Objects[Relations->Count++] = Dx->DeviceObject;
    }

    ASSERT3U(Relations->Count, <=, Count);

    Trace("%d PDO(s)\n", Relations->Count);

    __FdoReleaseMutex(Fdo);

    Irp->IoStatus.Information = (ULONG_PTR)Relations;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail2;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    __FdoAcquireMutex(Fdo);

    ListEntry = Fdo->List.Flink;
    while (ListEntry != &Fdo->List) {
        PXENBUS_DX  Dx = CONTAINING_RECORD(ListEntry, XENBUS_DX, ListEntry);
        PXENBUS_PDO Pdo = Dx->Pdo;
        PLIST_ENTRY Next = ListEntry->Flink;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (PdoGetDevicePnpState(Pdo) == Deleted &&
            PdoIsMissing(Pdo))
            PdoDestroy(Pdo);

        ListEntry = Next;
    }

    __FdoReleaseMutex(Fdo);

done:
    return status;

fail2:
    Error("fail2\n");

    __FdoAcquireMutex(Fdo);

fail1:
    Error("fail1 (%08x)\n", status);

    __FdoReleaseMutex(Fdo);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoQueryCapabilities(
    IN  PXENBUS_FDO         Fdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    PDEVICE_CAPABILITIES    Capabilities;
    SYSTEM_POWER_STATE      SystemPowerState;
    NTSTATUS                status;

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Capabilities = StackLocation->Parameters.DeviceCapabilities.Capabilities;

    Fdo->LowerDeviceCapabilities = *Capabilities;

    // Make sure that the FDO is non-removable
    Capabilities->Removable = 0;

    for (SystemPowerState = 0; SystemPowerState < PowerSystemMaximum; SystemPowerState++) {
        DEVICE_POWER_STATE  DevicePowerState;

        DevicePowerState = Fdo->LowerDeviceCapabilities.DeviceState[SystemPowerState];
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoDeviceUsageNotification(
    IN  PXENBUS_FDO                 Fdo,
    IN  PIRP                        Irp
    )
{
    PIO_STACK_LOCATION              StackLocation;
    DEVICE_USAGE_NOTIFICATION_TYPE  Type;
    BOOLEAN                         InPath;
    BOOLEAN                         NotDisableable;
    NTSTATUS                        status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Type = StackLocation->Parameters.UsageNotification.Type;
    InPath = StackLocation->Parameters.UsageNotification.InPath;

    if (InPath) {
        Trace("%s: ADDING %s\n",
              __FdoGetName(Fdo),
              DeviceUsageNotificationTypeName(Type));
        Fdo->Usage[Type]++;
    } else {
        if (Fdo->Usage[Type] != 0) {
            Trace("%s: REMOVING %s\n",
                  __FdoGetName(Fdo),
                  DeviceUsageNotificationTypeName(Type));
            --Fdo->Usage[Type];
        }
    }

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    NotDisableable = FALSE;    
    for (Type = 0; Type <= DeviceUsageTypeDumpFile; Type++) {
        if (Fdo->Usage[Type] != 0) {
            NotDisableable = TRUE;
            break;
        }
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (Fdo->NotDisableable != NotDisableable) {
        Fdo->NotDisableable = NotDisableable;
    
        IoInvalidateDeviceState(__FdoGetPhysicalDeviceObject(Fdo));
    }

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoQueryPnpDeviceState(
    IN  PXENBUS_FDO                 Fdo,
    IN  PIRP                        Irp
    )
{
    ULONG_PTR                       State;
    NTSTATUS                        status;

    if (Irp->IoStatus.Status == STATUS_SUCCESS)
        State = Irp->IoStatus.Information;
    else if (Irp->IoStatus.Status == STATUS_NOT_SUPPORTED)
        State = 0;
    else
        goto done;

    if (Fdo->NotDisableable) {
        Info("%s: not disableable\n", __FdoGetName(Fdo));
        State |= PNP_DEVICE_NOT_DISABLEABLE;
    }

    Irp->IoStatus.Information = State;
    Irp->IoStatus.Status = STATUS_SUCCESS;

done:
    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static NTSTATUS
FdoDispatchPnp(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    Trace("====> (%02x:%s)\n",
          MinorFunction, 
          PnpMinorFunctionName(MinorFunction)); 

    switch (StackLocation->MinorFunction) {
    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
        status = FdoFilterResourceRequirements(Fdo, Irp);
        break;

    case IRP_MN_START_DEVICE:
        status = FdoStartDevice(Fdo, Irp);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        status = FdoQueryStopDevice(Fdo, Irp);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        status = FdoCancelStopDevice(Fdo, Irp);
        break;

    case IRP_MN_STOP_DEVICE:
        status = FdoStopDevice(Fdo, Irp);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        status = FdoQueryRemoveDevice(Fdo, Irp);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        status = FdoSurpriseRemoval(Fdo, Irp);
        break;

    case IRP_MN_REMOVE_DEVICE:
        status = FdoRemoveDevice(Fdo, Irp);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        status = FdoCancelRemoveDevice(Fdo, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        status = FdoQueryDeviceRelations(Fdo, Irp);
        break;

    case IRP_MN_QUERY_CAPABILITIES:
        status = FdoQueryCapabilities(Fdo, Irp);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        status = FdoDeviceUsageNotification(Fdo, Irp);
        break;

    case IRP_MN_QUERY_PNP_DEVICE_STATE:
        status = FdoQueryPnpDeviceState(Fdo, Irp);
        break;

    default:
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
        break;
    }

    Trace("<==== (%02x:%s)(%08x)\n",
          MinorFunction, 
          PnpMinorFunctionName(MinorFunction),
          status); 

    return status;
}

static NTSTATUS
FdoSetDevicePowerUp(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __FdoGetDevicePowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Info("%s: %s -> %s\n",
         __FdoGetName(Fdo),
         DevicePowerStateName(__FdoGetDevicePowerState(Fdo)),
         DevicePowerStateName(DeviceState));

    ASSERT3U(DeviceState, ==, PowerDeviceD0);
    status = FdoD3ToD0(Fdo);
    ASSERT(NT_SUCCESS(status));

done:
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoSetDevicePowerDown(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __FdoGetDevicePowerState(Fdo));

    Info("%s: %s -> %s\n",
         __FdoGetName(Fdo),
         DevicePowerStateName(__FdoGetDevicePowerState(Fdo)),
         DevicePowerStateName(DeviceState));

    ASSERT3U(DeviceState, ==, PowerDeviceD3);

    if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0)
        FdoD0ToD3(Fdo);

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoSetDevicePower(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <,  PowerActionShutdown);

    if (DeviceState == __FdoGetDevicePowerState(Fdo)) {
        status = FdoForwardIrpSynchronously(Fdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (DeviceState < __FdoGetDevicePowerState(Fdo)) ?
             FdoSetDevicePowerUp(Fdo, Irp) :
             FdoSetDevicePowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

__drv_functionClass(REQUEST_POWER_COMPLETE)
__drv_sameIRQL
VOID
FdoRequestSetDevicePowerCompletion(
    IN  PDEVICE_OBJECT      DeviceObject,
    IN  UCHAR               MinorFunction,
    IN  POWER_STATE         PowerState,
    IN  PVOID               Context,
    IN  PIO_STATUS_BLOCK    IoStatus
    )
{
    PKEVENT                 Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(MinorFunction);
    UNREFERENCED_PARAMETER(PowerState);

    ASSERT(NT_SUCCESS(IoStatus->Status));

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static VOID
FdoRequestSetDevicePower(
    IN  PXENBUS_FDO         Fdo,
    IN  DEVICE_POWER_STATE  DeviceState
    )
{
    POWER_STATE             PowerState;
    KEVENT                  Event;
    NTSTATUS                status;

    Trace("%s\n", DevicePowerStateName(DeviceState));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    PowerState.DeviceState = DeviceState;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = PoRequestPowerIrp(Fdo->LowerDeviceObject,
                               IRP_MN_SET_POWER,
                               PowerState,
                               FdoRequestSetDevicePowerCompletion,
                               &Event,
                               NULL);
    ASSERT(NT_SUCCESS(status));

    (VOID) KeWaitForSingleObject(&Event,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);
}

static NTSTATUS
FdoSetSystemPowerUp(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{

    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __FdoGetSystemPowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Info("%s: %s -> %s\n",
         __FdoGetName(Fdo),
         SystemPowerStateName(__FdoGetSystemPowerState(Fdo)),
         SystemPowerStateName(SystemState));

    if (SystemState < PowerSystemHibernate &&
        __FdoGetSystemPowerState(Fdo) >= PowerSystemHibernate) {
        __FdoSetSystemPowerState(Fdo, PowerSystemHibernate);
        FdoS4ToS3(Fdo);
    }

    __FdoSetSystemPowerState(Fdo, SystemState);

    DeviceState = Fdo->LowerDeviceCapabilities.DeviceState[SystemState];
    FdoRequestSetDevicePower(Fdo, DeviceState);

done:
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoSetSystemPowerDown(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __FdoGetSystemPowerState(Fdo));

    DeviceState = Fdo->LowerDeviceCapabilities.DeviceState[SystemState];

    FdoRequestSetDevicePower(Fdo, DeviceState);

    Info("%s: %s -> %s\n",
         __FdoGetName(Fdo),
         SystemPowerStateName(__FdoGetSystemPowerState(Fdo)),
         SystemPowerStateName(SystemState));

    if (SystemState >= PowerSystemHibernate &&
        __FdoGetSystemPowerState(Fdo) < PowerSystemHibernate) {
        __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
        FdoS3ToS4(Fdo);
    }

    __FdoSetSystemPowerState(Fdo, SystemState);

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoSetSystemPower(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <,  PowerActionShutdown);

    if (SystemState == __FdoGetSystemPowerState(Fdo)) {
        status = FdoForwardIrpSynchronously(Fdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (SystemState < __FdoGetSystemPowerState(Fdo)) ?
             FdoSetSystemPowerUp(Fdo, Irp) :
             FdoSetSystemPowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

static NTSTATUS
FdoQueryDevicePowerUp(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __FdoGetDevicePowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoQueryDevicePowerDown(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __FdoGetDevicePowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoQueryDevicePower(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <,  PowerActionShutdown);

    if (DeviceState == __FdoGetDevicePowerState(Fdo)) {
        status = FdoForwardIrpSynchronously(Fdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (DeviceState < __FdoGetDevicePowerState(Fdo)) ?
             FdoQueryDevicePowerUp(Fdo, Irp) :
             FdoQueryDevicePowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

__drv_functionClass(REQUEST_POWER_COMPLETE)
__drv_sameIRQL
VOID
FdoRequestQueryDevicePowerCompletion(
    IN  PDEVICE_OBJECT      DeviceObject,
    IN  UCHAR               MinorFunction,
    IN  POWER_STATE         PowerState,
    IN  PVOID               Context,
    IN  PIO_STATUS_BLOCK    IoStatus
    )
{
    PKEVENT                 Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(MinorFunction);
    UNREFERENCED_PARAMETER(PowerState);

    ASSERT(NT_SUCCESS(IoStatus->Status));

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static VOID
FdoRequestQueryDevicePower(
    IN  PXENBUS_FDO         Fdo,
    IN  DEVICE_POWER_STATE  DeviceState
    )
{
    POWER_STATE             PowerState;
    KEVENT                  Event;
    NTSTATUS                status;

    Trace("%s\n", DevicePowerStateName(DeviceState));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    PowerState.DeviceState = DeviceState;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = PoRequestPowerIrp(Fdo->LowerDeviceObject,
                               IRP_MN_QUERY_POWER,
                               PowerState,
                               FdoRequestQueryDevicePowerCompletion,
                               &Event,
                               NULL);
    ASSERT(NT_SUCCESS(status));

    (VOID) KeWaitForSingleObject(&Event,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);
}

static NTSTATUS
FdoQuerySystemPowerUp(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{

    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __FdoGetSystemPowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    DeviceState = Fdo->LowerDeviceCapabilities.DeviceState[SystemState];

    FdoRequestQueryDevicePower(Fdo, DeviceState);

done:
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoQuerySystemPowerDown(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __FdoGetSystemPowerState(Fdo));

    DeviceState = Fdo->LowerDeviceCapabilities.DeviceState[SystemState];

    FdoRequestQueryDevicePower(Fdo, DeviceState);

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoQuerySystemPower(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <,  PowerActionShutdown);

    if (SystemState == __FdoGetSystemPowerState(Fdo)) {
        status = FdoForwardIrpSynchronously(Fdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (SystemState < __FdoGetSystemPowerState(Fdo)) ?
             FdoQuerySystemPowerUp(Fdo, Irp) :
             FdoQuerySystemPowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction),
          status);

    return status;
}

static NTSTATUS
FdoDevicePower(
    IN  PXENBUS_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENBUS_FDO         Fdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  StackLocation;
        UCHAR               MinorFunction;

        if (Fdo->DevicePowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Fdo->DevicePowerIrp;

        if (Irp == NULL)
            continue;

        Fdo->DevicePowerIrp = NULL;
        KeMemoryBarrier();

        StackLocation = IoGetCurrentIrpStackLocation(Irp);
        MinorFunction = StackLocation->MinorFunction;

        switch (StackLocation->MinorFunction) {
        case IRP_MN_SET_POWER:
            (VOID) FdoSetDevicePower(Fdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) FdoQueryDevicePower(Fdo, Irp);
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoSystemPower(
    IN  PXENBUS_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENBUS_FDO         Fdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  StackLocation;
        UCHAR               MinorFunction;

        if (Fdo->SystemPowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Fdo->SystemPowerIrp;

        if (Irp == NULL)
            continue;

        Fdo->SystemPowerIrp = NULL;
        KeMemoryBarrier();

        StackLocation = IoGetCurrentIrpStackLocation(Irp);
        MinorFunction = StackLocation->MinorFunction;

        switch (StackLocation->MinorFunction) {
        case IRP_MN_SET_POWER:
            (VOID) FdoSetSystemPower(Fdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) FdoQuerySystemPower(Fdo, Irp);
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoDispatchPower(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    POWER_STATE_TYPE    PowerType;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    if (MinorFunction != IRP_MN_QUERY_POWER &&
        MinorFunction != IRP_MN_SET_POWER) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    PowerType = StackLocation->Parameters.Power.Type;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    if (PowerAction >= PowerActionShutdown) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    switch (PowerType) {
    case DevicePowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Fdo->DevicePowerIrp, ==, NULL);
        Fdo->DevicePowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Fdo->DevicePowerThread);

        status = STATUS_PENDING;
        break;

    case SystemPowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Fdo->SystemPowerIrp, ==, NULL);
        Fdo->SystemPowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Fdo->SystemPowerThread);

        status = STATUS_PENDING;
        break;

    default:
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
        break;
    }

done:
    return status;
}

static NTSTATUS
FdoDispatchDefault(
    IN  PXENBUS_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

NTSTATUS
FdoDispatch(
    IN  PXENBUS_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->MajorFunction) {
    case IRP_MJ_PNP:
        status = FdoDispatchPnp(Fdo, Irp);
        break;

    case IRP_MJ_POWER:
        status = FdoDispatchPower(Fdo, Irp);
        break;

    default:
        status = FdoDispatchDefault(Fdo, Irp);
        break;
    }

    return status;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
FdoQueryInterface(
    IN  PXENBUS_FDO     Fdo,
    IN  const GUID      *Guid,
    IN  ULONG           Version,
    OUT PINTERFACE      Interface,
    IN  ULONG           Size,
    IN  BOOLEAN         Optional
    )
{
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = Guid;
    StackLocation->Parameters.QueryInterface.Size = (USHORT)Size;
    StackLocation->Parameters.QueryInterface.Version = (USHORT)Version;
    StackLocation->Parameters.QueryInterface.Interface = Interface;
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_NOT_SUPPORTED && Optional)
            goto done;

        goto fail2;
    }

done:
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define FDO_QUERY_INTERFACE(                                                            \
    _Fdo,                                                                               \
    _ProviderName,                                                                      \
    _InterfaceName,                                                                     \
    _Interface,                                                                         \
    _Size,                                                                              \
    _Optional)                                                                          \
    FdoQueryInterface((_Fdo),                                                           \
                      &GUID_ ## _ProviderName ## _ ## _InterfaceName ## _INTERFACE,     \
                      _ProviderName ## _ ## _InterfaceName ## _INTERFACE_VERSION_MAX,   \
                      (_Interface),                                                     \
                      (_Size),                                                          \
                      (_Optional))


#define FDO_HOLE_SIZE   (2ull << 20)

static FORCEINLINE NTSTATUS
__FdoAllocateBuffer(
    IN  PXENBUS_FDO     Fdo
    )
{
    ULONG               Size;
    PHYSICAL_ADDRESS    Low;
    PHYSICAL_ADDRESS    High;
    PHYSICAL_ADDRESS    Align;
    PVOID               Buffer;
    PMDL                Mdl;
    NTSTATUS            status;

    Size = 2 << 20;

    Low.QuadPart = 0;
    High = SystemMaximumPhysicalAddress();
    Align.QuadPart = Size;

    Buffer = MmAllocateContiguousNodeMemory((SIZE_T)Size,
                                            Low,
                                            High,
                                            Align,
                                            PAGE_READWRITE,
                                            MM_ANY_NODE_OK);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Mdl = IoAllocateMdl(Buffer,
                        Size,
                        FALSE,
                        FALSE,
                        NULL);

    status = STATUS_NO_MEMORY;
    if (Mdl == NULL)
        goto fail2;

    MmBuildMdlForNonPagedPool(Mdl);

    ASSERT3U(Mdl->ByteOffset, ==, 0);
    ASSERT3U(Mdl->ByteCount, ==, Size);

    Fdo->Buffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    Fdo->Mdl = Mdl;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    MmFreeContiguousMemory(Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__FdoFreeBuffer(
    IN  PXENBUS_FDO Fdo
    )
{
    ExFreePool(Fdo->Mdl);
    Fdo->Mdl = NULL;

    MmFreeContiguousMemory(Fdo->Buffer);
    Fdo->Buffer = NULL;
}

static BOOLEAN
FdoIsBalloonEnabled(
    IN  PXENBUS_FDO Fdo
    )
{
    CHAR            Key[] = "XEN:BALLOON=";
    PANSI_STRING    Option;
    PCHAR           Value;
    BOOLEAN         Enabled;
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Fdo);

    Enabled = TRUE;

    status = RegistryQuerySystemStartOption(Key, &Option);
    if (!NT_SUCCESS(status))
        goto done;

    Value = Option->Buffer + sizeof (Key) - 1;

    if (strcmp(Value, "OFF") == 0)
        Enabled = FALSE;

    RegistryFreeSzValue(Option);

done:
    return Enabled;
}

NTSTATUS
FdoCreate(
    IN  PDEVICE_OBJECT          PhysicalDeviceObject
    )
{
    PDEVICE_OBJECT              FunctionDeviceObject;
    PXENBUS_DX                  Dx;
    PXENBUS_FDO                 Fdo;
    PCI_COMMON_HEADER           Header;
    NTSTATUS                    status;

#pragma prefast(suppress:28197) // Possibly leaking memory 'FunctionDeviceObject'
    status = IoCreateDevice(DriverGetDriverObject(),
                            sizeof (XENBUS_DX),
                            NULL,
                            FILE_DEVICE_BUS_EXTENDER,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &FunctionDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXENBUS_DX)FunctionDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XENBUS_DX));

    Dx->Type = FUNCTION_DEVICE_OBJECT;
    Dx->DeviceObject = FunctionDeviceObject;
    Dx->DevicePnpState = Added;
    Dx->SystemPowerState = PowerSystemWorking;
    Dx->DevicePowerState = PowerDeviceD3;

    Fdo = __FdoAllocate(sizeof (XENBUS_FDO));

    status = STATUS_NO_MEMORY;
    if (Fdo == NULL)
        goto fail2;

    Fdo->Dx = Dx;
    Fdo->PhysicalDeviceObject = PhysicalDeviceObject;
    Fdo->LowerDeviceObject = IoAttachDeviceToDeviceStack(FunctionDeviceObject,
                                                         PhysicalDeviceObject);

    status = ThreadCreate(FdoSystemPower, Fdo, &Fdo->SystemPowerThread);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ThreadCreate(FdoDevicePower, Fdo, &Fdo->DevicePowerThread);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = FdoAcquireLowerBusInterface(Fdo);
    if (!NT_SUCCESS(status))
        goto fail5;

    if (FdoGetBusData(Fdo,
                      PCI_WHICHSPACE_CONFIG,
                      &Header,
                      0,
                      sizeof (PCI_COMMON_HEADER)) == 0)
        goto fail6;

    status = __FdoSetVendorName(Fdo,
                                Header.VendorID,
                                Header.DeviceID);
    if (!NT_SUCCESS(status))
        goto fail7;

    __FdoSetName(Fdo);

    status = FdoSetActive(Fdo);
    if (!NT_SUCCESS(status))
        goto fail8;

    if (!__FdoIsActive(Fdo))
        goto done;

    status = __FdoAllocateBuffer(Fdo);
    if (!NT_SUCCESS(status))
        goto fail9;

    status = DebugInitialize(Fdo, &Fdo->DebugContext);
    if (!NT_SUCCESS(status))
        goto fail10;

    status = SuspendInitialize(Fdo, &Fdo->SuspendContext);
    if (!NT_SUCCESS(status))
        goto fail11;

    status = SharedInfoInitialize(Fdo, &Fdo->SharedInfoContext);
    if (!NT_SUCCESS(status))
        goto fail12;

    status = EvtchnInitialize(Fdo, &Fdo->EvtchnContext);
    if (!NT_SUCCESS(status))
        goto fail13;

    status = RangeSetInitialize(Fdo, &Fdo->RangeSetContext);
    if (!NT_SUCCESS(status))
        goto fail14;

    status = CacheInitialize(Fdo, &Fdo->CacheContext);
    if (!NT_SUCCESS(status))
        goto fail15;

    status = GnttabInitialize(Fdo, &Fdo->GnttabContext);
    if (!NT_SUCCESS(status))
        goto fail16;

    status = StoreInitialize(Fdo, &Fdo->StoreContext);
    if (!NT_SUCCESS(status))
        goto fail17;

    status = ConsoleInitialize(Fdo, &Fdo->ConsoleContext);
    if (!NT_SUCCESS(status))
        goto fail18;

    status = UnplugInitialize(Fdo, &Fdo->UnplugContext);
    if (!NT_SUCCESS(status))
        goto fail19;

    if (FdoIsBalloonEnabled(Fdo)) {
        status = BalloonInitialize(Fdo, &Fdo->BalloonContext);
        if (!NT_SUCCESS(status))
            goto fail20;
    }

    status = DebugGetInterface(__FdoGetDebugContext(Fdo),
                               XENBUS_DEBUG_INTERFACE_VERSION_MAX,
                               (PINTERFACE)&Fdo->DebugInterface,
                               sizeof (Fdo->DebugInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT(Fdo->DebugInterface.Interface.Context != NULL);

    status = SuspendGetInterface(__FdoGetSuspendContext(Fdo),
                                 XENBUS_SUSPEND_INTERFACE_VERSION_MAX,
                                 (PINTERFACE)&Fdo->SuspendInterface,
                                 sizeof (Fdo->SuspendInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT(Fdo->SuspendInterface.Interface.Context != NULL);

    status = EvtchnGetInterface(__FdoGetEvtchnContext(Fdo),
                                XENBUS_EVTCHN_INTERFACE_VERSION_MAX,
                                (PINTERFACE)&Fdo->EvtchnInterface,
                                sizeof (Fdo->EvtchnInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT(Fdo->EvtchnInterface.Interface.Context != NULL);

    status = RangeSetGetInterface(__FdoGetRangeSetContext(Fdo),
                                  XENBUS_RANGE_SET_INTERFACE_VERSION_MAX,
                                  (PINTERFACE)&Fdo->RangeSetInterface,
                                  sizeof (Fdo->RangeSetInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT(Fdo->RangeSetInterface.Interface.Context != NULL);

    status = StoreGetInterface(__FdoGetStoreContext(Fdo),
                               XENBUS_STORE_INTERFACE_VERSION_MAX,
                               (PINTERFACE)&Fdo->StoreInterface,
                               sizeof (Fdo->StoreInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT(Fdo->StoreInterface.Interface.Context != NULL);

    status = ConsoleGetInterface(__FdoGetConsoleContext(Fdo),
                                 XENBUS_CONSOLE_INTERFACE_VERSION_MAX,
                                 (PINTERFACE)&Fdo->ConsoleInterface,
                                 sizeof (Fdo->ConsoleInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT(Fdo->ConsoleInterface.Interface.Context != NULL);

    status = BalloonGetInterface(__FdoGetBalloonContext(Fdo),
                                 XENBUS_BALLOON_INTERFACE_VERSION_MAX,
                                 (PINTERFACE)&Fdo->BalloonInterface,
                                 sizeof (Fdo->BalloonInterface));
    ASSERT(NT_SUCCESS(status));

done:
    InitializeMutex(&Fdo->Mutex);
    InitializeListHead(&Fdo->List);
    Fdo->References = 1;

    (VOID) FdoSetFriendlyName(Fdo, Header.DeviceID);

    Info("%p (%s) %s\n",
         FunctionDeviceObject,
         __FdoGetName(Fdo),
         (__FdoIsActive(Fdo)) ? "[ACTIVE]" : "");

    Dx->Fdo = Fdo;
    FunctionDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverAddFunctionDeviceObject(Fdo);

    return STATUS_SUCCESS;

fail20:
    Error("fail20\n");

    UnplugTeardown(Fdo->UnplugContext);
    Fdo->UnplugContext = NULL;

fail19:
    Error("fail19\n");

    ConsoleTeardown(Fdo->ConsoleContext);
    Fdo->ConsoleContext = NULL;

fail18:
    Error("fail18\n");

    StoreTeardown(Fdo->StoreContext);
    Fdo->StoreContext = NULL;

fail17:
    Error("fail17\n");

    GnttabTeardown(Fdo->GnttabContext);
    Fdo->GnttabContext = NULL;

fail16:
    Error("fail16\n");

    CacheTeardown(Fdo->CacheContext);
    Fdo->CacheContext = NULL;

fail15:
    Error("fail15\n");

    RangeSetTeardown(Fdo->RangeSetContext);
    Fdo->RangeSetContext = NULL;

fail14:
    Error("fail14\n");

    EvtchnTeardown(Fdo->EvtchnContext);
    Fdo->EvtchnContext = NULL;

fail13:
    Error("fail13\n");

    SharedInfoTeardown(Fdo->SharedInfoContext);
    Fdo->SharedInfoContext = NULL;

fail12:
    Error("fail12\n");

    SuspendTeardown(Fdo->SuspendContext);
    Fdo->SuspendContext = NULL;

fail11:
    Error("fail11\n");

    DebugTeardown(Fdo->DebugContext);
    Fdo->DebugContext = NULL;

fail10:
    Error("fail10\n");

    __FdoFreeBuffer(Fdo);

fail9:
    Error("fail9\n");

    //
    // We don't want to call DriverClearActive() so just
    // clear the FDO flag.
    //
    Fdo->Active = FALSE;

fail8:
    Error("fail8\n");

    RtlZeroMemory(Fdo->VendorName, MAXNAMELEN);

fail7:
    Error("fail7\n");

fail6:
    Error("fail6\n");

    FdoReleaseLowerBusInterface(Fdo);

fail5:
    Error("fail5\n");

    ThreadAlert(Fdo->DevicePowerThread);
    ThreadJoin(Fdo->DevicePowerThread);
    Fdo->DevicePowerThread = NULL;
    
fail4:
    Error("fail4\n");

    ThreadAlert(Fdo->SystemPowerThread);
    ThreadJoin(Fdo->SystemPowerThread);
    Fdo->SystemPowerThread = NULL;
    
fail3:
    Error("fail3\n");

#pragma prefast(suppress:28183) // Fdo->LowerDeviceObject could be NULL
    IoDetachDevice(Fdo->LowerDeviceObject);

    Fdo->PhysicalDeviceObject = NULL;
    Fdo->LowerDeviceObject = NULL;
    Fdo->Dx = NULL;

    ASSERT(IsZeroMemory(Fdo, sizeof (XENBUS_FDO)));
    __FdoFree(Fdo);

fail2:
    Error("fail2\n");

    IoDeleteDevice(FunctionDeviceObject);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
FdoDestroy(
    IN  PXENBUS_FDO Fdo
    )
{
    PXENBUS_DX      Dx = Fdo->Dx;
    PDEVICE_OBJECT  FunctionDeviceObject = Dx->DeviceObject;

    ASSERT(IsListEmpty(&Fdo->List));
    ASSERT3U(Fdo->References, ==, 0);
    ASSERT3U(__FdoGetDevicePnpState(Fdo), ==, Deleted);

    DriverRemoveFunctionDeviceObject(Fdo);

    Fdo->NotDisableable = FALSE;

    Info("%p (%s)\n",
         FunctionDeviceObject,
         __FdoGetName(Fdo));

    Dx->Fdo = NULL;

    RtlZeroMemory(&Fdo->List, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->Mutex, sizeof (MUTEX));

    if (__FdoIsActive(Fdo)) {
        RtlZeroMemory(&Fdo->BalloonInterface,
                      sizeof (XENBUS_BALLOON_INTERFACE));

        RtlZeroMemory(&Fdo->ConsoleInterface,
                      sizeof (XENBUS_CONSOLE_INTERFACE));

        RtlZeroMemory(&Fdo->StoreInterface,
                      sizeof (XENBUS_STORE_INTERFACE));

        RtlZeroMemory(&Fdo->RangeSetInterface,
                      sizeof (XENBUS_RANGE_SET_INTERFACE));

        RtlZeroMemory(&Fdo->EvtchnInterface,
                      sizeof (XENBUS_EVTCHN_INTERFACE));

        RtlZeroMemory(&Fdo->SuspendInterface,
                      sizeof (XENBUS_SUSPEND_INTERFACE));

        RtlZeroMemory(&Fdo->DebugInterface,
                      sizeof (XENBUS_DEBUG_INTERFACE));

        if (Fdo->BalloonContext != NULL) {
            BalloonTeardown(Fdo->BalloonContext);
            Fdo->BalloonContext = NULL;
        }

        UnplugTeardown(Fdo->UnplugContext);
        Fdo->UnplugContext = NULL;

        ConsoleTeardown(Fdo->ConsoleContext);
        Fdo->ConsoleContext = NULL;

        StoreTeardown(Fdo->StoreContext);
        Fdo->StoreContext = NULL;

        GnttabTeardown(Fdo->GnttabContext);
        Fdo->GnttabContext = NULL;

        CacheTeardown(Fdo->CacheContext);
        Fdo->CacheContext = NULL;

        RangeSetTeardown(Fdo->RangeSetContext);
        Fdo->RangeSetContext = NULL;

        EvtchnTeardown(Fdo->EvtchnContext);
        Fdo->EvtchnContext = NULL;

        SharedInfoTeardown(Fdo->SharedInfoContext);
        Fdo->SharedInfoContext = NULL;

        SuspendTeardown(Fdo->SuspendContext);
        Fdo->SuspendContext = NULL;

        DebugTeardown(Fdo->DebugContext);
        Fdo->DebugContext = NULL;

        __FdoFreeBuffer(Fdo);

        FdoClearActive(Fdo);
    }

    RtlZeroMemory(Fdo->VendorName, MAXNAMELEN);

    FdoReleaseLowerBusInterface(Fdo);

    ThreadAlert(Fdo->DevicePowerThread);
    ThreadJoin(Fdo->DevicePowerThread);
    Fdo->DevicePowerThread = NULL;

    ThreadAlert(Fdo->SystemPowerThread);
    ThreadJoin(Fdo->SystemPowerThread);
    Fdo->SystemPowerThread = NULL;

    IoDetachDevice(Fdo->LowerDeviceObject);

    RtlZeroMemory(&Fdo->LowerDeviceCapabilities, sizeof (DEVICE_CAPABILITIES));
    Fdo->LowerDeviceObject = NULL;
    Fdo->PhysicalDeviceObject = NULL;
    Fdo->Dx = NULL;

    ASSERT(IsZeroMemory(Fdo, sizeof (XENBUS_FDO)));
    __FdoFree(Fdo);

    ASSERT3U(Dx->DevicePowerState, ==, PowerDeviceD3);
    ASSERT3U(Dx->SystemPowerState, ==, PowerSystemWorking);

    IoDeleteDevice(FunctionDeviceObject);
}
