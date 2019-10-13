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

#define INITGUID 1

#include <ntddk.h>
#include <wdmguid.h>
#include <ntstrsafe.h>
#include <stdlib.h>

#include "emulated.h"
#include "names.h"
#include "fdo.h"
#include "pdo.h"
#include "thread.h"
#include "driver.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define PDO_TAG 'ODP'

#define MAXNAMELEN  128

struct _XENFILT_PDO {
    PXENFILT_DX                     Dx;
    PDEVICE_OBJECT                  LowerDeviceObject;
    PDEVICE_OBJECT                  PhysicalDeviceObject;
    CHAR                            Name[MAXNAMELEN];

    PXENFILT_THREAD                 SystemPowerThread;
    PIRP                            SystemPowerIrp;
    PXENFILT_THREAD                 DevicePowerThread;
    PIRP                            DevicePowerIrp;

    PXENFILT_FDO                    Fdo;
    BOOLEAN                         Missing;
    const CHAR                      *Reason;

    XENFILT_EMULATED_OBJECT_TYPE    Type;
    PXENFILT_EMULATED_OBJECT        EmulatedObject;
    BOOLEAN                         Active;
};

static FORCEINLINE PVOID
__PdoAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, PDO_TAG);
}

static FORCEINLINE VOID
__PdoFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, PDO_TAG);
}

static FORCEINLINE VOID
__PdoSetDevicePnpState(
    IN  PXENFILT_PDO        Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENFILT_DX             Dx = Pdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

VOID
PdoSetDevicePnpState(
    IN  PXENFILT_PDO        Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    __PdoSetDevicePnpState(Pdo, State);
}

static FORCEINLINE VOID
__PdoRestoreDevicePnpState(
    IN  PXENFILT_PDO        Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENFILT_DX             Dx = Pdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__PdoGetDevicePnpState(
    IN  PXENFILT_PDO    Pdo
    )
{
    PXENFILT_DX         Dx = Pdo->Dx;

    return Dx->DevicePnpState;
}

DEVICE_PNP_STATE
PdoGetDevicePnpState(
    IN  PXENFILT_PDO    Pdo
    )
{
    return __PdoGetDevicePnpState(Pdo);
}

static FORCEINLINE VOID
__PdoSetDevicePowerState(
    IN  PXENFILT_PDO        Pdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXENFILT_DX             Dx = Pdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__PdoGetDevicePowerState(
    IN  PXENFILT_PDO    Pdo
    )
{
    PXENFILT_DX         Dx = Pdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__PdoSetSystemPowerState(
    IN  PXENFILT_PDO        Pdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXENFILT_DX             Dx = Pdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__PdoGetSystemPowerState(
    IN  PXENFILT_PDO    Pdo
    )
{
    PXENFILT_DX         Dx = Pdo->Dx;

    return Dx->SystemPowerState;
}

PDEVICE_OBJECT
PdoGetPhysicalDeviceObject(
    IN  PXENFILT_PDO    Pdo
    )
{
    return Pdo->PhysicalDeviceObject;
}

static FORCEINLINE VOID
__PdoSetMissing(
    IN  PXENFILT_PDO    Pdo,
    IN  const CHAR      *Reason
    )
{
    Pdo->Reason = Reason;
    Pdo->Missing = TRUE;
}

VOID
PdoSetMissing(
    IN  PXENFILT_PDO    Pdo,
    IN  const CHAR      *Reason
    )
{
    __PdoSetMissing(Pdo, Reason);
}

static FORCEINLINE BOOLEAN
__PdoIsMissing(
    IN  PXENFILT_PDO    Pdo
    )
{
    return Pdo->Missing;
}

BOOLEAN
PdoIsMissing(
    IN  PXENFILT_PDO    Pdo
    )
{
    return __PdoIsMissing(Pdo);
}

static FORCEINLINE PDEVICE_OBJECT
__PdoGetDeviceObject(
    IN  PXENFILT_PDO    Pdo
    )
{
    PXENFILT_DX         Dx = Pdo->Dx;

    return Dx->DeviceObject;
}
    
PDEVICE_OBJECT
PdoGetDeviceObject(
    IN  PXENFILT_PDO    Pdo
    )
{
    return __PdoGetDeviceObject(Pdo);
}

static FORCEINLINE PXENFILT_FDO
__PdoGetFdo(
    IN  PXENFILT_PDO Pdo
    )
{
    return Pdo->Fdo;
}

static NTSTATUS
PdoSetDeviceInformation(
    IN  PXENFILT_PDO    Pdo
    )
{
    PXENFILT_DX         Dx = Pdo->Dx;
    PCHAR               DeviceID;
    PCHAR               ActiveDeviceID;
    PCHAR               InstanceID;
    PCHAR               LocationInformation;
    NTSTATUS            status;

    status = DriverQueryId(Pdo->LowerDeviceObject,
                           BusQueryDeviceID,
                           &DeviceID);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = DriverGetActive("DeviceID",
                             &ActiveDeviceID);
    if (NT_SUCCESS(status)) {
        Pdo->Active = (_stricmp(DeviceID, ActiveDeviceID) == 0) ?
                      TRUE :
                      FALSE;

        ExFreePool(ActiveDeviceID);
    } else {
        Pdo->Active = FALSE;
    }

    if (Pdo->Active) {
        status = DriverGetActive("InstanceID",
                                 &InstanceID);
        if (!NT_SUCCESS(status))
            goto fail2;

        status = DriverGetActive("LocationInformation",
                                 &LocationInformation);
        if (!NT_SUCCESS(status)) {
            status = DriverQueryDeviceText(Pdo->LowerDeviceObject,
                                           DeviceTextLocationInformation,
                                           &LocationInformation);
            if (!NT_SUCCESS(status))
                LocationInformation = NULL;
        }
    } else {
        status = DriverQueryId(Pdo->LowerDeviceObject,
                               BusQueryInstanceID,
                               &InstanceID);
        if (!NT_SUCCESS(status))
            InstanceID = NULL;

        status = DriverQueryDeviceText(Pdo->LowerDeviceObject,
                                       DeviceTextLocationInformation,
                                       &LocationInformation);
        if (!NT_SUCCESS(status))
            LocationInformation = NULL;
    }

    Dx->DeviceID = DeviceID;
    Dx->InstanceID = InstanceID;
    Dx->LocationInformation = LocationInformation;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    ASSERT(Pdo->Active);
    ExFreePool(DeviceID);

    Pdo->Active = FALSE;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
PdoClearDeviceInformation(
    IN  PXENFILT_PDO    Pdo
    )
{
    PXENFILT_DX         Dx = Pdo->Dx;

    if (Dx->LocationInformation != NULL) {
        ExFreePool(Dx->LocationInformation);
        Dx->LocationInformation = NULL;
    }

    if (Dx->InstanceID != NULL) {
        ExFreePool(Dx->InstanceID);
        Dx->InstanceID = NULL;
    }

    ASSERT(Dx->DeviceID != NULL);
    ExFreePool(Dx->DeviceID);
    Dx->DeviceID = NULL;

    Pdo->Active = FALSE;
}

static FORCEINLINE PCHAR
__PdoGetDeviceID(
    IN  PXENFILT_PDO    Pdo
    )
{
    PXENFILT_DX         Dx = Pdo->Dx;

    ASSERT(Dx->DeviceID != NULL);
    return Dx->DeviceID;
}

static FORCEINLINE PCHAR
__PdoGetInstanceID(
    IN  PXENFILT_PDO    Pdo
    )
{
    PXENFILT_DX         Dx = Pdo->Dx;

    return (Dx->InstanceID != NULL) ?
           Dx->InstanceID : "";
}

static FORCEINLINE PCHAR
__PdoGetLocationInformation(
    IN  PXENFILT_PDO    Pdo
    )
{
    PXENFILT_DX         Dx = Pdo->Dx;

    return (Dx->LocationInformation != NULL) ?
           Dx->LocationInformation : "";
}

static FORCEINLINE VOID
__PdoSetName(
    IN  PXENFILT_PDO    Pdo
    )
{
    NTSTATUS            status;

    if (strlen(__PdoGetInstanceID(Pdo)) == 0)
        status = RtlStringCbPrintfA(Pdo->Name,
                                    MAXNAMELEN,
                                    "%s",
                                    __PdoGetDeviceID(Pdo));
    else
        status = RtlStringCbPrintfA(Pdo->Name,
                                    MAXNAMELEN,
                                    "%s\\%s",
                                    __PdoGetDeviceID(Pdo),
                                    __PdoGetInstanceID(Pdo));

    ASSERT(NT_SUCCESS(status));
}

static FORCEINLINE PCHAR
__PdoGetName(
    IN  PXENFILT_PDO    Pdo
    )
{
    return Pdo->Name;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoForwardIrpSynchronouslyCompletion(
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
PdoForwardIrpSynchronously(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    KEVENT              Event;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           PdoForwardIrpSynchronouslyCompletion,
                           &Event,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);
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

static NTSTATUS
PdoStartDevice(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    POWER_STATE         PowerState;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail2;

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    __PdoSetDevicePowerState(Pdo, PowerDeviceD0);

    __PdoSetDevicePnpState(Pdo, Started);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

fail2:
    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoQueryStopDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoQueryStopDevice(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoSetDevicePnpState(Pdo, StopPending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           PdoQueryStopDeviceCompletion,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoCancelStopDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoCancelStopDevice(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    Irp->IoStatus.Status = STATUS_SUCCESS;

    __PdoRestoreDevicePnpState(Pdo, StopPending);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           PdoCancelStopDeviceCompletion,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoStopDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoStopDevice(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    POWER_STATE         PowerState;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (__PdoGetDevicePowerState(Pdo) != PowerDeviceD0)
        goto done;

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    __PdoSetDevicePowerState(Pdo, PowerDeviceD3);

done:
    __PdoSetDevicePnpState(Pdo, Stopped);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           PdoStopDeviceCompletion,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoQueryRemoveDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoQueryRemoveDevice(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoSetDevicePnpState(Pdo, RemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           PdoQueryRemoveDeviceCompletion,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoCancelRemoveDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoCancelRemoveDevice(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoRestoreDevicePnpState(Pdo, RemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           PdoCancelRemoveDeviceCompletion,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoSurpriseRemovalCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoSurpriseRemoval(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoSetDevicePnpState(Pdo, SurpriseRemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           PdoSurpriseRemovalCompletion,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoRemoveDevice(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PXENFILT_FDO        Fdo = __PdoGetFdo(Pdo);
    POWER_STATE         PowerState;
    BOOLEAN             NeedInvalidate;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (__PdoGetDevicePowerState(Pdo) != PowerDeviceD0)
        goto done;

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    __PdoSetDevicePowerState(Pdo, PowerDeviceD3);

done:
    status = PdoForwardIrpSynchronously(Pdo, Irp);

    FdoAcquireMutex(Fdo);

    NeedInvalidate = FALSE;

    if (__PdoIsMissing(Pdo)) {
        DEVICE_PNP_STATE    State = __PdoGetDevicePnpState(Pdo);

        __PdoSetDevicePnpState(Pdo, Deleted);
        IoReleaseRemoveLockAndWait(&Pdo->Dx->RemoveLock, Irp);

        if (State == SurpriseRemovePending)
            PdoDestroy(Pdo);
        else
            NeedInvalidate = TRUE;
    } else {
        __PdoSetDevicePnpState(Pdo, Enumerated);
        IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    }

    FdoReleaseMutex(Fdo);

    if (NeedInvalidate)
        IoInvalidateDeviceRelations(FdoGetPhysicalDeviceObject(Fdo),
                                    BusRelations);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoQueryInterfaceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

#define DEFINE_PDO_QUERY_INTERFACE(_Interface)                      \
static NTSTATUS                                                     \
PdoQuery ## _Interface ## Interface(                                \
    IN  PXENFILT_PDO    Pdo,                                        \
    IN  PIRP            Irp                                         \
    )                                                               \
{                                                                   \
    PIO_STACK_LOCATION  StackLocation;                              \
    USHORT              Size;                                       \
    USHORT              Version;                                    \
    PINTERFACE          Interface;                                  \
    PVOID               Context;                                    \
    NTSTATUS            status;                                     \
                                                                    \
    UNREFERENCED_PARAMETER(Pdo);                                    \
                                                                    \
    status = Irp->IoStatus.Status;                                  \
                                                                    \
    StackLocation = IoGetCurrentIrpStackLocation(Irp);              \
    Size = StackLocation->Parameters.QueryInterface.Size;           \
    Version = StackLocation->Parameters.QueryInterface.Version;     \
    Interface = StackLocation->Parameters.QueryInterface.Interface; \
                                                                    \
    Context = DriverGet ## _Interface ## Context();                 \
                                                                    \
    status = _Interface ## GetInterface(Context,                    \
                                        Version,                    \
                                        Interface,                  \
                                        Size);                      \
    if (!NT_SUCCESS(status))                                        \
        goto done;                                                  \
                                                                    \
    Irp->IoStatus.Information = 0;                                  \
    status = STATUS_SUCCESS;                                        \
                                                                    \
done:                                                               \
    return status;                                                  \
}                                                                   \

DEFINE_PDO_QUERY_INTERFACE(Emulated)

struct _INTERFACE_ENTRY {
    const GUID  *Guid;
    const CHAR  *Name;
    NTSTATUS    (*Query)(PXENFILT_PDO, PIRP);
};

#define DEFINE_INTERFACE_ENTRY(_Guid, _Interface)   \
    { &GUID_XENFILT_ ## _Guid, #_Guid, PdoQuery ## _Interface ## Interface }

struct _INTERFACE_ENTRY PdoInterfaceTable[] = {
    DEFINE_INTERFACE_ENTRY(EMULATED_INTERFACE, Emulated),
    { NULL, NULL, NULL }
};

static NTSTATUS
PdoQueryInterface(
    IN  PXENFILT_PDO        Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    const GUID              *InterfaceType;
    struct _INTERFACE_ENTRY *Entry;
    USHORT                  Version;
    NTSTATUS                status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (Irp->IoStatus.Status != STATUS_NOT_SUPPORTED)
        goto done;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    InterfaceType = StackLocation->Parameters.QueryInterface.InterfaceType;
    Version = StackLocation->Parameters.QueryInterface.Version;

    for (Entry = PdoInterfaceTable; Entry->Guid != NULL; Entry++) {
        if (IsEqualGUID(InterfaceType, Entry->Guid)) {
            Info("%s: %s (VERSION %d)\n",
                 __PdoGetName(Pdo),
                 Entry->Name,
                 Version);
            Irp->IoStatus.Status = Entry->Query(Pdo, Irp);
            goto done;
        }
    }

done:
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           PdoQueryInterfaceCompletion,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryDeviceText(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UNICODE_STRING      Text;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail2;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    RtlZeroMemory(&Text, sizeof (UNICODE_STRING));

    switch (StackLocation->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextLocationInformation:
        Text.MaximumLength =
            (USHORT)(strlen(__PdoGetLocationInformation(Pdo)) *
                     sizeof (WCHAR));

        Trace("DeviceTextLocationInformation\n");
        break;

    default:
        goto done;
    }

    status = STATUS_OBJECT_NAME_NOT_FOUND;
    if (Text.MaximumLength == 0)
        goto fail3;

    Text.MaximumLength += sizeof (WCHAR);
    Text.Buffer = __AllocatePoolWithTag(PagedPool,
                                        Text.MaximumLength,
                                        'TLIF');

    status = STATUS_NO_MEMORY;
    if (Text.Buffer == NULL)
        goto fail4;

    switch (StackLocation->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextLocationInformation:
        status = RtlStringCbPrintfW(Text.Buffer,
                                    Text.MaximumLength,
                                    L"%hs",
                                    __PdoGetLocationInformation(Pdo));
        ASSERT(NT_SUCCESS(status));

        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Text.Length = (USHORT)(wcslen(Text.Buffer) * sizeof (WCHAR));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Trace("- %wZ\n", &Text);

    ExFreePool((PVOID)Irp->IoStatus.Information);
    Irp->IoStatus.Information = (ULONG_PTR)Text.Buffer;

done:
    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

fail4:
fail3:
fail2:
    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryId(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UNICODE_STRING      Id;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail2;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    RtlZeroMemory(&Id, sizeof (UNICODE_STRING));

    switch (StackLocation->Parameters.QueryId.IdType) {
    case BusQueryInstanceID:
        Id.MaximumLength = (USHORT)(strlen(__PdoGetInstanceID(Pdo)) *
                                    sizeof (WCHAR));

        Trace("BusQueryInstanceID\n");
        break;

    case BusQueryDeviceID:
        Id.MaximumLength = (USHORT)(strlen(__PdoGetDeviceID(Pdo)) *
                                    sizeof (WCHAR));

        Trace("BusQueryDeviceID\n");
        break;

    default:
        goto done;
    }

    status = STATUS_OBJECT_NAME_NOT_FOUND;
    if (Id.MaximumLength == 0)
        goto fail3;

    Id.MaximumLength += sizeof (WCHAR);
    Id.Buffer = __AllocatePoolWithTag(PagedPool, Id.MaximumLength, 'TLIF');

    status = STATUS_NO_MEMORY;
    if (Id.Buffer == NULL)
        goto fail4;

    switch (StackLocation->Parameters.QueryId.IdType) {
    case BusQueryInstanceID:
        status = RtlStringCbPrintfW(Id.Buffer,
                                    Id.MaximumLength,
                                    L"%hs",
                                    __PdoGetInstanceID(Pdo));
        ASSERT(NT_SUCCESS(status));

        break;

    case BusQueryDeviceID:
        status = RtlStringCbPrintfW(Id.Buffer,
                                    Id.MaximumLength,
                                    L"%hs",
                                    __PdoGetDeviceID(Pdo));
        ASSERT(NT_SUCCESS(status));

        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Id.Length = (USHORT)(wcslen(Id.Buffer) * sizeof (WCHAR));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Trace("- %wZ\n", &Id);

    ExFreePool((PVOID)Irp->IoStatus.Information);
    Irp->IoStatus.Information = (ULONG_PTR)Id.Buffer;

done:
    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

fail4:
fail3:
fail2:
    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoEject(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PXENFILT_FDO        Fdo = __PdoGetFdo(Pdo);
    NTSTATUS            status;

    FdoAcquireMutex(Fdo);
    __PdoSetMissing(Pdo, "Ejected");
    __PdoSetDevicePnpState(Pdo, Deleted);
    FdoReleaseMutex(Fdo);

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    FdoAcquireMutex(Fdo);
    PdoDestroy(Pdo);
    FdoReleaseMutex(Fdo);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoDispatchPnpCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

static NTSTATUS
PdoDispatchPnp(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    switch (StackLocation->MinorFunction) {
    case IRP_MN_START_DEVICE:
        status = PdoStartDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        status = PdoQueryStopDevice(Pdo, Irp);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        status = PdoCancelStopDevice(Pdo, Irp);
        break;

    case IRP_MN_STOP_DEVICE:
        status = PdoStopDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        status = PdoQueryRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        status = PdoSurpriseRemoval(Pdo, Irp);
        break;

    case IRP_MN_REMOVE_DEVICE:
        status = PdoRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        status = PdoCancelRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_INTERFACE:
        status = PdoQueryInterface(Pdo, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_TEXT:
        status = PdoQueryDeviceText(Pdo, Irp);
        break;

    case IRP_MN_QUERY_ID:
        status = PdoQueryId(Pdo, Irp);
        break;

    case IRP_MN_EJECT:
        status = PdoEject(Pdo, Irp);
        break;

    default:
        status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
        if (!NT_SUCCESS(status))
            goto fail1;

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               PdoDispatchPnpCompletion,
                               Pdo,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(Pdo->LowerDeviceObject, Irp);
        break;
    }

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoSetDevicePowerUp(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_STATE         PowerState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __PdoGetDevicePowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Trace("%s: %s -> %s\n",
          __PdoGetName(Pdo),
          DevicePowerStateName(__PdoGetDevicePowerState(Pdo)),
          DevicePowerStateName(DeviceState));

    PowerState.DeviceState = DeviceState;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    __PdoSetDevicePowerState(Pdo, DeviceState);

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoSetDevicePowerDown(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_STATE         PowerState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __PdoGetDevicePowerState(Pdo));

    Trace("%s: %s -> %s\n",
          __PdoGetName(Pdo),
          DevicePowerStateName(__PdoGetDevicePowerState(Pdo)),
          DevicePowerStateName(DeviceState));

    PowerState.DeviceState = DeviceState;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    __PdoSetDevicePowerState(Pdo, DeviceState);

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoSetDevicePower(
    IN  PXENFILT_PDO    Pdo,
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

    Trace("%s: ====> (%s:%s)\n",
          __PdoGetName(Pdo),
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction));

    if (DeviceState == __PdoGetDevicePowerState(Pdo)) {
        status = PdoForwardIrpSynchronously(Pdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (DeviceState < __PdoGetDevicePowerState(Pdo)) ?
             PdoSetDevicePowerUp(Pdo, Irp) :
             PdoSetDevicePowerDown(Pdo, Irp);

done:
    Trace("%s: <==== (%s:%s)(%08x)\n",
          __PdoGetName(Pdo),
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

static NTSTATUS
PdoSetSystemPowerUp(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __PdoGetSystemPowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Trace("%s: %s -> %s\n",
          __PdoGetName(Pdo),
          SystemPowerStateName(__PdoGetSystemPowerState(Pdo)),
          SystemPowerStateName(SystemState));

    __PdoSetSystemPowerState(Pdo, SystemState);

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoSetSystemPowerDown(
    IN  PXENFILT_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __PdoGetSystemPowerState(Pdo));

    Trace("%s: %s -> %s\n",
          __PdoGetName(Pdo),
          SystemPowerStateName(__PdoGetSystemPowerState(Pdo)),
          SystemPowerStateName(SystemState));

    __PdoSetSystemPowerState(Pdo, SystemState);

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoSetSystemPower(
    IN  PXENFILT_PDO    Pdo,
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

    Trace("%s: ====> (%s:%s)\n",
          __PdoGetName(Pdo),
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction));

    if (SystemState == __PdoGetSystemPowerState(Pdo)) {
        status = PdoForwardIrpSynchronously(Pdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (SystemState < __PdoGetSystemPowerState(Pdo)) ?
             PdoSetSystemPowerUp(Pdo, Irp) :
             PdoSetSystemPowerDown(Pdo, Irp);

done:
    Trace("%s: <==== (%s:%s)(%08x)\n",
          __PdoGetName(Pdo),
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

static NTSTATUS
PdoQueryDevicePowerUp(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __PdoGetDevicePowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryDevicePowerDown(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __PdoGetDevicePowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryDevicePower(
    IN  PXENFILT_PDO    Pdo,
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

    Trace("%s: ====> (%s:%s)\n",
          __PdoGetName(Pdo),
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction));

    if (DeviceState == __PdoGetDevicePowerState(Pdo)) {
        status = PdoForwardIrpSynchronously(Pdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (DeviceState < __PdoGetDevicePowerState(Pdo)) ?
             PdoQueryDevicePowerUp(Pdo, Irp) :
             PdoQueryDevicePowerDown(Pdo, Irp);

done:
    Trace("%s: <==== (%s:%s)(%08x)\n",
          __PdoGetName(Pdo),
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

static NTSTATUS
PdoQuerySystemPowerUp(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __PdoGetSystemPowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQuerySystemPowerDown(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __PdoGetSystemPowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQuerySystemPower(
    IN  PXENFILT_PDO    Pdo,
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

    Trace("%s: ====> (%s:%s)\n",
          __PdoGetName(Pdo),
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction));

    if (SystemState == __PdoGetSystemPowerState(Pdo)) {
        status = PdoForwardIrpSynchronously(Pdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (SystemState < __PdoGetSystemPowerState(Pdo)) ?
             PdoQuerySystemPowerUp(Pdo, Irp) :
             PdoQuerySystemPowerDown(Pdo, Irp);

done:
    Trace("%s: <==== (%s:%s)(%08x)\n",
          __PdoGetName(Pdo),
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction),
          status);

    return status;
}

static NTSTATUS
PdoDevicePower(
    IN  PXENFILT_THREAD Self,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  StackLocation;
        UCHAR               MinorFunction;

        if (Pdo->DevicePowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Pdo->DevicePowerIrp;

        if (Irp == NULL)
            continue;

        Pdo->DevicePowerIrp = NULL;
        KeMemoryBarrier();

        StackLocation = IoGetCurrentIrpStackLocation(Irp);
        MinorFunction = StackLocation->MinorFunction;

        switch (StackLocation->MinorFunction) {
        case IRP_MN_SET_POWER:
            (VOID) PdoSetDevicePower(Pdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) PdoQueryDevicePower(Pdo, Irp);
            break;

        default:
            ASSERT(FALSE);
            break;
        }

        IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoSystemPower(
    IN  PXENFILT_THREAD Self,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  StackLocation;
        UCHAR               MinorFunction;

        if (Pdo->SystemPowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Pdo->SystemPowerIrp;

        if (Irp == NULL)
            continue;

        Pdo->SystemPowerIrp = NULL;
        KeMemoryBarrier();

        StackLocation = IoGetCurrentIrpStackLocation(Irp);
        MinorFunction = StackLocation->MinorFunction;

        switch (StackLocation->MinorFunction) {
        case IRP_MN_SET_POWER:
            (VOID) PdoSetSystemPower(Pdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) PdoQuerySystemPower(Pdo, Irp);
            break;

        default:
            ASSERT(FALSE);
            break;
        }

        IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    }

    return STATUS_SUCCESS;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoDispatchPowerCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

static NTSTATUS
PdoDispatchPower(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    POWER_STATE_TYPE    PowerType;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    if (MinorFunction != IRP_MN_QUERY_POWER &&
        MinorFunction != IRP_MN_SET_POWER) {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               PdoDispatchPowerCompletion,
                               Pdo,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

        goto done;
    }

    PowerType = StackLocation->Parameters.Power.Type;

    Trace("%s: ====> (%02x:%s)\n",
          __PdoGetName(Pdo),
          MinorFunction, 
          PowerMinorFunctionName(MinorFunction)); 

    switch (PowerType) {
    case DevicePowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Pdo->DevicePowerIrp, ==, NULL);
        Pdo->DevicePowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Pdo->DevicePowerThread);

        status = STATUS_PENDING;
        break;

    case SystemPowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Pdo->SystemPowerIrp, ==, NULL);
        Pdo->SystemPowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Pdo->SystemPowerThread);

        status = STATUS_PENDING;
        break;

    default:
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               PdoDispatchPowerCompletion,
                               Pdo,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(Pdo->LowerDeviceObject, Irp);
        break;
    }

    Trace("%s: <==== (%02x:%s) (%08x)\n",
          __PdoGetName(Pdo),
          MinorFunction, 
          PowerMinorFunctionName(MinorFunction),
          status);

done:
    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
PdoDispatchDefaultCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoDispatchDefault(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           PdoDispatchDefaultCompletion,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS
PdoDispatch(
    IN  PXENFILT_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->MajorFunction) {
    case IRP_MJ_PNP:
        status = PdoDispatchPnp(Pdo, Irp);
        break;

    case IRP_MJ_POWER:
        status = PdoDispatchPower(Pdo, Irp);
        break;

    default:
        status = PdoDispatchDefault(Pdo, Irp);
        break;
    }

    return status;
}

VOID
PdoResume(
    IN  PXENFILT_PDO    Pdo
    )
{
    UNREFERENCED_PARAMETER(Pdo);
}

VOID
PdoSuspend(
    IN  PXENFILT_PDO    Pdo
    )
{
    UNREFERENCED_PARAMETER(Pdo);
}

NTSTATUS
PdoCreate(
    PXENFILT_FDO                    Fdo,
    PDEVICE_OBJECT                  PhysicalDeviceObject,
    XENFILT_EMULATED_OBJECT_TYPE    Type
    )
{
    PDEVICE_OBJECT                  LowerDeviceObject;
    ULONG                           DeviceType;
    PDEVICE_OBJECT                  FilterDeviceObject;
    PXENFILT_DX                     Dx;
    PXENFILT_PDO                    Pdo;
    NTSTATUS                        status;

    ASSERT(Type != XENFILT_EMULATED_OBJECT_TYPE_UNKNOWN);

    LowerDeviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);
    DeviceType = LowerDeviceObject->DeviceType;
    ObDereferenceObject(LowerDeviceObject);

#pragma prefast(suppress:28197) // Possibly leaking memory 'PhysicalDeviceObject'
    status = IoCreateDevice(DriverGetDriverObject(),
                            sizeof(XENFILT_DX),
                            NULL,
                            DeviceType,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &FilterDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXENFILT_DX)FilterDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XENFILT_DX));

    Dx->Type = PHYSICAL_DEVICE_OBJECT;
    Dx->DeviceObject = FilterDeviceObject;
    Dx->DevicePnpState = Present;
    Dx->SystemPowerState = PowerSystemWorking;
    Dx->DevicePowerState = PowerDeviceD3;

    IoInitializeRemoveLock(&Dx->RemoveLock, PDO_TAG, 0, 0);

    Pdo = __PdoAllocate(sizeof (XENFILT_PDO));

    status = STATUS_NO_MEMORY;
    if (Pdo == NULL)
        goto fail2;

    LowerDeviceObject = IoAttachDeviceToDeviceStack(FilterDeviceObject,
                                                    PhysicalDeviceObject);

    status = STATUS_UNSUCCESSFUL;
    if (LowerDeviceObject == NULL)
        goto fail3;

    Pdo->Dx = Dx;
    Pdo->Fdo = Fdo;
    Pdo->PhysicalDeviceObject = PhysicalDeviceObject;
    Pdo->LowerDeviceObject = LowerDeviceObject;
    Pdo->Type = Type;

    status = ThreadCreate(PdoSystemPower, Pdo, &Pdo->SystemPowerThread);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = ThreadCreate(PdoDevicePower, Pdo, &Pdo->DevicePowerThread);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = PdoSetDeviceInformation(Pdo);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = EmulatedAddObject(DriverGetEmulatedContext(),
                               __PdoGetDeviceID(Pdo),
                               __PdoGetInstanceID(Pdo),
                               Pdo->Type,
                               &Pdo->EmulatedObject);
    if (!NT_SUCCESS(status))
        goto fail7;

    __PdoSetName(Pdo);

    Info("%p (%s) %s\n",
         FilterDeviceObject,
         __PdoGetName(Pdo),
         Pdo->Active ? "[ACTIVE]" : "");

    Dx->Pdo = Pdo;

#pragma prefast(suppress:28182) // Dereferencing NULL pointer
    FilterDeviceObject->DeviceType = LowerDeviceObject->DeviceType;
    FilterDeviceObject->Characteristics = LowerDeviceObject->Characteristics;

    FilterDeviceObject->Flags |= LowerDeviceObject->Flags;
    FilterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    FdoAddPhysicalDeviceObject(Fdo, Pdo);

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    PdoClearDeviceInformation(Pdo);

fail6:
    Error("fail6\n");

    ThreadAlert(Pdo->DevicePowerThread);
    ThreadJoin(Pdo->DevicePowerThread);
    Pdo->DevicePowerThread = NULL;

fail5:
    Error("fail5\n");

    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

fail4:
    Error("fail4\n");

    Pdo->Type = XENFILT_EMULATED_OBJECT_TYPE_UNKNOWN;
    Pdo->PhysicalDeviceObject = NULL;
    Pdo->LowerDeviceObject = NULL;
    Pdo->Fdo = NULL;
    Pdo->Dx = NULL;

    IoDetachDevice(LowerDeviceObject);

fail3:
    Error("fail3\n");

    ASSERT(IsZeroMemory(Pdo, sizeof (XENFILT_PDO)));
    __PdoFree(Pdo);

fail2:
    Error("fail2\n");

    IoDeleteDevice(FilterDeviceObject);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
PdoDestroy(
    IN  PXENFILT_PDO            Pdo
    )
{
    PDEVICE_OBJECT              LowerDeviceObject = Pdo->LowerDeviceObject;
    PXENFILT_DX                 Dx = Pdo->Dx;
    PDEVICE_OBJECT              FilterDeviceObject = Dx->DeviceObject;
    PXENFILT_FDO                Fdo = __PdoGetFdo(Pdo);

    ASSERT3U(__PdoGetDevicePnpState(Pdo), ==, Deleted);

    ASSERT(__PdoIsMissing(Pdo));
    Pdo->Missing = FALSE;

    FdoRemovePhysicalDeviceObject(Fdo, Pdo);

    Dx->Pdo = NULL;

    Info("%p (%s) (%s)\n",
         FilterDeviceObject,
         __PdoGetName(Pdo),
         Pdo->Reason);
    Pdo->Reason = NULL;

    RtlZeroMemory(Pdo->Name, sizeof (Pdo->Name));

    EmulatedRemoveObject(DriverGetEmulatedContext(),
                         Pdo->EmulatedObject);
    Pdo->EmulatedObject = NULL;

    PdoClearDeviceInformation(Pdo);

    ThreadAlert(Pdo->DevicePowerThread);
    ThreadJoin(Pdo->DevicePowerThread);
    Pdo->DevicePowerThread = NULL;

    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

    Pdo->Type = XENFILT_EMULATED_OBJECT_TYPE_UNKNOWN;
    Pdo->PhysicalDeviceObject = NULL;
    Pdo->LowerDeviceObject = NULL;
    Pdo->Fdo = NULL;
    Pdo->Dx = NULL;

    IoDetachDevice(LowerDeviceObject);

    ASSERT(IsZeroMemory(Pdo, sizeof (XENFILT_PDO)));
    __PdoFree(Pdo);

    IoDeleteDevice(FilterDeviceObject);
}
