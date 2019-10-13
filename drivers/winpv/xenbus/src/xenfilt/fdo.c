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
#include <xen.h>

#include "emulated.h"
#include "names.h"
#include "fdo.h"
#include "pdo.h"
#include "thread.h"
#include "driver.h"
#include "registry.h"
#include "mutex.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define FDO_TAG 'ODF'

#define MAXNAMELEN  128

struct _XENFILT_FDO {
    PXENFILT_DX                     Dx;
    PDEVICE_OBJECT                  LowerDeviceObject;
    PDEVICE_OBJECT                  PhysicalDeviceObject;
    CHAR                            Name[MAXNAMELEN];

    PXENFILT_THREAD                 SystemPowerThread;
    PIRP                            SystemPowerIrp;
    PXENFILT_THREAD                 DevicePowerThread;
    PIRP                            DevicePowerIrp;

    MUTEX                           Mutex;
    LIST_ENTRY                      List;
    ULONG                           References;

    BOOLEAN                         Enumerated;

    XENFILT_EMULATED_OBJECT_TYPE    Type;
};

static FORCEINLINE PVOID
__FdoAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, FDO_TAG);
}

static FORCEINLINE VOID
__FdoFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, FDO_TAG);
}

static FORCEINLINE VOID
__FdoSetDevicePnpState(
    IN  PXENFILT_FDO        Fdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENFILT_DX             Dx = Fdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

static FORCEINLINE VOID
__FdoRestoreDevicePnpState(
    IN  PXENFILT_FDO        Fdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENFILT_DX             Dx = Fdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__FdoGetDevicePnpState(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    return Dx->DevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__FdoGetPreviousDevicePnpState(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    return Dx->PreviousDevicePnpState;
}

static FORCEINLINE VOID
__FdoSetDevicePowerState(
    IN  PXENFILT_FDO        Fdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXENFILT_DX             Dx = Fdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__FdoGetDevicePowerState(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__FdoSetSystemPowerState(
    IN  PXENFILT_FDO        Fdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXENFILT_DX              Dx = Fdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__FdoGetSystemPowerState(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    return Dx->SystemPowerState;
}

static FORCEINLINE PDEVICE_OBJECT
__FdoGetDeviceObject(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    return Dx->DeviceObject;
}
    
PDEVICE_OBJECT
FdoGetDeviceObject(
    IN  PXENFILT_FDO    Fdo
    )
{
    return __FdoGetDeviceObject(Fdo);
}

static FORCEINLINE PDEVICE_OBJECT
__FdoGetPhysicalDeviceObject(
    IN  PXENFILT_FDO    Fdo
    )
{
    return Fdo->PhysicalDeviceObject;
}

PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    IN  PXENFILT_FDO    Fdo
    )
{
    return __FdoGetPhysicalDeviceObject(Fdo);
}

static FORCEINLINE NTSTATUS
__FdoSetDeviceID(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    return DriverQueryId(Fdo->PhysicalDeviceObject,
                         BusQueryDeviceID,
                         &Dx->DeviceID);

}

static FORCEINLINE PCHAR
__FdoGetDeviceID(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    return Dx->DeviceID;
}

static FORCEINLINE VOID
__FdoClearDeviceID(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    ExFreePool(Dx->DeviceID);
    Dx->DeviceID = NULL;
}

static FORCEINLINE NTSTATUS
__FdoSetInstanceID(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    return DriverQueryId(Fdo->PhysicalDeviceObject,
                         BusQueryInstanceID,
                         &Dx->InstanceID);
}

static FORCEINLINE PCHAR
__FdoGetInstanceID(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    return Dx->InstanceID;
}

static FORCEINLINE VOID
__FdoClearInstanceID(
    IN  PXENFILT_FDO    Fdo
    )
{
    PXENFILT_DX         Dx = Fdo->Dx;

    ExFreePool(Dx->InstanceID);
    Dx->InstanceID = NULL;
}

static FORCEINLINE VOID
__FdoSetName(
    IN  PXENFILT_FDO    Fdo
    )
{
    NTSTATUS            status;

    status = RtlStringCbPrintfA(Fdo->Name,
                                MAXNAMELEN,
                                "%s\\%s",
                                __FdoGetDeviceID(Fdo),
                                __FdoGetInstanceID(Fdo));
    ASSERT(NT_SUCCESS(status));
}

static FORCEINLINE PCHAR
__FdoGetName(
    IN  PXENFILT_FDO    Fdo
    )
{
    return Fdo->Name;
}

VOID
FdoAddPhysicalDeviceObject(
    IN  PXENFILT_FDO    Fdo,
    IN  PXENFILT_PDO    Pdo
    )
{
    PDEVICE_OBJECT      DeviceObject;
    PXENFILT_DX         Dx;

    DeviceObject = PdoGetDeviceObject(Pdo);
    Dx = (PXENFILT_DX)DeviceObject->DeviceExtension;
    ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

    InsertTailList(&Fdo->List, &Dx->ListEntry);
    ASSERT3U(Fdo->References, !=, 0);
    Fdo->References++;

    PdoResume(Pdo);
}

VOID
FdoRemovePhysicalDeviceObject(
    IN  PXENFILT_FDO    Fdo,
    IN  PXENFILT_PDO    Pdo
    )
{
    PDEVICE_OBJECT      DeviceObject;
    PXENFILT_DX         Dx;

    DeviceObject = PdoGetDeviceObject(Pdo);
    Dx = (PXENFILT_DX)DeviceObject->DeviceExtension;
    ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

    PdoSuspend(Pdo);

    RemoveEntryList(&Dx->ListEntry);
    ASSERT3U(Fdo->References, !=, 0);
    --Fdo->References;
}

static FORCEINLINE VOID
__FdoAcquireMutex(
    IN  PXENFILT_FDO     Fdo
    )
{
    AcquireMutex(&Fdo->Mutex);
}

VOID
FdoAcquireMutex(
    IN  PXENFILT_FDO     Fdo
    )
{
    __FdoAcquireMutex(Fdo);
}

static FORCEINLINE VOID
__FdoReleaseMutex(
    IN  PXENFILT_FDO     Fdo
    )
{
    ReleaseMutex(&Fdo->Mutex);
}

VOID
FdoReleaseMutex(
    IN  PXENFILT_FDO     Fdo
    )
{
    __FdoReleaseMutex(Fdo);

    if (Fdo->References == 0) {
        DriverAcquireMutex();
        FdoDestroy(Fdo);
        DriverReleaseMutex();
    }
}

static FORCEINLINE VOID
__FdoSetEnumerated(
    IN  PXENFILT_FDO    Fdo
    )
{
    Fdo->Enumerated = TRUE;

    if (Fdo->Type == XENFILT_EMULATED_OBJECT_TYPE_PCI)
        DriverSetFilterState();
}

BOOLEAN
FdoHasEnumerated(
    IN  PXENFILT_FDO    Fdo
    )
{
    return Fdo->Enumerated;
}

static VOID
FdoEnumerate(
    IN  PXENFILT_FDO        Fdo,
    IN  PDEVICE_RELATIONS   Relations
    )
{
    PDEVICE_OBJECT          *PhysicalDeviceObject;
    ULONG                   Count;
    PLIST_ENTRY             ListEntry;
    ULONG                   Index;
    NTSTATUS                status;

    Count = Relations->Count;
    ASSERT(Count != 0);

    PhysicalDeviceObject = __FdoAllocate(sizeof (PDEVICE_OBJECT) * Count);

    status = STATUS_NO_MEMORY;
    if (PhysicalDeviceObject == NULL)
        goto fail1;

    RtlCopyMemory(PhysicalDeviceObject,
                  Relations->Objects,
                  sizeof (PDEVICE_OBJECT) * Count);

    // Remove any PDOs that do not appear in the device list
    ListEntry = Fdo->List.Flink;
    while (ListEntry != &Fdo->List) {
        PLIST_ENTRY     Next = ListEntry->Flink;
        PXENFILT_DX     Dx = CONTAINING_RECORD(ListEntry, XENFILT_DX, ListEntry);
        PXENFILT_PDO    Pdo = Dx->Pdo;

        if (!PdoIsMissing(Pdo) && PdoGetDevicePnpState(Pdo) != Deleted) {
            BOOLEAN         Missing;

            Missing = TRUE;

            for (Index = 0; Index < Count; Index++) {
                if (PdoGetPhysicalDeviceObject(Pdo) == PhysicalDeviceObject[Index]) {
                    Missing = FALSE;
#pragma prefast(suppress:6387)  // PhysicalDeviceObject[Index] could be NULL
                    ObDereferenceObject(PhysicalDeviceObject[Index]);
                    PhysicalDeviceObject[Index] = NULL; // avoid duplication
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
                }
            }
        }

        ListEntry = Next;
    }

    // Walk the list and create PDO filters for any new devices
    for (Index = 0; Index < Count; Index++) {
#pragma warning(suppress:6385)  // Reading invalid data from 'PhysicalDeviceObject'
        if (PhysicalDeviceObject[Index] != NULL) {
            (VOID) PdoCreate(Fdo, PhysicalDeviceObject[Index], Fdo->Type);
            ObDereferenceObject(PhysicalDeviceObject[Index]);
        }
    }
    
    __FdoSetEnumerated(Fdo);

    __FdoFree(PhysicalDeviceObject);
    return;

fail1:
    Error("fail1 (%08x)\n", status);
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
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    KEVENT              Event;
    NTSTATUS            status;

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

static NTSTATUS
FdoStartDevice(
    IN  PXENFILT_FDO            Fdo,
    IN  PIRP                    Irp
    )
{
    POWER_STATE                 PowerState;
    NTSTATUS                    status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail2;

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(Fdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    __FdoSetDevicePowerState(Fdo, PowerDeviceD0);

    __FdoSetDevicePnpState(Fdo, Started);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail2:
    Error("fail2\n");

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoQueryStopDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoQueryStopDevice(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __FdoSetDevicePnpState(Fdo, StopPending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           FdoQueryStopDeviceCompletion,
                           Fdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoCancelStopDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoCancelStopDevice(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    Irp->IoStatus.Status = STATUS_SUCCESS;

    __FdoRestoreDevicePnpState(Fdo, StopPending);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           FdoCancelStopDeviceCompletion,
                           Fdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoStopDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoStopDevice(
    IN  PXENFILT_FDO            Fdo,
    IN  PIRP                    Irp
    )
{
    NTSTATUS                    status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0) {
        POWER_STATE PowerState;

        PowerState.DeviceState = PowerDeviceD3;
        PoSetPowerState(Fdo->Dx->DeviceObject,
                        DevicePowerState,
                        PowerState);

        __FdoSetDevicePowerState(Fdo, PowerDeviceD3);
    }

    __FdoSetDevicePnpState(Fdo, Stopped);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           FdoStopDeviceCompletion,
                           Fdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoQueryRemoveDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoQueryRemoveDevice(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __FdoSetDevicePnpState(Fdo, RemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           FdoQueryRemoveDeviceCompletion,
                           Fdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoCancelRemoveDeviceCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoCancelRemoveDevice(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __FdoRestoreDevicePnpState(Fdo, RemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           FdoCancelRemoveDeviceCompletion,
                           Fdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoSurpriseRemovalCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoSurpriseRemoval(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __FdoSetDevicePnpState(Fdo, SurpriseRemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           FdoSurpriseRemovalCompletion,
                           Fdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoRemoveDevice(
    IN  PXENFILT_FDO            Fdo,
    IN  PIRP                    Irp
    )
{
    PLIST_ENTRY                 ListEntry;
    NTSTATUS                    status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (__FdoGetPreviousDevicePnpState(Fdo) != Started)
        goto done;

    __FdoAcquireMutex(Fdo);

    ListEntry = Fdo->List.Flink;
    while (ListEntry != &Fdo->List) {
        PLIST_ENTRY     Flink = ListEntry->Flink;
        PXENFILT_DX     Dx = CONTAINING_RECORD(ListEntry, XENFILT_DX, ListEntry);
        PXENFILT_PDO    Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (!PdoIsMissing(Pdo))
            PdoSetMissing(Pdo, "FDO removed");

        PdoSetDevicePnpState(Pdo, Deleted);
        PdoDestroy(Pdo);

        ListEntry = Flink;
    }

    __FdoReleaseMutex(Fdo);

    if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0) {
        POWER_STATE PowerState;

        PowerState.DeviceState = PowerDeviceD3;
        PoSetPowerState(Fdo->Dx->DeviceObject,
                        DevicePowerState,
                        PowerState);

        __FdoSetDevicePowerState(Fdo, PowerDeviceD3);
    }

done:
    __FdoSetDevicePnpState(Fdo, Deleted);

    IoReleaseRemoveLockAndWait(&Fdo->Dx->RemoveLock, Irp);

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

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

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoQueryDeviceRelationsCompletion(
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
FdoQueryDeviceRelations(
    IN  PXENFILT_FDO        Fdo,
    IN  PIRP                Irp
    )
{
    KEVENT                  Event;
    PIO_STACK_LOCATION      StackLocation;
    ULONG                   Size;
    PDEVICE_RELATIONS       Relations;
    PLIST_ENTRY             ListEntry;
    XENFILT_FILTER_STATE    State;
    ULONG                   Count;
    NTSTATUS                status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           FdoQueryDeviceRelationsCompletion,
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

    if (!NT_SUCCESS(status))
        goto fail2;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    if (StackLocation->Parameters.QueryDeviceRelations.Type != BusRelations)
        goto done;

    __FdoAcquireMutex(Fdo);

    Relations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;

    if (Relations->Count != 0)
        FdoEnumerate(Fdo, Relations);

    ExFreePool(Relations);

    State = DriverGetFilterState();
    Count = 0;

    if (State == XENFILT_FILTER_DISABLED) {
        for (ListEntry = Fdo->List.Flink;
             ListEntry != &Fdo->List;
             ListEntry = ListEntry->Flink)
            Count++;
    }

    Size = FIELD_OFFSET(DEVICE_RELATIONS, Objects) +
           (sizeof (PDEVICE_OBJECT) * __max(Count, 1));

    Relations = __AllocatePoolWithTag(PagedPool, Size, 'TLIF');

    status = STATUS_NO_MEMORY;
    if (Relations == NULL)
        goto fail3;

    if (State == XENFILT_FILTER_DISABLED) {
        ListEntry = Fdo->List.Flink;
        while (ListEntry != &Fdo->List) {
            PXENFILT_DX     Dx = CONTAINING_RECORD(ListEntry, XENFILT_DX, ListEntry);
            PXENFILT_PDO    Pdo = Dx->Pdo;
            PLIST_ENTRY     Next = ListEntry->Flink;

            ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

            if (PdoIsMissing(Pdo)) {
                if (PdoGetDevicePnpState(Pdo) == Deleted)
                    PdoDestroy(Pdo);

                continue;
            }

            if (PdoGetDevicePnpState(Pdo) == Present)
                PdoSetDevicePnpState(Pdo, Enumerated);

            ObReferenceObject(PdoGetPhysicalDeviceObject(Pdo));
            Relations->Objects[Relations->Count++] = PdoGetPhysicalDeviceObject(Pdo);

            ListEntry = Next;
        }

        ASSERT3U(Relations->Count, <=, Count);

        Trace("%s: %d PDO(s)\n",
              __FdoGetName(Fdo),
              Relations->Count);
    } else {
        Trace("%s: FILTERED\n",
              __FdoGetName(Fdo));

        IoInvalidateDeviceRelations(__FdoGetPhysicalDeviceObject(Fdo),
                                    BusRelations);
    }

    __FdoReleaseMutex(Fdo);

    Irp->IoStatus.Information = (ULONG_PTR)Relations;
    status = STATUS_SUCCESS;

done:
    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail3:
    __FdoReleaseMutex(Fdo);

fail2:
    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoDispatchPnpCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

static NTSTATUS
FdoDispatchPnp(
    IN  PXENFILT_FDO    Fdo,
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

    default:
        status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
        if (!NT_SUCCESS(status))
            goto fail1;

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               FdoDispatchPnpCompletion,
                               Fdo,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
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
FdoSetDevicePowerUp(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_STATE         PowerState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __FdoGetDevicePowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Trace("%s: %s -> %s\n",
          __FdoGetName(Fdo),
          DevicePowerStateName(__FdoGetDevicePowerState(Fdo)),
          DevicePowerStateName(DeviceState));

    PowerState.DeviceState = DeviceState;
    PoSetPowerState(Fdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    __FdoSetDevicePowerState(Fdo, DeviceState);

done:
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoSetDevicePowerDown(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_STATE         PowerState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __FdoGetDevicePowerState(Fdo));

    Trace("%s: %s -> %s\n",
          __FdoGetName(Fdo),
          DevicePowerStateName(__FdoGetDevicePowerState(Fdo)),
          DevicePowerStateName(DeviceState));

    PowerState.DeviceState = DeviceState;
    PoSetPowerState(Fdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    __FdoSetDevicePowerState(Fdo, DeviceState);

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoSetDevicePower(
    IN  PXENFILT_FDO    Fdo,
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
          __FdoGetName(Fdo),
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction));

    if (DeviceState == __FdoGetDevicePowerState(Fdo)) {
        status = FdoForwardIrpSynchronously(Fdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (DeviceState < __FdoGetDevicePowerState(Fdo)) ?
             FdoSetDevicePowerUp(Fdo, Irp) :
             FdoSetDevicePowerDown(Fdo, Irp);

done:
    Trace("%s: <==== (%s:%s)(%08x)\n",
          __FdoGetName(Fdo),
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

static NTSTATUS
FdoSetSystemPowerUp(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __FdoGetSystemPowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Trace("%s: %s -> %s\n",
          __FdoGetName(Fdo),
          SystemPowerStateName(__FdoGetSystemPowerState(Fdo)),
          SystemPowerStateName(SystemState));

    __FdoSetSystemPowerState(Fdo, SystemState);

done:
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoSetSystemPowerDown(
    IN  PXENFILT_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __FdoGetSystemPowerState(Fdo));

    Trace("%s: %s -> %s\n",
          __FdoGetName(Fdo),
          SystemPowerStateName(__FdoGetSystemPowerState(Fdo)),
          SystemPowerStateName(SystemState));

    __FdoSetSystemPowerState(Fdo, SystemState);

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoSetSystemPower(
    IN  PXENFILT_FDO    Fdo,
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
          __FdoGetName(Fdo),
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction));

    if (SystemState == __FdoGetSystemPowerState(Fdo)) {
        status = FdoForwardIrpSynchronously(Fdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (SystemState < __FdoGetSystemPowerState(Fdo)) ?
             FdoSetSystemPowerUp(Fdo, Irp) :
             FdoSetSystemPowerDown(Fdo, Irp);

done:
    Trace("%s: <==== (%s:%s)(%08x)\n",
          __FdoGetName(Fdo),
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

static NTSTATUS
FdoQueryDevicePowerUp(
    IN  PXENFILT_FDO    Fdo,
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
    IN  PXENFILT_FDO    Fdo,
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
    IN  PXENFILT_FDO    Fdo,
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
          __FdoGetName(Fdo),
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction));

    if (DeviceState == __FdoGetDevicePowerState(Fdo)) {
        status = FdoForwardIrpSynchronously(Fdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (DeviceState < __FdoGetDevicePowerState(Fdo)) ?
             FdoQueryDevicePowerUp(Fdo, Irp) :
             FdoQueryDevicePowerDown(Fdo, Irp);

done:
    Trace("%s: <==== (%s:%s)(%08x)\n",
          __FdoGetName(Fdo),
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

static NTSTATUS
FdoQuerySystemPowerUp(
    IN  PXENFILT_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __FdoGetSystemPowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoQuerySystemPowerDown(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __FdoGetSystemPowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
FdoQuerySystemPower(
    IN  PXENFILT_FDO    Fdo,
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
          __FdoGetName(Fdo),
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction));

    if (SystemState == __FdoGetSystemPowerState(Fdo)) {
        status = FdoForwardIrpSynchronously(Fdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (SystemState < __FdoGetSystemPowerState(Fdo)) ?
             FdoQuerySystemPowerUp(Fdo, Irp) :
             FdoQuerySystemPowerDown(Fdo, Irp);

done:
    Trace("%s: <==== (%s:%s)(%08x)\n",
          __FdoGetName(Fdo),
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction),
          status);

    return status;
}

static NTSTATUS
FdoDevicePower(
    IN  PXENFILT_THREAD Self,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;
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

        IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoSystemPower(
    IN  PXENFILT_THREAD Self,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;
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

        IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    }

    return STATUS_SUCCESS;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
FdoDispatchPowerCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

static NTSTATUS
FdoDispatchPower(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    POWER_STATE_TYPE    PowerType;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    if (MinorFunction != IRP_MN_QUERY_POWER &&
        MinorFunction != IRP_MN_SET_POWER) {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               FdoDispatchPowerCompletion,
                               Fdo,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    PowerType = StackLocation->Parameters.Power.Type;

    Trace("%s: ====> (%02x:%s)\n",
          __FdoGetName(Fdo),
          MinorFunction, 
          PowerMinorFunctionName(MinorFunction)); 

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
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               FdoDispatchPowerCompletion,
                               Fdo,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
        break;
    }

    Trace("%s: <==== (%02x:%s) (%08x)\n",
          __FdoGetName(Fdo),
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
FdoDispatchDefaultCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENFILT_FDO        Fdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Fdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoDispatchDefault(
    IN  PXENFILT_FDO    Fdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Fdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           FdoDispatchDefaultCompletion,
                           Fdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS
FdoDispatch(
    IN  PXENFILT_FDO    Fdo,
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

NTSTATUS
FdoCreate(
    IN  PDEVICE_OBJECT                  PhysicalDeviceObject,
    IN  XENFILT_EMULATED_OBJECT_TYPE    Type
    )
{
    PDEVICE_OBJECT                      LowerDeviceObject;
    ULONG                               DeviceType;
    PDEVICE_OBJECT                      FilterDeviceObject;
    PXENFILT_DX                         Dx;
    PXENFILT_FDO                        Fdo;
    NTSTATUS                            status;

    ASSERT(Type != XENFILT_EMULATED_OBJECT_TYPE_UNKNOWN);

    LowerDeviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);
    DeviceType = LowerDeviceObject->DeviceType;
    ObDereferenceObject(LowerDeviceObject);

#pragma prefast(suppress:28197) // Possibly leaking memory 'FilterDeviceObject'
    status = IoCreateDevice(DriverGetDriverObject(),
                            sizeof (XENFILT_DX),
                            NULL,
                            DeviceType,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &FilterDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXENFILT_DX)FilterDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XENFILT_DX));

    Dx->Type = FUNCTION_DEVICE_OBJECT;
    Dx->DeviceObject = FilterDeviceObject;
    Dx->DevicePnpState = Added;
    Dx->SystemPowerState = PowerSystemWorking;
    Dx->DevicePowerState = PowerDeviceD3;

    IoInitializeRemoveLock(&Dx->RemoveLock, FDO_TAG, 0, 0);

    Fdo = __FdoAllocate(sizeof (XENFILT_FDO));

    status = STATUS_NO_MEMORY;
    if (Fdo == NULL)
        goto fail2;

    LowerDeviceObject = IoAttachDeviceToDeviceStack(FilterDeviceObject,
                                                    PhysicalDeviceObject);

    status = STATUS_UNSUCCESSFUL;
    if (LowerDeviceObject == NULL)
        goto fail3;

    Fdo->Dx = Dx;
    Fdo->PhysicalDeviceObject = PhysicalDeviceObject;
    Fdo->LowerDeviceObject = LowerDeviceObject;
    Fdo->Type = Type;

    status = ThreadCreate(FdoSystemPower, Fdo, &Fdo->SystemPowerThread);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = ThreadCreate(FdoDevicePower, Fdo, &Fdo->DevicePowerThread);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = __FdoSetDeviceID(Fdo);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = __FdoSetInstanceID(Fdo);
    if (!NT_SUCCESS(status))
        goto fail7;

    __FdoSetName(Fdo);

    InitializeMutex(&Fdo->Mutex);
    InitializeListHead(&Fdo->List);
    Fdo->References = 1;

    Info("%p (%s)\n",
         FilterDeviceObject,
         __FdoGetName(Fdo));

    Dx->Fdo = Fdo;

#pragma prefast(suppress:28182)  // Dereferencing NULL pointer
    FilterDeviceObject->DeviceType = LowerDeviceObject->DeviceType;
    FilterDeviceObject->Characteristics = LowerDeviceObject->Characteristics;

    FilterDeviceObject->Flags |= LowerDeviceObject->Flags;
    FilterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverAddFunctionDeviceObject(Fdo);

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    __FdoClearDeviceID(Fdo);

fail6:
    Error("fail6\n");

    ThreadAlert(Fdo->DevicePowerThread);
    ThreadJoin(Fdo->DevicePowerThread);
    Fdo->DevicePowerThread = NULL;

fail5:
    Error("fail5\n");

    ThreadAlert(Fdo->SystemPowerThread);
    ThreadJoin(Fdo->SystemPowerThread);
    Fdo->SystemPowerThread = NULL;

fail4:
    Error("fail4\n");

    Fdo->Type = XENFILT_EMULATED_OBJECT_TYPE_UNKNOWN;
    Fdo->PhysicalDeviceObject = NULL;
    Fdo->LowerDeviceObject = NULL;
    Fdo->Dx = NULL;

    IoDetachDevice(LowerDeviceObject);

fail3:
    Error("fail3\n");

    ASSERT(IsZeroMemory(Fdo, sizeof (XENFILT_FDO)));
    __FdoFree(Fdo);

fail2:
    Error("fail2\n");

    IoDeleteDevice(FilterDeviceObject);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
FdoDestroy(
    IN  PXENFILT_FDO    Fdo
    )
{
    PDEVICE_OBJECT      LowerDeviceObject = Fdo->LowerDeviceObject;
    PXENFILT_DX         Dx = Fdo->Dx;
    PDEVICE_OBJECT      FilterDeviceObject = Dx->DeviceObject;

    ASSERT(IsListEmpty(&Fdo->List));
    ASSERT3U(Fdo->References, ==, 0);
    ASSERT3U(__FdoGetDevicePnpState(Fdo), ==, Deleted);

    DriverRemoveFunctionDeviceObject(Fdo);

    Fdo->Enumerated = FALSE;

    Dx->Fdo = NULL;

    Info("%p (%s)\n",
         FilterDeviceObject,
         __FdoGetName(Fdo));

    RtlZeroMemory(&Fdo->List, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->Mutex, sizeof (MUTEX));

    RtlZeroMemory(Fdo->Name, sizeof (Fdo->Name));

    __FdoClearInstanceID(Fdo);
    __FdoClearDeviceID(Fdo);

    ThreadAlert(Fdo->DevicePowerThread);
    ThreadJoin(Fdo->DevicePowerThread);
    Fdo->DevicePowerThread = NULL;

    ThreadAlert(Fdo->SystemPowerThread);
    ThreadJoin(Fdo->SystemPowerThread);
    Fdo->SystemPowerThread = NULL;

    Fdo->Type = XENFILT_EMULATED_OBJECT_TYPE_UNKNOWN;
    Fdo->LowerDeviceObject = NULL;
    Fdo->PhysicalDeviceObject = NULL;
    Fdo->Dx = NULL;

    IoDetachDevice(LowerDeviceObject);

    ASSERT(IsZeroMemory(Fdo, sizeof (XENFILT_FDO)));
    __FdoFree(Fdo);

    ASSERT3U(Dx->DevicePowerState, ==, PowerDeviceD3);
    ASSERT3U(Dx->SystemPowerState, ==, PowerSystemWorking);

    IoDeleteDevice(FilterDeviceObject);
}
