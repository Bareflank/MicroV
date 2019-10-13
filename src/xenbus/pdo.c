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

#include <emulated_interface.h>

#include "names.h"
#include "fdo.h"
#include "pdo.h"
#include "bus.h"
#include "driver.h"
#include "thread.h"
#include "registry.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"
#include "version.h"
#include "revision.h"

#define PDO_TAG 'ODP'

#define MAXNAMELEN  128

struct _XENBUS_PDO {
    PXENBUS_DX                  Dx;

    PXENBUS_THREAD              SystemPowerThread;
    PIRP                        SystemPowerIrp;
    PXENBUS_THREAD              DevicePowerThread;
    PIRP                        DevicePowerIrp;

    PXENBUS_FDO                 Fdo;
    BOOLEAN                     Missing;
    const CHAR                  *Reason;

    BOOLEAN                     Removable;
    BOOLEAN                     Ejectable;

    BUS_INTERFACE_STANDARD      BusInterface;

    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
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
    IN  PXENBUS_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENBUS_DX              Dx = Pdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

VOID
PdoSetDevicePnpState(
    IN  PXENBUS_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    __PdoSetDevicePnpState(Pdo, State);
}

static FORCEINLINE VOID
__PdoRestoreDevicePnpState(
    IN  PXENBUS_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENBUS_DX              Dx = Pdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__PdoGetDevicePnpState(
    IN  PXENBUS_PDO Pdo
    )
{
    PXENBUS_DX      Dx = Pdo->Dx;

    return Dx->DevicePnpState;
}

DEVICE_PNP_STATE
PdoGetDevicePnpState(
    IN  PXENBUS_PDO Pdo
    )
{
    return __PdoGetDevicePnpState(Pdo);
}

static FORCEINLINE VOID
__PdoSetDevicePowerState(
    IN  PXENBUS_PDO         Pdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXENBUS_DX              Dx = Pdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__PdoGetDevicePowerState(
    IN  PXENBUS_PDO Pdo
    )
{
    PXENBUS_DX      Dx = Pdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__PdoSetSystemPowerState(
    IN  PXENBUS_PDO         Pdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXENBUS_DX              Dx = Pdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__PdoGetSystemPowerState(
    IN  PXENBUS_PDO Pdo
    )
{
    PXENBUS_DX      Dx = Pdo->Dx;

    return Dx->SystemPowerState;
}

static FORCEINLINE VOID
__PdoSetMissing(
    IN  PXENBUS_PDO Pdo,
    IN  const CHAR  *Reason
    )
{
    Pdo->Reason = Reason;
    Pdo->Missing = TRUE;
}

VOID
PdoSetMissing(
    IN  PXENBUS_PDO Pdo,
    IN  const CHAR  *Reason
    )
{
    __PdoSetMissing(Pdo, Reason);
}

static FORCEINLINE BOOLEAN
__PdoIsMissing(
    IN  PXENBUS_PDO Pdo
    )
{
    return Pdo->Missing;
}

BOOLEAN
PdoIsMissing(
    IN  PXENBUS_PDO Pdo
    )
{
    return __PdoIsMissing(Pdo);
}

static FORCEINLINE VOID
__PdoSetName(
    IN  PXENBUS_PDO     Pdo,
    IN  PANSI_STRING    Name
    )
{
    PXENBUS_DX          Dx = Pdo->Dx;
    NTSTATUS            status;

    status = RtlStringCbPrintfA(Dx->Name,
                                MAX_DEVICE_ID_LEN,
                                "%Z",
                                Name);
    ASSERT(NT_SUCCESS(status));
}

static FORCEINLINE PCHAR
__PdoGetName(
    IN  PXENBUS_PDO Pdo
    )
{
    PXENBUS_DX      Dx = Pdo->Dx;

    return Dx->Name;
}

PCHAR
PdoGetName(
    IN  PXENBUS_PDO Pdo
    )
{
    return __PdoGetName(Pdo);
}

static FORCEINLINE VOID
__PdoSetRemovable(
    IN  PXENBUS_PDO     Pdo
    )
{
    HANDLE              ParametersKey;
    HANDLE              Key;
    ULONG               Value;
    NTSTATUS            status;

    Value = 1;

    ParametersKey = DriverGetParametersKey();

    status = RegistryOpenSubKey(ParametersKey,
                                __PdoGetName(Pdo),
                                KEY_READ,
                                &Key);
    if (!NT_SUCCESS(status))
        goto done;

    (VOID) RegistryQueryDwordValue(Key,
                                   "AllowPdoRemove",
                                   &Value);

    RegistryCloseKey(Key);

done:
    Pdo->Removable = (Value != 0) ? TRUE : FALSE;
}

static FORCEINLINE BOOLEAN
__PdoIsRemovable(
    IN  PXENBUS_PDO     Pdo
    )
{
    return Pdo->Removable;
}

static FORCEINLINE VOID
__PdoSetEjectable(
    IN  PXENBUS_PDO     Pdo
    )
{
    HANDLE              ParametersKey;
    HANDLE              Key;
    ULONG               Value;
    NTSTATUS            status;

    Value = 1;

    ParametersKey = DriverGetParametersKey();

    status = RegistryOpenSubKey(ParametersKey,
                                __PdoGetName(Pdo),
                                KEY_READ,
                                &Key);
    if (!NT_SUCCESS(status))
        goto done;

    (VOID) RegistryQueryDwordValue(Key,
                                   "AllowPdoEject",
                                   &Value);

    RegistryCloseKey(Key);

done:
    Pdo->Ejectable = (Value != 0) ? TRUE : FALSE;
}

static FORCEINLINE BOOLEAN
__PdoIsEjectable(
    IN  PXENBUS_PDO     Pdo
    )
{
    return Pdo->Ejectable;
}

#define MAXTEXTLEN  1024

static FORCEINLINE PXENBUS_FDO
__PdoGetFdo(
    IN  PXENBUS_PDO Pdo
    )
{
    return Pdo->Fdo;
}

PXENBUS_FDO
PdoGetFdo(
    IN  PXENBUS_PDO Pdo
    )
{
    return __PdoGetFdo(Pdo);
}

typedef struct _XENBUS_PDO_REVISION {
    ULONG   Number;
    ULONG   SuspendInterfaceVersion;
    ULONG   SharedInfoInterfaceVersion;
    ULONG   EvtchnInterfaceVersion;
    ULONG   DebugInterfaceVersion;
    ULONG   StoreInterfaceVersion;
    ULONG   RangeSetInterfaceVersion;
    ULONG   CacheInterfaceVersion;
    ULONG   GnttabInterfaceVersion;
    ULONG   UnplugInterfaceVersion;
    ULONG   ConsoleInterfaceVersion;
    ULONG   EmulatedInterfaceVersion;
} XENBUS_PDO_REVISION, *PXENBUS_PDO_REVISION;

#define DEFINE_REVISION(_N, _S, _SI, _E, _D, _ST, _R, _C, _G, _U, _CO, _EM) \
    { (_N), (_S), (_SI), (_E), (_D), (_ST), (_R), (_C), (_G), (_U), (_CO), (_EM) }

static XENBUS_PDO_REVISION PdoRevision[] = {
    DEFINE_REVISION_TABLE
};

#undef DEFINE_REVISION

static VOID
PdoDumpRevisions(
    IN  PXENBUS_PDO Pdo
    )
{
    ULONG           Index;

    UNREFERENCED_PARAMETER(Pdo);

    for (Index = 0; Index < ARRAYSIZE(PdoRevision); Index++) {
        PXENBUS_PDO_REVISION Revision = &PdoRevision[Index];

        ASSERT3U(Revision->SuspendInterfaceVersion, >=, XENBUS_SUSPEND_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->SuspendInterfaceVersion, <=, XENBUS_SUSPEND_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->SuspendInterfaceVersion == XENBUS_SUSPEND_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->SharedInfoInterfaceVersion, >=, XENBUS_SHARED_INFO_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->SharedInfoInterfaceVersion, <=, XENBUS_SHARED_INFO_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->SharedInfoInterfaceVersion == XENBUS_SHARED_INFO_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->EvtchnInterfaceVersion, >=, XENBUS_EVTCHN_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->EvtchnInterfaceVersion, <=, XENBUS_EVTCHN_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->EvtchnInterfaceVersion == XENBUS_EVTCHN_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->DebugInterfaceVersion, >=, XENBUS_DEBUG_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->DebugInterfaceVersion, <=, XENBUS_DEBUG_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->DebugInterfaceVersion == XENBUS_DEBUG_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->StoreInterfaceVersion, >=, XENBUS_STORE_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->StoreInterfaceVersion, <=, XENBUS_STORE_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->StoreInterfaceVersion == XENBUS_STORE_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->RangeSetInterfaceVersion, >=, XENBUS_RANGE_SET_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->RangeSetInterfaceVersion, <=, XENBUS_RANGE_SET_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->RangeSetInterfaceVersion == XENBUS_RANGE_SET_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->CacheInterfaceVersion, >=, XENBUS_CACHE_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->CacheInterfaceVersion, <=, XENBUS_CACHE_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->CacheInterfaceVersion == XENBUS_CACHE_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->GnttabInterfaceVersion, >=, XENBUS_GNTTAB_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->GnttabInterfaceVersion, <=, XENBUS_GNTTAB_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->GnttabInterfaceVersion == XENBUS_GNTTAB_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->UnplugInterfaceVersion, >=, XENBUS_UNPLUG_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->UnplugInterfaceVersion, <=, XENBUS_UNPLUG_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->UnplugInterfaceVersion == XENBUS_UNPLUG_INTERFACE_VERSION_MAX));

        ASSERT(IMPLY(Revision->ConsoleInterfaceVersion != 0,
                     Revision->ConsoleInterfaceVersion >= XENBUS_CONSOLE_INTERFACE_VERSION_MIN));
        ASSERT(IMPLY(Revision->ConsoleInterfaceVersion != 0,
                     Revision->ConsoleInterfaceVersion <= XENBUS_CONSOLE_INTERFACE_VERSION_MAX));
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->ConsoleInterfaceVersion == XENBUS_CONSOLE_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->EmulatedInterfaceVersion, >=, XENFILT_EMULATED_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->EmulatedInterfaceVersion, <=, XENFILT_EMULATED_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->EmulatedInterfaceVersion == XENFILT_EMULATED_INTERFACE_VERSION_MAX));

        Info("%08X -> "
             "SUSPEND v%u "
             "SHARED_INFO v%u "
             "EVTCHN v%u "
             "DEBUG v%u "
             "STORE v%u "
             "RANGE_SET v%u "
             "CACHE v%u "
             "GNTTAB v%u "
             "UNPLUG v%u "
             "CONSOLE v%u "
             "EMULATED v%u\n",
             Revision->Number,
             Revision->SuspendInterfaceVersion,
             Revision->SharedInfoInterfaceVersion,
             Revision->EvtchnInterfaceVersion,
             Revision->DebugInterfaceVersion,
             Revision->StoreInterfaceVersion,
             Revision->RangeSetInterfaceVersion,
             Revision->CacheInterfaceVersion,
             Revision->GnttabInterfaceVersion,
             Revision->UnplugInterfaceVersion,
             Revision->ConsoleInterfaceVersion,
             Revision->EmulatedInterfaceVersion);
    }
}

static FORCEINLINE PDEVICE_OBJECT
__PdoGetDeviceObject(
    IN  PXENBUS_PDO Pdo
    )
{
    PXENBUS_DX      Dx = Pdo->Dx;

    return (Dx->DeviceObject);
}
    
PDEVICE_OBJECT
PdoGetDeviceObject(
    IN  PXENBUS_PDO Pdo
    )
{
    return __PdoGetDeviceObject(Pdo);
}

static FORCEINLINE PCHAR
__PdoGetVendorName(
    IN  PXENBUS_PDO Pdo
    )
{
    return FdoGetVendorName(__PdoGetFdo(Pdo));
}

PDMA_ADAPTER
PdoGetDmaAdapter(
    IN  PXENBUS_PDO         Pdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    )
{
    Trace("<===>\n");

    return FdoGetDmaAdapter(__PdoGetFdo(Pdo),
                            DeviceDescriptor,
                            NumberOfMapRegisters);
}

BOOLEAN
PdoTranslateBusAddress(
    IN      PXENBUS_PDO         Pdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    )
{
    Trace("<===>\n");

    return FdoTranslateBusAddress(__PdoGetFdo(Pdo),
                                  BusAddress,
                                  Length,
                                  AddressSpace,
                                  TranslatedAddress);
}

ULONG
PdoSetBusData(
    IN  PXENBUS_PDO     Pdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    )
{
    Trace("<===>\n");

    return FdoSetBusData(__PdoGetFdo(Pdo),
                         DataType,
                         Buffer,
                         Offset,
                         Length);
}

ULONG
PdoGetBusData(
    IN  PXENBUS_PDO     Pdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    )
{
    Trace("<===>\n");

    return FdoGetBusData(__PdoGetFdo(Pdo),
                         DataType,
                         Buffer,
                         Offset,
                         Length);
}

static FORCEINLINE VOID
__PdoD3ToD0(
    IN  PXENBUS_PDO     Pdo
    )
{
    POWER_STATE         PowerState;

    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3U(__PdoGetDevicePowerState(Pdo), ==, PowerDeviceD3);

    __PdoSetDevicePowerState(Pdo, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

static FORCEINLINE VOID
__PdoD0ToD3(
    IN  PXENBUS_PDO     Pdo
    )
{
    POWER_STATE         PowerState;

    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3U(__PdoGetDevicePowerState(Pdo), ==, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    __PdoSetDevicePowerState(Pdo, PowerDeviceD3);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

static VOID
PdoSuspendCallbackLate(
    IN  PVOID   Argument
    )
{
    PXENBUS_PDO Pdo = Argument;

    __PdoD0ToD3(Pdo);
    __PdoD3ToD0(Pdo);
}

// This function must not touch pageable code or data
static NTSTATUS
PdoD3ToD0(
    IN  PXENBUS_PDO Pdo
    )
{
    KIRQL           Irql;
    NTSTATUS        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    status = XENBUS_SUSPEND(Acquire, &Pdo->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoD3ToD0(Pdo);

    status = XENBUS_SUSPEND(Register,
                            &Pdo->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            PdoSuspendCallbackLate,
                            Pdo,
                            &Pdo->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail2;

    KeLowerIrql(Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __PdoD0ToD3(Pdo);

    XENBUS_SUSPEND(Release, &Pdo->SuspendInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    KeLowerIrql(Irql);

    return status;
}

// This function must not touch pageable code or data
static VOID
PdoD0ToD3(
    IN  PXENBUS_PDO Pdo
    )
{
    KIRQL           Irql;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    XENBUS_SUSPEND(Deregister,
                   &Pdo->SuspendInterface,
                   Pdo->SuspendCallbackLate);
    Pdo->SuspendCallbackLate = NULL;

    __PdoD0ToD3(Pdo);

    XENBUS_SUSPEND(Release, &Pdo->SuspendInterface);

    KeLowerIrql(Irql);
}

// This function must not touch pageable code or data
static VOID
PdoS4ToS3(
    IN  PXENBUS_PDO Pdo
    )
{
    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__PdoGetSystemPowerState(Pdo), ==, PowerSystemHibernate);

    __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

// This function must not touch pageable code or data
static VOID
PdoS3ToS4(
    IN  PXENBUS_PDO Pdo
    )
{
    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__PdoGetSystemPowerState(Pdo), ==, PowerSystemSleeping3);

    __PdoSetSystemPowerState(Pdo, PowerSystemHibernate);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

static NTSTATUS
PdoStartDevice(
    IN  PXENBUS_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    PdoD3ToD0(Pdo);

    __PdoSetDevicePnpState(Pdo, Started);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoQueryStopDevice(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoSetDevicePnpState(Pdo, StopPending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoCancelStopDevice(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoRestoreDevicePnpState(Pdo, StopPending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoStopDevice(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    PdoD0ToD3(Pdo);

    __PdoSetDevicePnpState(Pdo, Stopped);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryRemoveDevice(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoSetDevicePnpState(Pdo, RemovePending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoCancelRemoveDevice(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoRestoreDevicePnpState(Pdo, RemovePending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoSurpriseRemoval(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    Warning("%s\n", __PdoGetName(Pdo));

    __PdoSetDevicePnpState(Pdo, SurpriseRemovePending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoRemoveDevice(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    PXENBUS_FDO     Fdo = __PdoGetFdo(Pdo);
    BOOLEAN         NeedInvalidate;
    NTSTATUS        status;

    if (__PdoGetDevicePowerState(Pdo) != PowerDeviceD0)
        goto done;

    PdoD0ToD3(Pdo);

done:
    NeedInvalidate = FALSE;

    FdoAcquireMutex(Fdo);

    if (__PdoIsMissing(Pdo)) {
        DEVICE_PNP_STATE    State = __PdoGetDevicePnpState(Pdo);

        __PdoSetDevicePnpState(Pdo, Deleted);

        if (State == SurpriseRemovePending)
            PdoDestroy(Pdo);
        else
            NeedInvalidate = TRUE;
    } else {
        __PdoSetDevicePnpState(Pdo, Enumerated);
    }

    FdoReleaseMutex(Fdo);

    if (NeedInvalidate)
        IoInvalidateDeviceRelations(FdoGetPhysicalDeviceObject(Fdo),
                                    BusRelations);

    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryDeviceRelations(
    IN  PXENBUS_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PDEVICE_RELATIONS   Relations;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    status = Irp->IoStatus.Status;

    if (StackLocation->Parameters.QueryDeviceRelations.Type != TargetDeviceRelation)
        goto done;

    Relations = __AllocatePoolWithTag(PagedPool, sizeof (DEVICE_RELATIONS), 'SUB');

    status = STATUS_NO_MEMORY;
    if (Relations == NULL)
        goto done;

    Relations->Count = 1;
    ObReferenceObject(__PdoGetDeviceObject(Pdo));
    Relations->Objects[0] = __PdoGetDeviceObject(Pdo);

    Irp->IoStatus.Information = (ULONG_PTR)Relations;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoDelegateIrp(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    return FdoDelegateIrp(__PdoGetFdo(Pdo), Irp);
}

static NTSTATUS
PdoDelegateIrp(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    return __PdoDelegateIrp(Pdo, Irp);
}

static NTSTATUS
PdoQueryBusInterface(
    IN  PXENBUS_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    USHORT                  Size;
    USHORT                  Version;
    PBUS_INTERFACE_STANDARD BusInterface;
    NTSTATUS                status;

    status = Irp->IoStatus.Status;        

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Size = StackLocation->Parameters.QueryInterface.Size;
    Version = StackLocation->Parameters.QueryInterface.Version;
    BusInterface = (PBUS_INTERFACE_STANDARD)StackLocation->Parameters.QueryInterface.Interface;

    if (Version != 1)
        goto done;

    status = STATUS_BUFFER_TOO_SMALL;        
    if (Size < sizeof (BUS_INTERFACE_STANDARD))
        goto done;

    *BusInterface = Pdo->BusInterface;
    BusInterface->InterfaceReference(BusInterface->Context);

    Irp->IoStatus.Information = 0;
    status = STATUS_SUCCESS;

done:
    return status;
}

#define DEFINE_PDO_QUERY_INTERFACE(_Interface)                      \
static NTSTATUS                                                     \
PdoQuery ## _Interface ## Interface(                                \
    IN  PXENBUS_PDO     Pdo,                                        \
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
    status = Irp->IoStatus.Status;                                  \
                                                                    \
    StackLocation = IoGetCurrentIrpStackLocation(Irp);              \
    Size = StackLocation->Parameters.QueryInterface.Size;           \
    Version = StackLocation->Parameters.QueryInterface.Version;     \
    Interface = StackLocation->Parameters.QueryInterface.Interface; \
                                                                    \
    Context = FdoGet ## _Interface ## Context(__PdoGetFdo(Pdo));    \
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

DEFINE_PDO_QUERY_INTERFACE(Debug)
DEFINE_PDO_QUERY_INTERFACE(Suspend)
DEFINE_PDO_QUERY_INTERFACE(SharedInfo)
DEFINE_PDO_QUERY_INTERFACE(Evtchn)
DEFINE_PDO_QUERY_INTERFACE(Store)
DEFINE_PDO_QUERY_INTERFACE(RangeSet)
DEFINE_PDO_QUERY_INTERFACE(Cache)
DEFINE_PDO_QUERY_INTERFACE(Gnttab)
DEFINE_PDO_QUERY_INTERFACE(Unplug)
DEFINE_PDO_QUERY_INTERFACE(Console)

struct _INTERFACE_ENTRY {
    const GUID  *Guid;
    const CHAR  *Name;
    NTSTATUS    (*Query)(PXENBUS_PDO, PIRP);
};

static struct _INTERFACE_ENTRY PdoInterfaceTable[] = {
    { &GUID_BUS_INTERFACE_STANDARD, "BUS_INTERFACE", PdoQueryBusInterface },
    { &GUID_XENBUS_DEBUG_INTERFACE, "DEBUG_INTERFACE", PdoQueryDebugInterface },
    { &GUID_XENBUS_SUSPEND_INTERFACE, "SUSPEND_INTERFACE", PdoQuerySuspendInterface },
    { &GUID_XENBUS_SHARED_INFO_INTERFACE, "SHARED_INFO_INTERFACE", PdoQuerySharedInfoInterface },
    { &GUID_XENBUS_EVTCHN_INTERFACE, "EVTCHN_INTERFACE", PdoQueryEvtchnInterface },
    { &GUID_XENBUS_STORE_INTERFACE, "STORE_INTERFACE", PdoQueryStoreInterface },
    { &GUID_XENBUS_RANGE_SET_INTERFACE, "RANGE_SET_INTERFACE", PdoQueryRangeSetInterface },
    { &GUID_XENBUS_CACHE_INTERFACE, "CACHE_INTERFACE", PdoQueryCacheInterface },
    { &GUID_XENBUS_GNTTAB_INTERFACE, "GNTTAB_INTERFACE", PdoQueryGnttabInterface },
    { &GUID_XENBUS_UNPLUG_INTERFACE, "UNPLUG_INTERFACE", PdoQueryUnplugInterface },
    { &GUID_XENBUS_CONSOLE_INTERFACE, "CONSOLE_INTERFACE", PdoQueryConsoleInterface },
    { &GUID_XENFILT_EMULATED_INTERFACE, "EMULATED_INTERFACE", PdoDelegateIrp },
    { NULL, NULL, NULL }
};

static NTSTATUS
PdoQueryInterface(
    IN  PXENBUS_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    const GUID              *InterfaceType;
    struct _INTERFACE_ENTRY *Entry;
    USHORT                  Version;
    NTSTATUS                status;

    status = Irp->IoStatus.Status;

    if (status != STATUS_NOT_SUPPORTED)
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
            status = Entry->Query(Pdo, Irp);
            goto done;
        }
    }

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryCapabilities(
    IN  PXENBUS_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    PDEVICE_CAPABILITIES    Capabilities;
    SYSTEM_POWER_STATE      SystemPowerState;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Pdo);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Capabilities = StackLocation->Parameters.DeviceCapabilities.Capabilities;

    status = STATUS_INVALID_PARAMETER;
    if (Capabilities->Version != 1)
        goto done;

    Capabilities->DeviceD1 = 0;
    Capabilities->DeviceD2 = 0;
    Capabilities->LockSupported = 0;
    Capabilities->DockDevice = 0;
    Capabilities->UniqueID = 1;
    Capabilities->SilentInstall = 1;
    Capabilities->RawDeviceOK = 0;
    Capabilities->HardwareDisabled = 0;
    Capabilities->NoDisplayInUI = 0;

    Capabilities->Removable = __PdoIsRemovable(Pdo) ? 1 : 0;
    Capabilities->SurpriseRemovalOK = Capabilities->Removable;
    Capabilities->EjectSupported = __PdoIsEjectable(Pdo) ? 1 : 0;

    Capabilities->Address = 0xffffffff;
    Capabilities->UINumber = 0xffffffff;

    for (SystemPowerState = 0; SystemPowerState < PowerSystemMaximum; SystemPowerState++) {
        switch (SystemPowerState) {
        case PowerSystemUnspecified:
        case PowerSystemSleeping1:
        case PowerSystemSleeping2:
            break;

        case PowerSystemWorking:
            Capabilities->DeviceState[SystemPowerState] = PowerDeviceD0;
            break;

        default:
            Capabilities->DeviceState[SystemPowerState] = PowerDeviceD3;
            break;
        }
    }

    Capabilities->SystemWake = PowerSystemUnspecified;
    Capabilities->DeviceWake = PowerDeviceUnspecified;
    Capabilities->D1Latency = 0;
    Capabilities->D2Latency = 0;
    Capabilities->D3Latency = 0;

    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryResourceRequirements(
    IN  PXENBUS_PDO                 Pdo,
    IN  PIRP                        Irp
    )
{
    IO_RESOURCE_DESCRIPTOR          Memory;
    IO_RESOURCE_DESCRIPTOR          Interrupt;
    ULONG                           Size;
    PIO_RESOURCE_REQUIREMENTS_LIST  Requirements;
    PIO_RESOURCE_LIST               List;
    NTSTATUS                        status;

    UNREFERENCED_PARAMETER(Pdo);

    RtlZeroMemory(&Memory, sizeof (IO_RESOURCE_DESCRIPTOR));
    Memory.Type = CmResourceTypeMemory;
    Memory.ShareDisposition = CmResourceShareDeviceExclusive;
    Memory.Flags = CM_RESOURCE_MEMORY_READ_WRITE |
                   CM_RESOURCE_MEMORY_PREFETCHABLE |
                   CM_RESOURCE_MEMORY_CACHEABLE;

    Memory.u.Memory.Length = PAGE_SIZE;
    Memory.u.Memory.Alignment = PAGE_SIZE;
    Memory.u.Memory.MinimumAddress.QuadPart = 0;
    Memory.u.Memory.MaximumAddress.QuadPart = -1;

    RtlZeroMemory(&Interrupt, sizeof (IO_RESOURCE_DESCRIPTOR));
    Interrupt.Type = CmResourceTypeInterrupt;
    Interrupt.ShareDisposition = CmResourceShareDeviceExclusive;
    Interrupt.Flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;

    Interrupt.u.Interrupt.MinimumVector = (ULONG)0;
    Interrupt.u.Interrupt.MaximumVector = (ULONG)-1;
    Interrupt.u.Interrupt.AffinityPolicy = IrqPolicyOneCloseProcessor;
    Interrupt.u.Interrupt.PriorityPolicy = IrqPriorityUndefined;
    Interrupt.u.Interrupt.Group = ALL_PROCESSOR_GROUPS;

    Size = sizeof (IO_RESOURCE_DESCRIPTOR) * 2;
    Size += FIELD_OFFSET(IO_RESOURCE_LIST, Descriptors);
    Size += FIELD_OFFSET(IO_RESOURCE_REQUIREMENTS_LIST, List);

    Requirements = __AllocatePoolWithTag(PagedPool, Size, 'SUB');

    status = STATUS_NO_MEMORY;
    if (Requirements == NULL)
        goto fail1;

    Requirements->ListSize = Size;
    Requirements->InterfaceType = Internal;
    Requirements->BusNumber = 0;
    Requirements->SlotNumber = 0;
    Requirements->AlternativeLists = 1;

    List = &Requirements->List[0];
    List->Version = 1;
    List->Revision = 1;
    List->Count = 2;
    List->Descriptors[0] = Memory;
    List->Descriptors[1] = Interrupt;

    Irp->IoStatus.Information = (ULONG_PTR)Requirements;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryDeviceText(
    IN  PXENBUS_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PWCHAR              Buffer;
    UNICODE_STRING      Text;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextDescription:
        Trace("DeviceTextDescription\n");
        break;

    case DeviceTextLocationInformation:
        Trace("DeviceTextLocationInformation\n");
        break;

    default:
        Irp->IoStatus.Information = 0;
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    Buffer = __AllocatePoolWithTag(PagedPool, MAXTEXTLEN, 'SUB');

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto done;

    Text.Buffer = Buffer;
    Text.MaximumLength = MAXTEXTLEN;
    Text.Length = 0;

    switch (StackLocation->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextDescription:
        status = RtlStringCbPrintfW(Buffer,
                                    MAXTEXTLEN,
                                    L"%hs %hs",
                                    FdoGetName(__PdoGetFdo(Pdo)),
                                    __PdoGetName(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    case DeviceTextLocationInformation:
        status = RtlStringCbPrintfW(Buffer,
                                    MAXTEXTLEN,
                                    L"%hs",
                                    __PdoGetName(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Text.Length = (USHORT)((ULONG_PTR)Buffer - (ULONG_PTR)Text.Buffer);

    Trace("%s: %wZ\n", __PdoGetName(Pdo), &Text);

    Irp->IoStatus.Information = (ULONG_PTR)Text.Buffer;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoReadConfig(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS
PdoWriteConfig(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

#define REGSTR_VAL_MAX_HCID_LEN 1024

static NTSTATUS
PdoQueryId(
    IN  PXENBUS_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PWCHAR              Buffer;
    UNICODE_STRING      Id;
    ULONG               Type;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->Parameters.QueryId.IdType) {
    case BusQueryInstanceID:
        Trace("BusQueryInstanceID\n");
        Id.MaximumLength = 2 * sizeof (WCHAR);
        break;

    case BusQueryDeviceID:
        Trace("BusQueryDeviceID\n");
        Id.MaximumLength = (MAX_DEVICE_ID_LEN - 2) * sizeof (WCHAR);
        break;

    case BusQueryHardwareIDs:
        Trace("BusQueryHardwareIDs\n");
        Id.MaximumLength = (USHORT)(MAX_DEVICE_ID_LEN * ARRAYSIZE(PdoRevision)) * sizeof (WCHAR);
        break;

    case BusQueryCompatibleIDs:
        Trace("BusQueryCompatibleIDs\n");
        Id.MaximumLength = (USHORT)(MAX_DEVICE_ID_LEN * ARRAYSIZE(PdoRevision)) * sizeof (WCHAR);
        break;

    default:
        Irp->IoStatus.Information = 0;
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    Buffer = __AllocatePoolWithTag(PagedPool, Id.MaximumLength, 'SUB');

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto done;

    Id.Buffer = Buffer;
    Id.Length = 0;

    switch (StackLocation->Parameters.QueryId.IdType) {
    case BusQueryInstanceID:
        Type = REG_SZ;

        status = RtlAppendUnicodeToString(&Id, L"_");
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    case BusQueryDeviceID: {
        ULONG                   Index;
        PXENBUS_PDO_REVISION    Revision;

        Type = REG_SZ;
        Index = ARRAYSIZE(PdoRevision) - 1;
        Revision = &PdoRevision[Index];

        status = RtlStringCbPrintfW(Buffer,
                                    Id.MaximumLength,
                                    L"XENBUS\\VEN_%hs&DEV_%hs&REV_%08X",
                                    __PdoGetVendorName(Pdo),
                                    __PdoGetName(Pdo),
                                    Revision->Number);
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;
    }
    case BusQueryHardwareIDs:
    case BusQueryCompatibleIDs: {
        LONG    Index;
        ULONG   Length;

        Type = REG_MULTI_SZ;
        Index = ARRAYSIZE(PdoRevision) - 1;

        Length = Id.MaximumLength;

        while (Index >= 0) {
            PXENBUS_PDO_REVISION Revision = &PdoRevision[Index];

            status = RtlStringCbPrintfW(Buffer,
                                        Length,
                                        L"XENBUS\\VEN_%hs&DEV_%hs&REV_%08X",
                                        __PdoGetVendorName(Pdo),
                                        __PdoGetName(Pdo),
                                        Revision->Number);
            ASSERT(NT_SUCCESS(status));

            Buffer += wcslen(Buffer);
            Length -= (ULONG)(wcslen(Buffer) * sizeof (WCHAR));

            Buffer++;
            Length -= sizeof (WCHAR);

            --Index;
        }

        status = RtlStringCbPrintfW(Buffer,
                                    Length,
                                    L"XENCLASS");
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);
        Buffer++;

        ASSERT3U((ULONG_PTR)Buffer - (ULONG_PTR)Id.Buffer, <,
                 REGSTR_VAL_MAX_HCID_LEN);
        break;
    }
    default:
        Type = REG_NONE;

        ASSERT(FALSE);
        break;
    }

    Id.Length = (USHORT)((ULONG_PTR)Buffer - (ULONG_PTR)Id.Buffer);
    Buffer = Id.Buffer;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    switch (Type) {
    case REG_SZ:
        Trace("- %ws\n", Buffer);
        break;

    case REG_MULTI_SZ:
        do {
            Trace("- %ws\n", Buffer);
            Buffer += wcslen(Buffer);
            Buffer++;
        } while (*Buffer != L'\0');
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Irp->IoStatus.Information = (ULONG_PTR)Id.Buffer;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoQueryBusInformation(
    IN  PXENBUS_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PPNP_BUS_INFORMATION    Info;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Pdo);

    Info = __AllocatePoolWithTag(PagedPool, sizeof (PNP_BUS_INFORMATION), 'SUB');

    status = STATUS_NO_MEMORY;
    if (Info == NULL)
        goto done;

    Info->BusTypeGuid = GUID_BUS_TYPE_INTERNAL;
    Info->LegacyBusType = Internal;
    Info->BusNumber = 0;

    Irp->IoStatus.Information = (ULONG_PTR)Info;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoDeviceUsageNotification(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    status = __PdoDelegateIrp(Pdo, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoEject(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    PXENBUS_FDO     Fdo = __PdoGetFdo(Pdo);
    NTSTATUS        status;

    Trace("%s\n", __PdoGetName(Pdo));

    FdoAcquireMutex(Fdo);

    __PdoSetDevicePnpState(Pdo, Deleted);
    __PdoSetMissing(Pdo, "device ejected");

    FdoReleaseMutex(Fdo);

    IoInvalidateDeviceRelations(FdoGetPhysicalDeviceObject(Fdo),
                                BusRelations);

    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoDispatchPnp(
    IN  PXENBUS_PDO     Pdo,
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

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        status = PdoCancelRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        status = PdoSurpriseRemoval(Pdo, Irp);
        break;

    case IRP_MN_REMOVE_DEVICE:
        status = PdoRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        status = PdoQueryDeviceRelations(Pdo, Irp);
        break;

    case IRP_MN_QUERY_INTERFACE:
        status = PdoQueryInterface(Pdo, Irp);
        break;

    case IRP_MN_QUERY_CAPABILITIES:
        status = PdoQueryCapabilities(Pdo, Irp);
        break;

    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
        status = PdoQueryResourceRequirements(Pdo, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_TEXT:
        status = PdoQueryDeviceText(Pdo, Irp);
        break;

    case IRP_MN_READ_CONFIG:
        status = PdoReadConfig(Pdo, Irp);
        break;

    case IRP_MN_WRITE_CONFIG:
        status = PdoWriteConfig(Pdo, Irp);
        break;

    case IRP_MN_QUERY_ID:
        status = PdoQueryId(Pdo, Irp);
        break;

    case IRP_MN_QUERY_BUS_INFORMATION:
        status = PdoQueryBusInformation(Pdo, Irp);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        status = PdoDeviceUsageNotification(Pdo, Irp);
        break;

    case IRP_MN_EJECT:
        status = PdoEject(Pdo, Irp);
        break;

    default:
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

    Trace("<==== (%02x:%s)(%08x)\n",
          MinorFunction, 
          PnpMinorFunctionName(MinorFunction),
          status);

    return status;
}

static NTSTATUS
PdoSetDevicePower(
    IN  PXENBUS_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_ACTION        PowerAction;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (__PdoGetDevicePowerState(Pdo) > DeviceState) {
        Trace("%s: POWERING UP: %s -> %s\n",
              __PdoGetName(Pdo),
              DevicePowerStateName(__PdoGetDevicePowerState(Pdo)),
              DevicePowerStateName(DeviceState));

        ASSERT3U(DeviceState, ==, PowerDeviceD0);
        PdoD3ToD0(Pdo);
    } else if (__PdoGetDevicePowerState(Pdo) < DeviceState) {
        Trace("%s: POWERING DOWN: %s -> %s\n",
              __PdoGetName(Pdo),
              DevicePowerStateName(__PdoGetDevicePowerState(Pdo)),
              DevicePowerStateName(DeviceState));

        ASSERT3U(DeviceState, ==, PowerDeviceD3);
        PdoD0ToD3(Pdo);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Trace("<==== (%s:%s)\n",
          DevicePowerStateName(DeviceState), 
          PowerActionName(PowerAction));

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoDevicePower(
    IN  PXENBUS_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENBUS_PDO         Pdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP    Irp;

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

        (VOID) PdoSetDevicePower(Pdo, Irp);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoSetSystemPower(
    IN  PXENBUS_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    POWER_ACTION        PowerAction;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (__PdoGetSystemPowerState(Pdo) > SystemState) {
        if (SystemState < PowerSystemHibernate &&
            __PdoGetSystemPowerState(Pdo) >= PowerSystemHibernate) {
            __PdoSetSystemPowerState(Pdo, PowerSystemHibernate);
            PdoS4ToS3(Pdo);
        }

        Trace("%s: POWERING UP: %s -> %s\n",
              __PdoGetName(Pdo),
              SystemPowerStateName(__PdoGetSystemPowerState(Pdo)),
              SystemPowerStateName(SystemState));

    } else if (__PdoGetSystemPowerState(Pdo) < SystemState) {
        Trace("%s: POWERING DOWN: %s -> %s\n",
              __PdoGetName(Pdo),
              SystemPowerStateName(__PdoGetSystemPowerState(Pdo)),
              SystemPowerStateName(SystemState));

        if (SystemState >= PowerSystemHibernate &&
            __PdoGetSystemPowerState(Pdo) < PowerSystemHibernate) {
            __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);
            PdoS3ToS4(Pdo);
        }
    }

    __PdoSetSystemPowerState(Pdo, SystemState);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Trace("<==== (%s:%s)\n",
          SystemPowerStateName(SystemState), 
          PowerActionName(PowerAction));

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoSystemPower(
    IN  PXENBUS_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENBUS_PDO         Pdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP    Irp;

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

        (VOID) PdoSetSystemPower(Pdo, Irp);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoSetPower(
    IN  PXENBUS_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    POWER_STATE_TYPE    PowerType;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;
    
    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    PowerType = StackLocation->Parameters.Power.Type;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    if (PowerAction >= PowerActionShutdown) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

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
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

done:
    return status;
}

static NTSTATUS
PdoQueryPower(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Pdo);

    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
PdoDispatchPower(
    IN  PXENBUS_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    switch (StackLocation->MinorFunction) {
    case IRP_MN_SET_POWER:
        status = PdoSetPower(Pdo, Irp);
        break;

    case IRP_MN_QUERY_POWER:
        status = PdoQueryPower(Pdo, Irp);
        break;

    default:
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

    return status;
}

static NTSTATUS
PdoDispatchDefault(
    IN  PXENBUS_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Pdo);

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS
PdoDispatch(
    IN  PXENBUS_PDO     Pdo,
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
    IN  PXENBUS_PDO     Pdo
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Trace("<===>\n");
}

VOID
PdoSuspend(
    IN  PXENBUS_PDO     Pdo
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Trace("<===>\n");
}

NTSTATUS
PdoCreate(
    IN  PXENBUS_FDO     Fdo,
    IN  PANSI_STRING    Name
    )
{
    PDEVICE_OBJECT      PhysicalDeviceObject;
    PXENBUS_DX          Dx;
    PXENBUS_PDO         Pdo;
    NTSTATUS            status;

#pragma prefast(suppress:28197) // Possibly leaking memory 'PhysicalDeviceObject'
    status = IoCreateDevice(DriverGetDriverObject(),
                            sizeof(XENBUS_DX),
                            NULL,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN | FILE_AUTOGENERATED_DEVICE_NAME,
                            FALSE,
                            &PhysicalDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXENBUS_DX)PhysicalDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XENBUS_DX));

    Dx->Type = PHYSICAL_DEVICE_OBJECT;
    Dx->DeviceObject = PhysicalDeviceObject;
    Dx->DevicePnpState = Present;

    Dx->SystemPowerState = PowerSystemWorking;
    Dx->DevicePowerState = PowerDeviceD3;

    Pdo = __PdoAllocate(sizeof (XENBUS_PDO));

    status = STATUS_NO_MEMORY;
    if (Pdo == NULL)
        goto fail2;

    Pdo->Dx = Dx;
    Pdo->Fdo = Fdo;

    status = ThreadCreate(PdoSystemPower, Pdo, &Pdo->SystemPowerThread);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ThreadCreate(PdoDevicePower, Pdo, &Pdo->DevicePowerThread);
    if (!NT_SUCCESS(status))
        goto fail4;

    __PdoSetName(Pdo, Name);
    __PdoSetRemovable(Pdo);
    __PdoSetEjectable(Pdo);

    status = BusInitialize(Pdo, &Pdo->BusInterface);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = SuspendGetInterface(FdoGetSuspendContext(Fdo),
                                 XENBUS_SUSPEND_INTERFACE_VERSION_MAX,
                                 (PINTERFACE)&Pdo->SuspendInterface,
                                 sizeof (Pdo->SuspendInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT(Pdo->SuspendInterface.Interface.Context != NULL);

    Info("%p (%s)\n",
         PhysicalDeviceObject,
         __PdoGetName(Pdo));

    PdoDumpRevisions(Pdo);

    Dx->Pdo = Pdo;
    PhysicalDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    FdoAddPhysicalDeviceObject(Fdo, Pdo);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    Pdo->Ejectable = FALSE;
    Pdo->Removable = FALSE;

    ThreadAlert(Pdo->DevicePowerThread);
    ThreadJoin(Pdo->DevicePowerThread);
    Pdo->DevicePowerThread = NULL;

fail4:
    Error("fail4\n");

    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

fail3:
    Error("fail3\n");

    Pdo->Fdo = NULL;
    Pdo->Dx = NULL;

    ASSERT(IsZeroMemory(Pdo, sizeof (XENBUS_PDO)));
    __PdoFree(Pdo);

fail2:
    Error("fail2\n");

    IoDeleteDevice(PhysicalDeviceObject);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
PdoDestroy(
    IN  PXENBUS_PDO Pdo
    )
{
    PXENBUS_DX      Dx = Pdo->Dx;
    PDEVICE_OBJECT  PhysicalDeviceObject = Dx->DeviceObject;
    PXENBUS_FDO     Fdo = __PdoGetFdo(Pdo);

    ASSERT3U(__PdoGetDevicePnpState(Pdo), ==, Deleted);

    ASSERT(__PdoIsMissing(Pdo));
    Pdo->Missing = FALSE;

    FdoRemovePhysicalDeviceObject(Fdo, Pdo);

    Info("%p (%s) (%s)\n",
         PhysicalDeviceObject,
         __PdoGetName(Pdo),
         Pdo->Reason);
    Pdo->Reason = NULL;

    Dx->Pdo = NULL;

    RtlZeroMemory(&Pdo->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    BusTeardown(&Pdo->BusInterface);

    Pdo->Ejectable = FALSE;
    Pdo->Removable = FALSE;

    ThreadAlert(Pdo->DevicePowerThread);
    ThreadJoin(Pdo->DevicePowerThread);
    Pdo->DevicePowerThread = NULL;
    
    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

    Pdo->Fdo = NULL;
    Pdo->Dx = NULL;

    ASSERT(IsZeroMemory(Pdo, sizeof (XENBUS_PDO)));
    __PdoFree(Pdo);

    IoDeleteDevice(PhysicalDeviceObject);
}
