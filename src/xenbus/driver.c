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

#include <ntddk.h>
#include <procgrp.h>
#include <ntstrsafe.h>

#include "registry.h"
#include "fdo.h"
#include "pdo.h"
#include "driver.h"
#include "names.h"
#include "mutex.h"
#include "filters.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"
#include "version.h"

typedef struct _XENBUS_DRIVER {
    PDRIVER_OBJECT      DriverObject;
    HANDLE              ParametersKey;
    LOG_LEVEL           ConsoleLogLevel;

    MUTEX               Mutex;
    LIST_ENTRY          List;
    ULONG               References;
} XENBUS_DRIVER, *PXENBUS_DRIVER;

static XENBUS_DRIVER    Driver;

#define XENBUS_DRIVER_TAG   'VIRD'
#define DEFAULT_CONSOLE_LOG_LEVEL   (LOG_LEVEL_INFO |       \
                                     LOG_LEVEL_WARNING |    \
                                     LOG_LEVEL_ERROR |      \
                                     LOG_LEVEL_CRITICAL)

static FORCEINLINE PVOID
__DriverAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_DRIVER_TAG);
}

static FORCEINLINE VOID
__DriverFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_DRIVER_TAG);
}

static FORCEINLINE VOID
__DriverSetDriverObject(
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    Driver.DriverObject = DriverObject;
}

static FORCEINLINE PDRIVER_OBJECT
__DriverGetDriverObject(
    VOID
    )
{
    return Driver.DriverObject;
}

PDRIVER_OBJECT
DriverGetDriverObject(
    VOID
    )
{
    return __DriverGetDriverObject();
}

static FORCEINLINE VOID
__DriverSetParametersKey(
    IN  HANDLE  Key
    )
{
    Driver.ParametersKey = Key;
}

static FORCEINLINE HANDLE
__DriverGetParametersKey(
    VOID
    )
{
    return Driver.ParametersKey;
}

HANDLE
DriverGetParametersKey(
    VOID
    )
{
    return __DriverGetParametersKey();
}

static FORCEINLINE VOID
__DriverSetConsoleLogLevel(
    IN  LOG_LEVEL   LogLevel
    )
{
    Driver.ConsoleLogLevel = LogLevel;
}

static FORCEINLINE LOG_LEVEL
__DriverGetConsoleLogLevel(
    VOID
    )
{
    return Driver.ConsoleLogLevel;
}

LOG_LEVEL
DriverGetConsoleLogLevel(
    VOID
    )
{
    return __DriverGetConsoleLogLevel();
}

#define MAXNAMELEN  128

static FORCEINLINE VOID
__DriverRequestReboot(
    VOID
    )
{
    PANSI_STRING    Ansi;
    CHAR            RequestKeyName[MAXNAMELEN];
    HANDLE          RequestKey;
    HANDLE          SubKey;
    NTSTATUS        status;

    Info("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    status = RegistryQuerySzValue(__DriverGetParametersKey(),
                                  "RequestKey",
                                  NULL,
                                  &Ansi);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringCbPrintfA(RequestKeyName,
                                MAXNAMELEN,
                                "\\Registry\\Machine\\%Z",
                                &Ansi[0]);
    ASSERT(NT_SUCCESS(status));

    status = RegistryCreateSubKey(NULL,
                                  RequestKeyName,
                                  REG_OPTION_NON_VOLATILE,
                                  &RequestKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryCreateSubKey(RequestKey,
                                  __MODULE__,
                                  REG_OPTION_VOLATILE,
                                  &SubKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RegistryUpdateDwordValue(SubKey,
                                      "Reboot",
                                      1);
    if (!NT_SUCCESS(status))
        goto fail4;

    RegistryCloseKey(SubKey);

    RegistryFreeSzValue(Ansi);

    Info("<====\n");

    return;

fail4:
    Error("fail4\n");

    RegistryCloseKey(SubKey);

fail3:
    Error("fail3\n");

    RegistryCloseKey(RequestKey);

fail2:
    Error("fail2\n");

    RegistryFreeSzValue(Ansi);

fail1:
    Error("fail1 (%08x)\n", status);
}

static FORCEINLINE VOID
__DriverAcquireMutex(
    VOID
    )
{
    AcquireMutex(&Driver.Mutex);
}

VOID
DriverAcquireMutex(
    VOID
    )
{
    __DriverAcquireMutex();
}

static FORCEINLINE VOID
__DriverReleaseMutex(
    VOID
    )
{
    ReleaseMutex(&Driver.Mutex);
}

VOID
DriverReleaseMutex(
    VOID
    )
{
    __DriverReleaseMutex();
}

VOID
DriverAddFunctionDeviceObject(
    IN  PXENBUS_FDO Fdo
    )
{
    PDEVICE_OBJECT  DeviceObject;
    PXENBUS_DX      Dx;
    ULONG           References;

    DeviceObject = FdoGetDeviceObject(Fdo);
    Dx = (PXENBUS_DX)DeviceObject->DeviceExtension;
    ASSERT3U(Dx->Type, ==, FUNCTION_DEVICE_OBJECT);

    InsertTailList(&Driver.List, &Dx->ListEntry);
    References = Driver.References++;

    if (References == 1)
        FiltersInstall();
}

VOID
DriverRemoveFunctionDeviceObject(
    IN  PXENBUS_FDO Fdo
    )
{
    PDEVICE_OBJECT  DeviceObject;
    PXENBUS_DX      Dx;
    ULONG           References;

    DeviceObject = FdoGetDeviceObject(Fdo);
    Dx = (PXENBUS_DX)DeviceObject->DeviceExtension;
    ASSERT3U(Dx->Type, ==, FUNCTION_DEVICE_OBJECT);

    RemoveEntryList(&Dx->ListEntry);
    ASSERT3U(Driver.References, !=, 0);
    References = --Driver.References;
}

//
// The canonical location for active device information is the XENFILT
// Parameters key.
//
#define ACTIVE_PATH "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\XENFILT\\Parameters"

NTSTATUS
DriverGetActive(
    IN  const CHAR  *Key,
    OUT PCHAR       *Value
    )
{
    HANDLE          ActiveKey;
    CHAR            Name[MAXNAMELEN];
    PANSI_STRING    Ansi;
    ULONG           Length;
    NTSTATUS        status;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    status = RegistryOpenSubKey(NULL,
                                ACTIVE_PATH,
                                KEY_READ,
                                &ActiveKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringCbPrintfA(Name, MAXNAMELEN, "Active%s", Key);
    ASSERT(NT_SUCCESS(status));

    status = RegistryQuerySzValue(ActiveKey,
                                  Name,
                                  NULL,
                                  &Ansi);
    if (!NT_SUCCESS(status))
        goto fail2;

    Length = Ansi[0].Length + sizeof (CHAR);
    *Value = __AllocatePoolWithTag(PagedPool, Length, 'SUB');

    status = STATUS_NO_MEMORY;
    if (*Value == NULL)
        goto fail3;

    status = RtlStringCbPrintfA(*Value,
                                Length,
                                "%Z",
                                &Ansi[0]);
    ASSERT(NT_SUCCESS(status));

    RegistryFreeSzValue(Ansi);

    RegistryCloseKey(ActiveKey);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    if (status != STATUS_OBJECT_NAME_NOT_FOUND)
        Error("fail2\n");

    RegistryCloseKey(ActiveKey);

fail1:
    if (status != STATUS_OBJECT_NAME_NOT_FOUND)
        Error("fail1 (%08x)\n", status);

    return status;
}

static const CHAR *DriverLegacyDevicePrefix[] = {
    "PCI\\VEN_5853&DEV_0001",
    "PCI\\VEN_5853&DEV_0002"
};

static FORCEINLINE BOOLEAN
__DriverIsDeviceLegacy(
    IN  PCHAR   DeviceID
    )
{
    ULONG       Index;

    for (Index = 0; Index < ARRAYSIZE(DriverLegacyDevicePrefix); Index++) {
        const CHAR  *Prefix = DriverLegacyDevicePrefix[Index];

        if (_strnicmp(DeviceID, Prefix, strlen(Prefix)) == 0)
            return TRUE;
    }

    return FALSE;
}

static const CHAR *DriverVendorDeviceID =
#ifdef VENDOR_DEVICE_ID_STR
    "PCI\\VEN_5853&DEV_" VENDOR_DEVICE_ID_STR "&SUBSYS_C0005853&REV_01";
#else
    NULL;
#endif

#define ENUM_PATH "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum"

static FORCEINLINE BOOLEAN
__DriverIsVendorDevicePresent(
    VOID
    )
{
    HANDLE      EnumKey;
    HANDLE      DeviceKey;
    BOOLEAN     Found;
    NTSTATUS    status;

    if (DriverVendorDeviceID == NULL)
        return FALSE;

    status = RegistryOpenSubKey(NULL,
                                ENUM_PATH,
                                KEY_READ,
                                &EnumKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    Found = FALSE;

    status = RegistryOpenSubKey(EnumKey,
                                (PCHAR)DriverVendorDeviceID,
                                KEY_READ,
                                &DeviceKey);
    if (!NT_SUCCESS(status))
        goto done;

    RegistryCloseKey(DeviceKey);
    Found = TRUE;

done:
    RegistryCloseKey(EnumKey);

    return Found;

fail1:
    Error("fail1 (%08x)\n", status);

    return FALSE;
}

NTSTATUS
DriverSetActive(
    IN  PCHAR   DeviceID,
    IN  PCHAR   InstanceID,
    IN  PCHAR   LocationInformation
    )
{
    HANDLE      ActiveKey;
    ANSI_STRING Ansi[2];
    NTSTATUS    status;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    status = RegistryOpenSubKey(NULL,
                                ACTIVE_PATH,
                                KEY_ALL_ACCESS,
                                &ActiveKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = STATUS_UNSUCCESSFUL;
    if (__DriverIsDeviceLegacy(DeviceID) &&
        __DriverIsVendorDevicePresent())
        goto fail2;

    RtlZeroMemory(Ansi, sizeof (ANSI_STRING) * 2);

    RtlInitAnsiString(&Ansi[0], DeviceID);

    status = RegistryUpdateSzValue(ActiveKey,
                                   "ActiveDeviceID",
                                   REG_SZ,
                                   Ansi);
    if (!NT_SUCCESS(status))
        goto fail3;

    RtlInitAnsiString(&Ansi[0], InstanceID);

    status = RegistryUpdateSzValue(ActiveKey,
                                   "ActiveInstanceID",
                                   REG_SZ,
                                   Ansi);
    if (!NT_SUCCESS(status))
        goto fail4;

    RtlInitAnsiString(&Ansi[0], LocationInformation);

    status = RegistryUpdateSzValue(ActiveKey,
                                   "ActiveLocationInformation",
                                   REG_SZ,
                                   Ansi);
    if (!NT_SUCCESS(status))
        goto fail5;

    Info("%s\\%s: %s\n", DeviceID, InstanceID, LocationInformation);

    RegistryCloseKey(ActiveKey);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    RegistryCloseKey(ActiveKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
DriverUpdateActive(
    IN  PCHAR   DeviceID,
    IN  PCHAR   InstanceID,
    IN  PCHAR   LocationInformation
    )
{
    HANDLE      ActiveKey;
    ANSI_STRING Ansi[2];
    PCHAR       ActiveInstanceID;
    PCHAR       ActiveLocationInformation;
    NTSTATUS    status;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    status = RegistryOpenSubKey(NULL,
                                ACTIVE_PATH,
                                KEY_ALL_ACCESS,
                                &ActiveKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = STATUS_UNSUCCESSFUL;
    if (__DriverIsDeviceLegacy(DeviceID) &&
        __DriverIsVendorDevicePresent())
        goto fail2;

    RtlZeroMemory(Ansi, sizeof (ANSI_STRING) * 2);

    status = DriverGetActive("InstanceID", &ActiveInstanceID);
    if (NT_SUCCESS(status)) {
        ExFreePool(ActiveInstanceID);
    } else {
        RtlInitAnsiString(&Ansi[0], InstanceID);

        status = RegistryUpdateSzValue(ActiveKey,
                                       "ActiveInstanceID",
                                       REG_SZ,
                                       Ansi);
        if (!NT_SUCCESS(status))
            goto fail3;
    }

    status = DriverGetActive("LocationInformation", &ActiveLocationInformation);
    if (NT_SUCCESS(status)) {
        ExFreePool(ActiveLocationInformation);
    } else {
        RtlInitAnsiString(&Ansi[0], LocationInformation);

        status = RegistryUpdateSzValue(ActiveKey,
                                       "ActiveLocationInformation",
                                       REG_SZ,
                                       Ansi);
        if (!NT_SUCCESS(status))
            goto fail4;
    }

    Info("%s\\%s: %s\n", DeviceID, InstanceID, LocationInformation);

    RegistryCloseKey(ActiveKey);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    RegistryCloseKey(ActiveKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
DriverClearActive(
    VOID
    )
{
    HANDLE      ActiveKey;
    NTSTATUS    status;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    status = RegistryOpenSubKey(NULL,
                                ACTIVE_PATH,
                                KEY_ALL_ACCESS,
                                &ActiveKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryDeleteValue(ActiveKey,
                                 "ActiveDeviceID");
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryDeleteValue(ActiveKey,
                                 "ActiveInstanceID");
    if (!NT_SUCCESS(status))
        goto fail3;

    Info("DONE\n");

    RegistryCloseKey(ActiveKey);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    RegistryCloseKey(ActiveKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

DRIVER_UNLOAD       DriverUnload;

VOID
DriverUnload(
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    HANDLE              ParametersKey;

    ASSERT3P(DriverObject, ==, __DriverGetDriverObject());

    Trace("====>\n");

    ASSERT(IsListEmpty(&Driver.List));
    ASSERT3U(Driver.References, ==, 1);
    --Driver.References;

    RtlZeroMemory(&Driver.List, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Driver.Mutex, sizeof (MUTEX));

    __DriverSetConsoleLogLevel(0);

    ParametersKey = __DriverGetParametersKey();

    RegistryCloseKey(ParametersKey);
    __DriverSetParametersKey(NULL);

    RegistryTeardown();

    Info("XENBUS %d.%d.%d (%d) (%02d.%02d.%04d)\n",
         MAJOR_VERSION,
         MINOR_VERSION,
         MICRO_VERSION,
         BUILD_NUMBER,
         DAY,
         MONTH,
         YEAR);

    __DriverSetDriverObject(NULL);

    ASSERT(IsZeroMemory(&Driver, sizeof (XENBUS_DRIVER)));

    Trace("<====\n");
}

DRIVER_ADD_DEVICE   DriverAddDevice;

NTSTATUS
#pragma prefast(suppress:28152) // Does not clear DO_DEVICE_INITIALIZING
DriverAddDevice(
    IN  PDRIVER_OBJECT  DriverObject,
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    NTSTATUS            status;

    ASSERT3P(DriverObject, ==, __DriverGetDriverObject());

    Trace("====>\n");

    __DriverAcquireMutex();

    status = FdoCreate(DeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    __DriverReleaseMutex();

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    __DriverReleaseMutex();

    return status;
}

DRIVER_DISPATCH DriverDispatch;

NTSTATUS 
DriverDispatch(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PXENBUS_DX          Dx;
    NTSTATUS            status;

    Dx = (PXENBUS_DX)DeviceObject->DeviceExtension;
    ASSERT3P(Dx->DeviceObject, ==, DeviceObject);

    if (Dx->DevicePnpState == Deleted) {
        status = STATUS_NO_SUCH_DEVICE;

        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        goto done;
    }

    status = STATUS_NOT_SUPPORTED;
    switch (Dx->Type) {
    case PHYSICAL_DEVICE_OBJECT: {
        PXENBUS_PDO Pdo = Dx->Pdo;

        status = PdoDispatch(Pdo, Irp);
        break;
    }
    case FUNCTION_DEVICE_OBJECT: {
        PXENBUS_FDO Fdo = Dx->Fdo;

        status = FdoDispatch(Fdo, Irp);
        break;
    }
    default:
        ASSERT(FALSE);
        break;
    }

done:
    return status;
}

DRIVER_INITIALIZE   DriverEntry;

NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT  DriverObject,
    IN  PUNICODE_STRING RegistryPath
    )
{
    HANDLE              ServiceKey;
    HANDLE              ParametersKey;
    ULONG               Index;
    LOG_LEVEL           LogLevel;
    NTSTATUS            status;

    ASSERT3P(__DriverGetDriverObject(), ==, NULL);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    WdmlibProcgrpInitialize();

    __DbgPrintEnable();

    Trace("====>\n");

    __DriverSetDriverObject(DriverObject);

    Driver.DriverObject->DriverUnload = DriverUnload;

    Info("%d.%d.%d (%d) (%02d.%02d.%04d)\n",
         MAJOR_VERSION,
         MINOR_VERSION,
         MICRO_VERSION,
         BUILD_NUMBER,
         DAY,
         MONTH,
         YEAR);

    status = RegistryInitialize(RegistryPath);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryOpenServiceKey(KEY_READ, &ServiceKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryOpenSubKey(ServiceKey,
                                "Parameters",
                                KEY_READ,
                                &ParametersKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    __DriverSetParametersKey(ParametersKey);

    status = LogReadLogLevel(ParametersKey,
                             "ConsoleLogLevel",
                             &LogLevel);
    if (!NT_SUCCESS(status))
        LogLevel = DEFAULT_CONSOLE_LOG_LEVEL;

    __DriverSetConsoleLogLevel(LogLevel);

    RegistryCloseKey(ServiceKey);

    status = XenTouch(__MODULE__,
                      MAJOR_VERSION,
                      MINOR_VERSION,
                      MICRO_VERSION,
                      BUILD_NUMBER);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_INCOMPATIBLE_DRIVER_BLOCKED)
            __DriverRequestReboot();

        goto done;
    }

    // Remove the filters from the registry. They will be re-instated by
    // the first successful AddDevice.
    FiltersUninstall();

    DriverObject->DriverExtension->AddDevice = DriverAddDevice;

    for (Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; Index++) {
#pragma prefast(suppress:28169) // No __drv_dispatchType annotation
#pragma prefast(suppress:28168) // No matching __drv_dispatchType annotation for IRP_MJ_CREATE
       DriverObject->MajorFunction[Index] = DriverDispatch;
    }

done:
    InitializeMutex(&Driver.Mutex);
    InitializeListHead(&Driver.List);
    Driver.References = 1;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    RegistryCloseKey(ServiceKey);

fail2:
    Error("fail2\n");

    RegistryTeardown();

fail1:
    Error("fail1 (%08x)\n", status);

    __DriverSetDriverObject(NULL);

    ASSERT(IsZeroMemory(&Driver, sizeof (XENBUS_DRIVER)));

    return status;
}
