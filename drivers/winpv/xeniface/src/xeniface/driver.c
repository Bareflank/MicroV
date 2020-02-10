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

#include <ntifs.h>
#include <procgrp.h>
#include <version.h>

#include "fdo.h"
#include "driver.h"

#include "assert.h"
#include "wmi.h"

PDRIVER_OBJECT      DriverObject;

DRIVER_UNLOAD       DriverUnload;

XENIFACE_PARAMETERS DriverParameters;

VOID
DriverUnload(
    IN  PDRIVER_OBJECT  _DriverObject
    )
{
    ASSERT3P(_DriverObject, ==, DriverObject);

    Trace("====>\n");

    if (DriverParameters.RegistryPath.Buffer != NULL) {
        ExFreePool(DriverParameters.RegistryPath.Buffer);
    }

    DriverObject = NULL;

    Trace("<====\n");
}

DRIVER_ADD_DEVICE   AddDevice;

NTSTATUS
AddDevice(
    IN  PDRIVER_OBJECT  _DriverObject,
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    NTSTATUS            status;

    ASSERT3P(_DriverObject, ==, DriverObject);

    status = FdoCreate(DeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    // prefast stupidity
    ASSERT(!(DeviceObject->Flags & DO_DEVICE_INITIALIZING));
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

DRIVER_DISPATCH Dispatch;

NTSTATUS 
Dispatch(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PXENIFACE_DX        Dx;
    NTSTATUS            status;

    Dx = (PXENIFACE_DX)DeviceObject->DeviceExtension;
    ASSERT3P(Dx->DeviceObject, ==, DeviceObject);

    if (Dx->DevicePnpState == Deleted) {
        status = STATUS_NO_SUCH_DEVICE;

        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        goto done;
    }

    status = STATUS_NOT_SUPPORTED;
    switch (Dx->Type) {
    case FUNCTION_DEVICE_OBJECT: {
        PXENIFACE_FDO Fdo = Dx->Fdo;

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
    IN  PDRIVER_OBJECT  _DriverObject,
    IN  PUNICODE_STRING RegistryPath
    )
{
    ULONG               Index;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ASSERT3P(DriverObject, ==, NULL);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    WdmlibProcgrpInitialize();

    Trace("====>\n");

    Info("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    DriverParameters.RegistryPath.MaximumLength = RegistryPath->Length + sizeof(UNICODE_NULL);
    DriverParameters.RegistryPath.Length = RegistryPath->Length;
    DriverParameters.RegistryPath.Buffer = ExAllocatePoolWithTag (PagedPool,
                                                DriverParameters.RegistryPath.MaximumLength,
                                                XENIFACE_POOL_TAG);
    if (NULL == DriverParameters.RegistryPath.Buffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fail1;
    }
    RtlCopyUnicodeString(&DriverParameters.RegistryPath, RegistryPath);


    DriverObject = _DriverObject;
    DriverObject->DriverUnload = DriverUnload;

    DriverObject->DriverExtension->AddDevice = AddDevice;

    for (Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; Index++) {
#pragma prefast(suppress:28169) // No __drv_dispatchType annotation
#pragma prefast(suppress:28168) // No matching __drv_dispatchType annotation for IRP_MJ_CREATE
        DriverObject->MajorFunction[Index] = Dispatch;
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
fail1:
    Error("fail1 (%08x)\n", status);
    return status;
}
