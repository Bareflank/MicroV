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

#include <ndis.h>
#include <procgrp.h>
#include <version.h>

#include "driver.h"
#include "miniport.h"
#include "dbg_print.h"
#include "assert.h"

typedef struct _XENNET_DRIVER {
    NDIS_HANDLE MiniportHandle;
} XENNET_DRIVER;

static XENNET_DRIVER Driver;

typedef struct _XENNET_CONTEXT {
    PDEVICE_CAPABILITIES    Capabilities;
    PIO_COMPLETION_ROUTINE  CompletionRoutine;
    PVOID                   CompletionContext;
    UCHAR                   CompletionControl;
} XENNET_CONTEXT, *PXENNET_CONTEXT;

static NTSTATUS (*NdisDispatchPnp)(PDEVICE_OBJECT, PIRP);

__drv_functionClass(IO_COMPLETION_ROUTINE)
static NTSTATUS
__QueryCapabilities(
    IN  PDEVICE_OBJECT      DeviceObject,
    IN  PIRP                Irp,
    IN  PVOID               _Context
    )
{
    PXENNET_CONTEXT         Context = _Context;
    NTSTATUS                status;

    Context->Capabilities->SurpriseRemovalOK = 1;

    if (Context->CompletionRoutine != NULL &&
        (Context->CompletionControl & SL_INVOKE_ON_SUCCESS))
        status = Context->CompletionRoutine(DeviceObject, Irp, Context->CompletionContext);
    else
        status = STATUS_SUCCESS;

    ExFreePool(Context);

    return status;
}

NTSTATUS
QueryCapabilities(
    IN PDEVICE_OBJECT       DeviceObject,
    IN PIRP                 Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    PXENNET_CONTEXT         Context;
    NTSTATUS                status;

    Trace("====>\n");

    Trace("%p\n", DeviceObject);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof (XENNET_CONTEXT), ' TEN');
    if (Context != NULL) {
        Context->Capabilities = StackLocation->Parameters.DeviceCapabilities.Capabilities;
        Context->CompletionRoutine = StackLocation->CompletionRoutine;
        Context->CompletionContext = StackLocation->Context;
        Context->CompletionControl = StackLocation->Control;

        StackLocation->CompletionRoutine = __QueryCapabilities;
        StackLocation->Context = Context;
        StackLocation->Control = SL_INVOKE_ON_SUCCESS;
    }

    status = NdisDispatchPnp(DeviceObject, Irp);

    Trace("<====\n");

    return status;
}

DRIVER_DISPATCH DispatchPnp;

NTSTATUS
DispatchPnp(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    switch (StackLocation->MinorFunction) {
    case IRP_MN_QUERY_CAPABILITIES:
        status = QueryCapabilities(DeviceObject, Irp);
        break;

    default:
        status = NdisDispatchPnp(DeviceObject, Irp);
        break;
    }

    return status;
}

DRIVER_DISPATCH DispatchFail;

NTSTATUS
DispatchFail(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_UNSUCCESSFUL;
}

VOID
DriverUnload(
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    Trace("====>\n");

    if (Driver.MiniportHandle)
        NdisMDeregisterMiniportDriver(Driver.MiniportHandle);
    Driver.MiniportHandle = NULL;

    Info("XENNET %d.%d.%d (%d) (%02d.%02d.%04d)\n",
         MAJOR_VERSION,
         MINOR_VERSION,
         MICRO_VERSION,
         BUILD_NUMBER,
         DAY,
         MONTH,
         YEAR);

    Trace("<====\n");
}

DRIVER_INITIALIZE       DriverEntry;

NTSTATUS
DriverEntry (
    IN  PDRIVER_OBJECT  DriverObject,
    IN  PUNICODE_STRING RegistryPath
    )
{
    NDIS_STATUS ndisStatus;
    NDIS_CONFIGURATION_OBJECT ConfigurationObject;
    NDIS_HANDLE ConfigurationHandle;
    NDIS_STRING ParameterName;
    PNDIS_CONFIGURATION_PARAMETER ParameterValue;
    ULONG FailCreateClose;
    ULONG FailDeviceControl;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    WdmlibProcgrpInitialize();

    Trace("====>\n");

    Info("XENNET %d.%d.%d (%d) (%02d.%02d.%04d)\n",
         MAJOR_VERSION,
         MINOR_VERSION,
         MICRO_VERSION,
         BUILD_NUMBER,
         DAY,
         MONTH,
         YEAR);

    ndisStatus = MiniportRegister(DriverObject,
                                  RegistryPath,
                                  &Driver.MiniportHandle);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        Error("Failed (0x%08X) to register miniport.\n", ndisStatus);
        goto fail;
    }

    ConfigurationObject.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    ConfigurationObject.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    ConfigurationObject.Header.Size = NDIS_SIZEOF_CONFIGURATION_OBJECT_REVISION_1;
    ConfigurationObject.NdisHandle = Driver.MiniportHandle;
    ConfigurationObject.Flags = 0;

    ndisStatus = NdisOpenConfigurationEx(&ConfigurationObject, &ConfigurationHandle);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        Error("Failed (0x%08X) to open driver configuration.\n", ndisStatus);
        NdisMDeregisterMiniportDriver(Driver.MiniportHandle);
        goto fail;
    }

    RtlInitUnicodeString(&ParameterName, L"FailCreateClose");

    NdisReadConfiguration(&ndisStatus,
                          &ParameterValue,
                          ConfigurationHandle,
                          &ParameterName,
                          NdisParameterInteger);
#pragma prefast(suppress:6102)
    if (ndisStatus == NDIS_STATUS_SUCCESS &&
        ParameterValue->ParameterType == NdisParameterInteger)
        FailCreateClose = ParameterValue->ParameterData.IntegerData;
    else
        FailCreateClose = 0;

    RtlInitUnicodeString(&ParameterName, L"FailDeviceControl");

    NdisReadConfiguration(&ndisStatus,
                          &ParameterValue,
                          ConfigurationHandle,
                          &ParameterName,
                          NdisParameterInteger);
#pragma prefast(suppress:6102)
    if (ndisStatus == NDIS_STATUS_SUCCESS &&
        ParameterValue->ParameterType == NdisParameterInteger)
        FailDeviceControl = ParameterValue->ParameterData.IntegerData;
    else
        FailDeviceControl = 0;

    NdisCloseConfiguration(ConfigurationHandle);
    ndisStatus = NDIS_STATUS_SUCCESS;

    NdisDispatchPnp = DriverObject->MajorFunction[IRP_MJ_PNP];
#pragma prefast(suppress:28168) // No matching __drv_dispatchType annotation
    DriverObject->MajorFunction[IRP_MJ_PNP] = DispatchPnp;

    if (FailCreateClose != 0) {
#pragma prefast(suppress:28168) // No matching__drv_dispatchType annotation
        DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchFail;
#pragma prefast(suppress:28168) // No matching __drv_dispatchType annotation
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchFail;
    }

    if (FailDeviceControl != 0) {
#pragma prefast(suppress:28168) // No matching __drv_dispatchType annotation
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchFail;
    }

    Trace("<====\n");
    return ndisStatus;

fail:
    Error("fail\n");
    return ndisStatus;
}
