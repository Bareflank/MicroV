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
#include <wdmguid.h>
#include <ntstrsafe.h>
#include <stdlib.h>

#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <suspend_interface.h>
#include <version.h>

#include "driver.h"
#include "registry.h"
#include "fdo.h"
#include "thread.h"
#include "mutex.h"
#include "log.h"
#include "assert.h"
#include "util.h"
#include "names.h"
#include "ioctls.h"
#include "wmi.h"
#include "xeniface_ioctls.h"
#include "irp_queue.h"

#define FDO_POOL 'ODF'

#define MAXNAMELEN  128


static void
FdoInitialiseXSRegistryEntries(
    IN PXENIFACE_FDO        Fdo
    )
{
    OBJECT_ATTRIBUTES Attributes;
    HANDLE RegHandle;
    UNICODE_STRING UnicodeValueName;
    UNICODE_STRING UnicodeValue;
    ANSI_STRING AnsiValue;
    char *value;
    NTSTATUS status;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    status = XENBUS_STORE(Read,
                          &Fdo->StoreInterface,
                          NULL,
                          NULL,
                          "/mh/boot-time/management-mac-address",
                          &value);
    if (!NT_SUCCESS(status)){
        Error("no such xenstore key\n");
        goto failXS;
    }

    InitializeObjectAttributes(&Attributes, &DriverParameters.RegistryPath,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL,
                                NULL);

    status = ZwOpenKey(&RegHandle, KEY_WRITE, &Attributes);

    if (!NT_SUCCESS(status)) {
        Error("no such registry key %s\n", DriverParameters.RegistryPath);
        goto failReg;
    }

    RtlInitUnicodeString(&UnicodeValueName, L"MgmtMacAddr");
    RtlInitUnicodeString(&UnicodeValue, NULL);
    RtlInitAnsiString(&AnsiValue, value);

    Info("About to convert unicode string\n");
    status = RtlAnsiStringToUnicodeString(&UnicodeValue, &AnsiValue, TRUE);
    if (!NT_SUCCESS(status)) {
        Error("Can't convert string\n");
        goto failReg;
    }

    Info("About to write unicode string\n");
    status = ZwSetValueKey(RegHandle, &UnicodeValueName, 0, REG_SZ, UnicodeValue.Buffer, UnicodeValue.Length+sizeof(WCHAR));
    if (!NT_SUCCESS(status)) {
        Error("Can't write key\n");
        goto failWrite;
    }

    ZwClose(RegHandle);

    RtlFreeUnicodeString(&UnicodeValue);
    XENBUS_STORE(Free, &Fdo->StoreInterface, value);

    return;

failWrite:

    Error("Fail : Write\n");
    ZwClose(RegHandle);
    RtlFreeUnicodeString(&UnicodeValue);

failReg:

    Error("Fail : Reg\n");
    XENBUS_STORE(Free, &Fdo->StoreInterface, value);

failXS:
    Error("Failed to initialise registry (%08x)\n", status);
    return;
}


#define REGISTRY_WRITE_EVENT 0
#define REGISTRY_THREAD_END_EVENT 1
#define REGISTRY_EVENTS 2

static NTSTATUS FdoRegistryThreadHandler(IN  PXENIFACE_THREAD  Self,
                                         IN  PVOID StartContext) {
    KEVENT* threadevents[REGISTRY_EVENTS];
    PXENIFACE_FDO Fdo = (PXENIFACE_FDO)StartContext;
    NTSTATUS status;

    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    threadevents[REGISTRY_WRITE_EVENT] = &Fdo->registryWriteEvent;
    threadevents[REGISTRY_THREAD_END_EVENT] = Event;

    for(;;) {

        status = KeWaitForMultipleObjects(REGISTRY_EVENTS, (PVOID *)threadevents, WaitAny, Executive, KernelMode, TRUE, NULL, NULL);
        if ((status>=STATUS_WAIT_0) && (status < STATUS_WAIT_0+REGISTRY_EVENTS)) {
            if (status == STATUS_WAIT_0+REGISTRY_WRITE_EVENT) {
                Info("WriteRegistry\n");
                FdoInitialiseXSRegistryEntries(Fdo);
                KeClearEvent(threadevents[REGISTRY_WRITE_EVENT]);
            }
            if (status == STATUS_WAIT_0+REGISTRY_THREAD_END_EVENT) {
                if (ThreadIsAlerted(Self))
                    return STATUS_SUCCESS;
                KeClearEvent(threadevents[REGISTRY_THREAD_END_EVENT]);
            }

        }
        else if (!NT_SUCCESS(status)) {
            Error("Registry handler thread failed %x\n", status);
            return status;
        }
    }

}



static FORCEINLINE PVOID
__FdoAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, FDO_POOL);
}

static FORCEINLINE VOID
__FdoFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, FDO_POOL);
}

static FORCEINLINE VOID
__FdoSetDevicePnpState(
    IN  PXENIFACE_FDO         Fdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENIFACE_DX              Dx = Fdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

static FORCEINLINE VOID
__FdoRestoreDevicePnpState(
    IN  PXENIFACE_FDO         Fdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENIFACE_DX               Dx = Fdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__FdoGetDevicePnpState(
    IN  PXENIFACE_FDO     Fdo
    )
{
    PXENIFACE_DX          Dx = Fdo->Dx;

    return Dx->DevicePnpState;
}

static FORCEINLINE VOID
__FdoSetDevicePowerState(
    IN  PXENIFACE_FDO         Fdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXENIFACE_DX              Dx = Fdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__FdoGetDevicePowerState(
    IN  PXENIFACE_FDO     Fdo
    )
{
    PXENIFACE_DX          Dx = Fdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__FdoSetSystemPowerState(
    IN  PXENIFACE_FDO         Fdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXENIFACE_DX              Dx = Fdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__FdoGetSystemPowerState(
    IN  PXENIFACE_FDO     Fdo
    )
{
    PXENIFACE_DX          Dx = Fdo->Dx;

    return Dx->SystemPowerState;
}

static FORCEINLINE PDEVICE_OBJECT
__FdoGetPhysicalDeviceObject(
    IN  PXENIFACE_FDO Fdo
    )
{
    return Fdo->PhysicalDeviceObject;
}

PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    IN  PXENIFACE_FDO Fdo
    )
{
    return __FdoGetPhysicalDeviceObject(Fdo);
}

static FORCEINLINE NTSTATUS
__FdoSetName(
    IN  PXENIFACE_FDO Fdo,
    IN  PWCHAR      Name
    )
{
    PXENIFACE_DX      Dx = Fdo->Dx;
    UNICODE_STRING  Unicode;
    ANSI_STRING     Ansi;
    ULONG           Index;
    NTSTATUS        status;

    RtlInitUnicodeString(&Unicode, Name);

    Ansi.Buffer = Dx->Name;
    Ansi.MaximumLength = sizeof (Dx->Name);
    Ansi.Length = 0;

    status = RtlUnicodeStringToAnsiString(&Ansi, &Unicode, FALSE);
    if (!NT_SUCCESS(status))
        goto fail1;

    for (Index = 0; Dx->Name[Index] != '\0'; Index++) {
        if (!isalnum((UCHAR)Dx->Name[Index]))
            Dx->Name[Index] = '_';
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE PCHAR
__FdoGetName(
    IN  PXENIFACE_FDO Fdo
    )
{
    PXENIFACE_DX      Dx = Fdo->Dx;

    return Dx->Name;
}

PCHAR
FdoGetName(
    IN  PXENIFACE_FDO Fdo
    )
{
    return __FdoGetName(Fdo);
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__FdoDelegateIrp(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PKEVENT             Event = (PKEVENT)Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
FdoDelegateIrp(
    IN  PXENIFACE_FDO     Fdo,
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
                           __FdoDelegateIrp,
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
__FdoForwardIrpSynchronously(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PKEVENT             Event = (PKEVENT)Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
FdoForwardIrpSynchronously(
    IN  PXENIFACE_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    KEVENT              Event;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __FdoForwardIrpSynchronously,
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

    Trace("%08x\n", status);

    return status;
}

static FORCEINLINE VOID
__FdoAcquireMutex(
    IN  PXENIFACE_FDO     Fdo
    )
{
    AcquireMutex(&Fdo->Mutex);
}

VOID
FdoAcquireMutex(
    IN  PXENIFACE_FDO     Fdo
    )
{
    __FdoAcquireMutex(Fdo);
}

static FORCEINLINE VOID
__FdoReleaseMutex(
    IN  PXENIFACE_FDO     Fdo
    )
{
    ReleaseMutex(&Fdo->Mutex);
}

VOID
FdoReleaseMutex(
    IN  PXENIFACE_FDO     Fdo
    )
{
    __FdoReleaseMutex(Fdo);

    if (Fdo->References == 0)
        FdoDestroy(Fdo);
}

static DECLSPEC_NOINLINE VOID
FdoParseResources(
    IN  PXENIFACE_FDO             Fdo,
    IN  PCM_RESOURCE_LIST       RawResourceList,
    IN  PCM_RESOURCE_LIST       TranslatedResourceList
    )
{
    PCM_PARTIAL_RESOURCE_LIST   RawPartialList;
    PCM_PARTIAL_RESOURCE_LIST   TranslatedPartialList;
    ULONG                       Index;

    ASSERT3U(RawResourceList->Count, ==, 1);
    RawPartialList = &RawResourceList->List[0].PartialResourceList;

    ASSERT3U(RawPartialList->Version, ==, 1);
    ASSERT3U(RawPartialList->Revision, ==, 1);

    ASSERT3U(TranslatedResourceList->Count, ==, 1);
    TranslatedPartialList = &TranslatedResourceList->List[0].PartialResourceList;

    ASSERT3U(TranslatedPartialList->Version, ==, 1);
    ASSERT3U(TranslatedPartialList->Revision, ==, 1);

    for (Index = 0; Index < TranslatedPartialList->Count; Index++) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR RawPartialDescriptor;
        PCM_PARTIAL_RESOURCE_DESCRIPTOR TranslatedPartialDescriptor;

        RawPartialDescriptor = &RawPartialList->PartialDescriptors[Index];
        TranslatedPartialDescriptor = &TranslatedPartialList->PartialDescriptors[Index];

        switch (TranslatedPartialDescriptor->Type) {
        case CmResourceTypeMemory:
            Fdo->Resource[MEMORY_RESOURCE].Raw = *RawPartialDescriptor;
            Fdo->Resource[MEMORY_RESOURCE].Translated = *TranslatedPartialDescriptor;
            break;

        case CmResourceTypeInterrupt:
            Fdo->Resource[INTERRUPT_RESOURCE].Raw = *RawPartialDescriptor;
            Fdo->Resource[INTERRUPT_RESOURCE].Translated = *TranslatedPartialDescriptor;
            break;

        default:
            break;
        }
    }
}

static FORCEINLINE PANSI_STRING
__FdoMultiSzToUpcaseAnsi(
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

static FORCEINLINE VOID
__FdoFreeAnsi(
    IN  PANSI_STRING    Ansi
    )
{
    ULONG               Index;

    for (Index = 0; Ansi[Index].Buffer != NULL; Index++)
        __FdoFree(Ansi[Index].Buffer);
        
    __FdoFree(Ansi);
}

static FORCEINLINE BOOLEAN
__FdoMatchDistribution(
    IN  PXENIFACE_FDO   Fdo,
    IN  PCHAR           Buffer
    )
{
    PCHAR               Vendor;
    PCHAR               Product;
    PCHAR               Context;
    const CHAR          *Text;
    BOOLEAN             Match;
    ULONG               Index;
    NTSTATUS            status;

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

    Text = "XENIFACE";

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
    IN  PXENIFACE_FDO   Fdo
    )
{
    PCHAR               Buffer;
    PANSI_STRING        Distributions;
    ULONG               Index;
    NTSTATUS            status;

    Trace("====>\n");

    status = XENBUS_STORE(Directory,
                          &Fdo->StoreInterface,
                          NULL,
                          NULL,
                          "drivers",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Distributions = __FdoMultiSzToUpcaseAnsi(Buffer);

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

    __FdoFreeAnsi(Distributions);

done:
    Trace("<====\n");
}

#define MAXIMUM_INDEX   255

static NTSTATUS
FdoSetDistribution(
    IN  PXENIFACE_FDO   Fdo
    )
{
    ULONG               Index;
    CHAR                Distribution[MAXNAMELEN];
    CHAR                Vendor[MAXNAMELEN];
    const CHAR          *Product;
    NTSTATUS            status;

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

    Product = "XENIFACE";

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

static FORCEINLINE NTSTATUS
__FdoD3ToD0(
    IN  PXENIFACE_FDO   Fdo
    )
{
    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    (VOID) FdoSetDistribution(Fdo);

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
__FdoD0ToD3(
    IN  PXENIFACE_FDO   Fdo
    )
{
    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    FdoClearDistribution(Fdo);

    Trace("<====\n");
}

static DECLSPEC_NOINLINE VOID
FdoSuspendCallbackLate(
    IN  PVOID       Argument
    )
{
    PXENIFACE_FDO   Fdo = Argument;
    NTSTATUS        status;

    __FdoD0ToD3(Fdo);

    status = __FdoD3ToD0(Fdo);
    ASSERT(NT_SUCCESS(status));

    WmiFireSuspendEvent(Fdo);
    SuspendEventFire(Fdo);
}

static DECLSPEC_NOINLINE NTSTATUS
FdoD3ToD0(
    IN  PXENIFACE_FDO   Fdo
    )
{
    KIRQL               Irql;
    NTSTATUS            status;
    POWER_STATE         PowerState;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetDevicePowerState(Fdo), ==, PowerDeviceD3);

    Trace("====>\n");

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    ASSERT3U(__FdoGetDevicePowerState(Fdo), ==, PowerDeviceD3);

    status = XENBUS_STORE(Acquire, &Fdo->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_EVTCHN(Acquire, &Fdo->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_GNTTAB(Acquire, &Fdo->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_SUSPEND(Acquire, &Fdo->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_SHARED_INFO(Acquire, &Fdo->SharedInfoInterface);
    if (!NT_SUCCESS(status))
        goto fail5;

    Fdo->InterfacesAcquired = TRUE;

    status = __FdoD3ToD0(Fdo);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = XENBUS_SUSPEND(Register,
                            &Fdo->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            FdoSuspendCallbackLate,
                            Fdo,
                            &Fdo->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = XENBUS_GNTTAB(CreateCache,
                           &Fdo->GnttabInterface,
                           "xeniface-gnttab",
                           0,
                           0,
                           GnttabAcquireLock,
                           GnttabReleaseLock,
                           Fdo,
                           &Fdo->GnttabCache);
    if (!NT_SUCCESS(status))
        goto fail8;

    KeLowerIrql(Irql);

    __FdoSetDevicePowerState(Fdo, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(Fdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    WmiSessionsResumeAll(Fdo);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail8:
    Error("fail8\n");

    XENBUS_SUSPEND(Deregister,
                   &Fdo->SuspendInterface,
                   Fdo->SuspendCallbackLate);
    Fdo->SuspendCallbackLate = NULL;

fail7:
    Error("fail7\n");

    __FdoD0ToD3(Fdo);

fail6:
    Error("fail6\n");

    XENBUS_SHARED_INFO(Release, &Fdo->SharedInfoInterface);

fail5:
    Error("fail5\n");

    XENBUS_SUSPEND(Release, &Fdo->SuspendInterface);

fail4:
    Error("fail4\n");

    XENBUS_GNTTAB(Release, &Fdo->GnttabInterface);

fail3:
    Error("fail3\n");

    XENBUS_EVTCHN(Release, &Fdo->EvtchnInterface);

fail2:
    Error("fail2\n");

    XENBUS_STORE(Release, &Fdo->StoreInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    KeLowerIrql(Irql);

    return status;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static DECLSPEC_NOINLINE VOID
FdoD0ToD3(
    IN  PXENIFACE_FDO   Fdo
    )
{
    KIRQL               Irql;
    POWER_STATE         PowerState;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetDevicePowerState(Fdo), ==, PowerDeviceD0);

    Trace("====>\n");

    WmiSessionsSuspendAll(Fdo);
    XenIfaceCleanup(Fdo, NULL);

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(Fdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    __FdoSetDevicePowerState(Fdo, PowerDeviceD3);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    Fdo->InterfacesAcquired = FALSE;

    XENBUS_GNTTAB(DestroyCache,
                  &Fdo->GnttabInterface,
                  Fdo->GnttabCache);
    Fdo->GnttabCache = NULL;

    XENBUS_SUSPEND(Deregister,
                   &Fdo->SuspendInterface,
                   Fdo->SuspendCallbackLate);
    Fdo->SuspendCallbackLate = NULL;

    __FdoD0ToD3(Fdo);

    XENBUS_SHARED_INFO(Release, &Fdo->SharedInfoInterface);

    XENBUS_SUSPEND(Release, &Fdo->SuspendInterface);

    XENBUS_GNTTAB(Release, &Fdo->GnttabInterface);

    XENBUS_EVTCHN(Release, &Fdo->EvtchnInterface);

    XENBUS_STORE(Release, &Fdo->StoreInterface);

    KeLowerIrql(Irql);

    Trace("<====\n");
}

static DECLSPEC_NOINLINE VOID
FdoS4ToS3(
    IN  PXENIFACE_FDO         Fdo
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetSystemPowerState(Fdo), ==, PowerSystemHibernate);

    __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
}

static DECLSPEC_NOINLINE VOID
FdoS3ToS4(
    IN  PXENIFACE_FDO Fdo
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetSystemPowerState(Fdo), ==, PowerSystemSleeping3);

    __FdoSetSystemPowerState(Fdo, PowerSystemHibernate);
}

static DECLSPEC_NOINLINE NTSTATUS
FdoStartDevice(
    IN  PXENIFACE_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    FdoParseResources(Fdo,
                      StackLocation->Parameters.StartDevice.AllocatedResources,
                      StackLocation->Parameters.StartDevice.AllocatedResourcesTranslated);

    __FdoSetSystemPowerState(Fdo, PowerSystemHibernate);
     FdoS4ToS3(Fdo);
    __FdoSetSystemPowerState(Fdo, PowerSystemWorking);

    status = WmiRegister(Fdo);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = FdoD3ToD0(Fdo);
    if (!NT_SUCCESS(status))
        goto fail4;

    status =  IoSetDeviceInterfaceState(&Fdo->InterfaceName, TRUE);
    if (!NT_SUCCESS(status))
        goto fail5;

    __FdoSetDevicePnpState(Fdo, Started);

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail5:
    Error("fail5\n");
    FdoD0ToD3(Fdo);

fail4:
    Error("fail4\n");

    WmiDeregister(Fdo);

fail3:
    Error("fail3\n");

    __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
    FdoS3ToS4(Fdo);
    __FdoSetSystemPowerState(Fdo, PowerSystemShutdown);

    RtlZeroMemory(&Fdo->Resource, sizeof (FDO_RESOURCE) * RESOURCE_COUNT);

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoQueryStopDevice(
    IN  PXENIFACE_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __FdoSetDevicePnpState(Fdo, StopPending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoCancelStopDevice(
    IN  PXENIFACE_FDO Fdo,
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

static DECLSPEC_NOINLINE NTSTATUS
FdoStopDevice(
    IN  PXENIFACE_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    FdoD0ToD3(Fdo);
    WmiDeregister(Fdo);

    __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
    FdoS3ToS4(Fdo);
    __FdoSetSystemPowerState(Fdo, PowerSystemShutdown);


    RtlZeroMemory(&Fdo->Resource, sizeof (FDO_RESOURCE) * RESOURCE_COUNT);

    __FdoSetDevicePnpState(Fdo, Stopped);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoQueryRemoveDevice(
    IN  PXENIFACE_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __FdoSetDevicePnpState(Fdo, RemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoCancelRemoveDevice(
    IN  PXENIFACE_FDO Fdo,
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

static DECLSPEC_NOINLINE NTSTATUS
FdoSurpriseRemoval(
    IN  PXENIFACE_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __FdoSetDevicePnpState(Fdo, SurpriseRemovePending);

    Irp->IoStatus.Status = STATUS_SUCCESS;
#pragma warning(suppress : 6031)
    IoSetDeviceInterfaceState(&Fdo->InterfaceName, FALSE);
    WmiDeregister(Fdo);

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static DECLSPEC_NOINLINE NTSTATUS
FdoRemoveDevice(
    IN  PXENIFACE_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    if (__FdoGetDevicePowerState(Fdo) != PowerDeviceD0)
        goto done;

    FdoD0ToD3(Fdo);

    __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
    FdoS3ToS4(Fdo);
    __FdoSetSystemPowerState(Fdo, PowerSystemShutdown);

    RtlZeroMemory(&Fdo->Resource, sizeof (FDO_RESOURCE) * RESOURCE_COUNT);

done:
    __FdoSetDevicePnpState(Fdo, Deleted);

    Irp->IoStatus.Status = STATUS_SUCCESS;
#pragma warning(suppress : 6031)
    IoSetDeviceInterfaceState(&Fdo->InterfaceName, FALSE);
    WmiDeregister(Fdo);

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    __FdoAcquireMutex(Fdo);
    ASSERT3U(Fdo->References, !=, 0);
    --Fdo->References;
    __FdoReleaseMutex(Fdo);

    if (Fdo->References == 0)
        FdoDestroy(Fdo);

    return status;
}


static DECLSPEC_NOINLINE NTSTATUS
FdoQueryCapabilities(
    IN  PXENIFACE_FDO         Fdo,
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

    for (SystemPowerState = (SYSTEM_POWER_STATE)0; SystemPowerState < PowerSystemMaximum; SystemPowerState++) {
        DEVICE_POWER_STATE  DevicePowerState;

        DevicePowerState = Fdo->LowerDeviceCapabilities.DeviceState[SystemPowerState];
        Trace("%s -> %s\n",
              PowerSystemStateName(SystemPowerState),
              PowerDeviceStateName(DevicePowerState));
    }

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoDeviceUsageNotification(
    IN  PXENIFACE_FDO                 Fdo,
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
              DeviceUsageTypeName(Type));
        Fdo->Usage[Type]++;
    } else {
        ASSERT(Fdo->Usage[Type] != 0);

        Trace("%s: REMOVING %s\n",
              __FdoGetName(Fdo),
              DeviceUsageTypeName(Type));
        --Fdo->Usage[Type];
    }

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    NotDisableable = FALSE;
    for (Type = (DEVICE_USAGE_NOTIFICATION_TYPE)0; Type <= DeviceUsageTypeDumpFile; Type++) {
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

static DECLSPEC_NOINLINE NTSTATUS
FdoQueryPnpDeviceState(
    IN  PXENIFACE_FDO                 Fdo,
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

static DECLSPEC_NOINLINE NTSTATUS
FdoDispatchPnp(
    IN  PXENIFACE_FDO   Fdo,
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

static FORCEINLINE NTSTATUS
__FdoSetDevicePowerUp(
    IN  PXENIFACE_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    Trace("====>\n");

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __FdoGetDevicePowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Info("%s -> %s\n",
         PowerDeviceStateName(__FdoGetDevicePowerState(Fdo)),
         PowerDeviceStateName(DeviceState));

    ASSERT3U(DeviceState, ==, PowerDeviceD0);
    status = FdoD3ToD0(Fdo);
    ASSERT(NT_SUCCESS(status));

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Trace("<==== (%08x)\n", status);
    return status;
}

static FORCEINLINE NTSTATUS
__FdoSetDevicePowerDown(
    IN  PXENIFACE_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __FdoGetDevicePowerState(Fdo));

    Info("%s -> %s\n",
         PowerDeviceStateName(__FdoGetDevicePowerState(Fdo)),
         PowerDeviceStateName(DeviceState));

    ASSERT3U(DeviceState, ==, PowerDeviceD3);

    if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0)
        FdoD0ToD3(Fdo);

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoSetDevicePower(
    IN  PXENIFACE_FDO     Fdo,
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
          PowerDeviceStateName(DeviceState),
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (DeviceState == __FdoGetDevicePowerState(Fdo)) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    status = (DeviceState < __FdoGetDevicePowerState(Fdo)) ?
             __FdoSetDevicePowerUp(Fdo, Irp) :
             __FdoSetDevicePowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerDeviceStateName(DeviceState),
          PowerActionName(PowerAction),
          status);
    return status;
}

__drv_functionClass(REQUEST_POWER_COMPLETE)
__drv_sameIRQL
VOID
__FdoRequestSetDevicePower(
    IN  PDEVICE_OBJECT      DeviceObject,
    IN  UCHAR               MinorFunction,
    IN  POWER_STATE         PowerState,
    IN  PVOID               Context,
    IN  PIO_STATUS_BLOCK    IoStatus
    )
{
    PKEVENT                 Event = (PKEVENT)Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(MinorFunction);
    UNREFERENCED_PARAMETER(PowerState);

    ASSERT(NT_SUCCESS(IoStatus->Status));

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

static VOID
FdoRequestSetDevicePower(
    IN  PXENIFACE_FDO         Fdo,
    IN  DEVICE_POWER_STATE  DeviceState
    )
{
    POWER_STATE             PowerState;
    KEVENT                  Event;
    NTSTATUS                status;

    Trace("%s\n", PowerDeviceStateName(DeviceState));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    PowerState.DeviceState = DeviceState;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = PoRequestPowerIrp(Fdo->LowerDeviceObject,
                               IRP_MN_SET_POWER,
                               PowerState,
                               __FdoRequestSetDevicePower,
                               &Event,
                               NULL);
    ASSERT(NT_SUCCESS(status));

    (VOID) KeWaitForSingleObject(&Event,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);
}

static FORCEINLINE NTSTATUS
__FdoSetSystemPowerUp(
    IN  PXENIFACE_FDO     Fdo,
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

    if (SystemState < PowerSystemHibernate &&
        __FdoGetSystemPowerState(Fdo) >= PowerSystemHibernate)
        __FdoSetSystemPowerState(Fdo, PowerSystemHibernate);
        FdoS4ToS3(Fdo);

    Info("%s -> %s\n",
         PowerSystemStateName(__FdoGetSystemPowerState(Fdo)),
         PowerSystemStateName(SystemState));

    __FdoSetSystemPowerState(Fdo, SystemState);

    DeviceState = Fdo->LowerDeviceCapabilities.DeviceState[SystemState];
    FdoRequestSetDevicePower(Fdo, DeviceState);

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoSetSystemPowerDown(
    IN  PXENIFACE_FDO     Fdo,
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

    Info("%s -> %s\n",
         PowerSystemStateName(__FdoGetSystemPowerState(Fdo)),
         PowerSystemStateName(SystemState));

    if (SystemState >= PowerSystemHibernate &&
        __FdoGetSystemPowerState(Fdo) < PowerSystemHibernate) {
        __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
        FdoS3ToS4(Fdo);
    }

    __FdoSetSystemPowerState(Fdo, SystemState);

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoSetSystemPower(
    IN  PXENIFACE_FDO     Fdo,
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
          PowerSystemStateName(SystemState),
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (SystemState == __FdoGetSystemPowerState(Fdo)) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    status = (SystemState < __FdoGetSystemPowerState(Fdo)) ?
             __FdoSetSystemPowerUp(Fdo, Irp) :
             __FdoSetSystemPowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerSystemStateName(SystemState),
          PowerActionName(PowerAction),
          status);
    return status;
}

static FORCEINLINE NTSTATUS
__FdoQueryDevicePowerUp(
    IN  PXENIFACE_FDO     Fdo,
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

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoQueryDevicePowerDown(
    IN  PXENIFACE_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __FdoGetDevicePowerState(Fdo));

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoQueryDevicePower(
    IN  PXENIFACE_FDO     Fdo,
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
          PowerDeviceStateName(DeviceState),
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (DeviceState == __FdoGetDevicePowerState(Fdo)) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    status = (DeviceState < __FdoGetDevicePowerState(Fdo)) ?
             __FdoQueryDevicePowerUp(Fdo, Irp) :
             __FdoQueryDevicePowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerDeviceStateName(DeviceState),
          PowerActionName(PowerAction),
          status);
    return status;
}

__drv_functionClass(REQUEST_POWER_COMPLETE)
__drv_sameIRQL
VOID
__FdoRequestQueryDevicePower(
    IN  PDEVICE_OBJECT      DeviceObject,
    IN  UCHAR               MinorFunction,
    IN  POWER_STATE         PowerState,
    IN  PVOID               Context,
    IN  PIO_STATUS_BLOCK    IoStatus
    )
{
    PKEVENT                 Event = (PKEVENT)Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(MinorFunction);
    UNREFERENCED_PARAMETER(PowerState);

    ASSERT(NT_SUCCESS(IoStatus->Status));

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

static VOID
FdoRequestQueryDevicePower(
    IN  PXENIFACE_FDO         Fdo,
    IN  DEVICE_POWER_STATE  DeviceState
    )
{
    POWER_STATE             PowerState;
    KEVENT                  Event;
    NTSTATUS                status;

    Trace("%s\n", PowerDeviceStateName(DeviceState));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    PowerState.DeviceState = DeviceState;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = PoRequestPowerIrp(Fdo->LowerDeviceObject,
                               IRP_MN_QUERY_POWER,
                               PowerState,
                               __FdoRequestQueryDevicePower,
                               &Event,
                               NULL);
    ASSERT(NT_SUCCESS(status));

    (VOID) KeWaitForSingleObject(&Event,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);
}

static FORCEINLINE NTSTATUS
__FdoQuerySystemPowerUp(
    IN  PXENIFACE_FDO     Fdo,
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
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoQuerySystemPowerDown(
    IN  PXENIFACE_FDO     Fdo,
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

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoQuerySystemPower(
    IN  PXENIFACE_FDO     Fdo,
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
          PowerSystemStateName(SystemState),
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (SystemState == __FdoGetSystemPowerState(Fdo)) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    status = (SystemState < __FdoGetSystemPowerState(Fdo)) ?
             __FdoQuerySystemPowerUp(Fdo, Irp) :
             __FdoQuerySystemPowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerSystemStateName(SystemState),
          PowerActionName(PowerAction),
          status);

    return status;
}

static NTSTATUS
FdoDevicePower(
    IN  PXENIFACE_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENIFACE_FDO         Fdo = (PXENIFACE_FDO)Context;
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
            (VOID) __FdoSetDevicePower(Fdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) __FdoQueryDevicePower(Fdo, Irp);
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
    IN  PXENIFACE_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENIFACE_FDO         Fdo = (PXENIFACE_FDO)Context;
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
            (VOID) __FdoSetSystemPower(Fdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) __FdoQuerySystemPower(Fdo, Irp);
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoDispatchPower(
    IN  PXENIFACE_FDO   Fdo,
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

static DECLSPEC_NOINLINE NTSTATUS
FdoDispatchDefault(
    IN  PXENIFACE_FDO   Fdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoDispatchComplete(
    IN  PXENIFACE_FDO   Fdo,
    IN  PIRP            Irp
    )
{
    UNREFERENCED_PARAMETER(Fdo);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoDispatchSystemControl(
    IN  PXENIFACE_FDO   Fdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = WmiProcessMinorFunction(Fdo, Irp);
    if (status == STATUS_NOT_SUPPORTED) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    } else {
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return status;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static DECLSPEC_NOINLINE NTSTATUS
FdoDispatchCleanup(
    IN  PXENIFACE_FDO   Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PFILE_OBJECT        FileObject;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    FileObject = StackLocation->FileObject;

    // XenIfaceCleanup requires PASSIVE_LEVEL as it can call KeFlushQueuedDpcs
    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    XenIfaceCleanup(Fdo, FileObject);

    return FdoDispatchComplete(Fdo, Irp);
}

NTSTATUS
FdoDispatch(
    IN  PXENIFACE_FDO   Fdo,
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

    case IRP_MJ_DEVICE_CONTROL:
        status = XenIfaceIoctl(Fdo, Irp);
        break;

    case IRP_MJ_SYSTEM_CONTROL:
        status = FdoDispatchSystemControl(Fdo, Irp);
        break;

    case IRP_MJ_CLEANUP:
        status = FdoDispatchCleanup(Fdo, Irp);
        break;

    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
    case IRP_MJ_READ:
    case IRP_MJ_WRITE:
        status = FdoDispatchComplete(Fdo, Irp);
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
    IN  PXENIFACE_FDO   Fdo,
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

NTSTATUS
FdoCreate(
    IN  PDEVICE_OBJECT  PhysicalDeviceObject
    )
{
    PDEVICE_OBJECT      FunctionDeviceObject;
    PXENIFACE_DX        Dx;
    PXENIFACE_FDO       Fdo;
    WCHAR               Name[MAXNAMELEN * sizeof (WCHAR)];
    ULONG               Size;
    NTSTATUS            status;

#pragma prefast(suppress:28197) // Possibly leaking memory 'FunctionDeviceObject'
    status = IoCreateDevice(DriverObject,
                            sizeof (XENIFACE_DX),
                            NULL,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &FunctionDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXENIFACE_DX)FunctionDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XENIFACE_DX));

    Dx->Type = FUNCTION_DEVICE_OBJECT;
    Dx->DeviceObject = FunctionDeviceObject;
    Dx->DevicePnpState = Added;
    Dx->SystemPowerState = PowerSystemShutdown;
    Dx->DevicePowerState = PowerDeviceD3;

    FunctionDeviceObject->Flags |= DO_POWER_PAGABLE;
    FunctionDeviceObject->Flags |= DO_BUFFERED_IO;

    Fdo = (PXENIFACE_FDO)__FdoAllocate(sizeof (XENIFACE_FDO));

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

    status = IoGetDeviceProperty(PhysicalDeviceObject,
                                 DevicePropertyLocationInformation,
                                 sizeof (Name),
                                 Name,
                                 &Size);
    if (!NT_SUCCESS(status))
        goto fail5;

#pragma prefast(suppress:6014) // Possibly leaking Fdo->InterfaceName
    status = IoRegisterDeviceInterface(PhysicalDeviceObject,
                                       (LPGUID)&GUID_INTERFACE_XENIFACE,
                                       NULL,
                                       &Fdo->InterfaceName);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = __FdoSetName(Fdo, Name);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = FDO_QUERY_INTERFACE(Fdo,
                                 XENBUS,
                                 SUSPEND,
                                 (PINTERFACE)&Fdo->SuspendInterface,
                                 sizeof (Fdo->SuspendInterface),
                                 FALSE);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = FDO_QUERY_INTERFACE(Fdo,
                                 XENBUS,
                                 SHARED_INFO,
                                 (PINTERFACE)&Fdo->SharedInfoInterface,
                                 sizeof (Fdo->SharedInfoInterface),
                                 FALSE);
    if (!NT_SUCCESS(status))
        goto fail9;

    status = FDO_QUERY_INTERFACE(Fdo,
                                 XENBUS,
                                 STORE,
                                 (PINTERFACE)&Fdo->StoreInterface,
                                 sizeof (Fdo->StoreInterface),
                                 FALSE);
    if (!NT_SUCCESS(status))
        goto fail10;

    status = FDO_QUERY_INTERFACE(Fdo,
                                 XENBUS,
                                 EVTCHN,
                                 (PINTERFACE)&Fdo->EvtchnInterface,
                                 sizeof (Fdo->EvtchnInterface),
                                 FALSE);
    if (!NT_SUCCESS(status))
        goto fail11;

    status = FDO_QUERY_INTERFACE(Fdo,
                                 XENBUS,
                                 GNTTAB,
                                 (PINTERFACE)&Fdo->GnttabInterface,
                                 sizeof (Fdo->GnttabInterface),
                                 FALSE);
    if (!NT_SUCCESS(status))
        goto fail12;

    InitializeMutex(&Fdo->Mutex);
    InitializeListHead(&Dx->ListEntry);
    Fdo->References = 1;

    FdoInitialiseXSRegistryEntries(Fdo);

    KeInitializeEvent(&Fdo->registryWriteEvent, NotificationEvent, FALSE);

    status = ThreadCreate(FdoRegistryThreadHandler, Fdo, &Fdo->registryThread);
    if (!NT_SUCCESS(status))
        goto fail13;

    status = WmiInitialize(Fdo);
    if (!NT_SUCCESS(status))
        goto fail14;

    KeInitializeSpinLock(&Fdo->StoreWatchLock);
    InitializeListHead(&Fdo->StoreWatchList);

    KeInitializeSpinLock(&Fdo->EvtchnLock);
    InitializeListHead(&Fdo->EvtchnList);

    KeInitializeSpinLock(&Fdo->SuspendLock);
    InitializeListHead(&Fdo->SuspendList);

    KeInitializeSpinLock(&Fdo->IrpQueueLock);
    InitializeListHead(&Fdo->IrpList);

    KeInitializeSpinLock(&Fdo->GnttabCacheLock);

    status = IoCsqInitializeEx(&Fdo->IrpQueue,
                               CsqInsertIrpEx,
                               CsqRemoveIrp,
                               CsqPeekNextIrp,
                               CsqAcquireLock,
                               CsqReleaseLock,
                               CsqCompleteCanceledIrp);
    if (!NT_SUCCESS(status))
        goto fail15;

    Info("%p (%s)\n",
         FunctionDeviceObject,
         __FdoGetName(Fdo));

    Dx->Fdo = Fdo;
    FunctionDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;

fail15:
    Error("fail15\n");

    RtlZeroMemory(&Fdo->GnttabCacheLock, sizeof (KSPIN_LOCK));
    ASSERT(IsListEmpty(&Fdo->IrpList));
    RtlZeroMemory(&Fdo->IrpList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->IrpQueueLock, sizeof (KSPIN_LOCK));

    ASSERT(IsListEmpty(&Fdo->SuspendList));
    RtlZeroMemory(&Fdo->SuspendList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->SuspendLock, sizeof (KSPIN_LOCK));

    ASSERT(IsListEmpty(&Fdo->EvtchnList));
    RtlZeroMemory(&Fdo->EvtchnList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->EvtchnLock, sizeof (KSPIN_LOCK));

    ASSERT(IsListEmpty(&Fdo->StoreWatchList));
    RtlZeroMemory(&Fdo->StoreWatchList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->StoreWatchLock, sizeof (KSPIN_LOCK));

    WmiTeardown(Fdo);

fail14:
    Error("fail14\n");

    ThreadAlert(Fdo->registryThread);
    ThreadJoin(Fdo->registryThread);
    Fdo->registryThread = NULL;

fail13:
    Error("fail13\n");

    RtlZeroMemory(&Fdo->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

fail12:
    Error("fail12\n");

    RtlZeroMemory(&Fdo->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

fail11:
    Error("fail11\n");

    RtlZeroMemory(&Fdo->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

fail10:
    Error("fail10\n");

    RtlZeroMemory(&Fdo->SharedInfoInterface,
                  sizeof (XENBUS_SHARED_INFO_INTERFACE));

fail9:
    Error("fail8\n");

    RtlZeroMemory(&Fdo->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

fail8:
    Error("fail8\n");

fail7:
    Error("fail7\n");
    RtlFreeUnicodeString(&Fdo->InterfaceName);
    RtlZeroMemory(&Fdo->InterfaceName,sizeof(UNICODE_STRING));

fail6:
    Error("fail6\n");

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

    ASSERT(IsZeroMemory(Fdo, sizeof (XENIFACE_FDO)));
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
    IN  PXENIFACE_FDO     Fdo
    )
{
    PXENIFACE_DX          Dx = Fdo->Dx;
    PDEVICE_OBJECT        FunctionDeviceObject = Dx->DeviceObject;

    ASSERT(IsListEmpty(&Dx->ListEntry));
    ASSERT3U(Fdo->References, ==, 0);
    ASSERT3U(__FdoGetDevicePnpState(Fdo), ==, Deleted);

    Fdo->NotDisableable = FALSE;

    Info("%p (%s)\n",
         FunctionDeviceObject,
         __FdoGetName(Fdo));

    Dx->Fdo = NULL;

    RtlZeroMemory(&Fdo->GnttabCacheLock, sizeof (KSPIN_LOCK));
    ASSERT(IsListEmpty(&Fdo->IrpList));
    RtlZeroMemory(&Fdo->IrpList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->IrpQueueLock, sizeof (KSPIN_LOCK));
    RtlZeroMemory(&Fdo->IrpQueue, sizeof (IO_CSQ));

    ASSERT(IsListEmpty(&Fdo->SuspendList));
    RtlZeroMemory(&Fdo->SuspendList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->SuspendLock, sizeof (KSPIN_LOCK));

    ASSERT(IsListEmpty(&Fdo->EvtchnList));
    RtlZeroMemory(&Fdo->EvtchnList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->EvtchnLock, sizeof (KSPIN_LOCK));

    ASSERT(IsListEmpty(&Fdo->StoreWatchList));
    RtlZeroMemory(&Fdo->StoreWatchList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Fdo->StoreWatchLock, sizeof (KSPIN_LOCK));

    RtlZeroMemory(&Fdo->Mutex, sizeof (XENIFACE_MUTEX));

    Fdo->InterfacesAcquired = FALSE;

    RtlZeroMemory(&Fdo->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    RtlZeroMemory(&Fdo->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&Fdo->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Fdo->SharedInfoInterface,
                  sizeof (XENBUS_SHARED_INFO_INTERFACE));

    RtlZeroMemory(&Fdo->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    ThreadAlert(Fdo->registryThread);
    ThreadJoin(Fdo->registryThread);
    Fdo->registryThread = NULL;

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

    WmiTeardown(Fdo);
    RtlZeroMemory(&Fdo->registryWriteEvent, sizeof(KEVENT));

    RtlFreeUnicodeString(&Fdo->InterfaceName);
    RtlZeroMemory(&Fdo->InterfaceName,sizeof(UNICODE_STRING));

    ASSERT(IsZeroMemory(Fdo, sizeof (XENIFACE_FDO)));
    __FdoFree(Fdo);

    IoDeleteDevice(FunctionDeviceObject);
}


