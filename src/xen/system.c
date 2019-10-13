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

#define XEN_API __declspec(dllexport)

#include <ntddk.h>
#include <procgrp.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <stdarg.h>
#include <xen.h>

#include "registry.h"
#include "system.h"
#include "acpi.h"
#include "names.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define XEN_SYSTEM_TAG  'TSYS'

typedef struct _SYSTEM_PROCESSOR {
    KDPC    Dpc;
    CHAR    Manufacturer[13];
    UCHAR   ApicID;
    UCHAR   ProcessorID;
} SYSTEM_PROCESSOR, *PSYSTEM_PROCESSOR;

typedef struct _SYSTEM_CONTEXT {
    LONG                References;
    PACPI_MADT          Madt;
    PSYSTEM_PROCESSOR   Processor;
    ULONG               ProcessorCount;
    PVOID               PowerStateHandle;
    PVOID               ProcessorChangeHandle;
    PHYSICAL_ADDRESS    MaximumPhysicalAddress;
    BOOLEAN             RealTimeIsUniversal;
} SYSTEM_CONTEXT, *PSYSTEM_CONTEXT;

static SYSTEM_CONTEXT   SystemContext;

static FORCEINLINE PVOID
__SystemAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XEN_SYSTEM_TAG);
}

static FORCEINLINE VOID
__SystemFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XEN_SYSTEM_TAG);
}

static FORCEINLINE const CHAR *
__PlatformIdName(
    IN  ULONG   PlatformId
    )
{
#define PLATFORM_ID_NAME(_PlatformId)       \
        case VER_PLATFORM_ ## _PlatformId:  \
            return #_PlatformId;

    switch (PlatformId) {
    PLATFORM_ID_NAME(WIN32s);
    PLATFORM_ID_NAME(WIN32_WINDOWS);
    PLATFORM_ID_NAME(WIN32_NT);
    default:
        break;
    }

    return "UNKNOWN";
#undef  PLATFORM_ID_NAME
}

static FORCEINLINE const CHAR *
__SuiteName(
    IN  ULONG  SuiteBit
    )
{
#define SUITE_NAME(_Suite)          \
        case VER_SUITE_ ## _Suite:  \
            return #_Suite;

    switch (1 << SuiteBit) {
    SUITE_NAME(SMALLBUSINESS);
    SUITE_NAME(ENTERPRISE);
    SUITE_NAME(BACKOFFICE);
    SUITE_NAME(COMMUNICATIONS);
    SUITE_NAME(TERMINAL);
    SUITE_NAME(SMALLBUSINESS_RESTRICTED);
    SUITE_NAME(EMBEDDEDNT);
    SUITE_NAME(DATACENTER);
    SUITE_NAME(SINGLEUSERTS);
    SUITE_NAME(PERSONAL);
    SUITE_NAME(BLADE);
    SUITE_NAME(EMBEDDED_RESTRICTED);
    SUITE_NAME(SECURITY_APPLIANCE);
    SUITE_NAME(STORAGE_SERVER);
    SUITE_NAME(COMPUTE_SERVER);
    default:
        break;
    }

    return "UNKNOWN";
#undef  SUITE_NAME
}

static FORCEINLINE const CHAR *
__ProductTypeName(
    IN  UCHAR   ProductType
    )
{
#define PRODUCT_TYPE_NAME(_ProductType) \
        case VER_NT_ ## _ProductType:   \
            return #_ProductType;

        switch (ProductType) {
        PRODUCT_TYPE_NAME(WORKSTATION);
        PRODUCT_TYPE_NAME(DOMAIN_CONTROLLER);
        PRODUCT_TYPE_NAME(SERVER);
    default:
        break;
    }

    return "UNKNOWN";
#undef  PRODUCT_TYPE_NAME
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
SystemGetVersionInformation(
    VOID
    )
{
    RTL_OSVERSIONINFOEXW    VersionInformation;
    ULONG                   Bit;
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    RtlZeroMemory(&VersionInformation, sizeof (RTL_OSVERSIONINFOEXW));
    VersionInformation.dwOSVersionInfoSize = sizeof (RTL_OSVERSIONINFOEXW);

    status = RtlGetVersion((PRTL_OSVERSIONINFOW)&VersionInformation);
    if (!NT_SUCCESS(status))
        goto fail1;

#if defined(__i386__)
    Info("KERNEL: %d.%d (BUILD %d) PLATFORM %s\n",
         VersionInformation.dwMajorVersion,
         VersionInformation.dwMinorVersion,
         VersionInformation.dwBuildNumber,
         __PlatformIdName(VersionInformation.dwPlatformId));
#elif defined(__x86_64__)
    Info("KERNEL: %d.%d (BUILD %d) PLATFORM %s (x64)\n",
         VersionInformation.dwMajorVersion,
         VersionInformation.dwMinorVersion,
         VersionInformation.dwBuildNumber,
         __PlatformIdName(VersionInformation.dwPlatformId));
#else
#error 'Unrecognised architecture'
#endif    

    if (VersionInformation.wServicePackMajor != 0 ||
        VersionInformation.wServicePackMinor != 0)
        Info("SP: %d.%d (%s)\n",
             VersionInformation.wServicePackMajor,
             VersionInformation.wServicePackMinor,
             VersionInformation.szCSDVersion);

    Info("SUITES:\n");
    Bit = 0;
    while (VersionInformation.wSuiteMask != 0) {
        if (VersionInformation.wSuiteMask & 0x0001)
            Info("- %s\n", __SuiteName(Bit));

        VersionInformation.wSuiteMask >>= 1;
        Bit++;
    }

    Info("TYPE: %s\n", __ProductTypeName(VersionInformation.wProductType));

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SystemGetMemoryInformation(
    VOID
    )
{
    PSYSTEM_CONTEXT         Context = &SystemContext;
    PHYSICAL_MEMORY_RANGE   *Range;
    ULONG                   Index;
    NTSTATUS                status;

    Range = MmGetPhysicalMemoryRanges();

    status = STATUS_UNSUCCESSFUL;
    if (Range == NULL)
        goto fail1;

    for (Index = 0;
         Range[Index].BaseAddress.QuadPart != 0 || Range[Index].NumberOfBytes.QuadPart != 0;
         Index++) {
        PHYSICAL_ADDRESS    Start;
        PHYSICAL_ADDRESS    End;

        Start.QuadPart = Range[Index].BaseAddress.QuadPart;
        End.QuadPart = Start.QuadPart + Range[Index].NumberOfBytes.QuadPart - 1;

        Info("RANGE[%u] %08x.%08x - %08x.%08x\n",
             Index,
             Start.HighPart, Start.LowPart,
             End.HighPart, End.LowPart);

        if (End.QuadPart > Context->MaximumPhysicalAddress.QuadPart)
            Context->MaximumPhysicalAddress.QuadPart = End.QuadPart;
    }

    ExFreePool(Range);

    Info("MaximumPhysicalAddress = %08x.%08x\n",
         Context->MaximumPhysicalAddress.HighPart,
         Context->MaximumPhysicalAddress.LowPart);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SystemGetAcpiInformation(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;
    ULONG           Length;
    NTSTATUS        status;

    status = AcpiGetTable("APIC", NULL, &Length);
    if (status != STATUS_BUFFER_OVERFLOW)
        goto fail1;

    Context->Madt = __SystemAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Context->Madt == NULL)
        goto fail2;

    status = AcpiGetTable("APIC", Context->Madt, &Length);
    if (!NT_SUCCESS(status))
        goto fail3;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#pragma warning(push)
#pragma warning(disable:4715)

static UCHAR
SystemApicIDToProcessorID(
    IN  UCHAR   ApicID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;
    PACPI_MADT      Madt = Context->Madt;
    ULONG           Offset;

    Offset = sizeof (ACPI_MADT);
    while (Offset < Madt->Header.Length) {
        PACPI_MADT_HEADER       Header;
        PACPI_MADT_LOCAL_APIC   Apic;

        Header = (PACPI_MADT_HEADER)((PUCHAR)Madt + Offset);
        Offset += Header->Length;

        if (Header->Type != ACPI_MADT_TYPE_LOCAL_APIC)
            continue;

        Apic = CONTAINING_RECORD(Header, ACPI_MADT_LOCAL_APIC, Header);

        if (Apic->ApicID == ApicID)
            return Apic->ProcessorID;
    }

    BUG(__FUNCTION__);
}

#pragma warning(pop)

static VOID
SystemViridianInformation(
    IN  ULONG   Count
    )
{
    ULONG       EAX;
    ULONG       EBX;
    CHAR        Signature[5];
    ULONG       Bit;

    Info("====>\n");

    if (Count < 1)
        goto done;

    RtlZeroMemory(Signature, sizeof (Signature));

    __CpuId(0x40000001, &EAX, NULL, NULL, NULL);

    *((PULONG)(Signature + 0)) = EAX;

    Info("Interface Identifier: %s\n", Signature);

    if (strcmp(Signature, "Hv#1") != 0)
        goto done;

    if (Count < 3)
        goto done;

    __CpuId(0x40000003, &EAX, NULL, NULL, NULL);

    Info("Hypervisor Features:\n");

    for (Bit = 0; Bit < sizeof (ULONG) * 8; Bit++) {
        if (EAX == 0)
            break;

        if (EAX & 1) {
            switch (Bit) {
            case 0:
                Info(" - VP Runtime\n");
                break;

            case 1:
                Info(" - Partition Reference Counter\n");
                break;

            case 2:
                Info(" - Basic SynIC MSRs\n");
                break;

            case 3:
                Info(" - Synthetic Timer MSRs\n");
                break;

            case 4:
                Info(" - APIC Access MSRs\n");
                break;

            case 5:
                Info(" - Hypercall MSRs\n");
                break;

            case 6:
                Info(" - Virtual Processor Index MSR\n");
                break;

            case 7:
                Info(" - Virtual System Reset MSR\n");
                break;

            case 8:
                Info(" - Statistics Pages MSRs\n");
                break;

            case 9:
                Info(" - Partition Reference TSC MSR\n");
                break;

            case 10:
                Info(" - Guest Idle State MSR\n");
                break;

            case 11:
                Info(" - Timer Frequency MSR\n");
                break;

            case 12:
                Info(" - Debug MSRs\n");
                break;

            default:
                break;
            }
        }

        EAX >>= 1;
    }

    if (Count < 4)
        goto done;

    __CpuId(0x40000004, &EAX, &EBX, NULL, NULL);

    Info("Recommendations:\n");

    for (Bit = 0; Bit < sizeof (ULONG) * 8; Bit++) {
        if (EAX == 0)
            break;

        if (EAX & 1) {
            switch (Bit) {
            case 0:
                Info(" - Address space switch via hypercall\n");
                break;

            case 1:
                Info(" - Local TLB flush via hypercall\n");
                break;

            case 2:
                Info(" - Remote TLB flush via hypercall\n");
                break;

            case 3:
                Info(" - EOI, ICR and TPR access via MSR\n");
                break;

            case 4:
                Info(" - Reset via MSR\n");
                break;

            case 5:
                Info(" - Use relaxed timing\n");
                break;

            case 6:
                Info(" - Use DMA remapping\n");
                break;

            case 7:
                Info(" - Use interrupt remapping\n");
                break;

            case 8:
                Info(" - Use x2APIC MSRs\n");
                break;

            case 9:
                Info(" - Deprecate AutoEOI\n");
                break;

            default:
                break;
            }
        }

        EAX >>= 1;
    }

    if (EBX != 0xFFFFFFFF)
        Info(" - Retry spinlocks %u times\n", EBX);

    if (Count < 6)
        goto done;

    __CpuId(0x40000006, &EAX, NULL, NULL, NULL);

    Info("Hardware Features:\n");

    for (Bit = 0; Bit < sizeof (ULONG) * 8; Bit++) {
        if (EAX == 0)
            break;

        if (EAX & 1) {
            switch (Bit) {
            case 0:
                Info(" - APIC overlay assist\n");
                break;

            case 1:
                Info(" - MSR bitmaps\n");
                break;

            case 2:
                Info(" - Architectural performance counters\n");
                break;

            case 3:
                Info(" - Second Level Address Translation (SLAT)\n");
                break;

            case 4:
                Info(" - DMA remapping\n");
                break;

            case 5:
                Info(" - Interrupt remapping\n");
                break;

            case 6:
                Info(" - Memory Patrol Scrubber\n");
                break;

            default:
                break;
            }
        }

        EAX >>= 1;
    }

done:
    Info("<====\n");
}

static
_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
SystemProcessorInformation(
    IN  PKDPC           Dpc,
    IN  PVOID           _Context,
    IN  PVOID           Argument1,
    IN  PVOID           Argument2
    )
{
    PSYSTEM_CONTEXT     Context = &SystemContext;
    PKEVENT             Event = Argument1;
    ULONG               Index;
    PROCESSOR_NUMBER    ProcNumber;
    PSYSTEM_PROCESSOR   Processor;
    ULONG               EAX;
    ULONG               EBX;
    ULONG               ECX;
    ULONG               EDX;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(_Context);
    UNREFERENCED_PARAMETER(Argument2);

    Index = KeGetCurrentProcessorNumberEx(&ProcNumber);
    ASSERT3U(Index, <, Context->ProcessorCount);

    Processor = &Context->Processor[Index];

    if (Index == 0) {
        CHAR    Signature[13];

        RtlZeroMemory(Signature, sizeof (Signature));

        __CpuId(0x40000000, &EAX, &EBX, &ECX, &EDX);
        *((PULONG)(Signature + 0)) = EBX;
        *((PULONG)(Signature + 4)) = ECX;
        *((PULONG)(Signature + 8)) = EDX;

        if (strcmp(Signature, "Microsoft Hv") == 0)
            SystemViridianInformation(EAX - 0x40000000);
    }

    Info("====> (%u:%u)\n", ProcNumber.Group, ProcNumber.Number);

    __CpuId(0, NULL, &EBX, &ECX, &EDX);

    RtlCopyMemory(&Processor->Manufacturer[0], &EBX, sizeof (ULONG));
    RtlCopyMemory(&Processor->Manufacturer[4], &EDX, sizeof (ULONG));
    RtlCopyMemory(&Processor->Manufacturer[8], &ECX, sizeof (ULONG));

    __CpuId(1, NULL, &EBX, NULL, NULL);

    Processor->ApicID = EBX >> 24;
    Processor->ProcessorID = SystemApicIDToProcessorID(Processor->ApicID);

    Info("Manufacturer: %s\n", Processor->Manufacturer);
    Info("APIC ID: %02X\n", Processor->ApicID);
    Info("PROCESSOR ID: %02X\n", Processor->ProcessorID);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    Info("<==== (%u:%u)\n", ProcNumber.Group, ProcNumber.Number);
}

static
_Function_class_(PROCESSOR_CALLBACK_FUNCTION)
VOID
SystemProcessorChangeCallback(
    IN      PVOID                               Argument,
    IN      PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT Change,
    IN OUT  PNTSTATUS                           Status
    )
{
    PSYSTEM_CONTEXT                             Context = &SystemContext;
    PROCESSOR_NUMBER                            ProcNumber;
    ULONG                                       Index;
    NTSTATUS                                    status;

    UNREFERENCED_PARAMETER(Argument);

    Index = Change->NtNumber;

    status = KeGetProcessorNumberFromIndex(Index, &ProcNumber);
    ASSERT(NT_SUCCESS(status));

    Trace("====> (%u:%u:%s)\n",
          ProcNumber.Group,
          ProcNumber.Number,
          ProcessorChangeName(Change->State));

    switch (Change->State) {
    case KeProcessorAddStartNotify: {
        PSYSTEM_PROCESSOR   Processor;
        ULONG               ProcessorCount;

        if (Index < Context->ProcessorCount)
            break;

        ProcessorCount = Index + 1;
        Processor = __SystemAllocate(sizeof (SYSTEM_PROCESSOR) *
                                     ProcessorCount);

        if (Processor == NULL) {
            *Status = STATUS_NO_MEMORY;
            break;
        }

        if (Context->ProcessorCount != 0) {
            RtlCopyMemory(Processor,
                          Context->Processor,
                          sizeof (SYSTEM_PROCESSOR) *
                          Context->ProcessorCount);
            __SystemFree(Context->Processor);
        }

        Context->Processor = Processor;
        KeMemoryBarrier();

        Context->ProcessorCount = ProcessorCount;
        break;
    }
    case KeProcessorAddCompleteNotify: {
        PSYSTEM_PROCESSOR   Processor;
        KEVENT              Event;

        ASSERT3U(Index, <, Context->ProcessorCount);

        Processor = &Context->Processor[Index];

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        KeInitializeDpc(&Processor->Dpc, SystemProcessorInformation, NULL);
        KeSetImportanceDpc(&Processor->Dpc, HighImportance);
        KeSetTargetProcessorDpcEx(&Processor->Dpc, &ProcNumber);

        KeInsertQueueDpc(&Processor->Dpc, &Event, NULL);

        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        break;
    }
    case KeProcessorAddFailureNotify:
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Trace("<==== (%u:%u:%s)\n",
          ProcNumber.Group,
          ProcNumber.Number,
          ProcessorChangeName(Change->State));
}

static NTSTATUS
SystemRegisterProcessorChangeCallback(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;
    PVOID           Handle;
    NTSTATUS        status;

    Handle = KeRegisterProcessorChangeCallback(SystemProcessorChangeCallback,
                                               NULL,
                                               KE_PROCESSOR_CHANGE_ADD_EXISTING);

    status = STATUS_UNSUCCESSFUL;
    if (Handle == NULL)
        goto fail1;

    Context->ProcessorChangeHandle = Handle;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
SystemDeregisterProcessorChangeCallback(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;

    KeDeregisterProcessorChangeCallback(Context->ProcessorChangeHandle);
    Context->ProcessorChangeHandle = NULL;

    __SystemFree(Context->Processor);
    Context->Processor = NULL;
    Context->ProcessorCount = 0;
}

static NTSTATUS
SystemGetStartOptions(
    VOID
    )
{
    UNICODE_STRING  Unicode;
    HANDLE          Key;
    PANSI_STRING    Ansi;
    NTSTATUS        status;

    RtlInitUnicodeString(&Unicode, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control");
    
    status = RegistryOpenKey(NULL, &Unicode, KEY_READ, &Key);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryQuerySzValue(Key, "SystemStartOptions", NULL, &Ansi);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_UNSUCCESSFUL;
    if (Ansi[0].Buffer == NULL)
        goto fail3;

    Info("%Z\n", Ansi);

    RegistryFreeSzValue(Ansi);
    RegistryCloseKey(Key);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    RegistryFreeSzValue(Ansi);

fail2:
    Error("fail2\n");

    RegistryCloseKey(Key);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SystemRegisterCallback(
    IN  PWCHAR              Name,
    IN  PCALLBACK_FUNCTION  Function,
    IN  PVOID               Argument,
    OUT PVOID               *Handle
    )
{
    UNICODE_STRING          Unicode;
    OBJECT_ATTRIBUTES       Attributes;
    PCALLBACK_OBJECT        Object;
    NTSTATUS                status;
    
    RtlInitUnicodeString(&Unicode, Name);

    InitializeObjectAttributes(&Attributes,
                               &Unicode,
                               OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                               NULL,
                               NULL);

    status = ExCreateCallback(&Object,
                              &Attributes,
                              FALSE,
                              FALSE);
    if (!NT_SUCCESS(status))
        goto fail1;

    *Handle = ExRegisterCallback(Object,
                                 Function,
                                 Argument);

    status = STATUS_UNSUCCESSFUL;
    if (*Handle == NULL)
        goto fail2;

    ObDereferenceObject(Object);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    ObDereferenceObject(Object);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
SystemDeregisterCallback(
    IN  PVOID   Handle
    )
{
    ExUnregisterCallback(Handle);
}

CALLBACK_FUNCTION   SystemPowerStateCallback;

VOID
SystemPowerStateCallback(
    IN  PVOID   _Context,
    IN  PVOID   Argument1,
    IN  PVOID   Argument2
    )
{
    ULONG_PTR   Type = (ULONG_PTR)Argument1;
    ULONG_PTR   Value = (ULONG_PTR)Argument2;

    UNREFERENCED_PARAMETER(_Context);

    if (Type == PO_CB_SYSTEM_STATE_LOCK) {
        if (Value)
            Info("-> S0\n");
        else
            Info("<- S0\n");
    }
}

static NTSTATUS
SystemRegisterPowerStateCallback(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;

    return SystemRegisterCallback(L"\\Callback\\PowerState",
                                  SystemPowerStateCallback,
                                  NULL,
                                  &Context->PowerStateHandle);
}

static VOID
SystemDeregisterPowerStateCallback(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;

    SystemDeregisterCallback(Context->PowerStateHandle);
    Context->PowerStateHandle = NULL;
}

static NTSTATUS
SystemGetTimeInformation(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;
    UNICODE_STRING  Unicode;
    HANDLE          Key;
    ULONG           RealTimeIsUniversal;
    NTSTATUS        status;

    RtlInitUnicodeString(&Unicode, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation");

    status = RegistryOpenKey(NULL, &Unicode, KEY_READ, &Key);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryQueryDwordValue(Key, "RealTimeIsUniversal",
                                     &RealTimeIsUniversal);
    if (!NT_SUCCESS(status)) {
        if (status != STATUS_OBJECT_NAME_NOT_FOUND)
            goto fail2;

        RealTimeIsUniversal = 0;
    }

    Context->RealTimeIsUniversal = RealTimeIsUniversal ? TRUE : FALSE;

    Info("%s\n", Context->RealTimeIsUniversal ? "TRUE" : "FALSE");

    RegistryCloseKey(Key);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RegistryCloseKey(Key);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
SystemInitialize(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;
    LONG            References;
    NTSTATUS        status;

    References = InterlockedIncrement(&Context->References);

    status = STATUS_OBJECTID_EXISTS;
    if (References != 1)
        goto fail1;

    status = SystemGetStartOptions();
    if (!NT_SUCCESS(status))
        goto fail2;

    status = SystemGetVersionInformation();
    if (!NT_SUCCESS(status))
        goto fail3;

    status = SystemGetMemoryInformation();
    if (!NT_SUCCESS(status))
        goto fail4;

    status = SystemGetAcpiInformation();
    if (!NT_SUCCESS(status))
        goto fail5;

    status = SystemRegisterProcessorChangeCallback();
    if (!NT_SUCCESS(status))
        goto fail6;

    status = SystemRegisterPowerStateCallback();
    if (!NT_SUCCESS(status))
        goto fail7;

    status = SystemGetTimeInformation();
    if (!NT_SUCCESS(status))
        goto fail8;

    return STATUS_SUCCESS;

fail8:
    Error("fail8\n");

    SystemDeregisterPowerStateCallback();

fail7:
    Error("fail7\n");

    SystemDeregisterProcessorChangeCallback();

fail6:
    Error("fail6\n");

    __SystemFree(Context->Madt);
    Context->Madt = NULL;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    (VOID) InterlockedDecrement(&Context->References);

    return status;
}

static FORCEINLINE ULONG
__SystemProcessorCount(
    VOID
    )
{
    PSYSTEM_CONTEXT     Context = &SystemContext;

    KeMemoryBarrier();

    return Context->ProcessorCount;
}

XEN_API
ULONG
SystemProcessorCount(
    VOID
    )
{
    return __SystemProcessorCount();
}

XEN_API
NTSTATUS
SystemVirtualCpuIndex(
    IN  ULONG           Index,
    OUT unsigned int    *vcpu_id
    )
{
    PSYSTEM_CONTEXT     Context = &SystemContext;
    PSYSTEM_PROCESSOR   Processor = &Context->Processor[Index];
    NTSTATUS            status;

    status = STATUS_UNSUCCESSFUL;
    if (Index >= __SystemProcessorCount())
        goto fail1;

    *vcpu_id = Processor->ProcessorID;
    return STATUS_SUCCESS;

fail1:
    return status;
}

XEN_API
PHYSICAL_ADDRESS
SystemMaximumPhysicalAddress(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;

    return Context->MaximumPhysicalAddress;
}

XEN_API
BOOLEAN
SystemRealTimeIsUniversal(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;

    return Context->RealTimeIsUniversal;
}

VOID
SystemTeardown(
    VOID
    )
{
    PSYSTEM_CONTEXT Context = &SystemContext;

    SystemDeregisterPowerStateCallback();

    SystemDeregisterProcessorChangeCallback();

    __SystemFree(Context->Madt);
    Context->Madt = NULL;

    Context->MaximumPhysicalAddress.QuadPart = 0;

    (VOID) InterlockedDecrement(&Context->References);

    ASSERT(IsZeroMemory(Context, sizeof (SYSTEM_CONTEXT)));
}
