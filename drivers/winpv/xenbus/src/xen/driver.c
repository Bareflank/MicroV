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
#include <xen.h>

#include "registry.h"
#include "driver.h"
#include "hypercall.h"
#include "log.h"
#include "module.h"
#include "process.h"
#include "system.h"
#include "acpi.h"
#include "unplug.h"
#include "bug_check.h"
#include "dbg_print.h"
#include "assert.h"
#include "version.h"

#define DEFAULT_XEN_LOG_LEVEL   LOG_LEVEL_CRITICAL
#define DEFAULT_QEMU_LOG_LEVEL  (LOG_LEVEL_INFO |       \
                                 LOG_LEVEL_WARNING |    \
                                 LOG_LEVEL_ERROR |      \
                                 LOG_LEVEL_CRITICAL)

typedef struct _XEN_DRIVER {
    PLOG_DISPOSITION    XenDisposition;
    PLOG_DISPOSITION    QemuDisposition;
    HANDLE              UnplugKey;
} XEN_DRIVER, *PXEN_DRIVER;

static XEN_DRIVER   Driver;

extern PULONG   InitSafeBootMode;

static FORCEINLINE BOOLEAN
__DriverSafeMode(
    VOID
    )
{
    return (*InitSafeBootMode > 0) ? TRUE : FALSE;
}

static FORCEINLINE VOID
__DriverSetUnplugKey(
    IN  HANDLE  Key
    )
{
    Driver.UnplugKey = Key;
}

static FORCEINLINE HANDLE
__DriverGetUnplugKey(
    VOID
    )
{
    return Driver.UnplugKey;
}

HANDLE
DriverGetUnplugKey(
    VOID
    )
{
    return __DriverGetUnplugKey();
}

XEN_API
NTSTATUS
XenTouch(
    IN  const CHAR  *Name,
    IN  ULONG       MajorVersion,
    IN  ULONG       MinorVersion,
    IN  ULONG       MicroVersion,
    IN  ULONG       BuildNumber
   )
{
    static ULONG    Reference;
    ULONG           Major;
    ULONG           Minor;
    CHAR            Extra[XEN_EXTRAVERSION_LEN];
    NTSTATUS        status;

    status = STATUS_INCOMPATIBLE_DRIVER_BLOCKED;
    if (MajorVersion != MAJOR_VERSION ||
        MinorVersion != MINOR_VERSION ||
        MicroVersion != MICRO_VERSION ||
        BuildNumber != BUILD_NUMBER)
        goto fail1;

    if (Reference != 0)
        goto done;

    status = XenVersion(&Major, &Minor);
    if (status == STATUS_NOT_IMPLEMENTED)
        goto fail2;

    ASSERT(NT_SUCCESS(status));

    status = XenVersionExtra(Extra);
    ASSERT(NT_SUCCESS(status));

    LogPrintf(LOG_LEVEL_INFO,
              "XEN: %u.%u%s (__XEN_INTERFACE_VERSION__ = %08x)\n",
              Major,
              Minor,
              Extra,
              __XEN_INTERFACE_VERSION__);

done:
    Reference++;

    return STATUS_SUCCESS;

fail2:
fail1:
    if (status == STATUS_INCOMPATIBLE_DRIVER_BLOCKED)
        Info("MODULE '%s' NOT COMPATIBLE (REBOOT REQUIRED)\n", Name);

    return status;
}

static VOID
DriverOutputBuffer(
    IN  PVOID   Argument,
    IN  PCHAR   Buffer,
    IN  ULONG   Length
    )
{
    ULONG_PTR   Port = (ULONG_PTR)Argument;

    __outbytestring((USHORT)Port, (PUCHAR)Buffer, Length);
}

#define XEN_PORT    0xE9
#define QEMU_PORT   0x12

NTSTATUS
DllInitialize(
    IN  PUNICODE_STRING RegistryPath
    )
{
    HANDLE              ServiceKey;
    HANDLE              UnplugKey;
    HANDLE              ParametersKey;
    LOG_LEVEL           LogLevel;
    NTSTATUS            status;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    WdmlibProcgrpInitialize();

    __DbgPrintEnable();

    Trace("====>\n");

    status = LogInitialize();
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryInitialize(RegistryPath);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryCreateServiceKey(&ServiceKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RegistryCreateSubKey(ServiceKey,
                                "Parameters",
                                REG_OPTION_NON_VOLATILE,
                                &ParametersKey);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = LogReadLogLevel(ParametersKey,
                             "XenLogLevel",
                             &LogLevel);
    if (!NT_SUCCESS(status))
        LogLevel = DEFAULT_XEN_LOG_LEVEL;

    status = LogAddDisposition(LogLevel,
                               DriverOutputBuffer,
                               (PVOID)XEN_PORT,
                               &Driver.XenDisposition);
    ASSERT(NT_SUCCESS(status));

    status = LogReadLogLevel(ParametersKey,
                             "QemuLogLevel",
                             &LogLevel);
    if (!NT_SUCCESS(status))
        LogLevel = DEFAULT_QEMU_LOG_LEVEL;

    status = LogAddDisposition(LogLevel,
                               DriverOutputBuffer,
                               (PVOID)QEMU_PORT,
                               &Driver.QemuDisposition);
    ASSERT(NT_SUCCESS(status));

    Info("%d.%d.%d (%d) (%02d.%02d.%04d)\n",
         MAJOR_VERSION,
         MINOR_VERSION,
         MICRO_VERSION,
         BUILD_NUMBER,
         DAY,
         MONTH,
         YEAR);

    if (__DriverSafeMode())
        Info("SAFE MODE\n");

    status = RegistryCreateSubKey(ServiceKey,
                                  "Unplug",
                                  REG_OPTION_NON_VOLATILE,
                                  &UnplugKey);
    if (!NT_SUCCESS(status))
        goto fail5;

    __DriverSetUnplugKey(UnplugKey);

    status = AcpiInitialize();
    if (!NT_SUCCESS(status))
        goto fail6;

    status = SystemInitialize();
    if (!NT_SUCCESS(status))
        goto fail7;

    HypercallInitialize();

    status = BugCheckInitialize();
    if (!NT_SUCCESS(status))
        goto fail8;

    status = ModuleInitialize();
    if (!NT_SUCCESS(status))
        goto fail9;

    status = ProcessInitialize();
    if (!NT_SUCCESS(status))
        goto fail10;

    status = UnplugInitialize();
    if (!NT_SUCCESS(status))
        goto fail11;

    RegistryCloseKey(ParametersKey);

    RegistryCloseKey(ServiceKey);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail11:
    Error("fail11\n");

    ProcessTeardown();

fail10:
    Error("fail10\n");

    ModuleTeardown();

fail9:
    Error("fail9\n");

    BugCheckTeardown();

    HypercallTeardown();

fail8:
    Error("fail8\n");

    SystemTeardown();

fail7:
    Error("fail7\n");

    AcpiTeardown();

fail6:
    Error("fail6\n");

    RegistryCloseKey(UnplugKey);
    __DriverSetUnplugKey(NULL);

fail5:
    Error("fail5\n");

    LogRemoveDisposition(Driver.QemuDisposition);
    Driver.QemuDisposition = NULL;

    LogRemoveDisposition(Driver.XenDisposition);
    Driver.XenDisposition = NULL;

    RegistryCloseKey(ParametersKey);

fail4:
    Error("fail4\n");

    RegistryCloseKey(ServiceKey);

fail3:
    Error("fail3\n");

    RegistryTeardown();

fail2:
    Error("fail2\n");

    LogTeardown();

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Driver, sizeof (XEN_DRIVER)));

    return status;
}

NTSTATUS
DllUnload(
    VOID
    )
{
    HANDLE  UnplugKey;

    Trace("====>\n");

    UnplugTeardown();

    ProcessTeardown();

    ModuleTeardown();

    BugCheckTeardown();

    HypercallTeardown();

    SystemTeardown();

    UnplugKey = __DriverGetUnplugKey();

    RegistryCloseKey(UnplugKey);
    __DriverSetUnplugKey(NULL);

    RegistryTeardown();

    Info("XEN %d.%d.%d (%d) (%02d.%02d.%04d)\n",
         MAJOR_VERSION,
         MINOR_VERSION,
         MICRO_VERSION,
         BUILD_NUMBER,
         DAY,
         MONTH,
         YEAR);

    LogRemoveDisposition(Driver.QemuDisposition);
    Driver.QemuDisposition = NULL;

    LogRemoveDisposition(Driver.XenDisposition);
    Driver.XenDisposition = NULL;

    LogTeardown();

    ASSERT(IsZeroMemory(&Driver, sizeof (XEN_DRIVER)));

    Trace("<====\n");

    return STATUS_SUCCESS;
}

DRIVER_INITIALIZE   DriverEntry;

NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT  DriverObject,
    IN  PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return STATUS_SUCCESS;
}
