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
#include <ntstrsafe.h>
#include <stdlib.h>
#include <stdarg.h>
#include <xen.h>
#include <version.h>

#include "driver.h"
#include "high.h"
#include "registry.h"
#include "unplug.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define UNPLUG_TAG  'LPNU'

typedef struct _UNPLUG_CONTEXT {
    LONG        References;
    HIGH_LOCK   Lock;
    BOOLEAN     BlackListed;
    BOOLEAN     Request[UNPLUG_TYPE_COUNT];
    BOOLEAN     BootEmulated;
} UNPLUG_CONTEXT, *PUNPLUG_CONTEXT;

static UNPLUG_CONTEXT   UnplugContext;

static FORCEINLINE PVOID
__UnplugAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, UNPLUG_TAG);
}

static FORCEINLINE VOID
__UnplugFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, UNPLUG_TAG);
}

static VOID
UnplugSetBootEmulated(
    VOID
    )
{
    PUNPLUG_CONTEXT Context = &UnplugContext;
    CHAR            Key[] = "XEN:BOOT_EMULATED=";
    PANSI_STRING    Option;
    PCHAR           Value;
    NTSTATUS        status;

    status = RegistryQuerySystemStartOption(Key, &Option);
    if (!NT_SUCCESS(status))
        return;

    Value = Option->Buffer + sizeof (Key) - 1;

    if (strcmp(Value, "TRUE") == 0)
        Context->BootEmulated = TRUE;

    RegistryFreeSzValue(Option);
}

static VOID
UnplugDeviceType(
    IN  UNPLUG_TYPE Type
    )
{
    PUNPLUG_CONTEXT Context = &UnplugContext;

    switch (Type) {
    case UNPLUG_DISKS:
        if (Context->BootEmulated) {
#pragma prefast(suppress:28138)
            WRITE_PORT_USHORT((PUSHORT)0x10, 0x0004);

            LogPrintf(LOG_LEVEL_WARNING, "UNPLUG: AUX DISKS\n");
        } else {
#pragma prefast(suppress:28138)
            WRITE_PORT_USHORT((PUSHORT)0x10, 0x0001);

            LogPrintf(LOG_LEVEL_WARNING, "UNPLUG: DISKS\n");
        }
        break;
    case UNPLUG_NICS:
#pragma prefast(suppress:28138)
        WRITE_PORT_USHORT((PUSHORT)0x10, 0x0002);

        LogPrintf(LOG_LEVEL_WARNING, "UNPLUG: NICS\n");
        break;
    default:
        ASSERT(FALSE);
    }
}

static NTSTATUS
UnplugPreamble(
    VOID
    )
{
    PUNPLUG_CONTEXT Context = &UnplugContext;
    USHORT          Magic;
    UCHAR           Version;
    NTSTATUS        status;

    // See docs/misc/hvm-emulated-unplug.markdown for details of the
    // protocol in use here

#pragma prefast(suppress:28138)
    Magic = READ_PORT_USHORT((PUSHORT)0x10);

    if (Magic == 0xd249) {
        Context->BlackListed = TRUE;
        goto done;
    }

    status = STATUS_NOT_SUPPORTED;
    if (Magic != 0x49d2)
        goto fail1;

#pragma prefast(suppress:28138)
    Version = READ_PORT_UCHAR((PUCHAR)0x12);
    if (Version != 0) {
#pragma prefast(suppress:28138)
        WRITE_PORT_USHORT((PUSHORT)0x12, 0xFFFF);   // FIXME

#pragma prefast(suppress:28138)
        WRITE_PORT_ULONG((PULONG)0x10,
                         (MAJOR_VERSION << 16) |
                         (MINOR_VERSION << 8) |
                         MICRO_VERSION);

#pragma prefast(suppress:28138)
        Magic = READ_PORT_USHORT((PUSHORT)0x10);
        if (Magic == 0xd249)
            Context->BlackListed = TRUE;
    }

done:
    LogPrintf(LOG_LEVEL_WARNING,
              "UNPLUG: PRE-AMBLE (DRIVERS %s)\n",
              (Context->BlackListed) ? "BLACKLISTED" : "NOT BLACKLISTED");

    return STATUS_SUCCESS;

fail1:
    return status;
}

static VOID
UnplugSetRequest(
    IN  UNPLUG_TYPE     Type
    )
{
    PUNPLUG_CONTEXT     Context = &UnplugContext;
    HANDLE              UnplugKey;
    PCHAR               ValueName;
    ULONG               Value;
    KIRQL               Irql;
    NTSTATUS            status;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    UnplugKey = DriverGetUnplugKey();

    switch (Type) {
    case UNPLUG_DISKS:
        ValueName = "DISKS";
        break;
    case UNPLUG_NICS:
        ValueName = "NICS";
        break;
    default:
        ValueName = NULL;
        ASSERT(FALSE);
    }

    status = RegistryQueryDwordValue(UnplugKey,
                                     ValueName,
                                     &Value);
    if (!NT_SUCCESS(status))
        goto done;

    (VOID) RegistryDeleteValue(UnplugKey, ValueName);

    Info("%s (%u)\n", ValueName, Value);

    AcquireHighLock(&Context->Lock, &Irql);
    Context->Request[Type] = (Value != 0) ? TRUE : FALSE;
    ReleaseHighLock(&Context->Lock, Irql);

done:
    Trace("<====\n");
}

XEN_API
NTSTATUS
UnplugIncrementValue(
    IN  UNPLUG_TYPE     Type
    )
{
    HANDLE              UnplugKey;
    PCHAR               ValueName;
    ULONG               Value;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    UnplugKey = DriverGetUnplugKey();

    switch (Type) {
    case UNPLUG_DISKS:
        ValueName = "DISKS";
        break;
    case UNPLUG_NICS:
        ValueName = "NICS";
        break;
    default:
        ValueName = NULL;
        ASSERT(FALSE);
    }

    status = RegistryQueryDwordValue(UnplugKey,
                                     ValueName,
                                     &Value);
    if (!NT_SUCCESS(status))
        Value = 0;

    Value++;

    status = RegistryUpdateDwordValue(UnplugKey,
                                      ValueName,
                                      Value);
    if (!NT_SUCCESS(status))
        goto fail1;

    Info("%s %u\n", ValueName, Value);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

XEN_API
NTSTATUS
UnplugDecrementValue(
    IN  UNPLUG_TYPE     Type
    )
{
    HANDLE              UnplugKey;
    PCHAR               ValueName;
    LONG                Value;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    UnplugKey = DriverGetUnplugKey();

    switch (Type) {
    case UNPLUG_DISKS:
        ValueName = "DISKS";
        break;
    case UNPLUG_NICS:
        ValueName = "NICS";
        break;
    default:
        ValueName = NULL;
        ASSERT(FALSE);
    }

    status = RegistryQueryDwordValue(UnplugKey,
                                     ValueName,
                                     (PULONG)&Value);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (--Value < 0)
        goto fail2;

    status = RegistryUpdateDwordValue(UnplugKey,
                                      ValueName,
                                      (ULONG)Value);
    if (!NT_SUCCESS(status))
        goto fail3;

    Info("%s %u\n", ValueName, (ULONG)Value);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

XEN_API
VOID
UnplugDevices(
    VOID
    )
{
    PUNPLUG_CONTEXT Context = &UnplugContext;
    UNPLUG_TYPE     Type;
    KIRQL           Irql;
    NTSTATUS        status;

    AcquireHighLock(&Context->Lock, &Irql);

    status = UnplugPreamble();
    ASSERT(NT_SUCCESS(status));

    for (Type = 0; Type < UNPLUG_TYPE_COUNT; Type++) {
        if (Context->Request[Type])
            UnplugDeviceType(Type);
    }

    ReleaseHighLock(&Context->Lock, Irql);
}

NTSTATUS
UnplugInitialize(
    VOID
    )
{
    PUNPLUG_CONTEXT Context = &UnplugContext;
    LONG            References;
    UNPLUG_TYPE     Type;
    NTSTATUS        status;

    References = InterlockedIncrement(&Context->References);

    status = STATUS_OBJECTID_EXISTS;
    if (References != 1)
        goto fail1;

    InitializeHighLock(&Context->Lock);

    for (Type = 0; Type < UNPLUG_TYPE_COUNT; Type++)
        UnplugSetRequest(Type);

    UnplugSetBootEmulated();

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    (VOID) InterlockedDecrement(&Context->References);

    ASSERT(IsZeroMemory(Context, sizeof (UNPLUG_CONTEXT)));

    return status;
}

VOID
UnplugTeardown(
    VOID
    )
{
    PUNPLUG_CONTEXT Context = &UnplugContext;
    UNPLUG_TYPE     Type;

    Context->BootEmulated = FALSE;

    for (Type = 0; Type < UNPLUG_TYPE_COUNT; Type++)
        Context->Request[Type] = FALSE;

    RtlZeroMemory(&Context->Lock, sizeof (HIGH_LOCK));

    (VOID) InterlockedDecrement(&Context->References);

    ASSERT(IsZeroMemory(Context, sizeof (UNPLUG_CONTEXT)));
}
