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
#include <ntstrsafe.h>
#include <devguid.h>
#include <xen.h>

#include "registry.h"
#include "driver.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define XENBUS_FILTERS_TAG 'TLIF'

static FORCEINLINE PVOID
__FiltersAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_FILTERS_TAG);
}

static FORCEINLINE VOID
__FiltersFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_FILTERS_TAG);
}

#define CLASS_PATH "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class"

static NTSTATUS
FiltersInstallClass(
    IN  const CHAR  *ClassName,
    IN  const GUID  *ClassGuid,
    IN  const CHAR  *DriverName
    )
{
    HANDLE          ClassKey;
    UNICODE_STRING  Unicode;
    HANDLE          Key;
    ULONG           Type;
    ULONG           Count;
    PANSI_STRING    Old;
    ULONG           Index;
    PANSI_STRING    New;
    NTSTATUS        status;

    Trace("====>\n");

    status = RegistryOpenSubKey(NULL,
                                CLASS_PATH,
                                KEY_ALL_ACCESS,
                                &ClassKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringFromGUID(ClassGuid, &Unicode);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryOpenKey(ClassKey,
                             &Unicode,
                             KEY_ALL_ACCESS,
                             &Key);
    if (!NT_SUCCESS(status))
        goto fail3;

    Count = 0;

    status = RegistryQuerySzValue(Key, "UpperFilters", &Type, &Old);
    if (NT_SUCCESS(status)) {
        status = STATUS_INVALID_PARAMETER;
        if (Type != REG_MULTI_SZ)
            goto fail4;

        for (Index = 0; Old[Index].Buffer != NULL; Index++) {
            if (_stricmp(Old[Index].Buffer, DriverName) == 0)
                goto done;

            Count++;
        }
    } else {
        Old = NULL;
    }

    New = __FiltersAllocate(sizeof (ANSI_STRING) * (Count + 2));

    status = STATUS_NO_MEMORY;
    if (New == NULL)
        goto fail5;

    Index = 0;
    while (Index < Count) {
        New[Index] = Old[Index];
        Index++;
    }

    RtlInitAnsiString(&New[Index], DriverName);

    status = RegistryUpdateSzValue(Key,
                                   "UpperFilters",
                                   REG_MULTI_SZ,
                                   New);
    if (!NT_SUCCESS(status))
        goto fail6;

    __FiltersFree(New);

    Info("%s %s\n", ClassName, DriverName);

done:
    if (Old != NULL)
        RegistryFreeSzValue(Old);

    RegistryCloseKey(Key);

    RtlFreeUnicodeString(&Unicode);

    RegistryCloseKey(ClassKey);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

    __FiltersFree(New);

fail5:
    Error("fail5\n");

    if (Old != NULL)
        RegistryFreeSzValue(Old);

fail4:
    Error("fail4\n");

    RegistryCloseKey(Key);

fail3:
    Error("fail3\n");

    RtlFreeUnicodeString(&Unicode);

fail2:
    Error("fail2\n");

    RegistryCloseKey(ClassKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define FILTERS_INSTALL_CLASS(_ClassGuid, _DriverName) \
        FiltersInstallClass(#_ClassGuid, &GUID_ ## _ClassGuid, (_DriverName))

static NTSTATUS
FiltersUninstallClass(
    IN  const CHAR  *ClassName,
    IN  const GUID  *ClassGuid,
    IN  const CHAR  *DriverName
    )
{
    HANDLE          ClassKey;
    UNICODE_STRING  Unicode;
    HANDLE          Key;
    ULONG           Type;
    ULONG           Count;
    PANSI_STRING    Old = NULL;
    ULONG           Index;
    PANSI_STRING    New;
    NTSTATUS        status;

    Trace("====>\n");

    status = RegistryOpenSubKey(NULL,
                                CLASS_PATH,
                                KEY_ALL_ACCESS,
                                &ClassKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringFromGUID(ClassGuid, &Unicode);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryOpenKey(ClassKey,
                             &Unicode,
                             KEY_ALL_ACCESS,
                             &Key);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RegistryQuerySzValue(Key, "UpperFilters", &Type, &Old);
    if (NT_SUCCESS(status)) {
        status = STATUS_INVALID_PARAMETER;
        if (Type != REG_MULTI_SZ)
            goto fail4;

        for (Index = 0; Old[Index].Buffer != NULL; Index++) {
            if (_stricmp(Old[Index].Buffer, DriverName) == 0)
                goto found;
        }
    }

    goto done;

found:
    Count = 0;
    for (Index = 0; Old[Index].Buffer != NULL; Index++)
        Count++;

    New = __FiltersAllocate(sizeof (ANSI_STRING) * Count);

    status = STATUS_NO_MEMORY;
    if (New == NULL)
        goto fail5;

    Count = 0;
    for (Index = 0; Old[Index].Buffer != NULL; Index++) {
        if (_stricmp(Old[Index].Buffer, DriverName) == 0)
            continue;

        New[Count] = Old[Index];
        Count++;
    }

    status = RegistryUpdateSzValue(Key,
                                   "UpperFilters",
                                   REG_MULTI_SZ,
                                   New);
    if (!NT_SUCCESS(status))
        goto fail6;

    __FiltersFree(New);

    Info("%s %s\n", ClassName, DriverName);

done:
    if (Old != NULL)
        RegistryFreeSzValue(Old);

    RegistryCloseKey(Key);

    RtlFreeUnicodeString(&Unicode);

    RegistryCloseKey(ClassKey);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

    __FiltersFree(New);

fail5:
    Error("fail5\n");

    if (Old != NULL)
        RegistryFreeSzValue(Old);

fail4:
    Error("fail4\n");

    RegistryCloseKey(Key);

fail3:
    Error("fail3\n");

    RtlFreeUnicodeString(&Unicode);

fail2:
    Error("fail2\n");

    RegistryCloseKey(ClassKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define FILTERS_UNINSTALL_CLASS(_ClassGuid, _DriverName) \
        FiltersUninstallClass(#_ClassGuid, &GUID_ ## _ClassGuid, (_DriverName))

VOID
FiltersInstall(
    VOID
    )
{
    (VOID) FILTERS_INSTALL_CLASS(DEVCLASS_SYSTEM, "XENFILT");
    (VOID) FILTERS_INSTALL_CLASS(DEVCLASS_HDC, "XENFILT");
}

VOID
FiltersUninstall(
    VOID
    )
{
    (VOID) FILTERS_UNINSTALL_CLASS(DEVCLASS_HDC, "XENFILT");
    (VOID) FILTERS_UNINSTALL_CLASS(DEVCLASS_SYSTEM, "XENFILT");
}
