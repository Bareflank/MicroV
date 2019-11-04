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
#include <ntstrsafe.h>

#include "registry.h"
#include "driver.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define SETTINGS_TAG 'TTES'

static FORCEINLINE PVOID
__SettingsAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, SETTINGS_TAG);
}

static FORCEINLINE VOID
__SettingsFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, SETTINGS_TAG);
}

typedef struct _SETTINGS_INTERFACE_COPY_PARAMETERS {
    PCHAR   SaveKeyName;
    HANDLE  DestinationKey;
} SETTINGS_INTERFACE_COPY_PARAMETERS, *PSETTINGS_INTERFACE_COPY_PARAMETERS;

static NTSTATUS
SettingsCopyInterfaceValue(
    IN  PVOID                           Context,
    IN  HANDLE                          SourceKey,
    IN  PANSI_STRING                    ValueName,
    IN  ULONG                           Type
    )
{
    PSETTINGS_INTERFACE_COPY_PARAMETERS Parameters = Context;
    NTSTATUS                            status;

    Trace("%s:%Z\n", Parameters->SaveKeyName, ValueName);

    switch (Type) {
    case REG_DWORD: {
        ULONG   Value;

        status = RegistryQueryDwordValue(SourceKey,
                                         ValueName->Buffer,
                                         &Value);
        if (NT_SUCCESS(status))
            (VOID) RegistryUpdateDwordValue(Parameters->DestinationKey,
                                            ValueName->Buffer,
                                            Value);

        break;
    }
    case REG_SZ:
    case REG_MULTI_SZ: {
        PANSI_STRING    Value;

        status = RegistryQuerySzValue(SourceKey,
                                      ValueName->Buffer,
                                      NULL,
                                      &Value);
        if (NT_SUCCESS(status)) {
            (VOID) RegistryUpdateSzValue(Parameters->DestinationKey,
                                         ValueName->Buffer,
                                         Type,
                                         Value);
            RegistryFreeSzValue(Value);
        }

        break;
    }
    case REG_BINARY: {
        PVOID   Value;
        ULONG   Length;

        status = RegistryQueryBinaryValue(SourceKey,
                                          ValueName->Buffer,
                                          &Value,
                                          &Length);
        if (NT_SUCCESS(status)) {
            (VOID) RegistryUpdateBinaryValue(Parameters->DestinationKey,
                                             ValueName->Buffer,
                                             Value,
                                             Length);
            if (Length != 0)
                RegistryFreeBinaryValue(Value);
        }

        break;
    }
    default:
        ASSERT(FALSE);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
SettingsCopyInterface(
    IN  HANDLE      SettingsKey,
    IN  PCHAR       SaveKeyName,
    IN  PCHAR       InterfacesPath,
    IN  PCHAR       InterfacePrefix,
    IN  LPGUID      Guid,
    IN  BOOLEAN     Save
    )
{
    UNICODE_STRING  Unicode;
    ULONG           Length;
    PCHAR           InterfaceName;
    HANDLE          InterfacesKey;
    PCHAR           KeyName;
    HANDLE          Key;
    HANDLE          SaveKey;
    NTSTATUS        status;

    Trace("====>\n");

    status = RtlStringFromGUID(Guid, &Unicode);
    if (!NT_SUCCESS(status))
        goto fail1;

    Length = (ULONG)(((Unicode.Length / sizeof (WCHAR)) +
                      1) * sizeof (CHAR));

    InterfaceName = __SettingsAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (InterfaceName == NULL)
        goto fail2;

    status = RtlStringCbPrintfA(InterfaceName,
                                Length,
                                "%wZ",
                                &Unicode);
    ASSERT(NT_SUCCESS(status));

    status = RegistryOpenSubKey(NULL,
                                InterfacesPath,
                                KEY_ALL_ACCESS,
                                &InterfacesKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    Length = (ULONG)((strlen(InterfacePrefix) +
                      strlen(InterfaceName) +
                      1) * sizeof (CHAR));

    KeyName = __SettingsAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (KeyName == NULL)
        goto fail4;

    status = RtlStringCbPrintfA(KeyName,
                                Length,
                                "%s%s",
                                InterfacePrefix,
                                InterfaceName);
    ASSERT(NT_SUCCESS(status));

    status = (!Save) ?
        RegistryCreateSubKey(InterfacesKey,
                             KeyName,
                             REG_OPTION_NON_VOLATILE,
                             &Key) :
        RegistryOpenSubKey(InterfacesKey,
                           KeyName,
                           KEY_READ,
                           &Key);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = (Save) ?
        RegistryCreateSubKey(SettingsKey,
                             SaveKeyName,
                             REG_OPTION_NON_VOLATILE,
                             &SaveKey) :
        RegistryOpenSubKey(SettingsKey,
                           SaveKeyName,
                           KEY_READ,
                           &SaveKey);
    if (!NT_SUCCESS(status))
        goto fail6;

    if (Save) {
        SETTINGS_INTERFACE_COPY_PARAMETERS  Parameters;

        Parameters.SaveKeyName = SaveKeyName;
        Parameters.DestinationKey = SaveKey;

        status = RegistryEnumerateValues(Key,
                                         SettingsCopyInterfaceValue,
                                         &Parameters);
    } else { // Restore
        SETTINGS_INTERFACE_COPY_PARAMETERS  Parameters;

        Parameters.SaveKeyName = SaveKeyName;
        Parameters.DestinationKey = Key;

        status = RegistryEnumerateValues(SaveKey,
                                         SettingsCopyInterfaceValue,
                                         &Parameters);
    }

    if (!NT_SUCCESS(status))
        goto fail7;

    RegistryCloseKey(SaveKey);

    RegistryCloseKey(Key);

    __SettingsFree(KeyName);

    RegistryCloseKey(InterfacesKey);

    __SettingsFree(InterfaceName);

    RtlFreeUnicodeString(&Unicode);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    RegistryCloseKey(SaveKey);

fail6:
    Error("fail6\n");

    RegistryCloseKey(Key);

fail5:
    Error("fail5\n");

    __SettingsFree(KeyName);

fail4:
    Error("fail4\n");

    RegistryCloseKey(InterfacesKey);

fail3:
    Error("fail3\n");

    __SettingsFree(InterfaceName);

fail2:
    Error("fail2\n");

    RtlFreeUnicodeString(&Unicode);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

typedef struct _SETTINGS_IP_ADDRESSES_COPY_PARAMETERS {
    UCHAR   Version;
    PCHAR   SourceValuePrefix;
    HANDLE  DestinationKey;
    PCHAR   DestinationValuePrefix;
} SETTINGS_IP_ADDRESSES_COPY_PARAMETERS, *PSETTINGS_IP_ADDRESSES_COPY_PARAMETERS;

static NTSTATUS
SettingsCopyIpAddressesValue(
    IN  PVOID                               Context,
    IN  HANDLE                              SourceKey,
    IN  PANSI_STRING                        SourceValueName,
    IN  ULONG                               Type
    )
{
    PSETTINGS_IP_ADDRESSES_COPY_PARAMETERS  Parameters = Context;
    ULONG                                   SourceValuePrefixLength;
    ULONG                                   DestinationValuePrefixLength;
    ULONG                                   DestinationValueNameLength;
    PCHAR                                   DestinationValueName;
    PVOID                                   Value;
    ULONG                                   ValueLength;
    NTSTATUS                                status;

    if (Type != REG_BINARY)
        goto done;

    SourceValuePrefixLength = (ULONG)strlen(Parameters->SourceValuePrefix);
    DestinationValuePrefixLength = (ULONG)strlen(Parameters->DestinationValuePrefix);

    if (_strnicmp(SourceValueName->Buffer,
                  Parameters->SourceValuePrefix,
                  SourceValuePrefixLength) != 0)
        goto done;

    DestinationValueNameLength = SourceValueName->Length -
                                 (SourceValuePrefixLength * sizeof (CHAR)) +
                                 ((DestinationValuePrefixLength + 1) * sizeof (CHAR));

    DestinationValueName = __SettingsAllocate(DestinationValueNameLength);

    status = STATUS_NO_MEMORY;
    if (DestinationValueName == NULL)
        goto fail1;

    status = RtlStringCbPrintfA(DestinationValueName,
                                DestinationValueNameLength,
                                "%s%s",
                                Parameters->DestinationValuePrefix,
                                SourceValueName->Buffer + SourceValuePrefixLength);
    ASSERT(NT_SUCCESS(status));

    Trace("Version%u: %Z -> %s\n",
          Parameters->Version,
          SourceValueName,
          DestinationValueName);

    status = RegistryQueryBinaryValue(SourceKey,
                                      SourceValueName->Buffer,
                                      &Value,
                                      &ValueLength);
    if (NT_SUCCESS(status)) {
        (VOID) RegistryUpdateBinaryValue(Parameters->DestinationKey,
                                         DestinationValueName,
                                         Value,
                                         ValueLength);
        RegistryFreeBinaryValue(Value);
    }

    __SettingsFree(DestinationValueName);

done:
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define IPV6_PATH "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Nsi\\{eb004a01-9b1a-11d4-9123-0050047759bc}\\10"

#define IPV4_PATH "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Nsi\\{eb004a00-9b1a-11d4-9123-0050047759bc}\\10"

static NTSTATUS
SettingsCopyIpAddresses(
    IN  HANDLE      SettingsKey,
    IN  UCHAR       Version,
    IN  PNET_LUID   Luid,
    IN  BOOLEAN     Save
    )
{
    const CHAR      *Path;
    HANDLE          Key;
    ULONG           ValuePrefixLength;
    PCHAR           ValuePrefix;
    const CHAR      *SaveKeyName;
    HANDLE          SaveKey;
    NTSTATUS        status;

    Trace("====>\n");

    ASSERT(Version == 4 || Version == 6);
    Path = (Version == 4) ? IPV4_PATH : IPV6_PATH;

    status = RegistryOpenSubKey(NULL,
                                (PCHAR)Path,
                                (Save) ? KEY_READ : KEY_ALL_ACCESS,
                                &Key);
    if (!NT_SUCCESS(status)) {
        Info("Version%u: ADDRESSES NOT FOUND\n", Version);
        goto done;
    }

    ValuePrefixLength = (ULONG)(((sizeof (NET_LUID) * 2) +
                                 1) * sizeof (CHAR));

    ValuePrefix = __SettingsAllocate(ValuePrefixLength);

    status = STATUS_NO_MEMORY;
    if (ValuePrefix == NULL)
        goto fail1;

    status = RtlStringCbPrintfA(ValuePrefix,
                                ValuePrefixLength,
                                "%016llX",
                                Luid->Value);
    ASSERT(NT_SUCCESS(status));

    SaveKeyName = (Version == 4) ? "IpVersion4Addresses" : "IpVersion6Addresses";

    status = (Save) ?
        RegistryCreateSubKey(SettingsKey,
                             (PCHAR)SaveKeyName,
                             REG_OPTION_NON_VOLATILE,
                             &SaveKey) :
        RegistryOpenSubKey(SettingsKey,
                           (PCHAR)SaveKeyName,
                           KEY_READ,
                           &SaveKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    if (Save) {
        SETTINGS_IP_ADDRESSES_COPY_PARAMETERS   Parameters;

        Parameters.Version = Version;
        Parameters.SourceValuePrefix = ValuePrefix;
        Parameters.DestinationKey = SaveKey;
        Parameters.DestinationValuePrefix = "LUID";

        status = RegistryEnumerateValues(Key,
                                         SettingsCopyIpAddressesValue,
                                         &Parameters);
    } else { // Restore
        SETTINGS_IP_ADDRESSES_COPY_PARAMETERS   Parameters;

        Parameters.Version = Version;
        Parameters.SourceValuePrefix = "LUID";
        Parameters.DestinationKey = Key;
        Parameters.DestinationValuePrefix = ValuePrefix;

        status = RegistryEnumerateValues(SaveKey,
                                         SettingsCopyIpAddressesValue,
                                         &Parameters);
    }

    RegistryCloseKey(SaveKey);

    __SettingsFree(ValuePrefix);

    RegistryCloseKey(Key);

done:
    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __SettingsFree(ValuePrefix);

fail1:
    Error("fail1 (%08x)\n", status);

    RegistryCloseKey(Key);

    return status;
}

#define INTERFACES_PATH(_Name) "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" ## #_Name ## "\\Parameters\\Interfaces\\"

static VOID
SettingsCopy(
     IN HANDLE      SettingsKey,
     IN LPGUID      InterfaceGuid,
     IN PNET_LUID   InterfaceLuid,
     IN BOOLEAN     Save
     )
{
    Trace("====>\n");

    (VOID) SettingsCopyInterface(SettingsKey,
                                 "NetBT",
                                 INTERFACES_PATH(NetBT),
                                 "Tcpip_",
                                 InterfaceGuid,
                                 Save);

    (VOID) SettingsCopyInterface(SettingsKey,
                                 "Tcpip",
                                 INTERFACES_PATH(Tcpip),
                                 "",
                                 InterfaceGuid,
                                 Save);

    (VOID) SettingsCopyInterface(SettingsKey,
                                 "Tcpip6",
                                 INTERFACES_PATH(Tcpip6),
                                 "",
                                 InterfaceGuid,
                                 Save);

    (VOID) SettingsCopyIpAddresses(SettingsKey,
                                   4,
                                   InterfaceLuid,
                                   Save);

    (VOID) SettingsCopyIpAddresses(SettingsKey,
                                   6,
                                   InterfaceLuid,
                                   Save);

    Trace("<====\n");
}

NTSTATUS
SettingsSave(
    IN  PCHAR       SubKeyName,
    IN  PWCHAR      Alias,
    IN  PWCHAR      Description,
    IN  LPGUID      InterfaceGuid,
    IN  PNET_LUID   InterfaceLuid
    )
{
    HANDLE          SettingsKey;
    HANDLE          SubKey;
    NTSTATUS        status;

    Info("FROM %ws (%ws)\n", Alias, Description);

    SettingsKey = DriverGetSettingsKey();

    status = RegistryCreateSubKey(SettingsKey,
                                  SubKeyName,
                                  REG_OPTION_NON_VOLATILE,
                                  &SubKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    SettingsCopy(SubKey, InterfaceGuid, InterfaceLuid, TRUE);

    RegistryCloseKey(SubKey);

    return STATUS_SUCCESS;

fail1:
    Error("fail1\n", status);

    return status;
}

NTSTATUS
SettingsRestore(
    IN  PCHAR       SubKeyName,
    IN  PWCHAR      Alias,
    IN  PWCHAR      Description,
    IN  LPGUID      InterfaceGuid,
    IN  PNET_LUID   InterfaceLuid
    )
{
    HANDLE          SettingsKey;
    HANDLE          SubKey;
    NTSTATUS        status;

    SettingsKey = DriverGetSettingsKey();

    status = RegistryOpenSubKey(SettingsKey,
                                SubKeyName,
                                KEY_READ,
                                &SubKey);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND)
            goto done;

        goto fail1;
    }

    Info("TO %ws (%ws)\n", Alias, Description);

    SettingsCopy(SubKey, InterfaceGuid, InterfaceLuid, FALSE);

    RegistryCloseKey(SubKey);

done:
    return STATUS_SUCCESS;

fail1:
    Error("fail1\n", status);

    return status;
}
