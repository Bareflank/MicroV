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
#include <devguid.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <netioapi.h>
#include <bcrypt.h>
#include <xen.h>

#include <suspend_interface.h>
#include <unplug_interface.h>

#include "names.h"
#include "fdo.h"
#include "pdo.h"
#include "bus.h"
#include "frontend.h"
#include "vif.h"
#include "driver.h"
#include "registry.h"
#include "thread.h"
#include "link.h"
#include "settings.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"
#include "version.h"
#include "revision.h"

#define PDO_POOL 'ODP'

#define MAXNAMELEN  128

struct _XENVIF_PDO {
    PXENVIF_DX                  Dx;

    PXENVIF_THREAD              SystemPowerThread;
    PIRP                        SystemPowerIrp;
    PXENVIF_THREAD              DevicePowerThread;
    PIRP                        DevicePowerIrp;

    PXENVIF_FDO                 Fdo;
    BOOLEAN                     Missing;
    const CHAR                  *Reason;
    LONG                        Eject;

    UNICODE_STRING              ContainerID;

    ETHERNET_ADDRESS            PermanentAddress;
    ETHERNET_ADDRESS            CurrentAddress;

    BUS_INTERFACE_STANDARD      BusInterface;

    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;

    XENBUS_UNPLUG_INTERFACE     UnplugInterface;
    BOOLEAN                     UnplugRequested;

    PXENVIF_FRONTEND            Frontend;

    PXENVIF_VIF_CONTEXT         VifContext;
    XENVIF_VIF_INTERFACE        VifInterface;

    BOOLEAN                     HasAlias;
};

static FORCEINLINE PVOID
__PdoAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, PDO_POOL);
}

static FORCEINLINE VOID
__PdoFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, PDO_POOL);
}

static FORCEINLINE VOID
__PdoSetDevicePnpState(
    IN  PXENVIF_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENVIF_DX              Dx = Pdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

VOID
PdoSetDevicePnpState(
    IN  PXENVIF_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    __PdoSetDevicePnpState(Pdo, State);
}

static FORCEINLINE VOID
__PdoRestoreDevicePnpState(
    IN  PXENVIF_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENVIF_DX              Dx = Pdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__PdoGetDevicePnpState(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return Dx->DevicePnpState;
}

DEVICE_PNP_STATE
PdoGetDevicePnpState(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetDevicePnpState(Pdo);
}

static FORCEINLINE VOID
__PdoSetSystemPowerState(
    IN  PXENVIF_PDO         Pdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXENVIF_DX              Dx = Pdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__PdoGetSystemPowerState(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return Dx->SystemPowerState;
}

static FORCEINLINE VOID
__PdoSetDevicePowerState(
    IN  PXENVIF_PDO         Pdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXENVIF_DX              Dx = Pdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__PdoGetDevicePowerState(
    IN  PXENVIF_PDO         Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__PdoSetMissing(
    IN  PXENVIF_PDO Pdo,
    IN  const CHAR  *Reason
    )
{
    Pdo->Reason = Reason;
    Pdo->Missing = TRUE;
}

VOID
PdoSetMissing(
    IN  PXENVIF_PDO Pdo,
    IN  const CHAR  *Reason
    )
{
    __PdoSetMissing(Pdo, Reason);
}

static FORCEINLINE BOOLEAN
__PdoIsMissing(
    IN  PXENVIF_PDO Pdo
    )
{
    return Pdo->Missing;
}

BOOLEAN
PdoIsMissing(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoIsMissing(Pdo);
}

static FORCEINLINE PXENVIF_FDO
__PdoGetFdo(
    IN  PXENVIF_PDO Pdo
    )
{
    return Pdo->Fdo;
}

PXENVIF_FDO
PdoGetFdo(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetFdo(Pdo);
}

static FORCEINLINE VOID
__PdoSetName(
    IN  PXENVIF_PDO Pdo,
    IN  ULONG       Number
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;
    NTSTATUS        status;

    status = RtlStringCbPrintfA(Dx->Name, 
                                MAX_DEVICE_ID_LEN, 
                                "%u", 
                                Number);
    ASSERT(NT_SUCCESS(status));
}

static FORCEINLINE PCHAR
__PdoGetName(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return Dx->Name;
}

PCHAR
PdoGetName(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetName(Pdo);
}

static FORCEINLINE BOOLEAN
__PdoSetEjectRequested(
    IN  PXENVIF_PDO Pdo
    )
{
    return (InterlockedBitTestAndSet(&Pdo->Eject, 0) == 0) ? TRUE : FALSE;
}

VOID
PdoRequestEject(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;
    PDEVICE_OBJECT  PhysicalDeviceObject = Dx->DeviceObject;
    PXENVIF_FDO     Fdo = __PdoGetFdo(Pdo);

    if (!__PdoSetEjectRequested(Pdo))
        return;

    Info("%p (%s)\n",
         PhysicalDeviceObject,
         __PdoGetName(Pdo));

    IoInvalidateDeviceRelations(FdoGetPhysicalDeviceObject(Fdo),
                                BusRelations);
}

static FORCEINLINE BOOLEAN
__PdoClearEjectRequested(
    IN  PXENVIF_PDO Pdo
    )
{
    return (InterlockedBitTestAndReset(&Pdo->Eject, 0) != 0) ? TRUE : FALSE;
}

static FORCEINLINE BOOLEAN
__PdoIsEjectRequested(
    IN  PXENVIF_PDO Pdo
    )
{
    KeMemoryBarrier();
    return (Pdo->Eject & 1) ? TRUE : FALSE;
}

BOOLEAN
PdoIsEjectRequested(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoIsEjectRequested(Pdo);
}

// {2A597D5E-8864-4428-A110-F568F316D4E4}
DEFINE_GUID(GUID_CONTAINER_ID_NAME_SPACE,
0x2a597d5e, 0x8864, 0x4428, 0xa1, 0x10, 0xf5, 0x68, 0xf3, 0x16, 0xd4, 0xe4);

static NTSTATUS
__PdoSetContainerID(
    IN  PXENVIF_PDO     Pdo
    )
{
    BCRYPT_ALG_HANDLE   Algorithm;
    ULONG               Length;
    ULONG               Size;
    PUCHAR              Object;
    BCRYPT_HASH_HANDLE  Hash;
    PUCHAR              Result;
    GUID                ContainerID;
    NTSTATUS            status;

    // Create a Name-Based GUID according to the algorithm presented
    // in section 4.3 of RFC 4122.

    // Choose a SHA1 hash
    status = BCryptOpenAlgorithmProvider(&Algorithm,
                                         BCRYPT_SHA1_ALGORITHM,
                                         MS_PRIMITIVE_PROVIDER,
                                         BCRYPT_PROV_DISPATCH);

    if (!NT_SUCCESS(status))
        goto fail1;

    status = BCryptGetProperty(Algorithm,
                               BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&Length,
                               sizeof (ULONG),
                               &Size,
                               0);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (Size != sizeof (ULONG))
        goto fail3;

    Object = __PdoAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Object == NULL)
        goto fail4;

    status = BCryptCreateHash(Algorithm,
                              &Hash,
                              Object,
                              Length,
                              NULL,
                              0,
                              0);
    if (!NT_SUCCESS(status))
        goto fail5;

    // Hash in the name space
    status = BCryptHashData(Hash,
                            (PUCHAR)&GUID_CONTAINER_ID_NAME_SPACE,
                            sizeof (GUID),
                            0);
    if (!NT_SUCCESS(status))
        goto fail6;

    // Hash in the permanent address
    status = BCryptHashData(Hash,
                            Pdo->PermanentAddress.Byte,
                            sizeof (ETHERNET_ADDRESS),
                            0);
    if (!NT_SUCCESS(status))
        goto fail7;

    // Get the result
    status = BCryptGetProperty(Algorithm,
                               BCRYPT_HASH_LENGTH,
                               (PUCHAR)&Length,
                               sizeof (ULONG),
                               &Size,
                               0);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (Size != sizeof (ULONG))
        goto fail9;

    status = STATUS_INVALID_PARAMETER;
    if (Length < sizeof (GUID))
        goto fail10;

    Result = __PdoAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Result == NULL)
        goto fail11;

    status = BCryptFinishHash(Hash,
                              (PUCHAR)Result,
                              Length,
                              0);
    if (!NT_SUCCESS(status))
        goto fail12;

    RtlCopyMemory(&ContainerID,
                  Result,
                  sizeof (GUID));

    ContainerID.Data3 &= 0x0FFF;     // Clear the version number
    ContainerID.Data3 |= (5 << 12);  // Set version = (name-based SHA1) = 5
    ContainerID.Data4[0] &= 0x3F;    // Clear the variant bits
    ContainerID.Data4[0] |= 0x80;           

    status = RtlStringFromGUID(&ContainerID, &Pdo->ContainerID);
    if (!NT_SUCCESS(status))
        goto fail13;

    Info("%s %wZ\n",
         __PdoGetName(Pdo),
         &Pdo->ContainerID);

    __PdoFree(Result);

    BCryptDestroyHash(Hash);

    __PdoFree(Object);

    BCryptCloseAlgorithmProvider(Algorithm, 0);

    return STATUS_SUCCESS;

fail13:
    Error("fail13\n");

fail12:
    Error("fail12\n");

    __PdoFree(Result);

fail11:
    Error("fail11\n");

fail10:
    Error("fail10\n");

fail9:
    Error("fail9\n");

fail8:
    Error("fail8\n");

fail7:
    Error("fail7\n");

fail6:
    Error("fail6\n");

    BCryptDestroyHash(Hash);

fail5:
    Error("fail5\n");

    __PdoFree(Object);

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    BCryptCloseAlgorithmProvider(Algorithm, 0);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define MAXTEXTLEN  1024

typedef struct _XENVIF_PDO_REVISION {
    ULONG   Number;
    ULONG   CacheInterfaceVersion;
    ULONG   VifInterfaceVersion;
    ULONG   StoreInterfaceVersion;
    ULONG   SuspendInterfaceVersion;
} XENVIF_PDO_REVISION, *PXENVIF_PDO_REVISION;

#define DEFINE_REVISION(_N, _C, _V, _ST, _SU) \
    { (_N), (_C), (_V), (_ST), (_SU) }

static XENVIF_PDO_REVISION PdoRevision[] = {
    DEFINE_REVISION_TABLE
};

#undef DEFINE_REVISION

static VOID
PdoDumpRevisions(
    IN  PXENVIF_PDO Pdo
    )
{
    ULONG           Index;

    UNREFERENCED_PARAMETER(Pdo);

    for (Index = 0; Index < ARRAYSIZE(PdoRevision); Index++) {
        PXENVIF_PDO_REVISION Revision = &PdoRevision[Index];

        ASSERT3U(Revision->CacheInterfaceVersion, >=, XENBUS_CACHE_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->CacheInterfaceVersion, <=, XENBUS_CACHE_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->CacheInterfaceVersion == XENBUS_CACHE_INTERFACE_VERSION_MAX));

        ASSERT3U(Revision->VifInterfaceVersion, >=, XENVIF_VIF_INTERFACE_VERSION_MIN);
        ASSERT3U(Revision->VifInterfaceVersion, <=, XENVIF_VIF_INTERFACE_VERSION_MAX);
        ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                     Revision->VifInterfaceVersion == XENVIF_VIF_INTERFACE_VERSION_MAX));

        if (Revision->StoreInterfaceVersion != 0) {
            ASSERT3U(Revision->StoreInterfaceVersion, >=, XENBUS_STORE_INTERFACE_VERSION_MIN);
            ASSERT3U(Revision->StoreInterfaceVersion, <=, XENBUS_STORE_INTERFACE_VERSION_MAX);
            ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                         Revision->StoreInterfaceVersion == XENBUS_STORE_INTERFACE_VERSION_MAX));
        }

        if (Revision->SuspendInterfaceVersion != 0) {
            ASSERT3U(Revision->SuspendInterfaceVersion, >=, XENBUS_SUSPEND_INTERFACE_VERSION_MIN);
            ASSERT3U(Revision->SuspendInterfaceVersion, <=, XENBUS_SUSPEND_INTERFACE_VERSION_MAX);
            ASSERT(IMPLY(Index == ARRAYSIZE(PdoRevision) - 1,
                         Revision->SuspendInterfaceVersion == XENBUS_SUSPEND_INTERFACE_VERSION_MAX));
        }

        Info("%08X -> "
             "CACHE v%u "
             "VIF v%u "
             "STORE v%u "
             "SUSPEND v%u\n",
             Revision->Number,
             Revision->CacheInterfaceVersion,
             Revision->VifInterfaceVersion,
             Revision->StoreInterfaceVersion,
             Revision->SuspendInterfaceVersion);
    }
}

static FORCEINLINE PDEVICE_OBJECT
__PdoGetDeviceObject(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return (Dx->DeviceObject);
}
    
PDEVICE_OBJECT
PdoGetDeviceObject(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetDeviceObject(Pdo);
}

static FORCEINLINE PCHAR
__PdoGetVendorName(
    IN  PXENVIF_PDO Pdo
    )
{
    return FdoGetVendorName(__PdoGetFdo(Pdo));
}

static FORCEINLINE PXENVIF_FRONTEND
__PdoGetFrontend(
    IN  PXENVIF_PDO Pdo
    )
{
    return Pdo->Frontend;
}

PXENVIF_FRONTEND
PdoGetFrontend(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetFrontend(Pdo);
}

static FORCEINLINE PXENVIF_VIF_CONTEXT
__PdoGetVifContext(
    IN  PXENVIF_PDO Pdo
    )
{
    return Pdo->VifContext;
}

PXENVIF_VIF_CONTEXT
PdoGetVifContext(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetVifContext(Pdo);
}

static FORCEINLINE NTSTATUS
__PdoParseAddress(
    IN  PCHAR               Buffer,
    OUT PETHERNET_ADDRESS   Address
    )
{
    ULONG                   Length;
    NTSTATUS                status;

    Length = 0;
    for (;;) {
        CHAR    Character;
        UCHAR   Byte;

        Character = *Buffer++;
        if (Character == '\0')
            break;

        if (Character >= '0' && Character <= '9')
            Byte = Character - '0';
        else if (Character >= 'A' && Character <= 'F')
            Byte = 0x0A + Character - 'A';
        else if (Character >= 'a' && Character <= 'f')
            Byte = 0x0A + Character - 'a';
        else
            break;

        Byte <<= 4;

        Character = *Buffer++;
        if (Character == '\0')
            break;

        if (Character >= '0' && Character <= '9')
            Byte += Character - '0';
        else if (Character >= 'A' && Character <= 'F')
            Byte += 0x0A + Character - 'A';
        else if (Character >= 'a' && Character <= 'f')
            Byte += 0x0A + Character - 'a';
        else
            break;

        Address->Byte[Length++] = Byte;

        // Skip over any separator
        if (*Buffer == ':' || *Buffer == '-')
            Buffer++;
    }

    status = STATUS_INVALID_PARAMETER;
    if (Length != ETHERNET_ADDRESS_LENGTH)
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetPermanentAddress(
    IN  PXENVIF_PDO Pdo,
    IN  PCHAR       Buffer
    )
{
    ANSI_STRING     Ansi[2];
    NTSTATUS        status;

    status = __PdoParseAddress(Buffer, &Pdo->PermanentAddress);
    if (!NT_SUCCESS(status))
        goto fail1;

    RtlZeroMemory(Ansi, sizeof (ANSI_STRING) * 2);
    RtlInitAnsiString(&Ansi[0], Buffer);

    status = RegistryUpdateSzValue(DriverGetAddressesKey(),
                                   __PdoGetName(Pdo),
                                   REG_SZ,
                                   Ansi);
    if (!NT_SUCCESS(status))
        goto fail2;

    Info("%s: %Z\n", __PdoGetName(Pdo), &Ansi[0]);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE PETHERNET_ADDRESS
__PdoGetPermanentAddress(
    IN  PXENVIF_PDO Pdo
    )
{
    return &Pdo->PermanentAddress;
}

PETHERNET_ADDRESS
PdoGetPermanentAddress(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetPermanentAddress(Pdo);
}

static FORCEINLINE VOID
__PdoClearPermanentAddress(
    IN  PXENVIF_PDO Pdo
    )
{
    (VOID) RegistryDeleteValue(DriverGetAddressesKey(),
                               __PdoGetName(Pdo));

    RtlZeroMemory(&Pdo->PermanentAddress, sizeof (ETHERNET_ADDRESS));
}

static NTSTATUS
PdoSetFriendlyName(
    IN  PXENVIF_PDO Pdo,
    IN  HANDLE      SoftwareKey,
    IN  HANDLE      HardwareKey
    )
{
    PANSI_STRING    DriverDesc;
    CHAR            Buffer[MAXNAMELEN];
    ANSI_STRING     Ansi[2];
    NTSTATUS        status;

    status = RegistryQuerySzValue(SoftwareKey,
                                  "DriverDesc",
                                  NULL,
                                  &DriverDesc);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringCbPrintfA(Buffer,
                                MAXNAMELEN,
                                "%Z #%s",
                                &DriverDesc[0],
                                __PdoGetName(Pdo)
                                );
    if (!NT_SUCCESS(status))
        goto fail2;

    RtlZeroMemory(Ansi, sizeof (ANSI_STRING) * 2);
    RtlInitAnsiString(&Ansi[0], Buffer);

    status = RegistryUpdateSzValue(HardwareKey,
                                   "FriendlyName",
                                   REG_SZ,
                                   Ansi);
    if (!NT_SUCCESS(status))
        goto fail3;

    Info("%s: %Z\n", __PdoGetName(Pdo), &Ansi[0]);

    RegistryFreeSzValue(DriverDesc);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetCurrentAddress(
    IN  PXENVIF_PDO Pdo,
    IN  HANDLE      Key
    )
{
    PANSI_STRING    Ansi;
    NTSTATUS        status;

    RtlFillMemory(Pdo->CurrentAddress.Byte, ETHERNET_ADDRESS_LENGTH, 0xFF);

    status = RegistryQuerySzValue(Key,
                                  "NetworkAddress",
                                  NULL,
                                  &Ansi);
    if (!NT_SUCCESS(status))
        goto done;

    status = __PdoParseAddress(Ansi[0].Buffer, &Pdo->CurrentAddress);
    if (!NT_SUCCESS(status))
        goto fail1;

    Info("%s: %Z\n", __PdoGetName(Pdo), &Ansi[0]);

    RegistryFreeSzValue(Ansi);

done:
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    RegistryFreeSzValue(Ansi);

    return status;
}

PETHERNET_ADDRESS
PdoGetCurrentAddress(
    IN  PXENVIF_PDO Pdo
    )
{
    return &Pdo->CurrentAddress;
}

PDMA_ADAPTER
PdoGetDmaAdapter(
    IN  PXENVIF_PDO         Pdo,
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
    IN      PXENVIF_PDO         Pdo,
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
    IN  PXENVIF_PDO     Pdo,
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
    IN  PXENVIF_PDO     Pdo,
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

static FORCEINLINE NTSTATUS
__PdoD3ToD0(
    IN  PXENVIF_PDO             Pdo
    )
{
    POWER_STATE                 PowerState;
    NTSTATUS                    status;

    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3U(__PdoGetDevicePowerState(Pdo), ==, PowerDeviceD3);

    status = FrontendSetState(__PdoGetFrontend(Pdo), FRONTEND_CONNECTED);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoSetDevicePowerState(Pdo, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    Trace("(%s) <====\n", __PdoGetName(Pdo));

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__PdoD0ToD3(
    IN  PXENVIF_PDO     Pdo
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

    (VOID) FrontendSetState(__PdoGetFrontend(Pdo), FRONTEND_CLOSED);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

static DECLSPEC_NOINLINE VOID
PdoSuspendCallbackLate(
    IN  PVOID               Argument
    )
{
    PXENVIF_PDO             Pdo = Argument;
    NTSTATUS                status;

    __PdoD0ToD3(Pdo);

    status = __PdoD3ToD0(Pdo);
    ASSERT(NT_SUCCESS(status));
}

// This function must not touch pageable code or data
static DECLSPEC_NOINLINE NTSTATUS
PdoD3ToD0(
    IN  PXENVIF_PDO Pdo
    )
{
    KIRQL           Irql;
    NTSTATUS        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    status = XENBUS_SUSPEND(Acquire, &Pdo->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = __PdoD3ToD0(Pdo);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_SUSPEND(Register,
                            &Pdo->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            PdoSuspendCallbackLate,
                            Pdo,
                            &Pdo->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail3;

    KeLowerIrql(Irql);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    __PdoD0ToD3(Pdo);

fail2:
    Error("fail2\n");

    XENBUS_SUSPEND(Release, &Pdo->SuspendInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    KeLowerIrql(Irql);

    return status;
}

// This function must not touch pageable code or data
static DECLSPEC_NOINLINE VOID
PdoD0ToD3(
    IN  PXENVIF_PDO Pdo
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
static DECLSPEC_NOINLINE VOID
PdoS4ToS3(
    IN  PXENVIF_PDO Pdo
    )
{
    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__PdoGetSystemPowerState(Pdo), ==, PowerSystemHibernate);

    __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

// This function must not touch pageable code or data
static DECLSPEC_NOINLINE VOID
PdoS3ToS4(
    IN  PXENVIF_PDO Pdo
    )
{
    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__PdoGetSystemPowerState(Pdo), ==, PowerSystemSleeping3);

    __PdoSetSystemPowerState(Pdo, PowerSystemHibernate);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

static NTSTATUS
PdoGetInterfaceGuid(
    IN  PXENVIF_PDO Pdo,
    IN  HANDLE      Key,
    OUT LPGUID      Guid
    )
{
    PANSI_STRING    Ansi;
    UNICODE_STRING  Unicode;
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Pdo);

    status = RegistryQuerySzValue(Key,
                                  "NetCfgInstanceId",
                                  NULL,
                                  &Ansi);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlAnsiStringToUnicodeString(&Unicode, &Ansi[0], TRUE);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlGUIDFromString(&Unicode, Guid);
    if (!NT_SUCCESS(status))
        goto fail3;

    RtlFreeUnicodeString(&Unicode);

    RegistryFreeSzValue(Ansi);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    RtlFreeUnicodeString(&Unicode);

fail2:
    Error("fail2\n");

    RegistryFreeSzValue(Ansi);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
PdoUnplugRequest(
    IN  PXENVIF_PDO Pdo,
    IN  BOOLEAN     Make
    )
{
    NTSTATUS        status;

    ASSERT3U(Pdo->UnplugRequested, !=, Make);
    Pdo->UnplugRequested = Make;

    status = XENBUS_UNPLUG(Acquire, &Pdo->UnplugInterface);
    if (!NT_SUCCESS(status))
        return;

    XENBUS_UNPLUG(Request,
                  &Pdo->UnplugInterface,
                  XENBUS_UNPLUG_DEVICE_TYPE_NICS,
                  Make);

    XENBUS_UNPLUG(Release, &Pdo->UnplugInterface);
}

static DECLSPEC_NOINLINE NTSTATUS
PdoStartDevice(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            (*__GetIfTable2)(PMIB_IF_TABLE2 *);
    VOID                (*__FreeMibTable)(PVOID);
    PMIB_IF_TABLE2      Table;
    ULONG               Index;
    PIO_STACK_LOCATION  StackLocation;
    HANDLE              SoftwareKey;
    HANDLE              HardwareKey;
    ULONG               HasSettings;
    GUID                Guid;
    NTSTATUS            status;

    status = STATUS_UNSUCCESSFUL;
    if (Pdo->HasAlias)
        goto fail1;

    if (DriverSafeMode())
        goto fail2;

    status = RegistryOpenSoftwareKey(__PdoGetDeviceObject(Pdo),
                                     KEY_ALL_ACCESS,
                                     &SoftwareKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RegistryOpenHardwareKey(__PdoGetDeviceObject(Pdo),
                                     KEY_ALL_ACCESS,
                                     &HardwareKey);
    if (!NT_SUCCESS(status))
        goto fail4;

    (VOID) PdoSetFriendlyName(Pdo,
                              SoftwareKey,
                              HardwareKey);

    status = __PdoSetCurrentAddress(Pdo, SoftwareKey);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = LinkGetRoutineAddress("netio.sys",
                                   "GetIfTable2",
                                   (PVOID *)&__GetIfTable2);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = LinkGetRoutineAddress("netio.sys",
                                   "FreeMibTable",
                                   (PVOID *)&__FreeMibTable);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = __GetIfTable2(&Table);
    if (!NT_SUCCESS(status))
        goto fail8;

    //
    // Look for a network interface with the same permanent address
    // that is already up. If there is one then it must be an
    // aliasing emulated device, so save its settings.
    //
    for (Index = 0; Index < Table->NumEntries; Index++) {
        PMIB_IF_ROW2    Row = &Table->Table[Index];

        Trace("%s: CHECKING %ws (%ws)\n",
              __PdoGetName(Pdo),
              Row->Alias,
              Row->Description);

        if (!Row->InterfaceAndOperStatusFlags.ConnectorPresent)
            continue;

        if (Row->PhysicalAddressLength != sizeof (ETHERNET_ADDRESS))
            continue;

        if (memcmp(Row->PermanentPhysicalAddress,
                   __PdoGetPermanentAddress(Pdo),
                   sizeof (ETHERNET_ADDRESS)) != 0)
            continue;

        if (Row->OperStatus != IfOperStatusUp)
            continue;

        (VOID) SettingsSave(__PdoGetName(Pdo),
                            Row->Alias,
                            Row->Description,
                            &Row->InterfaceGuid,
                            &Row->InterfaceLuid);

        Pdo->HasAlias = TRUE;
        break;
    }

    if (Pdo->HasAlias) {
        PdoUnplugRequest(Pdo, TRUE);

        status = STATUS_UNSUCCESSFUL;
        goto fail9;
    }

    status = RegistryQueryDwordValue(SoftwareKey,
                                     "HasSettings",
                                     &HasSettings);
    if (!NT_SUCCESS(status))
        HasSettings = 0;

    if (HasSettings == 0) {
        //
        // If there is a stack bound then restore any settings that
        // may have been saved from an aliasing emulated device.
        //
        status = PdoGetInterfaceGuid(Pdo, SoftwareKey, &Guid);
        if (NT_SUCCESS(status)) {
            for (Index = 0; Index < Table->NumEntries; Index++) {
                PMIB_IF_ROW2    Row = &Table->Table[Index];

                if (!IsEqualGUID(&Row->InterfaceGuid, &Guid))
                    continue;

                (VOID) SettingsRestore(__PdoGetName(Pdo),
                                       Row->Alias,
                                       Row->Description,
                                       &Row->InterfaceGuid,
                                       &Row->InterfaceLuid);
                break;
            }

            HasSettings = 1;

            (VOID) RegistryUpdateDwordValue(SoftwareKey,
                                            "HasSettings",
                                             HasSettings);
        }
    }

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    status = PdoD3ToD0(Pdo);
    if (!NT_SUCCESS(status))
        goto fail10;

    PdoUnplugRequest(Pdo, TRUE);

    __PdoSetDevicePnpState(Pdo, Started);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    __FreeMibTable(Table);

    RegistryCloseKey(SoftwareKey);

    return STATUS_SUCCESS;

fail10:
    Error("fail10\n");

    __FreeMibTable(Table);

    goto fail6;

fail9:
    Error("fail9\n");

    DriverRequestReboot();
    __FreeMibTable(Table);

fail8:
    Error("fail8\n");

fail7:
    Error("fail7\n");

fail6:
    Error("fail6\n");

    RtlZeroMemory(&Pdo->CurrentAddress, sizeof (ETHERNET_ADDRESS));

fail5:
    Error("fail5\n");

    RegistryCloseKey(HardwareKey);

fail4:
    Error("fail4\n");

    RegistryCloseKey(SoftwareKey);

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryStopDevice(
    IN  PXENVIF_PDO Pdo,
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

static DECLSPEC_NOINLINE NTSTATUS
PdoCancelStopDevice(
    IN  PXENVIF_PDO Pdo,
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

static DECLSPEC_NOINLINE NTSTATUS
PdoStopDevice(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    if (__PdoGetDevicePowerState(Pdo) != PowerDeviceD0)
        goto done;

    PdoUnplugRequest(Pdo, FALSE);

    PdoD0ToD3(Pdo);

done:
    RtlZeroMemory(&Pdo->CurrentAddress, sizeof (ETHERNET_ADDRESS));

    __PdoSetDevicePnpState(Pdo, Stopped);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryRemoveDevice(
    IN  PXENVIF_PDO Pdo,
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

static DECLSPEC_NOINLINE NTSTATUS
PdoCancelRemoveDevice(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    if (__PdoClearEjectRequested(Pdo))
        FrontendEjectFailed(__PdoGetFrontend(Pdo));

    __PdoRestoreDevicePnpState(Pdo, RemovePending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoSurpriseRemoval(
    IN  PXENVIF_PDO Pdo,
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

static DECLSPEC_NOINLINE NTSTATUS
PdoRemoveDevice(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PXENVIF_FDO         Fdo = __PdoGetFdo(Pdo);
    BOOLEAN             NeedInvalidate;
    NTSTATUS            status;

    if (__PdoGetDevicePowerState(Pdo) != PowerDeviceD0)
        goto done;

    PdoUnplugRequest(Pdo, FALSE);

    PdoD0ToD3(Pdo);

done:
    RtlZeroMemory(&Pdo->CurrentAddress, sizeof (ETHERNET_ADDRESS));

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

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryDeviceRelations(
    IN  PXENVIF_PDO     Pdo,
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

    Relations = ExAllocatePoolWithTag(PagedPool, sizeof (DEVICE_RELATIONS), 'FIV');

    status = STATUS_NO_MEMORY;
    if (Relations == NULL)
        goto done;

    RtlZeroMemory(Relations, sizeof (DEVICE_RELATIONS));

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

static NTSTATUS
PdoDelegateIrp(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    return FdoDelegateIrp(Pdo->Fdo, Irp);
}

static NTSTATUS
PdoQueryBusInterface(
    IN  PXENVIF_PDO         Pdo,
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

static NTSTATUS
PdoQueryVifInterface(
    IN  PXENVIF_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    USHORT                  Size;
    USHORT                  Version;
    PINTERFACE              Interface;
    PVOID                   Context;
    NTSTATUS                status;

    status = Irp->IoStatus.Status;        

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Size = StackLocation->Parameters.QueryInterface.Size;
    Version = StackLocation->Parameters.QueryInterface.Version;
    Interface = StackLocation->Parameters.QueryInterface.Interface;

    Context = __PdoGetVifContext(Pdo);

    status = VifGetInterface(Context,
                             Version,
                             Interface,
                             Size);
    if (!NT_SUCCESS(status))
        goto done;

    Irp->IoStatus.Information = 0;
    status = STATUS_SUCCESS;

done:
    return status;
}

struct _INTERFACE_ENTRY {
    const GUID  *Guid;
    const CHAR  *Name;
    NTSTATUS    (*Query)(PXENVIF_PDO, PIRP);
};

struct _INTERFACE_ENTRY PdoInterfaceTable[] = {
    { &GUID_BUS_INTERFACE_STANDARD, "BUS_INTERFACE", PdoQueryBusInterface },
    { &GUID_XENVIF_VIF_INTERFACE, "VIF_INTERFACE", PdoQueryVifInterface },
    { &GUID_XENBUS_CACHE_INTERFACE, "CACHE_INTERFACE", PdoDelegateIrp },
    { &GUID_XENBUS_STORE_INTERFACE, "STORE_INTERFACE", PdoDelegateIrp },
    { &GUID_XENBUS_SUSPEND_INTERFACE, "SUSPEND_INTERFACE", PdoDelegateIrp },
    { NULL, NULL, NULL }
};

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryInterface(
    IN  PXENVIF_PDO         Pdo,
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

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryCapabilities(
    IN  PXENVIF_PDO         Pdo,
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
    Capabilities->EjectSupported = 1;
    Capabilities->Removable = 1;
    Capabilities->DockDevice = 0;
    Capabilities->UniqueID = 1;
    Capabilities->SilentInstall = 1;
    Capabilities->RawDeviceOK = 0;
    Capabilities->SurpriseRemovalOK = 1;
    Capabilities->HardwareDisabled = 0;
    Capabilities->NoDisplayInUI = 0;

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

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryDeviceText(
    IN  PXENVIF_PDO     Pdo,
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

    Buffer = ExAllocatePoolWithTag(PagedPool, MAXTEXTLEN, 'FIV');

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto done;

    RtlZeroMemory(Buffer, MAXTEXTLEN);

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

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Trace("%s: %wZ\n", __PdoGetName(Pdo), &Text);

    Irp->IoStatus.Information = (ULONG_PTR)Text.Buffer;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoReadConfig(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoWriteConfig(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

#define REGSTR_VAL_MAX_HCID_LEN 1024

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryId(
    IN  PXENVIF_PDO     Pdo,
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
        Id.MaximumLength = (USHORT)(strlen(__PdoGetName(Pdo)) + 1) * sizeof (WCHAR);
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

        break;

    case BusQueryContainerID:
        Trace("BusQueryContainerID\n");
        Id.MaximumLength = MAX_GUID_STRING_LEN * sizeof (WCHAR);
        break;

    default:
        Irp->IoStatus.Information = 0;
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    Buffer = ExAllocatePoolWithTag(PagedPool, Id.MaximumLength, 'FIV');

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto done;

    RtlZeroMemory(Buffer, Id.MaximumLength);

    Id.Buffer = Buffer;
    Id.Length = 0;

    switch (StackLocation->Parameters.QueryId.IdType) {
    case BusQueryInstanceID:
        Type = REG_SZ;

        status = RtlStringCbPrintfW(Buffer,
                                    Id.MaximumLength,
                                    L"%hs",
                                    __PdoGetName(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    case BusQueryContainerID:
        Type = REG_SZ;

        status = RtlAppendUnicodeStringToString(&Id, &Pdo->ContainerID);
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    case BusQueryDeviceID: {
        ULONG                   Index;
        PXENVIF_PDO_REVISION    Revision;

        Type = REG_SZ;
        Index = ARRAYSIZE(PdoRevision) - 1;
        Revision = &PdoRevision[Index];

        status = RtlStringCbPrintfW(Buffer,
                                    Id.MaximumLength,
                                    L"XENVIF\\VEN_%hs&DEV_NET&REV_%08X",
                                    __PdoGetVendorName(Pdo),
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
            PXENVIF_PDO_REVISION    Revision = &PdoRevision[Index];

            status = RtlStringCbPrintfW(Buffer,
                                        Length,
                                        L"XENVIF\\VEN_%hs&DEV_NET&REV_%08X",
                                        __PdoGetVendorName(Pdo),
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
                                    L"XENDEVICE");
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

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Id.Length = (USHORT)((ULONG_PTR)Buffer - (ULONG_PTR)Id.Buffer);
    Buffer = Id.Buffer;

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

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryBusInformation(
    IN  PXENVIF_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PPNP_BUS_INFORMATION    Info;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Pdo);

    Info = ExAllocatePoolWithTag(PagedPool, sizeof (PNP_BUS_INFORMATION), 'FIV');

    status = STATUS_NO_MEMORY;
    if (Info == NULL)
        goto done;

    RtlZeroMemory(Info, sizeof (PNP_BUS_INFORMATION));

    Info->BusTypeGuid = GUID_BUS_TYPE_INTERNAL;
    Info->LegacyBusType = PNPBus;
    Info->BusNumber = 0;

    Irp->IoStatus.Information = (ULONG_PTR)Info;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDeviceUsageNotification(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    status = PdoDelegateIrp(Pdo, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoEject(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    PXENVIF_FDO     Fdo = __PdoGetFdo(Pdo);
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

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchPnp(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    Trace("====> (%s) (%02x:%s)\n",
          __PdoGetName(Pdo),
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

static FORCEINLINE NTSTATUS
__PdoSetDevicePower(
    IN  PXENVIF_PDO     Pdo,
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

    Trace("====> (%s) (%s:%s)\n",
          __PdoGetName(Pdo),
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (__PdoGetDevicePowerState(Pdo) > DeviceState) {
        Trace("%s: POWERING UP: %s -> %s\n",
              __PdoGetName(Pdo),
              PowerDeviceStateName(__PdoGetDevicePowerState(Pdo)),
              PowerDeviceStateName(DeviceState));

        ASSERT3U(DeviceState, ==, PowerDeviceD0);
        status = PdoD3ToD0(Pdo);
        ASSERT(NT_SUCCESS(status));
    } else if (__PdoGetDevicePowerState(Pdo) < DeviceState) {
        Trace("%s: POWERING DOWN: %s -> %s\n",
              __PdoGetName(Pdo),
              PowerDeviceStateName(__PdoGetDevicePowerState(Pdo)),
              PowerDeviceStateName(DeviceState));

        ASSERT3U(DeviceState, ==, PowerDeviceD3);
        PdoD0ToD3(Pdo);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Trace("<==== (%s:%s)\n",
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction));

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoDevicePower(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_PDO         Pdo = Context;
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

        (VOID) __PdoSetDevicePower(Pdo, Irp);
    }

    return STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__PdoSetSystemPower(
    IN  PXENVIF_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    SYSTEM_POWER_STATE      SystemState;
    POWER_ACTION            PowerAction;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s) (%s:%s)\n",
          __PdoGetName(Pdo),
          PowerSystemStateName(SystemState), 
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
              PowerSystemStateName(__PdoGetSystemPowerState(Pdo)),
              PowerSystemStateName(SystemState));
    } else if (__PdoGetSystemPowerState(Pdo) < SystemState) {
        Trace("%s: POWERING DOWN: %s -> %s\n",
              __PdoGetName(Pdo),
              PowerSystemStateName(__PdoGetSystemPowerState(Pdo)),
              PowerSystemStateName(SystemState));

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
          PowerSystemStateName(SystemState), 
          PowerActionName(PowerAction));

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoSystemPower(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_PDO         Pdo = Context;
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

        (VOID) __PdoSetSystemPower(Pdo, Irp);
    }

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoSetPower(
    IN  PXENVIF_PDO     Pdo,
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

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryPower(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;
    
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchPower(
    IN  PXENVIF_PDO     Pdo,
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

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchDefault(
    IN  PXENVIF_PDO Pdo,
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
    IN  PXENVIF_PDO     Pdo,
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

NTSTATUS
PdoResume(
    IN  PXENVIF_PDO Pdo
    )
{
    return FrontendResume(__PdoGetFrontend(Pdo));
}

VOID
PdoSuspend(
    IN  PXENVIF_PDO     Pdo
    )
{
    FrontendSuspend(__PdoGetFrontend(Pdo));
}

NTSTATUS
PdoCreate(
    IN  PXENVIF_FDO     Fdo,
    IN  ULONG           Number,
    IN  PCHAR           Address
    )
{
    PDEVICE_OBJECT      PhysicalDeviceObject;
    PXENVIF_DX          Dx;
    PXENVIF_PDO         Pdo;
    NTSTATUS            status;

#pragma prefast(suppress:28197) // Possibly leaking memory 'PhysicalDeviceObject'
    status = IoCreateDevice(DriverGetDriverObject(),
                            sizeof(XENVIF_DX),
                            NULL,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN | FILE_AUTOGENERATED_DEVICE_NAME,
                            FALSE,
                            &PhysicalDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXENVIF_DX)PhysicalDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XENVIF_DX));

    Dx->Type = PHYSICAL_DEVICE_OBJECT;
    Dx->DeviceObject = PhysicalDeviceObject;
    Dx->DevicePnpState = Present;
    Dx->SystemPowerState = PowerSystemWorking;
    Dx->DevicePowerState = PowerDeviceD3;

    Pdo = __PdoAllocate(sizeof (XENVIF_PDO));

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

    __PdoSetName(Pdo, Number);

    status = __PdoSetPermanentAddress(Pdo, Address);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = __PdoSetContainerID(Pdo);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = BusInitialize(Pdo, &Pdo->BusInterface);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = VifInitialize(Pdo, &Pdo->VifContext);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = FrontendInitialize(Pdo, &Pdo->Frontend);
    if (!NT_SUCCESS(status))
        goto fail9;

    FdoGetSuspendInterface(Fdo, &Pdo->SuspendInterface);
    FdoGetUnplugInterface(Fdo, &Pdo->UnplugInterface);

    Dx->Pdo = Pdo;

    status = FdoAddPhysicalDeviceObject(Fdo, Pdo);
    if (!NT_SUCCESS(status))
        goto fail10;

    status = STATUS_UNSUCCESSFUL;
    if (__PdoIsEjectRequested(Pdo))
        goto fail11;

    Info("%p (%s)\n",
         PhysicalDeviceObject,
         __PdoGetName(Pdo));

    PdoDumpRevisions(Pdo);

    PhysicalDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;

fail11:
    Error("fail11\n");

    FdoRemovePhysicalDeviceObject(Fdo, Pdo);

fail10:
    Error("fail10\n");

    (VOID) __PdoClearEjectRequested(Pdo);

    Dx->Pdo = NULL;

    RtlZeroMemory(&Pdo->UnplugInterface,
                  sizeof (XENBUS_UNPLUG_INTERFACE));

    RtlZeroMemory(&Pdo->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    FrontendTeardown(__PdoGetFrontend(Pdo));
    Pdo->Frontend = NULL;

fail9:
    Error("fail9\n");

    VifTeardown(Pdo->VifContext);
    Pdo->VifContext = NULL;

fail8:
    Error("fail8\n");

    BusTeardown(&Pdo->BusInterface);

fail7:
    Error("fail7\n");

    RtlFreeUnicodeString(&Pdo->ContainerID);
    RtlZeroMemory(&Pdo->ContainerID, sizeof (UNICODE_STRING));

fail6:
    Error("fail6\n");

    __PdoClearPermanentAddress(Pdo);

fail5:
    Error("fail5\n");

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

    ASSERT(IsZeroMemory(Pdo, sizeof (XENVIF_PDO)));
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
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;
    PDEVICE_OBJECT  PhysicalDeviceObject = Dx->DeviceObject;
    PXENVIF_FDO     Fdo = __PdoGetFdo(Pdo);

    Pdo->UnplugRequested = FALSE;
    Pdo->HasAlias = FALSE;

    ASSERT3U(__PdoGetDevicePnpState(Pdo), ==, Deleted);

    ASSERT(__PdoIsMissing(Pdo));
    Pdo->Missing = FALSE;

    Info("%p (%s) (%s)\n",
         PhysicalDeviceObject,
         __PdoGetName(Pdo),
         Pdo->Reason);

    Pdo->Reason = NULL;

    FdoRemovePhysicalDeviceObject(Fdo, Pdo);

    (VOID) __PdoClearEjectRequested(Pdo);

    Dx->Pdo = NULL;

    RtlZeroMemory(&Pdo->UnplugInterface,
                  sizeof (XENBUS_UNPLUG_INTERFACE));

    RtlZeroMemory(&Pdo->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    FrontendTeardown(__PdoGetFrontend(Pdo));
    Pdo->Frontend = NULL;    

    VifTeardown(Pdo->VifContext);
    Pdo->VifContext = NULL;

    BusTeardown(&Pdo->BusInterface);

    RtlFreeUnicodeString(&Pdo->ContainerID);
    RtlZeroMemory(&Pdo->ContainerID, sizeof (UNICODE_STRING));

    __PdoClearPermanentAddress(Pdo);

    ThreadAlert(Pdo->DevicePowerThread);
    ThreadJoin(Pdo->DevicePowerThread);
    Pdo->DevicePowerThread = NULL;

    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

    Pdo->Fdo = NULL;
    Pdo->Dx = NULL;

    ASSERT(IsZeroMemory(Pdo, sizeof (XENVIF_PDO)));
    __PdoFree(Pdo);

    IoDeleteDevice(PhysicalDeviceObject);
}
