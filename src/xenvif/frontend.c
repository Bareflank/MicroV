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
#include <stdlib.h>
#include <netioapi.h>
#include <xen.h>

#include "driver.h"
#include "registry.h"
#include "fdo.h"
#include "pdo.h"
#include "thread.h"
#include "frontend.h"
#include "names.h"
#include "mac.h"
#include "tcpip.h"
#include "receiver.h"
#include "transmitter.h"
#include "link.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

typedef struct _XENVIF_FRONTEND_STATISTICS {
    ULONGLONG   Value[XENVIF_VIF_STATISTIC_COUNT];
} XENVIF_FRONTEND_STATISTICS, *PXENVIF_FRONTEND_STATISTICS;

#define XENVIF_FRONTEND_MAXIMUM_HASH_MAPPING_SIZE   128

typedef struct _XENVIF_FRONTEND_HASH {
    XENVIF_PACKET_HASH_ALGORITHM    Algorithm;
    ULONG                           Flags;
    UCHAR                           Key[XENVIF_VIF_HASH_KEY_SIZE];
    ULONG                           Mapping[XENVIF_FRONTEND_MAXIMUM_HASH_MAPPING_SIZE];
    ULONG                           Size;
} XENVIF_FRONTEND_HASH, *PXENVIF_FRONTEND_HASH;

struct _XENVIF_FRONTEND {
    PXENVIF_PDO                 Pdo;
    PCHAR                       Path;
    PCHAR                       Prefix;
    XENVIF_FRONTEND_STATE       State;
    BOOLEAN                     Online;
    KSPIN_LOCK                  Lock;
    PXENVIF_THREAD              EjectThread;
    KEVENT                      EjectEvent;

    PCHAR                       BackendPath;
    USHORT                      BackendDomain;
    ULONG                       MaxQueues;
    ULONG                       NumQueues;
    BOOLEAN                     Split;
    ULONG                       DisableToeplitz;

    PXENVIF_MAC                 Mac;
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_CONTROLLER          Controller;

    XENBUS_DEBUG_INTERFACE      DebugInterface;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    XENBUS_STORE_INTERFACE      StoreInterface;

    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackEarly;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENBUS_STORE_WATCH         Watch;

    PXENVIF_FRONTEND_STATISTICS Statistics;
    ULONG                       StatisticsCount;

    PXENVIF_THREAD              MibThread;
    CHAR                        Alias[IF_MAX_STRING_SIZE + 1];
    NET_IFINDEX                 InterfaceIndex;
    PSOCKADDR_INET              AddressTable;
    ULONG                       AddressCount;

    XENVIF_FRONTEND_HASH        Hash;
};

static const PCHAR
FrontendStateName(
    IN  XENVIF_FRONTEND_STATE   State
    )
{
#define _STATE_NAME(_State)     \
    case  FRONTEND_ ## _State:  \
        return #_State;

    switch (State) {
    _STATE_NAME(UNKNOWN);
    _STATE_NAME(CLOSED);
    _STATE_NAME(PREPARED);
    _STATE_NAME(CONNECTED);
    _STATE_NAME(ENABLED);
    default:
        break;
    }

    return "INVALID";

#undef  _STATE_NAME
}

#define FRONTEND_POOL    'NORF'

static FORCEINLINE PVOID
__FrontendAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, FRONTEND_POOL);
}

static FORCEINLINE VOID
__FrontendFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, FRONTEND_POOL);
}

static FORCEINLINE PXENVIF_PDO
__FrontendGetPdo(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Pdo;
}

PXENVIF_PDO
FrontendGetPdo(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetPdo(Frontend);
}

static FORCEINLINE PCHAR
__FrontendGetPath(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Path;
}

PCHAR
FrontendGetPath(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetPath(Frontend);
}

static FORCEINLINE PCHAR
__FrontendGetPrefix(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Prefix;
}

PCHAR
FrontendGetPrefix(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetPrefix(Frontend);
}

static FORCEINLINE PCHAR
__FrontendGetBackendPath(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->BackendPath;
}

PCHAR
FrontendGetBackendPath(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetBackendPath(Frontend);
}

static FORCEINLINE USHORT
__FrontendGetBackendDomain(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->BackendDomain;
}

USHORT
FrontendGetBackendDomain(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetBackendDomain(Frontend);
}

static VOID
FrontendSetMaxQueues(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    HANDLE                  ParametersKey;
    ULONG                   FrontendMaxQueues;
    NTSTATUS                status;

    Frontend->MaxQueues = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    ParametersKey = DriverGetParametersKey();

    status = RegistryQueryDwordValue(ParametersKey,
                                     "FrontendMaxQueues",
                                     &FrontendMaxQueues);
    if (NT_SUCCESS(status) && FrontendMaxQueues < Frontend->MaxQueues)
        Frontend->MaxQueues = FrontendMaxQueues;

    if (Frontend->MaxQueues == 0)
        Frontend->MaxQueues = 1;

    Info("%s: %u\n", __FrontendGetPath(Frontend), Frontend->MaxQueues);
}

static FORCEINLINE ULONG
__FrontendGetMaxQueues(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->MaxQueues;
}

ULONG
FrontendGetMaxQueues(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetMaxQueues(Frontend);
}

PCHAR
FrontendFormatPath(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  ULONG               Index
    )
{
    ULONG                   Length;
    PCHAR                   Path;
    NTSTATUS                status;

    Length = (ULONG)(strlen(__FrontendGetPath(Frontend)) +
                     strlen("/queue-XX") +
                     1) * sizeof (CHAR);

    Path = __FrontendAllocate(Length);
    if (Path == NULL)
        goto fail1;

    status = RtlStringCbPrintfA(Path,
                                Length,
                                "%s/queue-%u",
                                __FrontendGetPath(Frontend),
                                Index);
    if (!NT_SUCCESS(status))
        goto fail2;

    return Path;

fail2:
    __FrontendFree(Path);

fail1:
    return NULL;
}

VOID
FrontendFreePath(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  PCHAR               Path
    )
{
    UNREFERENCED_PARAMETER(Frontend);

    __FrontendFree(Path);
}

#define DEFINE_FRONTEND_GET_FUNCTION(_Function, _Type)  \
static FORCEINLINE _Type                                \
__FrontendGet ## _Function(                             \
    IN  PXENVIF_FRONTEND    Frontend                    \
    )                                                   \
{                                                       \
    return Frontend-> ## _Function;                     \
}                                                       \
                                                        \
_Type                                                   \
FrontendGet ## _Function(                               \
    IN  PXENVIF_FRONTEND    Frontend                    \
    )                                                   \
{                                                       \
    return __FrontendGet ## _Function ## (Frontend);    \
}

DEFINE_FRONTEND_GET_FUNCTION(Mac, PXENVIF_MAC)
DEFINE_FRONTEND_GET_FUNCTION(Receiver, PXENVIF_RECEIVER)
DEFINE_FRONTEND_GET_FUNCTION(Transmitter, PXENVIF_TRANSMITTER)
DEFINE_FRONTEND_GET_FUNCTION(Controller, PXENVIF_CONTROLLER)

static BOOLEAN
FrontendIsOnline(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Online;
}

static BOOLEAN
FrontendIsBackendOnline(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    PCHAR                   Buffer;
    BOOLEAN                 Online;
    NTSTATUS                status;

    status = XENBUS_STORE(Read,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetBackendPath(Frontend),
                          "online",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Online = FALSE;
    } else {
        Online = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Frontend->StoreInterface,
                     Buffer);
    }

    return Online;
}

static DECLSPEC_NOINLINE NTSTATUS
FrontendEject(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_FRONTEND    Frontend = Context;
    PKEVENT             Event;

    Trace("%s: ====>\n", __FrontendGetPath(Frontend));

    Event = ThreadGetEvent(Self);

    for (;;) {
        KIRQL       Irql;

        KeWaitForSingleObject(Event,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        KeAcquireSpinLock(&Frontend->Lock, &Irql);

        // It is not safe to use interfaces before this point
        if (Frontend->State == FRONTEND_UNKNOWN ||
            Frontend->State == FRONTEND_CLOSED)
            goto loop;

        if (!FrontendIsOnline(Frontend))
            goto loop;

        if (!FrontendIsBackendOnline(Frontend))
            PdoRequestEject(__FrontendGetPdo(Frontend));

loop:
        KeReleaseSpinLock(&Frontend->Lock, Irql);

        KeSetEvent(&Frontend->EjectEvent, IO_NO_INCREMENT, FALSE);
    }

    KeSetEvent(&Frontend->EjectEvent, IO_NO_INCREMENT, FALSE);

    Trace("%s: <====\n", __FrontendGetPath(Frontend));

    return STATUS_SUCCESS;
}

VOID
FrontendEjectFailed(
    IN PXENVIF_FRONTEND Frontend
    )
{
    KIRQL               Irql;
    ULONG               Length;
    PCHAR               Path;
    NTSTATUS            status;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

    Info("%s: device eject failed\n", __FrontendGetPath(Frontend));

    Length = sizeof ("error/") + (ULONG)strlen(__FrontendGetPath(Frontend));
    Path = __FrontendAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Path == NULL)
        goto fail1;

    status = RtlStringCbPrintfA(Path, 
                                Length,
                                "error/%s", 
                                __FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail2;

    (VOID) XENBUS_STORE(Printf,
                        &Frontend->StoreInterface,
                        NULL,
                        Path,
                        "error",
                        "UNPLUG FAILED: device is still in use");

    __FrontendFree(Path);

    KeReleaseSpinLock(&Frontend->Lock, Irql);
    return;

fail2:
    Error("fail2\n");

    __FrontendFree(Path);

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Frontend->Lock, Irql);
}

static NTSTATUS
FrontendProcessInterfaceTable(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  PMIB_IF_TABLE2      Table
    )
{
    ETHERNET_ADDRESS        PermanentPhysicalAddress;
    ULONG                   Index;
    PMIB_IF_ROW2            Row;
    NTSTATUS                status;

    MacQueryPermanentAddress(__FrontendGetMac(Frontend),
                             &PermanentPhysicalAddress);

    for (Index = 0; Index < Table->NumEntries; Index++) {
        Row = &Table->Table[Index];

        if (!Row->InterfaceAndOperStatusFlags.ConnectorPresent)
            continue;

        if (Row->PhysicalAddressLength != sizeof (ETHERNET_ADDRESS))
            continue;

        if (memcmp(Row->PermanentPhysicalAddress,
                   &PermanentPhysicalAddress,
                   sizeof (ETHERNET_ADDRESS)) != 0)
            continue;

        if (Row->OperStatus != IfOperStatusUp)
            continue;

        goto found;
    }

    return STATUS_UNSUCCESSFUL;

found:
    Frontend->InterfaceIndex = Row->InterfaceIndex;

    status = RtlStringCbPrintfA(Frontend->Alias,
                                sizeof (Frontend->Alias),
                                "%ws",
                                Row->Alias);
    ASSERT(NT_SUCCESS(status));

    return STATUS_SUCCESS;
}

static NTSTATUS
FrontendInsertAddress(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  const SOCKADDR_INET *Address
    )
{
    ULONG                   Index;
    PSOCKADDR_INET          Table;
    NTSTATUS                status;

    Trace("====>\n");

    for (Index = 0; Index < Frontend->AddressCount; Index++) {
        if (Frontend->AddressTable[Index].si_family != Address->si_family)
            continue;

        if (Address->si_family == AF_INET) {
            if (RtlEqualMemory(&Address->Ipv4.sin_addr.s_addr,
                               &Frontend->AddressTable[Index].Ipv4.sin_addr.s_addr,
                                 IPV4_ADDRESS_LENGTH))
                goto done;
        } else {
            ASSERT3U(Address->si_family, ==, AF_INET6);

            if (RtlEqualMemory(&Address->Ipv6.sin6_addr.s6_addr,
                               &Frontend->AddressTable[Index].Ipv6.sin6_addr.s6_addr,
                               IPV6_ADDRESS_LENGTH))
                goto done;
        }
    }

    // We have an address we've not seen before so grow the table
    Table = __FrontendAllocate(sizeof (SOCKADDR_INET) * (Frontend->AddressCount + 1));

    status = STATUS_NO_MEMORY;
    if (Table == NULL)
        goto fail1;

    RtlCopyMemory(Table, Frontend->AddressTable, sizeof (SOCKADDR_INET) * Frontend->AddressCount);

    if (Frontend->AddressCount != 0)
        __FrontendFree(Frontend->AddressTable);

    Table[Frontend->AddressCount++] = *Address;
    Frontend->AddressTable = Table;

done:
    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
FrontendProcessAddressTable(
    IN  PXENVIF_FRONTEND            Frontend,
    IN  PMIB_UNICASTIPADDRESS_TABLE Table
    )
{
    ULONG                           Index;
    NTSTATUS                        status;

    UNREFERENCED_PARAMETER(Frontend);

    if (Frontend->AddressCount != 0) {
        __FrontendFree(Frontend->AddressTable);

        Frontend->AddressTable = NULL;
        Frontend->AddressCount = 0;
    }

    for (Index = 0; Index < Table->NumEntries; Index++) {
        PMIB_UNICASTIPADDRESS_ROW   Row = &Table->Table[Index];

        if (Row->InterfaceIndex != Frontend->InterfaceIndex)
            continue;

        if (Row->Address.si_family != AF_INET &&
            Row->Address.si_family != AF_INET6)
            continue;

        status = FrontendInsertAddress(Frontend, &Row->Address);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
FrontendDumpAlias(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    NTSTATUS                status;

    status = XENBUS_STORE(Remove,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetPrefix(Frontend),
                          "name");
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND)
        goto fail1;

    status = XENBUS_STORE(Printf,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetPrefix(Frontend),
                          "name",
                          "%s",
                          Frontend->Alias);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
FrontendDumpAddressTable(
    IN  PXENVIF_FRONTEND        Frontend
    )
{
    PXENBUS_STORE_TRANSACTION   Transaction;
    ULONG                       Index;
    ULONG                       IpVersion4Count;
    ULONG                       IpVersion6Count;
    NTSTATUS                    status;

    Trace("====>\n");

    status = XENBUS_STORE(TransactionStart,
                          &Frontend->StoreInterface,
                          &Transaction);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Remove,
                          &Frontend->StoreInterface,
                          Transaction,
                          __FrontendGetPrefix(Frontend),
                          "ipv4");
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND)
        goto fail2;

    status = XENBUS_STORE(Remove,
                          &Frontend->StoreInterface,
                          Transaction,
                          __FrontendGetPrefix(Frontend),
                          "ipv6");
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND)
        goto fail3;

    IpVersion4Count = 0;
    IpVersion6Count = 0;

    for (Index = 0; Index < Frontend->AddressCount; Index++) {
        switch (Frontend->AddressTable[Index].si_family) {
        case AF_INET: {
            IPV4_ADDRESS    Address;
            CHAR            Node[sizeof ("ipv4/XXXXXXXX")];

            RtlCopyMemory(Address.Byte,
                          &Frontend->AddressTable[Index].Ipv4.sin_addr.s_addr,
                          IPV4_ADDRESS_LENGTH);

            status = RtlStringCbPrintfA(Node,
                                        sizeof (Node),
                                        "ipv4/%u",
                                        IpVersion4Count);
            ASSERT(NT_SUCCESS(status));

            status = XENBUS_STORE(Printf,
                                  &Frontend->StoreInterface,
                                  Transaction,
                                  __FrontendGetPrefix(Frontend),
                                  Node,
                                  "%u.%u.%u.%u",
                                  Address.Byte[0],
                                  Address.Byte[1],
                                  Address.Byte[2],
                                  Address.Byte[3]);
            if (!NT_SUCCESS(status))
                goto fail4;

            IpVersion4Count++;
            break;
        }
        case AF_INET6: {
            IPV6_ADDRESS    Address;
            CHAR            Node[sizeof ("ipv6/XXXXXXXX")];

            RtlCopyMemory(Address.Byte,
                          &Frontend->AddressTable[Index].Ipv6.sin6_addr.s6_addr,
                          IPV6_ADDRESS_LENGTH);

            status = RtlStringCbPrintfA(Node,
                                        sizeof (Node),
                                        "ipv6/%u",
                                        IpVersion6Count);
            ASSERT(NT_SUCCESS(status));

            status = XENBUS_STORE(Printf,
                                  &Frontend->StoreInterface,
                                  Transaction,
                                  __FrontendGetPrefix(Frontend),
                                  Node,
                                  "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                                  NTOHS(Address.Word[0]),
                                  NTOHS(Address.Word[1]),
                                  NTOHS(Address.Word[2]),
                                  NTOHS(Address.Word[3]),
                                  NTOHS(Address.Word[4]),
                                  NTOHS(Address.Word[5]),
                                  NTOHS(Address.Word[6]),
                                  NTOHS(Address.Word[7]));
            if (!NT_SUCCESS(status))
                goto fail4;

            IpVersion6Count++;
            break;
        }
        default:
            break;
        }
    }

    status = XENBUS_STORE(TransactionEnd,
                          &Frontend->StoreInterface,
                          Transaction,
                          TRUE);

    Trace("<====\n");

    return status;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    (VOID) XENBUS_STORE(TransactionEnd,
                        &Frontend->StoreInterface,
                        Transaction,
                        FALSE);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
FrontendIpAddressChange(
    IN  PVOID                       Context,
    IN  PMIB_UNICASTIPADDRESS_ROW   Row OPTIONAL,
    IN  MIB_NOTIFICATION_TYPE       NotificationType
    )
{
    PXENVIF_FRONTEND                Frontend = Context;

    UNREFERENCED_PARAMETER(Row);
    UNREFERENCED_PARAMETER(NotificationType);

    ThreadWake(Frontend->MibThread);
}

static DECLSPEC_NOINLINE NTSTATUS
FrontendMib(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_FRONTEND    Frontend = Context;
    PKEVENT             Event;
    NTSTATUS            (*__GetIfTable2)(PMIB_IF_TABLE2 *);
    NTSTATUS            (*__NotifyUnicastIpAddressChange)(ADDRESS_FAMILY,
                                                          PUNICAST_IPADDRESS_CHANGE_CALLBACK,
                                                          PVOID,    
                                                          BOOLEAN,
                                                          HANDLE *);
    NTSTATUS            (*__GetUnicastIpAddressTable)(ADDRESS_FAMILY,
                                                      PMIB_UNICASTIPADDRESS_TABLE *);

    VOID                (*__FreeMibTable)(PVOID);
    NTSTATUS            (*__CancelMibChangeNotify2)(HANDLE);
    HANDLE              Handle;
    NTSTATUS            status;

    Trace("====>\n");

    status = LinkGetRoutineAddress("netio.sys",
                                   "GetIfTable2",
                                   (PVOID *)&__GetIfTable2);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = LinkGetRoutineAddress("netio.sys",
                                   "NotifyUnicastIpAddressChange",
                                   (PVOID *)&__NotifyUnicastIpAddressChange);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = LinkGetRoutineAddress("netio.sys",
                                   "GetUnicastIpAddressTable",
                                   (PVOID *)&__GetUnicastIpAddressTable);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = LinkGetRoutineAddress("netio.sys",
                                   "FreeMibTable",
                                   (PVOID *)&__FreeMibTable);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = LinkGetRoutineAddress("netio.sys",
                                   "CancelMibChangeNotify2",
                                   (PVOID *)&__CancelMibChangeNotify2);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = __NotifyUnicastIpAddressChange(AF_UNSPEC,
                                            FrontendIpAddressChange,
                                            Frontend,
                                            TRUE,
                                            &Handle);
    if (!NT_SUCCESS(status))
        goto fail6;

    Event = ThreadGetEvent(Self);

    for (;;) { 
        PMIB_IF_TABLE2              IfTable;
        PMIB_UNICASTIPADDRESS_TABLE UnicastIpAddressTable;
        KIRQL                       Irql;

        Trace("waiting...\n");

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        Trace("awake\n");

        if (ThreadIsAlerted(Self))
            break;

        IfTable = NULL;
        UnicastIpAddressTable = NULL;

        status = __GetIfTable2(&IfTable);
        if (!NT_SUCCESS(status))
            goto loop;

        status = FrontendProcessInterfaceTable(Frontend,
                                               IfTable);
        if (!NT_SUCCESS(status))
            goto loop;

        status = __GetUnicastIpAddressTable(AF_UNSPEC,
                                            &UnicastIpAddressTable);
        if (!NT_SUCCESS(status))
            goto loop;

        status = FrontendProcessAddressTable(Frontend,
                                             UnicastIpAddressTable);
        if (!NT_SUCCESS(status))
            goto loop;

        KeAcquireSpinLock(&Frontend->Lock, &Irql);

        if (Frontend->State == FRONTEND_CONNECTED ||
            Frontend->State == FRONTEND_ENABLED) {
            (VOID) FrontendDumpAlias(Frontend);
            (VOID) FrontendDumpAddressTable(Frontend);
        }

        KeReleaseSpinLock(&Frontend->Lock, Irql);

loop:
        if (UnicastIpAddressTable != NULL)
            __FreeMibTable(UnicastIpAddressTable);

        if (IfTable != NULL)
            __FreeMibTable(IfTable);
    }

    if (Frontend->AddressCount != 0) {
        __FrontendFree(Frontend->AddressTable);

        Frontend->AddressTable = NULL;
        Frontend->AddressCount = 0;
    }

    status = __CancelMibChangeNotify2(Handle);
    ASSERT(NT_SUCCESS(status));

    Trace("<====\n");

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

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

    return status;
}

NTSTATUS
FrontendSetMulticastAddresses(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  PETHERNET_ADDRESS   Address,
    IN  ULONG               Count
    )
{
    PXENVIF_TRANSMITTER     Transmitter;
    PXENVIF_MAC             Mac;
    KIRQL                   Irql;
    PETHERNET_ADDRESS       MulticastAddress;
    ULONG                   MulticastCount;
    ULONG                   MulticastIndex;
    ULONG                   Index;
    NTSTATUS                status;

    Transmitter = FrontendGetTransmitter(Frontend);
    Mac = FrontendGetMac(Frontend);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    status = MacQueryMulticastAddresses(Mac, NULL, &MulticastCount);
    ASSERT3U(status, ==, STATUS_BUFFER_OVERFLOW);

    if (MulticastCount != 0) {
        MulticastAddress = __FrontendAllocate(sizeof (ETHERNET_ADDRESS) *
                                              MulticastCount);

        status = STATUS_NO_MEMORY;
        if (MulticastAddress == NULL)
            goto fail1;

        status = MacQueryMulticastAddresses(Mac,
                                            MulticastAddress,
                                            &MulticastCount);
        if (!NT_SUCCESS(status))
            goto fail2;
    } else
        MulticastAddress = NULL;

    for (Index = 0; Index < Count; Index++) {
        BOOLEAN Found;

        ASSERT(Address[Index].Byte[0] & 0x01);

        Found = FALSE;

        // If the multicast address has already been added and it
        // appears in the updated list then we don't want to remove it.
        for (MulticastIndex = 0;
             MulticastIndex < MulticastCount;
             MulticastIndex++) {
            if (RtlEqualMemory(&Address[Index],
                               &MulticastAddress[MulticastIndex],
                               ETHERNET_ADDRESS_LENGTH)) {
                Found = TRUE;
                RtlZeroMemory(&MulticastAddress[MulticastIndex],
                              ETHERNET_ADDRESS_LENGTH);
                break;
            }
        }

        if (!Found) {
            (VOID) MacAddMulticastAddress(Mac, &Address[Index]);
            (VOID) TransmitterQueueMulticastControl(Transmitter,
                                                    &Address[Index],
                                                    TRUE);
        }
    }

    // Walk the multicast list removing any addresses not in the
    // updated list
    for (MulticastIndex = 0;
         MulticastIndex < MulticastCount;
         MulticastIndex++) {
        if (!(MulticastAddress[MulticastIndex].Byte[0] & 0x01))
            continue;

        (VOID) TransmitterQueueMulticastControl(Transmitter,
                                                &MulticastAddress[MulticastIndex],
                                                FALSE);
        (VOID) MacRemoveMulticastAddress(Mac,
                                         &MulticastAddress[MulticastIndex]);
    }

    if (MulticastAddress != NULL)
        __FrontendFree(MulticastAddress);

    KeLowerIrql(Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __FrontendFree(MulticastAddress);

fail1:
    Error("fail1 (%08x)\n", status);

    KeLowerIrql(Irql);

    return status;
}

static NTSTATUS
FrontendNotifyMulticastAddresses(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  BOOLEAN             Add
    )
{
    PXENVIF_TRANSMITTER     Transmitter;
    PXENVIF_MAC             Mac;
    PETHERNET_ADDRESS       Address;
    ULONG                   Count;
    ULONG                   Index;
    NTSTATUS                status;

    Transmitter = FrontendGetTransmitter(Frontend);
    Mac = FrontendGetMac(Frontend);

    status = MacQueryMulticastAddresses(Mac, NULL, &Count);
    ASSERT3U(status, ==, STATUS_BUFFER_OVERFLOW);

    if (Count != 0) {
        Address = __FrontendAllocate(sizeof (ETHERNET_ADDRESS) *
                                     Count);

        status = STATUS_NO_MEMORY;
        if (Address == NULL)
            goto fail1;

        status = MacQueryMulticastAddresses(Mac, Address, &Count);
        if (!NT_SUCCESS(status))
            goto fail2;
    } else
        Address = NULL;

    for (Index = 0; Index < Count; Index++)
        (VOID) TransmitterQueueMulticastControl(Transmitter,
                                                &Address[Index],
                                                Add);

    if (Address != NULL)
        __FrontendFree(Address);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __FrontendFree(Address);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
FrontendSetFilterLevel(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  ETHERNET_ADDRESS_TYPE   Type,
    IN  XENVIF_MAC_FILTER_LEVEL Level
    )
{
    PXENVIF_MAC                 Mac;
    KIRQL                       Irql;
    NTSTATUS                    status;

    Mac = FrontendGetMac(Frontend);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    status = MacSetFilterLevel(Mac, Type, Level);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (Type == ETHERNET_ADDRESS_MULTICAST) {
        PXENVIF_TRANSMITTER Transmitter;
        BOOLEAN             Enabled;

        Transmitter = FrontendGetTransmitter(Frontend);
        Enabled = (Level != XENVIF_MAC_FILTER_ALL) ? TRUE : FALSE;

        (VOID) TransmitterRequestMulticastControl(Transmitter, Enabled);
    }

    KeLowerIrql(Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    KeLowerIrql(Irql);

    return status;
}

VOID
FrontendAdvertiseIpAddresses(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    PXENVIF_TRANSMITTER     Transmitter;
    KIRQL                   Irql;
    ULONG                   Index;

    Transmitter = FrontendGetTransmitter(Frontend);

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

    for (Index = 0; Index < Frontend->AddressCount; Index++) {
        switch (Frontend->AddressTable[Index].si_family) {
        case AF_INET: {
            IPV4_ADDRESS    Address;

            RtlCopyMemory(Address.Byte,
                          &Frontend->AddressTable[Index].Ipv4.sin_addr.s_addr,
                          IPV4_ADDRESS_LENGTH);

            TransmitterQueueArp(Transmitter, &Address);
            break;
        }
        case AF_INET6: {
            IPV6_ADDRESS    Address;

            RtlCopyMemory(Address.Byte,
                          &Frontend->AddressTable[Index].Ipv6.sin6_addr.s6_addr,
                          IPV6_ADDRESS_LENGTH);

            TransmitterQueueNeighbourAdvertisement(Transmitter, &Address);
            break;
        }
        default:
            ASSERT(FALSE);
        }
    }

    KeReleaseSpinLock(&Frontend->Lock, Irql);
}

static VOID
FrontendSetOnline(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    Trace("====>\n");

    Frontend->Online = TRUE;

    Trace("<====\n");
}

static VOID
FrontendSetOffline(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    Trace("====>\n");

    Frontend->Online = FALSE;
    PdoRequestEject(__FrontendGetPdo(Frontend));

    Trace("<====\n");
}

static VOID
FrontendSetXenbusState(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  XenbusState         State
    )
{
    BOOLEAN                 Online;

    Trace("%s: ====> %s\n",
          __FrontendGetPath(Frontend),
          XenbusStateName(State));

    ASSERT(FrontendIsOnline(Frontend));

    Online = FrontendIsBackendOnline(Frontend);

    (VOID) XENBUS_STORE(Printf,
                        &Frontend->StoreInterface,
                        NULL,
                        __FrontendGetPath(Frontend),
                        "state",
                        "%u",
                        State);

    if (State == XenbusStateClosed && !Online)
        FrontendSetOffline(Frontend);

    Trace("%s: <==== %s\n",
          __FrontendGetPath(Frontend),
          XenbusStateName(State));
}

static NTSTATUS
FrontendAcquireBackend(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    PCHAR                   Buffer;
    NTSTATUS                status;

    Trace("=====>\n");

    status = XENBUS_STORE(Read,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetPath(Frontend),
                          "backend",
                          &Buffer);
    if (!NT_SUCCESS(status))
        goto fail1;

    Frontend->BackendPath = Buffer;

    status = XENBUS_STORE(Read,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetPath(Frontend),
                          "backend-id",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Frontend->BackendDomain = 0;
    } else {
        Frontend->BackendDomain = (USHORT)strtol(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Frontend->StoreInterface,
                     Buffer);
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    Trace("<====\n");
    return status;
}

static VOID
FrontendWaitForBackendXenbusStateChange(
    IN      PXENVIF_FRONTEND    Frontend,
    IN OUT  XenbusState         *State
    )
{
    KEVENT                      Event;
    PXENBUS_STORE_WATCH         Watch;
    LARGE_INTEGER               Start;
    ULONGLONG                   TimeDelta;
    LARGE_INTEGER               Timeout;
    XenbusState                 Old = *State;
    NTSTATUS                    status;

    Trace("%s: ====> %s\n",
          __FrontendGetBackendPath(Frontend),
          XenbusStateName(*State));

    ASSERT(FrontendIsOnline(Frontend));

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = XENBUS_STORE(WatchAdd,
                          &Frontend->StoreInterface,
                          __FrontendGetBackendPath(Frontend),
                          "state",
                          &Event,
                          &Watch);
    if (!NT_SUCCESS(status))
        Watch = NULL;

    KeQuerySystemTime(&Start);
    TimeDelta = 0;

    Timeout.QuadPart = 0;

    while (*State == Old && TimeDelta < 120000) {
        PCHAR           Buffer;
        LARGE_INTEGER   Now;

        if (Watch != NULL) {
            ULONG   Attempt = 0;

            while (++Attempt < 1000) {
                status = KeWaitForSingleObject(&Event,
                                               Executive,
                                               KernelMode,
                                               FALSE,
                                               &Timeout);
                if (status != STATUS_TIMEOUT)
                    break;

                // We are waiting for a watch event at DISPATCH_LEVEL so
                // it is our responsibility to poll the store ring.
                XENBUS_STORE(Poll,
                             &Frontend->StoreInterface);

                KeStallExecutionProcessor(1000);   // 1ms
            }

            KeClearEvent(&Event);
        }

        status = XENBUS_STORE(Read,
                              &Frontend->StoreInterface,
                              NULL,
                              __FrontendGetBackendPath(Frontend),
                              "state",
                              &Buffer);
        if (!NT_SUCCESS(status)) {
            *State = XenbusStateUnknown;
        } else {
            *State = (XenbusState)strtol(Buffer, NULL, 10);

            XENBUS_STORE(Free,
                         &Frontend->StoreInterface,
                         Buffer);
        }

        KeQuerySystemTime(&Now);

        TimeDelta = (Now.QuadPart - Start.QuadPart) / 10000ull;
    }

    if (Watch != NULL)
        (VOID) XENBUS_STORE(WatchRemove,
                            &Frontend->StoreInterface,
                            Watch);

    Trace("%s: <==== (%s)\n",
          __FrontendGetBackendPath(Frontend),
          XenbusStateName(*State));
}

static VOID
FrontendReleaseBackend(
    IN      PXENVIF_FRONTEND    Frontend
    )
{
    Trace("=====>\n");

    ASSERT(Frontend->BackendDomain != DOMID_INVALID);
    ASSERT(Frontend->BackendPath != NULL);

    Frontend->BackendDomain = DOMID_INVALID;

    XENBUS_STORE(Free,
                 &Frontend->StoreInterface,
                 Frontend->BackendPath);
    Frontend->BackendPath = NULL;

    Trace("<=====\n");
}

static VOID
FrontendClose(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    XenbusState             State;

    Trace("====>\n");

    ASSERT(Frontend->Watch != NULL);
    (VOID) XENBUS_STORE(WatchRemove,
                        &Frontend->StoreInterface,
                        Frontend->Watch);
    Frontend->Watch = NULL;

    State = XenbusStateUnknown;
    while (State != XenbusStateClosed) {
        if (!FrontendIsOnline(Frontend))
            break;

        FrontendWaitForBackendXenbusStateChange(Frontend,
                                                &State);

        switch (State) {
        case XenbusStateUnknown:
            FrontendSetOffline(Frontend);
            break;

        case XenbusStateConnected:
        case XenbusStateInitWait:
            FrontendSetXenbusState(Frontend,
                                   XenbusStateClosing);
            break;

        case XenbusStateClosing:
            FrontendSetXenbusState(Frontend,
                                   XenbusStateClosed);
            break;

        case XenbusStateClosed:
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    FrontendReleaseBackend(Frontend);

    (VOID) XENBUS_STORE(Remove,
                        &Frontend->StoreInterface,
                        NULL,
                        NULL,
                        __FrontendGetPrefix(Frontend));

    XENBUS_STORE(Release, &Frontend->StoreInterface);

    Trace("<====\n");
}

static NTSTATUS
FrontendPrepare(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    XenbusState             State;
    NTSTATUS                status;

    Trace("====>\n");

    status = XENBUS_STORE(Acquire, &Frontend->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    FrontendSetOnline(Frontend);

    status = FrontendAcquireBackend(Frontend);
    if (!NT_SUCCESS(status))
        goto fail2;

    State = XenbusStateUnknown;
    while (State != XenbusStateInitWait) {
        if (!FrontendIsOnline(Frontend))
            break;

        FrontendWaitForBackendXenbusStateChange(Frontend,
                                                &State);

        status = STATUS_SUCCESS;
        switch (State) {
        case XenbusStateUnknown:
            FrontendSetOffline(Frontend);
            break;

        case XenbusStateClosed:
            FrontendSetXenbusState(Frontend,
                                   XenbusStateInitialising);
            break;

        case XenbusStateConnected:
            FrontendSetXenbusState(Frontend,
                                   XenbusStateClosing);
            break;

        case XenbusStateClosing:
            FrontendSetXenbusState(Frontend,
                                   XenbusStateClosed);
            break;

        case XenbusStateInitialising:
        case XenbusStateInitWait:
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateInitWait)
        goto fail3;

    status = XENBUS_STORE(WatchAdd,
                          &Frontend->StoreInterface,
                          __FrontendGetBackendPath(Frontend),
                          "online",
                          ThreadGetEvent(Frontend->EjectThread),
                          &Frontend->Watch);
    if (!NT_SUCCESS(status))
        goto fail4;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    FrontendReleaseBackend(Frontend);

fail2:
    Error("fail2\n");

    FrontendSetOffline(Frontend);

    XENBUS_STORE(Release, &Frontend->StoreInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    Trace("<====\n");
    return status;
}

static FORCEINLINE VOID
__FrontendQueryStatistic(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_VIF_STATISTIC    Name,
    OUT PULONGLONG              Value
    )
{
    ULONG                       Index;

    ASSERT(Name < XENVIF_VIF_STATISTIC_COUNT);

    *Value = 0;
    for (Index = 0; Index < Frontend->StatisticsCount; Index++) {
        PXENVIF_FRONTEND_STATISTICS Statistics;

        Statistics = &Frontend->Statistics[Index];
        *Value += Statistics->Value[Name];
    }
}

VOID
FrontendQueryStatistic(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_VIF_STATISTIC    Name,
    OUT PULONGLONG              Value
    )
{
    __FrontendQueryStatistic(Frontend, Name, Value);
}

VOID
FrontendIncrementStatistic(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_VIF_STATISTIC    Name,
    IN  ULONGLONG               Delta
    )
{
    ULONG                       Index;
    PXENVIF_FRONTEND_STATISTICS Statistics;
    KIRQL                       Irql;

    ASSERT(Name < XENVIF_VIF_STATISTIC_COUNT);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    Index = KeGetCurrentProcessorNumberEx(NULL);

    ASSERT3U(Index, <, Frontend->StatisticsCount);
    Statistics = &Frontend->Statistics[Index];

    Statistics->Value[Name] += Delta;

    KeLowerIrql(Irql);
}

static FORCEINLINE const CHAR *
__FrontendStatisticName(
    IN  XENVIF_VIF_STATISTIC    Name
    )
{
#define _FRONTEND_STATISTIC_NAME(_Name)     \
    case XENVIF_ ## _Name:                  \
        return #_Name;

    switch (Name) {
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_PACKETS_DROPPED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_BACKEND_ERRORS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_FRONTEND_ERRORS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_UNICAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_UNICAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_MULTICAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_MULTICAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_BROADCAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_BROADCAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_PACKETS_DROPPED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_BACKEND_ERRORS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_FRONTEND_ERRORS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_UNICAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_UNICAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_MULTICAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_MULTICAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_BROADCAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_BROADCAST_OCTETS);

    _FRONTEND_STATISTIC_NAME(TRANSMITTER_TAGGED_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_LLC_SNAP_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_IPV4_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_IPV6_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_TCP_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_UDP_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_GSO_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_IPV4_CHECKSUM_SUCCEEDED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_IPV4_CHECKSUM_FAILED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_IPV4_CHECKSUM_NOT_VALIDATED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_TCP_CHECKSUM_SUCCEEDED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_TCP_CHECKSUM_FAILED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_TCP_CHECKSUM_NOT_VALIDATED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_UDP_CHECKSUM_SUCCEEDED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_UDP_CHECKSUM_FAILED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_UDP_CHECKSUM_NOT_VALIDATED);

    _FRONTEND_STATISTIC_NAME(RECEIVER_TAGGED_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_LLC_SNAP_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_IPV4_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_IPV6_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_TCP_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_UDP_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_GSO_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_IPV4_CHECKSUM_SUCCEEDED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_IPV4_CHECKSUM_FAILED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_IPV4_CHECKSUM_NOT_VALIDATED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_TCP_CHECKSUM_SUCCEEDED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_TCP_CHECKSUM_FAILED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_TCP_CHECKSUM_NOT_VALIDATED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_UDP_CHECKSUM_SUCCEEDED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_UDP_CHECKSUM_FAILED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_UDP_CHECKSUM_NOT_VALIDATED);

    default:
        break;
    }

    return "UNKNOWN";

#undef  _FRONTEND_STATISTIC_NAME
}

static VOID
FrontendDebugCallback(
    IN  PVOID               Argument,
    IN  BOOLEAN             Crashing
    )
{
    PXENVIF_FRONTEND        Frontend = Argument;
    XENVIF_VIF_STATISTIC    Name;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Frontend->DebugInterface,
                 "PATH: %s\n",
                 __FrontendGetPath(Frontend));

    XENBUS_DEBUG(Printf,
                 &Frontend->DebugInterface,
                 "STATISTICS:\n");

    for (Name = 0; Name < XENVIF_VIF_STATISTIC_COUNT; Name++) {
        ULONGLONG   Value;

        __FrontendQueryStatistic(Frontend, Name, &Value);

        XENBUS_DEBUG(Printf,
                     &Frontend->DebugInterface,
                     " - %40s %llu\n",
                     __FrontendStatisticName(Name),
                     Value);
    }
}

static VOID
FrontendSetNumQueues(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    PCHAR                   Buffer;
    ULONG                   BackendMaxQueues;
    NTSTATUS                status;

    status = XENBUS_STORE(Read,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetBackendPath(Frontend),
                          "multi-queue-max-queues",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        BackendMaxQueues = (ULONG)strtoul(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Frontend->StoreInterface,
                     Buffer);
    } else {
        BackendMaxQueues = 1;
    }

    Frontend->NumQueues = __min(__FrontendGetMaxQueues(Frontend),
                                BackendMaxQueues);

    Info("%s: %u\n", __FrontendGetPath(Frontend), Frontend->NumQueues);
}

static FORCEINLINE ULONG
__FrontendGetNumQueues(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->NumQueues;
}

ULONG
FrontendGetNumQueues(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetNumQueues(Frontend);
}

static VOID
FrontendSetSplit(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    PCHAR                   Buffer;
    NTSTATUS                status;

    status = XENBUS_STORE(Read,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetBackendPath(Frontend),
                          "feature-split-event-channels",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Frontend->Split = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Frontend->StoreInterface,
                     Buffer);
    } else {
        Frontend->Split = FALSE;
    }

    Info("%s: %s\n", __FrontendGetPath(Frontend),
         (Frontend->Split) ? "TRUE" : "FALSE");
}

static FORCEINLINE BOOLEAN
__FrontendIsSplit(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Split;
}

BOOLEAN
FrontendIsSplit(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendIsSplit(Frontend);
}

static FORCEINLINE NTSTATUS
__FrontendUpdateHash(
    PXENVIF_FRONTEND        Frontend,
    PXENVIF_FRONTEND_HASH   Hash
    )
{
    PXENVIF_CONTROLLER      Controller;
    ULONG                   Zero = 0;
    ULONG                   Size;
    PULONG                  Mapping;
    ULONG                   Flags;
    NTSTATUS                status;

    Controller = __FrontendGetController(Frontend);

    switch (Hash->Algorithm) {
    case XENVIF_PACKET_HASH_ALGORITHM_NONE:
        Size = 1;
        Mapping = &Zero;
        Flags = 0;
        break;

    case XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ:
        Size = Hash->Size;
        Mapping = Hash->Mapping;
        Flags = Hash->Flags;
        break;

    case XENVIF_PACKET_HASH_ALGORITHM_UNSPECIFIED:
    default:
        (VOID) ControllerSetHashAlgorithm(Controller,
                                          XEN_NETIF_CTRL_HASH_ALGORITHM_NONE);
        goto done;
    }

    status = ControllerSetHashAlgorithm(Controller,
                                        XEN_NETIF_CTRL_HASH_ALGORITHM_TOEPLITZ);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = ControllerSetHashMappingSize(Controller, Size);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = ControllerSetHashMapping(Controller, Mapping, Size, 0);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ControllerSetHashKey(Controller, Hash->Key, XENVIF_VIF_HASH_KEY_SIZE);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = ControllerSetHashFlags(Controller, Flags);
    if (!NT_SUCCESS(status))
        goto fail5;

done:
    return STATUS_SUCCESS;

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

    return status;
}

NTSTATUS
FrontendSetHashAlgorithm(
    IN  PXENVIF_FRONTEND                Frontend,
    IN  XENVIF_PACKET_HASH_ALGORITHM    Algorithm
    )
{
    XENVIF_FRONTEND_HASH                Hash;
    KIRQL                               Irql;
    NTSTATUS                            status;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

    switch (Algorithm) {
    case XENVIF_PACKET_HASH_ALGORITHM_NONE:
    case XENVIF_PACKET_HASH_ALGORITHM_UNSPECIFIED:
        status = STATUS_SUCCESS;
        break;

    case XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ:
        // Don't allow toeplitz hashing to be configured for a single
        // queue, or if it has been explicitly disabled
        ASSERT(__FrontendGetNumQueues(Frontend) != 0);
        status = (__FrontendGetNumQueues(Frontend) == 1 ||
                  Frontend->DisableToeplitz != 0) ?
                 STATUS_NOT_SUPPORTED :
                 STATUS_SUCCESS;
        break;

    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    if (!NT_SUCCESS(status))
        goto fail1;

    Info("%s: %s\n", __FrontendGetPath(Frontend),
         (Algorithm == XENVIF_PACKET_HASH_ALGORITHM_NONE) ? "NONE" :
         (Algorithm == XENVIF_PACKET_HASH_ALGORITHM_UNSPECIFIED) ? "UNSPECIFIED" :
         (Algorithm == XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ) ? "TOEPLITZ" :
         "");

    Hash = Frontend->Hash;

    Hash.Algorithm = Algorithm;

    status = __FrontendUpdateHash(Frontend, &Hash);
    if (!NT_SUCCESS(status))
        goto fail2;

    Frontend->Hash = Hash;

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return status;
}

NTSTATUS
FrontendQueryHashTypes(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PULONG              Types
    )
{
    KIRQL                   Irql;
    ULONG                   Flags;
    NTSTATUS                status;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

    status = ControllerGetHashFlags(__FrontendGetController(Frontend),
                                    &Flags);
    if (!NT_SUCCESS(status))
        goto fail1;

    *Types = 0;
    if (Flags & XEN_NETIF_CTRL_HASH_TYPE_IPV4)
        *Types |= 1 << XENVIF_PACKET_HASH_TYPE_IPV4;
    if (Flags & XEN_NETIF_CTRL_HASH_TYPE_IPV4_TCP)
        *Types |= 1 << XENVIF_PACKET_HASH_TYPE_IPV4_TCP;
    if (Flags & XEN_NETIF_CTRL_HASH_TYPE_IPV6)
        *Types |= 1 << XENVIF_PACKET_HASH_TYPE_IPV6;
    if (Flags & XEN_NETIF_CTRL_HASH_TYPE_IPV6_TCP)
        *Types |= 1 << XENVIF_PACKET_HASH_TYPE_IPV6_TCP;

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return status;
}

NTSTATUS
FrontendSetHashMapping(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  PULONG              Mapping,
    IN  ULONG               Size
    )
{
    XENVIF_FRONTEND_HASH    Hash;
    KIRQL                   Irql;
    NTSTATUS                status;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

    status = STATUS_INVALID_PARAMETER;
    if (Size > XENVIF_FRONTEND_MAXIMUM_HASH_MAPPING_SIZE)
        goto fail1;

    Hash = Frontend->Hash;

    RtlCopyMemory(Hash.Mapping, Mapping, sizeof (ULONG) * Size);
    Hash.Size = Size;

    status = __FrontendUpdateHash(Frontend, &Hash);
    if (!NT_SUCCESS(status))
        goto fail2;

    Frontend->Hash = Hash;

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return status;
}

NTSTATUS
FrontendSetHashKey(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  PUCHAR              Key
    )
{
    XENVIF_FRONTEND_HASH    Hash;
    KIRQL                   Irql;
    NTSTATUS                status;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

    Hash = Frontend->Hash;

    RtlCopyMemory(Hash.Key, Key, XENVIF_VIF_HASH_KEY_SIZE);

    status = __FrontendUpdateHash(Frontend, &Hash);
    if (!NT_SUCCESS(status))
        goto fail1;

    Frontend->Hash = Hash;

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return status;
}

NTSTATUS
FrontendSetHashTypes(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  ULONG               Types
    )
{
    XENVIF_FRONTEND_HASH    Hash;
    KIRQL                   Irql;
    ULONG                   Flags;
    NTSTATUS                status;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

    Hash = Frontend->Hash;

    Flags = 0;
    if (Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV4))
        Flags |= XEN_NETIF_CTRL_HASH_TYPE_IPV4;
    if (Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV4_TCP))
        Flags |= XEN_NETIF_CTRL_HASH_TYPE_IPV4_TCP;
    if (Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV6))
        Flags |= XEN_NETIF_CTRL_HASH_TYPE_IPV6;
    if (Types & (1 << XENVIF_PACKET_HASH_TYPE_IPV6_TCP))
        Flags |= XEN_NETIF_CTRL_HASH_TYPE_IPV6_TCP;

    Hash.Flags = Flags;

    status = __FrontendUpdateHash(Frontend, &Hash);
    if (!NT_SUCCESS(status))
        goto fail1;

    Frontend->Hash = Hash;

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    return status;
}

ULONG
FrontendGetQueue(
    IN  PXENVIF_FRONTEND                Frontend,
    IN  XENVIF_PACKET_HASH_ALGORITHM    Algorithm,
    IN  ULONG                           Value
    )
{
    ULONG                               Queue;

    switch (Algorithm) {
    case XENVIF_PACKET_HASH_ALGORITHM_NONE:
    case XENVIF_PACKET_HASH_ALGORITHM_UNSPECIFIED:
        Queue = Value % __FrontendGetNumQueues(Frontend);
        break;

    case XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ:
        Queue = (Frontend->Hash.Size != 0) ?
                Frontend->Hash.Mapping[Value % Frontend->Hash.Size] :
                0;
        break;

    default:
        ASSERT(FALSE);
        Queue = 0;
        break;
    }

    return Queue;
}

static NTSTATUS
FrontendConnect(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    XenbusState             State;
    ULONG                   Attempt;
    NTSTATUS                status;

    Trace("====>\n");

    status = XENBUS_DEBUG(Acquire, &Frontend->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Register,
                          &Frontend->DebugInterface,
                          __MODULE__ "|FRONTEND",
                          FrontendDebugCallback,
                          Frontend,
                          &Frontend->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = MacConnect(__FrontendGetMac(Frontend));
    if (!NT_SUCCESS(status))
        goto fail3;

    FrontendSetNumQueues(Frontend);
    FrontendSetSplit(Frontend);

    status = ReceiverConnect(__FrontendGetReceiver(Frontend));
    if (!NT_SUCCESS(status))
        goto fail4;

    status = TransmitterConnect(__FrontendGetTransmitter(Frontend));
    if (!NT_SUCCESS(status))
        goto fail5;

    status = ControllerConnect(__FrontendGetController(Frontend));
    if (!NT_SUCCESS(status))
        goto fail6;

    Attempt = 0;
    do {
        PXENBUS_STORE_TRANSACTION   Transaction;

        status = XENBUS_STORE(TransactionStart,
                              &Frontend->StoreInterface,
                              &Transaction);
        if (!NT_SUCCESS(status))
            break;

        status = ReceiverStoreWrite(__FrontendGetReceiver(Frontend),
                                    Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = TransmitterStoreWrite(__FrontendGetTransmitter(Frontend),
                                       Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = ControllerStoreWrite(__FrontendGetController(Frontend),
                                      Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = XENBUS_STORE(Printf,
                              &Frontend->StoreInterface,
                              Transaction,
                              __FrontendGetPath(Frontend),
                              "multi-queue-num-queues",
                              "%u",
                              __FrontendGetNumQueues(Frontend));
        if (!NT_SUCCESS(status))
            goto abort;

        status = XENBUS_STORE(TransactionEnd,
                              &Frontend->StoreInterface,
                              Transaction,
                              TRUE);
        if (status != STATUS_RETRY || ++Attempt > 10)
            break;

        continue;

abort:
        (VOID) XENBUS_STORE(TransactionEnd,
                            &Frontend->StoreInterface,
                            Transaction,
                            FALSE);
        break;
    } while (status == STATUS_RETRY);

    if (!NT_SUCCESS(status))
        goto fail7;

    State = XenbusStateUnknown;
    while (State != XenbusStateConnected) {
        if (!FrontendIsOnline(Frontend))
            break;

        FrontendWaitForBackendXenbusStateChange(Frontend,
                                                &State);

        status = STATUS_SUCCESS;
        switch (State) {
        case XenbusStateUnknown:
            FrontendSetOffline(Frontend);
            break;

        case XenbusStateInitWait:
        case XenbusStateInitialised:
            FrontendSetXenbusState(Frontend,
                                   XenbusStateConnected);
            break;

        case XenbusStateClosing:
            FrontendSetXenbusState(Frontend,
                                   XenbusStateClosed);
            break;

        case XenbusStateConnected:
        case XenbusStateClosed:
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateConnected)
        goto fail8;

    ControllerEnable(__FrontendGetController(Frontend));

    ThreadWake(Frontend->MibThread);

    Trace("<====\n");
    return STATUS_SUCCESS;

fail8:
    Error("fail8\n");

fail7:
    Error("fail7\n");

    ControllerDisconnect(__FrontendGetController(Frontend));

fail6:
    Error("fail6\n");

    TransmitterDisconnect(__FrontendGetTransmitter(Frontend));

fail5:
    Error("fail5\n");

    ReceiverDisconnect(__FrontendGetReceiver(Frontend));

fail4:
    Error("fail4\n");

    MacDisconnect(__FrontendGetMac(Frontend));

    Frontend->Split = FALSE;
    Frontend->NumQueues = 0;

fail3:
    Error("fail3\n");

    XENBUS_DEBUG(Deregister,
                 &Frontend->DebugInterface,
                 Frontend->DebugCallback);
    Frontend->DebugCallback = NULL;

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Frontend->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    Trace("<====\n");
    return status;
}

static VOID
FrontendDisconnect(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    Trace("====>\n");

    ControllerDisable(__FrontendGetController(Frontend));

    ControllerDisconnect(__FrontendGetController(Frontend));
    TransmitterDisconnect(__FrontendGetTransmitter(Frontend));
    ReceiverDisconnect(__FrontendGetReceiver(Frontend));
    MacDisconnect(__FrontendGetMac(Frontend));

    Frontend->Split = FALSE;
    Frontend->NumQueues = 0;

    XENBUS_DEBUG(Deregister,
                 &Frontend->DebugInterface,
                 Frontend->DebugCallback);
    Frontend->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Frontend->DebugInterface);

    Trace("<====\n");
}

static NTSTATUS
FrontendEnable(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    NTSTATUS                status;

    Trace("====>\n");

    status = MacEnable(__FrontendGetMac(Frontend));
    if (!NT_SUCCESS(status))
        goto fail1;

    status = ReceiverEnable(__FrontendGetReceiver(Frontend));
    if (!NT_SUCCESS(status))
        goto fail2;

    status = TransmitterEnable(__FrontendGetTransmitter(Frontend));
    if (!NT_SUCCESS(status))
        goto fail3;

    status = __FrontendUpdateHash(Frontend, &Frontend->Hash);
    if (!NT_SUCCESS(status))
        goto fail4;

    (VOID) FrontendNotifyMulticastAddresses(Frontend, TRUE);

    Trace("<====\n");
    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    TransmitterDisable(__FrontendGetTransmitter(Frontend));

fail3:
    Error("fail3\n");

    ReceiverDisable(__FrontendGetReceiver(Frontend));

fail2:
    Error("fail2\n");

    MacDisable(__FrontendGetMac(Frontend));

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
FrontendDisable(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    Trace("====>\n");

    (VOID) FrontendNotifyMulticastAddresses(Frontend, FALSE);

    TransmitterDisable(__FrontendGetTransmitter(Frontend));
    ReceiverDisable(__FrontendGetReceiver(Frontend));
    MacDisable(__FrontendGetMac(Frontend));

    Trace("<====\n");
}

NTSTATUS
FrontendSetState(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_FRONTEND_STATE   State
    )
{
    BOOLEAN                     Failed;
    KIRQL                       Irql;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

    Info("%s: ====> '%s' -> '%s'\n",
         __FrontendGetPath(Frontend),
         FrontendStateName(Frontend->State),
         FrontendStateName(State));

    Failed = FALSE;
    while (Frontend->State != State && !Failed) {
        NTSTATUS    status;

        switch (Frontend->State) {
        case FRONTEND_UNKNOWN:
            switch (State) {
            case FRONTEND_CLOSED:
            case FRONTEND_PREPARED:
            case FRONTEND_CONNECTED:
            case FRONTEND_ENABLED:
                status = FrontendPrepare(Frontend);
                if (NT_SUCCESS(status)) {
                    Frontend->State = FRONTEND_PREPARED;
                } else {
                    Failed = TRUE;
                }
                break;

            default:
                ASSERT(FALSE);
                break;
            }
            break;

        case FRONTEND_CLOSED:
            switch (State) {
            case FRONTEND_PREPARED:
            case FRONTEND_CONNECTED:
            case FRONTEND_ENABLED:
                status = FrontendPrepare(Frontend);
                if (NT_SUCCESS(status)) {
                    Frontend->State = FRONTEND_PREPARED;
                } else {
                    Failed = TRUE;
                }
                break;

            case FRONTEND_UNKNOWN:
                Frontend->State = FRONTEND_UNKNOWN;
                break;

            default:
                ASSERT(FALSE);
                break;
            }
            break;

        case FRONTEND_PREPARED:
            switch (State) {
            case FRONTEND_CONNECTED:
            case FRONTEND_ENABLED:
                status = FrontendConnect(Frontend);
                if (NT_SUCCESS(status)) {
                    Frontend->State = FRONTEND_CONNECTED;
                } else {
                    FrontendClose(Frontend);
                    Frontend->State = FRONTEND_CLOSED;

                    Failed = TRUE;
                }
                break;

            case FRONTEND_CLOSED:
            case FRONTEND_UNKNOWN:
                FrontendClose(Frontend);
                Frontend->State = FRONTEND_CLOSED;
                break;

            default:
                ASSERT(FALSE);
                break;
            }
            break;

        case FRONTEND_CONNECTED:
            switch (State) {
            case FRONTEND_ENABLED:
                status = FrontendEnable(Frontend);
                if (NT_SUCCESS(status)) {
                    Frontend->State = FRONTEND_ENABLED;
                } else {
                    FrontendClose(Frontend);
                    Frontend->State = FRONTEND_CLOSED;

                    FrontendDisconnect(Frontend);
                    Failed = TRUE;
                }
                break;

            case FRONTEND_PREPARED:
            case FRONTEND_CLOSED:
            case FRONTEND_UNKNOWN:
                FrontendClose(Frontend);
                Frontend->State = FRONTEND_CLOSED;

                FrontendDisconnect(Frontend);
                break;

            default:
                ASSERT(FALSE);
                break;
            }
            break;

        case FRONTEND_ENABLED:
            switch (State) {
            case FRONTEND_CONNECTED:
            case FRONTEND_PREPARED:
            case FRONTEND_CLOSED:
            case FRONTEND_UNKNOWN:
                FrontendDisable(Frontend);
                Frontend->State = FRONTEND_CONNECTED;
                break;

            default:
                ASSERT(FALSE);
                break;
            }
            break;

        default:
            ASSERT(FALSE);
            break;
        }

        Info("%s in state '%s'\n",
             __FrontendGetPath(Frontend),
             FrontendStateName(Frontend->State));
    }

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    Info("%s: <=====\n", __FrontendGetPath(Frontend));

    return (!Failed) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static FORCEINLINE VOID
__FrontendResume(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    ASSERT3U(Frontend->State, ==, FRONTEND_UNKNOWN);
    (VOID) FrontendSetState(Frontend, FRONTEND_CLOSED);
}

static FORCEINLINE VOID
__FrontendSuspend(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    (VOID) FrontendSetState(Frontend, FRONTEND_UNKNOWN);
}

static DECLSPEC_NOINLINE VOID
FrontendSuspendCallbackEarly(
    IN  PVOID           Argument
    )
{
    PXENVIF_FRONTEND    Frontend = Argument;

    Frontend->Online = FALSE;
}

static DECLSPEC_NOINLINE VOID
FrontendSuspendCallbackLate(
    IN  PVOID           Argument
    )
{
    PXENVIF_FRONTEND    Frontend = Argument;

    __FrontendSuspend(Frontend);
    __FrontendResume(Frontend);
}

NTSTATUS
FrontendResume(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    KIRQL                   Irql;
    NTSTATUS                status;

    Trace("====>\n");

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    status = XENBUS_SUSPEND(Acquire, &Frontend->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    __FrontendResume(Frontend);

    status = XENBUS_SUSPEND(Register,
                            &Frontend->SuspendInterface,
                            SUSPEND_CALLBACK_EARLY,
                            FrontendSuspendCallbackEarly,
                            Frontend,
                            &Frontend->SuspendCallbackEarly);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_SUSPEND(Register,
                            &Frontend->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            FrontendSuspendCallbackLate,
                            Frontend,
                            &Frontend->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail3;

    KeLowerIrql(Irql);

    KeClearEvent(&Frontend->EjectEvent);
    ThreadWake(Frontend->EjectThread);

    Trace("waiting for eject thread\n");

    (VOID) KeWaitForSingleObject(&Frontend->EjectEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    Trace("<====\n");

    return STATUS_SUCCESS;
    
fail3:
    Error("fail3\n");

    XENBUS_SUSPEND(Deregister,
                   &Frontend->SuspendInterface,
                   Frontend->SuspendCallbackEarly);
    Frontend->SuspendCallbackEarly = NULL;

fail2:
    Error("fail2\n");

    __FrontendSuspend(Frontend);

    XENBUS_SUSPEND(Release, &Frontend->SuspendInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    KeLowerIrql(Irql);

    return status;
}

VOID
FrontendSuspend(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    KIRQL                   Irql;

    Trace("====>\n");

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    XENBUS_SUSPEND(Deregister,
                   &Frontend->SuspendInterface,
                   Frontend->SuspendCallbackLate);
    Frontend->SuspendCallbackLate = NULL;

    XENBUS_SUSPEND(Deregister,
                   &Frontend->SuspendInterface,
                   Frontend->SuspendCallbackEarly);
    Frontend->SuspendCallbackEarly = NULL;

    __FrontendSuspend(Frontend);

    XENBUS_SUSPEND(Release, &Frontend->SuspendInterface);

    KeLowerIrql(Irql);

    KeClearEvent(&Frontend->EjectEvent);
    ThreadWake(Frontend->EjectThread);

    Trace("waiting for eject thread\n");

    (VOID) KeWaitForSingleObject(&Frontend->EjectEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    Trace("<====\n");
}

__drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS
FrontendInitialize(
    IN  PXENVIF_PDO         Pdo,
    OUT PXENVIF_FRONTEND    *Frontend
    )
{
    PCHAR                   Name;
    ULONG                   Length;
    PCHAR                   Path;
    PCHAR                   Prefix;
    HANDLE                  ParametersKey;
    ULONG                   FrontendDisableToeplitz;
    NTSTATUS                status;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Name = PdoGetName(Pdo);

    Length = sizeof ("devices/vif/") + (ULONG)strlen(Name);
    Path = __FrontendAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Path == NULL)
        goto fail1;

    status = RtlStringCbPrintfA(Path, 
                                Length,
                                "device/vif/%s", 
                                Name);
    if (!NT_SUCCESS(status))
        goto fail2;

    Length = sizeof ("attr/vif/") + (ULONG)strlen(Name);
    Prefix = __FrontendAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Prefix == NULL)
        goto fail3;

    status = RtlStringCbPrintfA(Prefix, 
                                Length,
                                "attr/vif/%s",
                                Name);
    if (!NT_SUCCESS(status))
        goto fail4;

    *Frontend = __FrontendAllocate(sizeof (XENVIF_FRONTEND));

    status = STATUS_NO_MEMORY;
    if (*Frontend == NULL)
        goto fail5;

    (*Frontend)->Pdo = Pdo;
    (*Frontend)->Path = Path;
    (*Frontend)->Prefix = Prefix;
    (*Frontend)->BackendDomain = DOMID_INVALID;

    KeInitializeSpinLock(&(*Frontend)->Lock);

    (*Frontend)->Online = TRUE;

    FdoGetDebugInterface(PdoGetFdo(Pdo), &(*Frontend)->DebugInterface);
    FdoGetSuspendInterface(PdoGetFdo(Pdo), &(*Frontend)->SuspendInterface);
    FdoGetStoreInterface(PdoGetFdo(Pdo), &(*Frontend)->StoreInterface);

    FrontendSetMaxQueues(*Frontend);
    (*Frontend)->Hash.Algorithm = XENVIF_PACKET_HASH_ALGORITHM_UNSPECIFIED;

    (*Frontend)->DisableToeplitz = 0;

    ParametersKey = DriverGetParametersKey();

    status = RegistryQueryDwordValue(ParametersKey,
                                     "FrontendDisableToeplitz",
                                     &FrontendDisableToeplitz);
    if (NT_SUCCESS(status))
        (*Frontend)->DisableToeplitz = FrontendDisableToeplitz;

    status = MacInitialize(*Frontend, &(*Frontend)->Mac);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = ReceiverInitialize(*Frontend, &(*Frontend)->Receiver);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = TransmitterInitialize(*Frontend, &(*Frontend)->Transmitter);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = ControllerInitialize(*Frontend, &(*Frontend)->Controller);
    if (!NT_SUCCESS(status))
        goto fail9;

    KeInitializeEvent(&(*Frontend)->EjectEvent, NotificationEvent, FALSE);

    status = ThreadCreate(FrontendEject, *Frontend, &(*Frontend)->EjectThread);
    if (!NT_SUCCESS(status))
        goto fail10;

    status = ThreadCreate(FrontendMib, *Frontend, &(*Frontend)->MibThread);
    if (!NT_SUCCESS(status))
        goto fail11;

    (*Frontend)->StatisticsCount = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    (*Frontend)->Statistics = __FrontendAllocate(sizeof (XENVIF_FRONTEND_STATISTICS) *
                                                 (*Frontend)->StatisticsCount);

    status = STATUS_NO_MEMORY;
    if ((*Frontend)->Statistics == NULL)
        goto fail12;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail12:
    Error("fail12\n");

    ThreadAlert((*Frontend)->MibThread);
    ThreadJoin((*Frontend)->MibThread);
    (*Frontend)->MibThread = NULL;

fail11:
    Error("fail11\n");

    ThreadAlert((*Frontend)->EjectThread);
    ThreadJoin((*Frontend)->EjectThread);
    (*Frontend)->EjectThread = NULL;

fail10:
    Error("fail10\n");

    RtlZeroMemory(&(*Frontend)->EjectEvent, sizeof (KEVENT));

    ControllerTeardown(__FrontendGetController(*Frontend));
    (*Frontend)->Controller = NULL;

fail9:
    TransmitterTeardown(__FrontendGetTransmitter(*Frontend));
    (*Frontend)->Transmitter = NULL;

fail8:
    Error("fail8\n");

    ReceiverTeardown(__FrontendGetReceiver(*Frontend));
    (*Frontend)->Receiver = NULL;

fail7:
    Error("fail7\n");

    MacTeardown(__FrontendGetMac(*Frontend));
    (*Frontend)->Mac = NULL;

fail6:
    Error("fail6\n");

    (*Frontend)->DisableToeplitz = 0;

    RtlZeroMemory(&(*Frontend)->Hash, sizeof (XENVIF_FRONTEND_HASH));
    (*Frontend)->MaxQueues = 0;

    RtlZeroMemory(&(*Frontend)->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&(*Frontend)->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&(*Frontend)->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    (*Frontend)->Online = FALSE;

    RtlZeroMemory(&(*Frontend)->Lock, sizeof (KSPIN_LOCK));

    (*Frontend)->BackendDomain = 0;
    (*Frontend)->Prefix = NULL;
    (*Frontend)->Path = NULL;
    (*Frontend)->Pdo = NULL;

    ASSERT(IsZeroMemory(*Frontend, sizeof (XENVIF_FRONTEND)));

    __FrontendFree(*Frontend);
    *Frontend = NULL;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

    __FrontendFree(Prefix);

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    __FrontendFree(Path);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
FrontendTeardown(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    ASSERT(Frontend->State == FRONTEND_UNKNOWN);

    __FrontendFree(Frontend->Statistics);
    Frontend->Statistics = NULL;
    Frontend->StatisticsCount = 0;

    ThreadAlert(Frontend->MibThread);
    ThreadJoin(Frontend->MibThread);
    Frontend->MibThread = NULL;

    if (Frontend->AddressCount != 0) {
        __FrontendFree(Frontend->AddressTable);

        Frontend->AddressTable = NULL;
        Frontend->AddressCount = 0;
    }

    RtlZeroMemory(Frontend->Alias, sizeof (Frontend->Alias));
    Frontend->InterfaceIndex = 0;

    ThreadAlert(Frontend->EjectThread);
    ThreadJoin(Frontend->EjectThread);
    Frontend->EjectThread = NULL;

    RtlZeroMemory(&Frontend->EjectEvent, sizeof (KEVENT));

    ControllerTeardown(__FrontendGetController(Frontend));
    Frontend->Controller = NULL;

    TransmitterTeardown(__FrontendGetTransmitter(Frontend));
    Frontend->Transmitter = NULL;

    ReceiverTeardown(__FrontendGetReceiver(Frontend));
    Frontend->Receiver = NULL;

    MacTeardown(__FrontendGetMac(Frontend));
    Frontend->Mac = NULL;

    Frontend->DisableToeplitz = 0;

    RtlZeroMemory(&Frontend->Hash, sizeof (XENVIF_FRONTEND_HASH));
    Frontend->MaxQueues = 0;

    RtlZeroMemory(&Frontend->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Frontend->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&Frontend->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    Frontend->Online = FALSE;

    RtlZeroMemory(&Frontend->Lock, sizeof (KSPIN_LOCK));

    Frontend->BackendDomain = 0;

    __FrontendFree(Frontend->Prefix);
    Frontend->Prefix = NULL;

    __FrontendFree(Frontend->Path);
    Frontend->Path = NULL;

    Frontend->Pdo = NULL;

    ASSERT(IsZeroMemory(Frontend, sizeof (XENVIF_FRONTEND)));

    __FrontendFree(Frontend);

    Trace("<====\n");
}
