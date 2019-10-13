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
#include <stdarg.h>
#include <xen.h>

#include "acpi.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define XENBUS_ACPI_TAG 'IPCA'

static ACPI_RSDP    AcpiRsdp;
static PACPI_XSDT   AcpiXsdt;

static FORCEINLINE PVOID
__AcpiAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_ACPI_TAG);
}

static FORCEINLINE VOID
__AcpiFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_ACPI_TAG);
}

static BOOLEAN
AcpiVerifyChecksum(
    IN  PVOID   Table,
    IN  ULONG   Length
    )
{
    UCHAR       Sum;
    ULONG       Index;

    Sum = 0;
    for (Index = 0; Index < Length; Index++)
        Sum += ((PUCHAR)Table)[Index];

    return (Sum == 0) ? TRUE : FALSE;
}

static NTSTATUS
AcpiFindRsdp(
    VOID
    )
{
    PHYSICAL_ADDRESS    Start;
    PHYSICAL_ADDRESS    End;
    ULONG               Length;
    PUCHAR              Data;
    ULONG               Offset;
    PACPI_RSDP          Rsdp;
    NTSTATUS            status;

    Trace("====>\n");

    if (strncmp(AcpiRsdp.Signature,
                "RSD PTR ",
                sizeof (AcpiRsdp.Signature)) == 0)
        goto done;

    Start.QuadPart = 0xE0000;
    End.QuadPart = 0xFFFFF;

    Length = (ULONG)(End.QuadPart + 1 - Start.QuadPart);

    Data = MmMapIoSpace(Start, Length, MmCached);

    status = STATUS_UNSUCCESSFUL;
    if (Data == NULL)
        goto fail1;

    for (Offset = 0;
         Offset + sizeof (ACPI_RSDP) < Length;
         Offset += 16) {
        Rsdp = (PACPI_RSDP)(Data + Offset);

        if (strncmp(Rsdp->Signature,
                    "RSD PTR ",
                    sizeof (Rsdp->Signature)) == 0 &&
            AcpiVerifyChecksum(Rsdp, sizeof (ACPI_RSDP)))
            goto found;
    }

    status = STATUS_UNSUCCESSFUL;
    goto fail2;

found:
    Info("0x%p\n", Start.QuadPart + Offset);

    // Copy the table for reference
    AcpiRsdp = *Rsdp;

    MmUnmapIoSpace(Data, Length);

done:
    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    MmUnmapIoSpace(Data, Length);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
AcpiGetXsdt(
    VOID
    )
{
    PHYSICAL_ADDRESS    Address;
    PACPI_XSDT          Xsdt;
    NTSTATUS            status;

    Trace("====>\n");

    if (AcpiXsdt != NULL)
        goto done;

    Address.QuadPart = AcpiRsdp.XsdtAddress;

    Info("0x%p\n", Address.QuadPart);

    Xsdt = MmMapIoSpace(Address, PAGE_SIZE, MmCached);

    status = STATUS_UNSUCCESSFUL;
    if (Xsdt == NULL)
        goto fail1;

    if (strncmp(Xsdt->Header.Signature,
                "XSDT",
                sizeof (Xsdt->Header.Signature)) != 0)
        goto fail2;

    if (!AcpiVerifyChecksum(Xsdt, Xsdt->Header.Length))
        goto fail3;

    AcpiXsdt = __AcpiAllocate(Xsdt->Header.Length);

    status = STATUS_NO_MEMORY;
    if (AcpiXsdt == NULL)
        goto fail4;

    RtlCopyMemory(AcpiXsdt, Xsdt, Xsdt->Header.Length);

    MmUnmapIoSpace(Xsdt, PAGE_SIZE);

done:
    Trace("<====\n");

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    MmUnmapIoSpace(Xsdt, PAGE_SIZE);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
AcpiGetTable(
    IN      const CHAR  *Signature,
    OUT     PVOID       Buffer OPTIONAL,
    IN OUT  PULONG      Length
    )
{
    ULONG               Count;
    ULONG               Index;
    PACPI_HEADER        Header;
    NTSTATUS            status;

    status = AcpiGetXsdt();
    if (!NT_SUCCESS(status))
        goto fail1;

    Count = (AcpiXsdt->Header.Length - FIELD_OFFSET(ACPI_XSDT, Entry)) /
            sizeof (ULONG64);

    for (Index = 0; Index < Count; Index++) {
        PHYSICAL_ADDRESS    Address;

        Address.QuadPart = AcpiXsdt->Entry[Index];

        Header = MmMapIoSpace(Address, PAGE_SIZE, MmCached);

        status = STATUS_UNSUCCESSFUL;
        if (Header == NULL)
            goto fail2;

        if (strncmp(Header->Signature,
                    Signature,
                    sizeof (Header->Signature)) == 0 &&
            AcpiVerifyChecksum(Header, Header->Length))
            goto found;

        MmUnmapIoSpace(Header, PAGE_SIZE);
    }

    status = STATUS_UNSUCCESSFUL;
    goto fail3;

found:
    status = STATUS_BUFFER_OVERFLOW;
    if (Buffer == NULL || Header->Length > *Length) {
        *Length = Header->Length;
        goto fail4;
    }

    RtlCopyMemory(Buffer, Header, Header->Length);

    MmUnmapIoSpace(Header, PAGE_SIZE);

    return STATUS_SUCCESS;

fail4:
    MmUnmapIoSpace(Header, PAGE_SIZE);

fail3:
    if (status != STATUS_BUFFER_OVERFLOW)
        Error("fail3\n");

fail2:
    if (status != STATUS_BUFFER_OVERFLOW)
        Error("fail2\n");

fail1:
    if (status != STATUS_BUFFER_OVERFLOW)
        Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
AcpiInitialize(
    VOID
    )
{
    NTSTATUS    status;

    status = AcpiFindRsdp();
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
AcpiTeardown(
    VOID
    )
{
    if (AcpiXsdt != NULL) {
        __AcpiFree(AcpiXsdt);
        AcpiXsdt = NULL;
    }
}
