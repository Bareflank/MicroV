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

#ifndef _XEN_ACPI_H
#define _XEN_ACPI_H

#include <ntddk.h>

#pragma pack(push, 1)

typedef struct _ACPI_RSDP {
    CHAR    Signature[8];
    UCHAR   Checksum;
    CHAR    OemID[6];
    UCHAR   Revision;
    ULONG   RsdtAddress;
    ULONG   Length;
    ULONG64 XsdtAddress;
    UCHAR   ExtendedChecksum;
    UCHAR   Reserved[3];
} ACPI_RSDP, *PACPI_RSDP;

typedef struct _ACPI_HEADER {
    CHAR    Signature[4];
    ULONG   Length;
    UCHAR   Revision;
    UCHAR   Checksum;
    CHAR    OemID[6];
    CHAR    OemTableID[8];
    ULONG   OemRevision;
    CHAR    CreatorID[4];
    ULONG   CreatorRevision;
} ACPI_HEADER, *PACPI_HEADER;

typedef struct _ACPI_XSDT {
    ACPI_HEADER Header;
    ULONG64     Entry[1];
} ACPI_XSDT, *PACPI_XSDT;

typedef struct _ACPI_MADT {
    ACPI_HEADER Header;
    ULONG       LocalAPICAddress;
    ULONG       Flags;
} ACPI_MADT, *PACPI_MADT;

typedef struct _ACPI_MADT_HEADER {
    UCHAR   Type;
    UCHAR   Length;
} ACPI_MADT_HEADER, *PACPI_MADT_HEADER;

#define ACPI_MADT_TYPE_LOCAL_APIC   0x00

typedef struct _ACPI_MADT_LOCAL_APIC {
    ACPI_MADT_HEADER    Header;
    UCHAR               ProcessorID;
    UCHAR               ApicID;
    ULONG               Flags;
} ACPI_MADT_LOCAL_APIC, *PACPI_MADT_LOCAL_APIC;

#pragma pack(pop)

extern NTSTATUS
AcpiInitialize(
    VOID
    );

extern NTSTATUS
AcpiGetTable(
    IN      const CHAR  *Signature,
    OUT     PVOID       Buffer OPTIONAL,
    IN OUT  PULONG      Length
    );

extern VOID
AcpiTeardown(
    VOID
    );

#endif  // _XEN_ACPI_H

