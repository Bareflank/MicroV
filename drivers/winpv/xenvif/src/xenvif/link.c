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
#include <aux_klib.h>

#include "link.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define LINK_TAG    'KNIL'

static FORCEINLINE PVOID
__LinkAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, LINK_TAG);
}

static FORCEINLINE VOID
__LinkFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, LINK_TAG);
}

static FORCEINLINE NTSTATUS
__LinkGetImageBase(
    IN  const CHAR              *ModuleName,
    OUT PVOID                   *ImageBase
    )
{
    ULONG                       BufferSize;
    ULONG                       Count;
    PAUX_MODULE_EXTENDED_INFO   QueryInfo;
    ULONG                       Index;
    NTSTATUS                    status;

    Trace("====>\n");

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status))
        goto fail1;

    status = AuxKlibQueryModuleInformation(&BufferSize,
                                           sizeof (AUX_MODULE_EXTENDED_INFO),
                                           NULL);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_UNSUCCESSFUL;
    if (BufferSize == 0)
        goto fail3;

again:
    Count = BufferSize / sizeof (AUX_MODULE_EXTENDED_INFO);
    QueryInfo = __LinkAllocate(sizeof (AUX_MODULE_EXTENDED_INFO) * Count);

    status = STATUS_NO_MEMORY;
    if (QueryInfo == NULL)
        goto fail4;

    status = AuxKlibQueryModuleInformation(&BufferSize,
                                           sizeof (AUX_MODULE_EXTENDED_INFO),
                                           QueryInfo);
    if (!NT_SUCCESS(status)) {
        if (status != STATUS_BUFFER_TOO_SMALL)
            goto fail5;

        __LinkFree(QueryInfo);
        goto again;
    }

    for (Index = 0; Index < Count; Index++) {
        PCHAR   Name;

        Name = strrchr((const CHAR *)QueryInfo[Index].FullPathName, '\\');
        Name = (Name == NULL) ? (PCHAR)QueryInfo[Index].FullPathName : (Name + 1);

        if (_stricmp(Name, ModuleName) == 0)
            goto found;
    }

    status = STATUS_UNSUCCESSFUL;
    goto fail6;

found:
    *ImageBase = QueryInfo[Index].BasicInfo.ImageBase;

    __LinkFree(QueryInfo);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    __LinkFree(QueryInfo);

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
LinkGetRoutineAddress(
    IN  const CHAR  *ModuleName,
    IN  const CHAR  *FunctionName,
    OUT PVOID       *Address
    )
{
#define MK_PTR(_ImageBase, _Type, _RVA) \
    (_Type)((ULONG_PTR)(_ImageBase) + (_RVA))

    PVOID                       ImageBase;
    PIMAGE_DOS_HEADER           DosHeader;
    PIMAGE_NT_HEADERS           NtHeaders;
    PIMAGE_OPTIONAL_HEADER      OptionalHeader;
    PIMAGE_DATA_DIRECTORY       Entry;
    PIMAGE_EXPORT_DIRECTORY     Exports;
    PULONG                      AddressOfFunctions;
    PULONG                      AddressOfNames;
    PUSHORT                     AddressOfNameOrdinals;
    ULONG                       Index;
    USHORT                      Ordinal;
    PVOID                       Function;
    NTSTATUS                    status;

    Trace("====>\n");

    status = __LinkGetImageBase(ModuleName, &ImageBase);
    if (!NT_SUCCESS(status))
        goto fail1;

    DosHeader = MK_PTR(ImageBase, PIMAGE_DOS_HEADER, 0);
    ASSERT3U(DosHeader->e_magic, ==, IMAGE_DOS_SIGNATURE);

    NtHeaders = MK_PTR(ImageBase, PIMAGE_NT_HEADERS, DosHeader->e_lfanew);
    ASSERT3U(NtHeaders->Signature, ==, IMAGE_NT_SIGNATURE);

    OptionalHeader = &NtHeaders->OptionalHeader;
    ASSERT3U(OptionalHeader->Magic, ==, IMAGE_NT_OPTIONAL_HDR_MAGIC);

    Entry = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    status = STATUS_UNSUCCESSFUL;
    if (Entry->Size == 0)
        goto fail2;

    Exports = MK_PTR(ImageBase, PIMAGE_EXPORT_DIRECTORY,
                     Entry->VirtualAddress);

    status = STATUS_UNSUCCESSFUL;
    if (Exports->NumberOfNames == 0)
        goto fail3;

    AddressOfFunctions = MK_PTR(ImageBase, PULONG,
                                Exports->AddressOfFunctions);
    AddressOfNames = MK_PTR(ImageBase, PULONG,
                            Exports->AddressOfNames);
    AddressOfNameOrdinals = MK_PTR(ImageBase, PUSHORT,
                                   Exports->AddressOfNameOrdinals);

    for (Index = 0; Index < Exports->NumberOfNames; Index++) {
        PCHAR   Name = MK_PTR(ImageBase, PCHAR, AddressOfNames[Index]);

        Ordinal = AddressOfNameOrdinals[Index];
        Function = MK_PTR(ImageBase, PVOID, AddressOfFunctions[Ordinal]);

        if (strcmp(Name, FunctionName) == 0)
            goto found;
    }

    status = STATUS_UNSUCCESSFUL;
    goto fail4;

found:
    *Address = Function;

    Trace("%s:%s (%04X) @ %p\n",
          ModuleName,
          FunctionName,
          Ordinal,
          Function);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;

#undef  MK_PTR
}
