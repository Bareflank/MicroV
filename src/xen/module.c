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
#include <aux_klib.h>

#include "high.h"
#include "module.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define MODULE_TAG   'UDOM'

typedef struct _MODULE {
    LIST_ENTRY  ListEntry;
    ULONG_PTR   Start;
    ULONG_PTR   End;
    CHAR        Name[AUX_KLIB_MODULE_PATH_LEN];
} MODULE, *PMODULE;

typedef struct _MODULE_CONTEXT {
    LONG        References;
    LIST_ENTRY  List;
    PLIST_ENTRY Cursor;
    HIGH_LOCK   Lock;
} MODULE_CONTEXT, *PMODULE_CONTEXT;

static MODULE_CONTEXT   ModuleContext;

static FORCEINLINE PVOID
__ModuleAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, MODULE_TAG);
}

static FORCEINLINE VOID
__ModuleFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, MODULE_TAG);
}

static VOID
ModuleSearchForwards(
    IN  PMODULE_CONTEXT Context,
    IN  ULONG_PTR       Address
    )
{
    while (Context->Cursor != &Context->List) {
        PMODULE Module;

        Module = CONTAINING_RECORD(Context->Cursor, MODULE, ListEntry);

        if (Address <= Module->End)
            break;

        Context->Cursor = Context->Cursor->Flink;
    }
}

static VOID
ModuleSearchBackwards(
    IN  PMODULE_CONTEXT Context,
    IN  ULONG_PTR       Address
    )
{
    while (Context->Cursor != &Context->List) {
        PMODULE Module;

        Module = CONTAINING_RECORD(Context->Cursor, MODULE, ListEntry);

        if (Address >= Module->Start)
            break;

        Context->Cursor = Context->Cursor->Blink;
    }
}

static NTSTATUS
ModuleAdd(
    IN  PMODULE_CONTEXT Context,
    IN  PCHAR           Name,
    IN  ULONG_PTR       Start,
    IN  ULONG_PTR       Size
    )
{
#define INSERT_AFTER(_Cursor, _New)             \
        do {                                    \
            (_New)->Flink = (_Cursor)->Flink;   \
            (_Cursor)->Flink->Blink = (_New);   \
                                                \
            (_Cursor)->Flink = (_New);          \
            (_New)->Blink = (_Cursor);          \
        } while (FALSE)

#define INSERT_BEFORE(_Cursor, _New)            \
        do {                                    \
            (_New)->Blink = (_Cursor)->Blink;   \
            (_Cursor)->Blink->Flink = (_New);   \
                                                \
            (_Cursor)->Blink = (_New);          \
            (_New)->Flink = (_Cursor);          \
        } while (FALSE)

    PMODULE             New;
    ULONG               Index;
    PMODULE             Module;
    KIRQL               Irql;
    LIST_ENTRY          List;
    BOOLEAN             After;
    NTSTATUS            status;

    New = __ModuleAllocate(sizeof (MODULE));

    status = STATUS_NO_MEMORY;
    if (New == NULL)
        goto fail1;

    for (Index = 0; Index < AUX_KLIB_MODULE_PATH_LEN; Index++) {
        if (Name[Index] == '\0')
            break;

        New->Name[Index] = __tolower(Name[Index]);
    }

    New->Start = Start;
    New->End = Start + Size - 1;

    InitializeListHead(&List);

    AcquireHighLock(&Context->Lock, &Irql);

again:
    After = TRUE;

    if (Context->Cursor == &Context->List) {
        ASSERT(IsListEmpty(&Context->List));
        goto done;
    }

    Module = CONTAINING_RECORD(Context->Cursor, MODULE, ListEntry);

    if (New->Start > Module->End) {
        ModuleSearchForwards(Context, New->Start);

        After = FALSE;

        if (Context->Cursor == &Context->List)    // End of list
            goto done;

        Module = CONTAINING_RECORD(Context->Cursor, MODULE, ListEntry);

        if (New->End >= Module->Start) {    // Overlap
            PLIST_ENTRY Cursor = Context->Cursor->Blink;

            RemoveEntryList(Context->Cursor);
            InsertTailList(&List, &Module->ListEntry);

            Context->Cursor = Cursor;
            goto again;
        }
    } else if (New->End < Module->Start) {
        ModuleSearchBackwards(Context, New->End);

        After = TRUE;

        if (Context->Cursor == &Context->List)    // Start of list
            goto done;

        Module = CONTAINING_RECORD(Context->Cursor, MODULE, ListEntry);

        if (New->Start <= Module->End) {    // Overlap
            PLIST_ENTRY Cursor = Context->Cursor->Flink;

            RemoveEntryList(Context->Cursor);
            InsertTailList(&List, &Module->ListEntry);

            Context->Cursor = Cursor;
            goto again;
        }
    } else {
        PLIST_ENTRY Cursor;
        
        Cursor = (Context->Cursor->Flink != &Context->List) ?
                 Context->Cursor->Flink :
                 Context->Cursor->Blink;

        RemoveEntryList(Context->Cursor);
        InsertTailList(&List, &Module->ListEntry);

        Context->Cursor = Cursor;
        goto again;
    }

done:
    if (After)
        INSERT_AFTER(Context->Cursor, &New->ListEntry);
    else
        INSERT_BEFORE(Context->Cursor, &New->ListEntry);

    Context->Cursor = &New->ListEntry;

    ReleaseHighLock(&Context->Lock, Irql);

    while (!IsListEmpty(&List)) {
        PLIST_ENTRY     ListEntry;

        ListEntry = RemoveHeadList(&List);
        ASSERT(ListEntry != &List);

        Module = CONTAINING_RECORD(ListEntry, MODULE, ListEntry);
        __ModuleFree(Module);
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;

#undef  INSERT_AFTER
#undef  INSERT_BEFORE
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static VOID
ModuleLoad(
    IN  PUNICODE_STRING FullImageName,
    IN  HANDLE          ProcessId,
    IN  PIMAGE_INFO     ImageInfo
    )
{
    PMODULE_CONTEXT     Context = &ModuleContext;
    ANSI_STRING         Ansi;
    PCHAR               Buffer;
    PCHAR               Name;
    NTSTATUS            status;

    UNREFERENCED_PARAMETER(ProcessId);

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    if (!ImageInfo->SystemModeImage)
        return;

    status = RtlUnicodeStringToAnsiString(&Ansi, FullImageName, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    Buffer = __ModuleAllocate(Ansi.Length + sizeof (CHAR));

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail2;

    RtlCopyMemory(Buffer, Ansi.Buffer, Ansi.Length);

    Name = strrchr((const CHAR *)Buffer, '\\');
    Name = (Name == NULL) ? Buffer : (Name + 1);

    status = ModuleAdd(Context,
                       Name,
                       (ULONG_PTR)ImageInfo->ImageBase,
                       (ULONG_PTR)ImageInfo->ImageSize);
    if (!NT_SUCCESS(status))
        goto fail3;

    __ModuleFree(Buffer);

    RtlFreeAnsiString(&Ansi);

    return;

fail3:
    Error("fail3\n");

    __ModuleFree(Buffer);

fail2:
    Error("fail2\n");

    RtlFreeAnsiString(&Ansi);

fail1:
    Error("fail1 (%08x)\n", status);
}

XEN_API
VOID
ModuleLookup(
    IN  ULONG_PTR   Address,
    OUT PCHAR       *Name,
    OUT PULONG_PTR  Offset
    )
{
    PMODULE_CONTEXT Context = &ModuleContext;
    PLIST_ENTRY     ListEntry;
    KIRQL           Irql;

    *Name = NULL;
    *Offset = 0;

    AcquireHighLock(&Context->Lock, &Irql);

    for (ListEntry = Context->List.Flink;
         ListEntry != &Context->List;
         ListEntry = ListEntry->Flink) {
        PMODULE Module;

        Module = CONTAINING_RECORD(ListEntry, MODULE, ListEntry);

        if (Address >= Module->Start &&
            Address <= Module->End) {
            *Name = Module->Name;
            *Offset = Address - Module->Start;
            break;
        }
    }

    ReleaseHighLock(&Context->Lock, Irql);
}

VOID
ModuleTeardown(
    VOID
    )
{
    PMODULE_CONTEXT Context = &ModuleContext;

    (VOID) PsRemoveLoadImageNotifyRoutine(ModuleLoad);

    Context->Cursor = NULL;

    while (!IsListEmpty(&Context->List)) {
        PLIST_ENTRY ListEntry;
        PMODULE     Module;

        ListEntry = RemoveHeadList(&Context->List);
        ASSERT(ListEntry != &Context->List);

        Module = CONTAINING_RECORD(ListEntry, MODULE, ListEntry);
        __ModuleFree(Module);
    }

    RtlZeroMemory(&Context->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&Context->Lock, sizeof (HIGH_LOCK));

    (VOID) InterlockedDecrement(&Context->References);

    ASSERT(IsZeroMemory(Context, sizeof (MODULE_CONTEXT)));
}

NTSTATUS
ModuleInitialize(
    VOID)
{
    PMODULE_CONTEXT             Context = &ModuleContext;
    ULONG                       References;
    ULONG                       BufferSize;
    ULONG                       Count;
    PAUX_MODULE_EXTENDED_INFO   QueryInfo;
    ULONG                       Index;
    NTSTATUS                    status;

    References = InterlockedIncrement(&Context->References);

    status = STATUS_OBJECTID_EXISTS;
    if (References != 1)
        goto fail1;

    InitializeHighLock(&Context->Lock);

    (VOID) AuxKlibInitialize();

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
    QueryInfo = __ModuleAllocate(sizeof (AUX_MODULE_EXTENDED_INFO) * Count);

    status = STATUS_NO_MEMORY;
    if (QueryInfo == NULL)
        goto fail4;

    status = AuxKlibQueryModuleInformation(&BufferSize,
                                           sizeof (AUX_MODULE_EXTENDED_INFO),
                                           QueryInfo);
    if (!NT_SUCCESS(status)) {
        if (status != STATUS_BUFFER_TOO_SMALL)
            goto fail5;

        __ModuleFree(QueryInfo);
        goto again;
    }

    InitializeListHead(&Context->List);
    Context->Cursor = &Context->List;

    for (Index = 0; Index < Count; Index++) {
        PCHAR   Name;

        Name = strrchr((const CHAR *)QueryInfo[Index].FullPathName, '\\');
        Name = (Name == NULL) ? (PCHAR)QueryInfo[Index].FullPathName : (Name + 1);

        status = ModuleAdd(Context,
                           Name,
                           (ULONG_PTR)QueryInfo[Index].BasicInfo.ImageBase,
                           (ULONG_PTR)QueryInfo[Index].ImageSize);
        if (!NT_SUCCESS(status))
            goto fail6;
    }

    status = PsSetLoadImageNotifyRoutine(ModuleLoad);
    if (!NT_SUCCESS(status))
        goto fail7;

    __ModuleFree(QueryInfo);

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

fail6:
    Error("fail6\n");

    while (!IsListEmpty(&Context->List)) {
        PLIST_ENTRY ListEntry;
        PMODULE     Module;

        ListEntry = RemoveHeadList(&Context->List);
        ASSERT(ListEntry != &Context->List);

        Module = CONTAINING_RECORD(ListEntry, MODULE, ListEntry);
        __ModuleFree(Module);
    }

    RtlZeroMemory(&Context->List, sizeof (LIST_ENTRY));

fail5:
    Error("fail5\n");

    __ModuleFree(QueryInfo);

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    (VOID) InterlockedDecrement(&Context->References);

    ASSERT(IsZeroMemory(Context, sizeof (MODULE_CONTEXT)));    

    return status;
}
