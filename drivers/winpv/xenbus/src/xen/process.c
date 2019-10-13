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

#define XEN_API extern

#include <ntddk.h>
#include <xen.h>

#include "process.h"
#include "dbg_print.h"
#include "assert.h"

typedef struct _PROCESS_CONTEXT {
    LONG            References;
} PROCESS_CONTEXT, *PPROCESS_CONTEXT;

static PROCESS_CONTEXT  ProcessContext;

static VOID
ProcessNotify(
    IN  HANDLE                      ParentId,
    IN  HANDLE                      ProcessId,
    IN  BOOLEAN                     Create
    )
{
    KIRQL                           Irql;
    PHYSICAL_ADDRESS                Address;

    UNREFERENCED_PARAMETER(ParentId);
    UNREFERENCED_PARAMETER(ProcessId);

    if (Create)
        return;

    // Process destruction callbacks occur within the context of the
    // dying process so just read the current CR3 and notify Xen that
    // it's about to cease pointing at a page table hierarchy.

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    Address.QuadPart = __readcr3();   
    (VOID)HvmPagetableDying(Address);

    KeLowerIrql(Irql);
}

VOID
ProcessTeardown(
    VOID
    )
{
    PPROCESS_CONTEXT    Context = &ProcessContext;

    (VOID) PsSetCreateProcessNotifyRoutine(ProcessNotify, TRUE);

    (VOID) InterlockedDecrement(&Context->References);

    ASSERT(IsZeroMemory(Context, sizeof (PROCESS_CONTEXT)));
}

NTSTATUS
ProcessInitialize(
    VOID              
    )
{
    PPROCESS_CONTEXT    Context = &ProcessContext;
    ULONG               References;
    NTSTATUS            status;

    References = InterlockedIncrement(&Context->References);

    status = STATUS_OBJECTID_EXISTS;
    if (References != 1)
        goto fail1;

    status = PsSetCreateProcessNotifyRoutine(ProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    (VOID) InterlockedDecrement(&Context->References);

    ASSERT(IsZeroMemory(Context, sizeof (PROCESS_CONTEXT)));

    return status;
}
