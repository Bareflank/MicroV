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
#include <stdarg.h>
#include <xen.h>

#include "sync.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

// Routines to capture all CPUs in a spinning state with interrupts
// disabled (so that we remain in a known code context).
// These routines are used for suspend/resume and live snapshot.

// The general sequence of steps is follows:
//
// - SyncCapture() is called on an arbitrary CPU. It must be called at
//   DISPATCH_LEVEL so it cannot be pre-empted and moved to another CPU.
//   It schedules a DPC on each of the other CPUs and spins until all
//   CPUs are executing the DPC, which will in-turn spin awaiting
//   further instruction.
//
// - SyncDisableInterrputs() instructs the DPC routines to all raise
//   to HIGH_LEVEL and disable interrupts for its CPU. It then raises
//   to HIGH_LEVEL itself, spins waiting for confirmation from each
//   DPC that it has disabled interrupts and then disables interrupts
//   itself.
//
//   NOTE: There is a back-off in trying to disable interrupts. It is
//         possible that CPU A is waiting for an IPI to CPU B to
//         complete, but CPU B is spinning with interrupts disabled.
//         Thus the DPC on CPU A will never make it to HIGH_LEVEL and
//         hence never get to disable interrupts. Thus if, while
//         spinning with interrupts disabled, one DPC notices that
//         another DPC has not made it, it briefly enables interrupts
//         and drops back down to DISPATCH_LEVEL before trying again.
//         This should allow any pending IPI to complete.
//
// - SyncEnableInterrupts() instructs the DPC routines to all enable
//   interrupts and drop back to DISPATCH_LEVEL before enabling
//   interrupts and dropping back to DISPATCH_LEVEL itself.
//
// - SyncRelease() instructs the DPC routines to exit, thus allowing
//   the scheduler to run on the other CPUs again. It spins until all
//   DPCs have completed and then returns.

#pragma data_seg("sync")
__declspec(allocate("sync"))
static UCHAR        __Section[PAGE_SIZE];

typedef struct  _SYNC_PROCESSOR {
    KDPC                Dpc;
    BOOLEAN             DisableInterrupts;
    BOOLEAN             Exit;
} SYNC_PROCESSOR, *PSYNC_PROCESSOR;

typedef struct  _SYNC_CONTEXT {
    ULONG               Sequence;
    LONG                ProcessorCount;
    LONG                CompletionCount;
    SYNC_PROCESSOR      Processor[1];
} SYNC_CONTEXT, *PSYNC_CONTEXT;

static PSYNC_CONTEXT    SyncContext = (PVOID)__Section;
static LONG             SyncOwner = -1;

static FORCEINLINE VOID
__SyncAcquire(
    IN  LONG    Index
    )
{
    LONG        Old;

    Old = InterlockedExchange(&SyncOwner, Index);
    ASSERT3U(Old, ==, -1);
}

static FORCEINLINE VOID
__SyncRelease(
    IN  LONG    Index
    )
{
    LONG        Old;

    Old = InterlockedExchange(&SyncOwner, -1);
    ASSERT3U(Old, ==, Index);
}


KDEFERRED_ROUTINE   SyncWorker;

#pragma intrinsic(_enable)
#pragma intrinsic(_disable)

VOID
#pragma prefast(suppress:28166) // Function does not restore IRQL
SyncWorker(
    IN  PKDPC           Dpc,
    IN  PVOID           _Context,
    IN  PVOID           Argument1,
    IN  PVOID           Argument2
    )
{
    PSYNC_CONTEXT       Context = SyncContext;
    BOOLEAN             InterruptsDisabled;
    ULONG               Index;
    PSYNC_PROCESSOR     Processor;
    PROCESSOR_NUMBER    ProcNumber;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(_Context);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    InterruptsDisabled = FALSE;
    Index = KeGetCurrentProcessorNumberEx(&ProcNumber);
    Processor = &Context->Processor[Index];

    Trace("====> (%u:%u)\n", ProcNumber.Group, ProcNumber.Number);
    InterlockedIncrement(&Context->CompletionCount);

    for (;;) {
        ULONG   Sequence;

        if (Processor->Exit)
            break;

        if (Processor->DisableInterrupts == InterruptsDisabled) {
            _mm_pause();
            KeMemoryBarrier();

            continue;
        }

        Sequence = Context->Sequence;

        if (Processor->DisableInterrupts) {
            ULONG       Attempts;
            NTSTATUS    status;

            (VOID) KfRaiseIrql(HIGH_LEVEL);
            status = STATUS_SUCCESS;

            InterlockedIncrement(&Context->CompletionCount);

            Attempts = 0;
            while (Context->Sequence == Sequence &&
                   Context->CompletionCount < Context->ProcessorCount) {
                _mm_pause();
                KeMemoryBarrier();

                if (++Attempts > 1000) {
                    LONG    Old;
                    LONG    New;

                    do {
                        Old = Context->CompletionCount;
                        New = Old - 1;

                        if (Old == Context->ProcessorCount)
                            break;
                    } while (InterlockedCompareExchange(&Context->CompletionCount, New, Old) != Old);

                    if (Old < Context->ProcessorCount) {
#pragma prefast(suppress:28138) // Use constant rather than variable
                        KeLowerIrql(DISPATCH_LEVEL);
                        status = STATUS_UNSUCCESSFUL;
                        break;
                    }
                }
            }
                    
            if (!NT_SUCCESS(status))
                continue;

            _disable();

            InterruptsDisabled = TRUE;
        } else {
            InterruptsDisabled = FALSE;

            _enable();

#pragma prefast(suppress:28138) // Use constant rather than variable
            KeLowerIrql(DISPATCH_LEVEL);

            InterlockedIncrement(&Context->CompletionCount);

            while (Context->Sequence == Sequence &&
                   Context->CompletionCount < Context->ProcessorCount) {
                _mm_pause();
                KeMemoryBarrier();
            }

        }
    }

    Trace("<==== (%u:%u)\n", ProcNumber.Group, ProcNumber.Number);
    InterlockedIncrement(&Context->CompletionCount);

    ASSERT(!InterruptsDisabled);
}

__drv_maxIRQL(DISPATCH_LEVEL)
__drv_raisesIRQL(DISPATCH_LEVEL)
VOID
SyncCapture(
    VOID
    )
{
    PSYNC_CONTEXT       Context = SyncContext;
    LONG                Index;
    PROCESSOR_NUMBER    ProcNumber;
    USHORT              Group;
    UCHAR               Number;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Index = KeGetCurrentProcessorNumberEx(&ProcNumber);
    __SyncAcquire(Index);

    Group = ProcNumber.Group;
    Number = ProcNumber.Number;

    Trace("====> (%u:%u)\n", Group, Number);

    ASSERT(IsZeroMemory(Context, PAGE_SIZE));

    Context->Sequence++;
    Context->CompletionCount = 0;

    Context->ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (Index = 0; Index < Context->ProcessorCount; Index++) {
        PSYNC_PROCESSOR Processor = &Context->Processor[Index];
        NTSTATUS        status;

        ASSERT3U((ULONG_PTR)(Processor + 1), <, (ULONG_PTR)__Section + PAGE_SIZE);

        status = KeGetProcessorNumberFromIndex(Index, &ProcNumber);
        ASSERT(NT_SUCCESS(status));

        if (ProcNumber.Group == Group &&
            ProcNumber.Number == Number)
            continue;

        KeInitializeDpc(&Processor->Dpc, SyncWorker, NULL);
        KeSetTargetProcessorDpcEx(&Processor->Dpc, &ProcNumber);
        KeInsertQueueDpc(&Processor->Dpc, NULL, NULL);
    }

    InterlockedIncrement(&Context->CompletionCount);

    while (Context->CompletionCount < Context->ProcessorCount) {
        _mm_pause();
        KeMemoryBarrier();
    }

    Trace("<==== (%u:%u)\n", Group, Number);
}

__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_setsIRQL(HIGH_LEVEL)
VOID
SyncDisableInterrupts(
    VOID
    )
{
    PSYNC_CONTEXT   Context = SyncContext;
    LONG            Index;
    ULONG           Attempts;
    NTSTATUS        status;

    Trace("====>\n");

    Context->Sequence++;
    Context->CompletionCount = 0;

    for (Index = 0; Index < Context->ProcessorCount; Index++) {
        PSYNC_PROCESSOR Processor = &Context->Processor[Index];

        Processor->DisableInterrupts = TRUE;
    }

    KeMemoryBarrier();

again:
    (VOID) KfRaiseIrql(HIGH_LEVEL);
    status = STATUS_SUCCESS;

    InterlockedIncrement(&Context->CompletionCount);

    Attempts = 0;
    while (Context->CompletionCount < Context->ProcessorCount) {
        _mm_pause();
        KeMemoryBarrier();

        if (++Attempts > 1000) {
            LONG    Old;
            LONG    New;

            do {
                Old = Context->CompletionCount;
                New = Old - 1;

                if (Old == Context->ProcessorCount)
                    break;
            } while (InterlockedCompareExchange(&Context->CompletionCount, New, Old) != Old);

            if (Old < Context->ProcessorCount) {
                LogPrintf(LOG_LEVEL_WARNING,
                          "SYNC: %d < %d\n",
                          Old,
                          Context->ProcessorCount);

#pragma prefast(suppress:28138) // Use constant rather than variable
                KeLowerIrql(DISPATCH_LEVEL);
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }
    }
            
    if (!NT_SUCCESS(status))
        goto again;

    _disable();
}

__drv_requiresIRQL(HIGH_LEVEL)
__drv_setsIRQL(DISPATCH_LEVEL)
VOID
SyncEnableInterrupts(
    )
{
    PSYNC_CONTEXT   Context = SyncContext;
    KIRQL           Irql;
    LONG            Index;

    _enable();

    Irql = KeGetCurrentIrql();
    ASSERT3U(Irql, ==, HIGH_LEVEL);

    Context->Sequence++;
    Context->CompletionCount = 0;

    for (Index = 0; Index < Context->ProcessorCount; Index++) {
        PSYNC_PROCESSOR Processor = &Context->Processor[Index];

        Processor->DisableInterrupts = FALSE;
    }

    KeMemoryBarrier();

    InterlockedIncrement(&Context->CompletionCount);

    while (Context->CompletionCount < Context->ProcessorCount) {
        _mm_pause();
        KeMemoryBarrier();
    }

#pragma prefast(suppress:28138) // Use constant rather than variable
    KeLowerIrql(DISPATCH_LEVEL);

    Trace("<====\n");
}

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID
#pragma prefast(suppress:28167) // Function changes IRQL
SyncRelease(
    VOID
    )
{
    PSYNC_CONTEXT   Context = SyncContext;
    LONG            Index;

    Trace("====>\n");

    Context->Sequence++;
    Context->CompletionCount = 0;

    for (Index = 0; Index < Context->ProcessorCount; Index++) {
        PSYNC_PROCESSOR Processor = &Context->Processor[Index];

        Processor->Exit = TRUE;
    }

    KeMemoryBarrier();

    InterlockedIncrement(&Context->CompletionCount);

    while (Context->CompletionCount < Context->ProcessorCount) {
        _mm_pause();
        KeMemoryBarrier();
    }

    RtlZeroMemory(Context, PAGE_SIZE);

    Index = KeGetCurrentProcessorNumberEx(NULL);
    __SyncRelease(Index);

    Trace("<====\n");
}
