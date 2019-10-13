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
#include <stdlib.h>
#include <xen.h>
#include <bugcodes.h>

#include "hypercall.h"
#include "module.h"
#include "log.h"
#include "bug_check.h"
#include "dbg_print.h"
#include "assert.h"

static KBUGCHECK_CALLBACK_RECORD BugCheckBugCheckCallbackRecord;

VOID
BugCheckTeardown(
    VOID
    )
{
    (VOID) KeDeregisterBugCheckCallback(&BugCheckBugCheckCallbackRecord);
}

#pragma warning(push)
#pragma warning(disable: 6320) // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER. This might mask exceptions that were not intended to be handled.
#pragma warning(disable: 6322) // Empty _except block.

static VOID
BugCheckDumpExceptionRecord(
    IN  PEXCEPTION_RECORD   Exception
    )
{
    __try {
        while (Exception != NULL) {
            ULONG   NumberParameters;
            ULONG   Index;

            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: EXCEPTION (%p):\n",
                      __MODULE__,
                      Exception);
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: - Code = %08X\n",
                      __MODULE__,
                      Exception->ExceptionCode);
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: - Flags = %08X\n",
                      __MODULE__,
                      Exception->ExceptionFlags);
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: - Address = %p\n",
                      __MODULE__,
                      Exception->ExceptionAddress);

            NumberParameters = __min(EXCEPTION_MAXIMUM_PARAMETERS,
                                     Exception->NumberParameters);

            for (Index = 0; Index < NumberParameters; Index++)
                LogPrintf(LOG_LEVEL_CRITICAL,
                          "%s|BUGCHECK: - Parameter[%u] = %p\n", __MODULE__,
                          Index,
                          (PVOID)Exception->ExceptionInformation[Index]);

            Exception = Exception->ExceptionRecord;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Nothing to to
    }
}

#pragma warning(push)
#pragma warning(disable:6262) // Uses more than 1024 bytes of stack

#if defined(__i386__)
static VOID
BugCheckDumpContext(
    IN  PCONTEXT    Context
    )
{
    __try {
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: CONTEXT (%p):\n",
                  __MODULE__,
                  Context);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - GS = %04X\n",
                  __MODULE__,
                  Context->SegGs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - FS = %04X\n",
                  __MODULE__,
                  Context->SegFs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - ES = %08X\n",
                  __MODULE__,
                  Context->SegEs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - DS = %08X\n",
                  __MODULE__,
                  Context->SegDs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - SS = %08X\n",
                  __MODULE__,
                  Context->SegSs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - CS = %08X\n",
                  __MODULE__,
                  Context->SegCs);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - EFLAGS = %08X\n",
                  __MODULE__,
                  Context->EFlags);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - EDI = %08X\n",
                  __MODULE__,
                  Context->Edi);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - ESI = %08X\n",
                  __MODULE__,
                  Context->Esi);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - EBX = %08X\n",
                  __MODULE__,
                  Context->Ebx);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - EDX = %08X\n",
                  __MODULE__,
                  Context->Edx);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - ECX = %08X\n",
                  __MODULE__,
                  Context->Ecx);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - EAX = %08X\n",
                  __MODULE__,
                  Context->Eax);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - EBP = %08X\n",
                  __MODULE__,
                  Context->Ebp);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - EIP = %08X\n",
                  __MODULE__,
                  Context->Eip);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - ESP = %08X\n",
                  __MODULE__,
                  Context->Esp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Nothing to to
    }
}

static VOID
BugCheckStackDump(
    IN  PCONTEXT    Context
    )
{
#define PARAMETER_COUNT     3
#define MAXIMUM_ITERATIONS  20

    __try {
        ULONG_PTR   EBP;
        ULONG       Iteration;

        BugCheckDumpContext(Context);

        EBP = (ULONG_PTR)Context->Ebp;

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: STACK:\n",
                  __MODULE__);

        for (Iteration = 0; Iteration < MAXIMUM_ITERATIONS; Iteration++) {
            ULONG       NextEBP;
            ULONG       EIP;
            ULONG       Parameter[PARAMETER_COUNT] = {0};
            ULONG       Index;
            PCHAR       Name;
            ULONG       Offset;

            NextEBP = *(PULONG)EBP;
            EIP = *(PULONG)(EBP + 4);

            if (EIP == 0)
                break;

            Index = 0;
            Offset = 8;
            for (;;) {
                if (EBP + Offset >= NextEBP)
                    break;

                if (Index == PARAMETER_COUNT)
                    break;

                Parameter[Index] = *(PULONG)(EBP + Offset);

                Index += 1;
                Offset += 4;
            }

            ModuleLookup(EIP, &Name, &Offset);

            if (Name != NULL)
                LogPrintf(LOG_LEVEL_CRITICAL,
                          "%s|BUGCHECK: %08X: (%08X %08X %08X) %s + %p\n", __MODULE__,
                          EBP,
                          Parameter[0],
                          Parameter[1],
                          Parameter[2],
                          Name,
                          (PVOID)Offset);
            else
                LogPrintf(LOG_LEVEL_CRITICAL,
                          "%s|BUGCHECK: %08X: (%08X %08X %08X) %p\n", __MODULE__,
                          EBP,
                          Parameter[0],
                          Parameter[1],
                          Parameter[2],
                          (PVOID)EIP);

            EBP = NextEBP;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // End of stack
    }

#undef  MAXIMUM_ITERATIONS
#undef  PARAMETER_COUNT
}
#elif defined(__x86_64__)
static VOID
BugCheckDumpContext(
    IN  PCONTEXT    Context
    )
{
    __try {
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: CONTEXT (%p):\n",
                  __MODULE__,
                  Context);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - GS = %04X\n",
                  __MODULE__,
                  Context->SegGs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - FS = %04X\n",
                  __MODULE__,
                  Context->SegFs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - ES = %04X\n",
                  __MODULE__,
                  Context->SegEs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - DS = %04X\n",
                  __MODULE__,
                  Context->SegDs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - SS = %04X\n",
                  __MODULE__,
                  Context->SegSs);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - CS = %04X\n",
                  __MODULE__,
                  Context->SegCs);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - EFLAGS = %08X\n",
                  __MODULE__,
                  Context->EFlags);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - RDI = %016X\n",
                  __MODULE__,
                  Context->Rdi);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - RSI = %016X\n",
                  __MODULE__,
                  Context->Rsi);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - RBX = %016X\n",
                  __MODULE__,
                  Context->Rbx);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - RDX = %016X\n",
                  __MODULE__,
                  Context->Rdx);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - RCX = %016X\n",
                  __MODULE__,
                  Context->Rcx);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - RAX = %016X\n",
                  __MODULE__,
                  Context->Rax);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - RBP = %016X\n",
                  __MODULE__,
                  Context->Rbp);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - RIP = %016X\n",
                  __MODULE__,
                  Context->Rip);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - RSP = %016X\n",
                  __MODULE__,
                  Context->Rsp);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - R8 = %016X\n",
                  __MODULE__,
                  Context->R8);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - R9 = %016X\n",
                  __MODULE__,
                  Context->R9);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - R10 = %016X\n",
                  __MODULE__,
                  Context->R10);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - R11 = %016X\n",
                  __MODULE__,
                  Context->R11);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - R12 = %016X\n",
                  __MODULE__,
                  Context->R12);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - R13 = %016X\n",
                  __MODULE__,
                  Context->R13);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - R14 = %016X\n",
                  __MODULE__,
                  Context->R14);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - R15 = %016X\n",
                  __MODULE__,
                  Context->R15);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Nothing to to
    }
}

typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
        ULONG64 ImageBase;
        PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

typedef struct _UNWIND_HISTORY_TABLE {
        ULONG Count;
        UCHAR Search;
        UCHAR RaiseStatusIndex;
        BOOLEAN Unwind;
        BOOLEAN Exception;
        ULONG64 LowAddress;
        ULONG64 HighAddress;
        UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

extern PRUNTIME_FUNCTION
RtlLookupFunctionEntry(
    __in ULONG64 ControlPc,
    __out PULONG64 ImageBase,
    __inout_opt PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
    );

#pragma prefast(suppress:28301) // No annotations
typedef EXCEPTION_DISPOSITION (*PEXCEPTION_ROUTINE) (
    __in struct _EXCEPTION_RECORD *ExceptionRecord,
    __in PVOID EstablisherFrame,
    __inout struct _CONTEXT *ContextRecord,
    __inout PVOID DispatcherContext
    );

#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used : nameless struct/union

typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    union {
        PM128A FloatingContext[16];
        struct {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        };
    };

    union {
        PULONG64 IntegerContext[16];
        struct {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        };
    };
} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;

#pragma warning(pop)

#define UNW_FLAG_NHANDLER   0
#define UNW_FLAG_EHANDLER   1
#define UNW_FLAG_UHANDLER   2

extern PEXCEPTION_ROUTINE
RtlVirtualUnwind(
    __in ULONG HandlerType,
    __in ULONG64 ImageBase,
    __in ULONG64 ControlPc,
    __in PRUNTIME_FUNCTION FunctionEntry,
    __inout PCONTEXT ContextRecord,
    __out PVOID *HandlerData,
    __out PULONG64 EstablisherFrame,
    __inout_opt PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
    );

static VOID
BugCheckStackDump(
    IN  PCONTEXT    Context
    )
{
#define PARAMETER_COUNT     4
#define MAXIMUM_ITERATIONS  20

    __try {
        ULONG   Iteration;

        BugCheckDumpContext(Context);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: STACK:\n",
                  __MODULE__);	

        for (Iteration = 0; Iteration < MAXIMUM_ITERATIONS; Iteration++) {
            PRUNTIME_FUNCTION   FunctionEntry;
            ULONG64             ImageBase;
            ULONG64             RIP;
            ULONG64             RSP;
            ULONG64             Parameter[PARAMETER_COUNT] = {0};
            ULONG               Index;
            PCHAR               Name;
            ULONG64             Offset;

            if (Context->Rip == 0)
                break;

            FunctionEntry = RtlLookupFunctionEntry(Context->Rip,
                                                   &ImageBase,
                                                   NULL);

            if (FunctionEntry != NULL) {
                CONTEXT                         UnwindContext;
                ULONG64                         ControlPc;
                PVOID                           HandlerData;
                ULONG64                         EstablisherFrame;
                KNONVOLATILE_CONTEXT_POINTERS   ContextPointers;

                UnwindContext = *Context;
                ControlPc = Context->Rip;
                HandlerData = NULL;
                EstablisherFrame = 0;
                RtlZeroMemory(&ContextPointers, sizeof (KNONVOLATILE_CONTEXT_POINTERS));

                (VOID) RtlVirtualUnwind(UNW_FLAG_UHANDLER,
                                        ImageBase,
                                        ControlPc,
                                        FunctionEntry,
                                        &UnwindContext,
                                        &HandlerData,
                                        &EstablisherFrame,
                                        &ContextPointers);

                *Context = UnwindContext;
            } else {
                Context->Rip = *(PULONG64)(Context->Rsp);
                Context->Rsp += sizeof (ULONG64);
            }

            RSP = Context->Rsp;
            RIP = Context->Rip;

            Index = 0;
            Offset = 0;
            for (;;) {
                if (Index == PARAMETER_COUNT)
                    break;

                Parameter[Index] = *(PULONG64)(RSP + Offset);

                Index += 1;
                Offset += 8;
            }

            ModuleLookup(RIP, &Name, &Offset);

            if (Name != NULL)
                LogPrintf(LOG_LEVEL_CRITICAL,
                          "%s|BUGCHECK: %016X: (%016X %016X %016X %016X) %s + %p\n",
                          __MODULE__,
                          RSP,
                          Parameter[0],
                          Parameter[1],
                          Parameter[2],
                          Parameter[3],
                          Name,
                          (PVOID)Offset);
            else
                LogPrintf(LOG_LEVEL_CRITICAL,
                          "%s|BUGCHECK: %016X: (%016X %016X %016X %016X) %p\n",
                          __MODULE__,
                          RSP,
                          Parameter[0],
                          Parameter[1],
                          Parameter[2],
                          Parameter[3],
                          (PVOID)RIP);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}
#else
#error 'Unrecognised architecture'
#endif

extern VOID
RtlCaptureContext(
    __out PCONTEXT    Context
    );

static VOID
BugCheckIrqlNotLessOrEqual(
    IN  ULONG_PTR   Parameter1,
    IN  ULONG_PTR   Parameter2,
    IN  ULONG_PTR   Parameter3,
    IN  ULONG_PTR   Parameter4
    )
{
    __try {
        CONTEXT     Context;
        PVOID       Memory = (PVOID)Parameter1;
        KIRQL       Irql = (KIRQL)Parameter2;
        ULONG_PTR   Access = Parameter3;
        PVOID       Address = (PVOID)Parameter4;
        PCHAR       Name;
        ULONG_PTR   Offset;

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: MEMORY REFERENCED: %p\n",
                  __MODULE__,
                  Memory);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK:              IRQL: %02x\n",
                  __MODULE__,
                  Irql);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK:            ACCESS: %p\n",
                  __MODULE__,
                  (PVOID)Access);

        ModuleLookup((ULONG_PTR)Address, &Name, &Offset);

        if (Name != NULL)
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK:           ADDRESS: %s + %p\n",
                      __MODULE__,
                      Name,
                      Offset);
        else
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK:           ADDRESS: %p\n",
                      __MODULE__,
                      Address);

        RtlCaptureContext(&Context);
        BugCheckStackDump(&Context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

static VOID
BugCheckDriverIrqlNotLessOrEqual(
    IN  ULONG_PTR   Parameter1,
    IN  ULONG_PTR   Parameter2,
    IN  ULONG_PTR   Parameter3,
    IN  ULONG_PTR   Parameter4
    )
{
    __try {
        CONTEXT     Context;
        PVOID       Memory = (PVOID)Parameter1;
        KIRQL       Irql = (KIRQL)Parameter2;
        ULONG_PTR   Access = Parameter3;
        PVOID       Address = (PVOID)Parameter4;
        PCHAR       Name;
        ULONG_PTR   Offset;

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: MEMORY REFERENCED: %p\n",
                  __MODULE__,
                  Memory);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK:              IRQL: %02X\n",
                  __MODULE__,
                  Irql);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK:            ACCESS: %p\n",
                  __MODULE__,
                  (PVOID)Access);

        ModuleLookup((ULONG_PTR)Address, &Name, &Offset);

        if (Name != NULL)
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK:           ADDRESS: %s + %p\n",
                      __MODULE__,
                      Name,
                      Offset);
        else
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK:           ADDRESS: %p\n",
                      __MODULE__,
                      Address);

        RtlCaptureContext(&Context);
        BugCheckStackDump(&Context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

static VOID
BugCheckSystemServiceException(
    IN  ULONG_PTR   Parameter1,
    IN  ULONG_PTR   Parameter2,
    IN  ULONG_PTR   Parameter3,
    IN  ULONG_PTR   Parameter4
    )
{
    __try {
        PEXCEPTION_RECORD   Exception = (PEXCEPTION_RECORD)Parameter2;
        PCONTEXT            Context = (PCONTEXT)Parameter3;

        UNREFERENCED_PARAMETER(Parameter1);
        UNREFERENCED_PARAMETER(Parameter4);

        BugCheckDumpExceptionRecord(Exception);

        BugCheckStackDump(Context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

static VOID
BugCheckSystemThreadExceptionNotHandled(
    IN  ULONG_PTR   Parameter1,
    IN  ULONG_PTR   Parameter2,
    IN  ULONG_PTR   Parameter3,
    IN  ULONG_PTR   Parameter4
    )
{
    __try {
        ULONG               Code = (ULONG)Parameter1;
        PVOID               Address = (PVOID)Parameter2;
        PEXCEPTION_RECORD   Exception = (PEXCEPTION_RECORD)Parameter3;
        PCONTEXT            Context = (PCONTEXT)Parameter4;
        PCHAR               Name;
        ULONG_PTR           Offset;

        ModuleLookup((ULONG_PTR)Address, &Name, &Offset);

        if (Name != NULL)
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: %08X AT %s + %p\n",
                      __MODULE__,
                      Code,
                      Name,
                      Offset);
        else
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: %08X AT %p\n",
                      __MODULE__,
                      Code,
                      Name,
                      Address);

        BugCheckDumpExceptionRecord(Exception);

        BugCheckStackDump(Context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

static VOID
BugCheckKernelModeExceptionNotHandled(
    IN  ULONG_PTR   Parameter1,
    IN  ULONG_PTR   Parameter2,
    IN  ULONG_PTR   Parameter3,
    IN  ULONG_PTR   Parameter4
    )
{
    __try {
        CONTEXT     Context;
        ULONG       Code = (ULONG)Parameter1;
        PVOID       Address = (PVOID)Parameter2;
        PCHAR       Name;
        ULONG_PTR	Offset;

        UNREFERENCED_PARAMETER(Parameter3);
        UNREFERENCED_PARAMETER(Parameter4);

        ModuleLookup((ULONG_PTR)Address, &Name, &Offset);

        if (Name != NULL)
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: %08X AT %s + %p\n",
                      __MODULE__,
                      Code,
                      Name,
                      Offset);
        else
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: %08X AT %p\n",
                      __MODULE__,
                      Code,
                      Name,
                      Address);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: - Code = %08X\n",
                  __MODULE__,
                  Code);

        RtlCaptureContext(&Context);
        BugCheckStackDump(&Context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

static VOID
BugCheckCriticalObjectTermination(
    IN  ULONG_PTR   Parameter1,
    IN  ULONG_PTR   Parameter2,
    IN  ULONG_PTR   Parameter3,
    IN  ULONG_PTR   Parameter4
    )
{
    __try {
        ULONG       Type = (ULONG)Parameter1;
        PVOID	    Object = (PVOID)Parameter2;
        PCHAR	    Name = (PCHAR)Parameter3;
        PCHAR       Reason = (PCHAR)Parameter4;
        CONTEXT     Context;

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: Type = %08X\n",
                  __MODULE__,
                  Type);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: Object = %p\n",
                  __MODULE__,
                  Object);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: Name = %s\n",
                  __MODULE__,
                  Name);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: Reason = %s\n",
                  __MODULE__,
                  Reason);

        RtlCaptureContext(&Context);
        BugCheckStackDump(&Context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

static VOID
BugCheckInaccessibleBootDevice(
    IN  ULONG_PTR   Parameter1,
    IN  ULONG_PTR   Parameter2,
    IN  ULONG_PTR   Parameter3,
    IN  ULONG_PTR   Parameter4
    )
{
    __try {
        PUNICODE_STRING Unicode = (PUNICODE_STRING)Parameter1;
        CONTEXT         Context;

        UNREFERENCED_PARAMETER(Parameter2);
        UNREFERENCED_PARAMETER(Parameter3);
        UNREFERENCED_PARAMETER(Parameter4);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: %wZ\n",
                  __MODULE__,
                  Unicode);

        RtlCaptureContext(&Context);
        BugCheckStackDump(&Context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

static VOID
BugCheckDriverPowerStateFailure(
    IN  ULONG_PTR       Parameter1,
    IN  ULONG_PTR       Parameter2,
    IN  ULONG_PTR       Parameter3,
    IN  ULONG_PTR       Parameter4
    )
{
    __try {
        ULONG_PTR       Code = Parameter1;

        UNREFERENCED_PARAMETER(Parameter3);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: Code %08x\n",
                  __MODULE__,
                  Code);

        switch (Code) {
        case 0x1: {
            PDEVICE_OBJECT  DeviceObject = (PDEVICE_OBJECT)Parameter2;

            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: OUTSTANDING IRP (Device Object %p)\n",
                      __MODULE__,
                      DeviceObject);

            break;
        }
        case 0x3: {
            PDEVICE_OBJECT      DeviceObject = (PDEVICE_OBJECT)Parameter2;
            PIRP                Irp = (PIRP)Parameter4;
            PIO_STACK_LOCATION  StackLocation;
            LONG                Index;

            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: OUTSTANDING IRP %p (Device Object %p)\n",
                      __MODULE__,
                      Irp,
                      DeviceObject);

            StackLocation = IoGetCurrentIrpStackLocation(Irp);

            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: IRP STACK:\n",
                      __MODULE__);	

            for (Index = 0; Index <= Irp->StackCount; Index++) {
                PCHAR       Name;
                ULONG_PTR   Offset;

                LogPrintf(LOG_LEVEL_CRITICAL,
                          "%s|BUGCHECK: [%c%u] %02x %02x %02x %02x\n",
                          __MODULE__,
                          (Index == Irp->CurrentLocation) ? '>' : ' ',
                          Index,
                          StackLocation->MajorFunction,
                          StackLocation->MinorFunction,
                          StackLocation->Flags,
                          StackLocation->Control);

                ModuleLookup((ULONG_PTR)StackLocation->CompletionRoutine, &Name, &Offset);

                if (Name != NULL)
                    LogPrintf(LOG_LEVEL_CRITICAL,
                              "%s|BUGCHECK: [%c%u] CompletionRoutine = %s + %p\n",
                              __MODULE__,
                              (Index == Irp->CurrentLocation) ? '>' : ' ',
                              Index,
                              Name,
                              (PVOID)Offset);
                else
                    LogPrintf(LOG_LEVEL_CRITICAL,
                              "%s|BUGCHECK: [%c%u] CompletionRoutine = %p\n",
                              __MODULE__,
                              (Index == Irp->CurrentLocation) ? '>' : ' ',
                              Index,
                              StackLocation->CompletionRoutine);

                LogPrintf(LOG_LEVEL_CRITICAL,
                          "%s|BUGCHECK: [%c%u] Context = %p\n",
                          __MODULE__,
                          (Index == Irp->CurrentLocation) ? '>' : ' ',
                          Index,
                          StackLocation->Context);

                StackLocation++;
            } 

            break;
        }
        default:
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

static VOID
BugCheckAssertionFailure(
    IN  ULONG_PTR   Parameter1,
    IN  ULONG_PTR   Parameter2,
    IN  ULONG_PTR   Parameter3,
    IN  ULONG_PTR   Parameter4
    )
{
    __try {
        PCHAR       Text = (PCHAR)Parameter1;
        PCHAR       File = (PCHAR)Parameter2;
        ULONG       Line = (ULONG)Parameter3;
        CONTEXT     Context;

        UNREFERENCED_PARAMETER(Parameter4);

        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: FILE: %s LINE: %u\n", __MODULE__,
                  File,
                  Line);
        LogPrintf(LOG_LEVEL_CRITICAL,
                  "%s|BUGCHECK: TEXT: %s\n", __MODULE__,
                  Text);

        RtlCaptureContext(&Context);
        BugCheckStackDump(&Context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

struct _BUG_CODE_ENTRY {
    ULONG       Code;
    const CHAR  *Name;
    VOID        (*Handler)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
};

#define DEFINE_HANDLER(_Code, _Function) \
        { (_Code), #_Code, (_Function) }

struct _BUG_CODE_ENTRY   BugCodeTable[] = {
    DEFINE_HANDLER(IRQL_NOT_LESS_OR_EQUAL, BugCheckIrqlNotLessOrEqual),
    DEFINE_HANDLER(DRIVER_IRQL_NOT_LESS_OR_EQUAL, BugCheckDriverIrqlNotLessOrEqual),
    DEFINE_HANDLER(SYSTEM_SERVICE_EXCEPTION, BugCheckSystemServiceException),
    DEFINE_HANDLER(SYSTEM_THREAD_EXCEPTION_NOT_HANDLED, BugCheckSystemThreadExceptionNotHandled),
    DEFINE_HANDLER(SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M, BugCheckSystemThreadExceptionNotHandled),
    DEFINE_HANDLER(KERNEL_MODE_EXCEPTION_NOT_HANDLED, BugCheckKernelModeExceptionNotHandled),
    DEFINE_HANDLER(KERNEL_MODE_EXCEPTION_NOT_HANDLED_M, BugCheckKernelModeExceptionNotHandled),
    DEFINE_HANDLER(CRITICAL_OBJECT_TERMINATION, BugCheckCriticalObjectTermination),
    DEFINE_HANDLER(INACCESSIBLE_BOOT_DEVICE, BugCheckInaccessibleBootDevice),
    DEFINE_HANDLER(DRIVER_POWER_STATE_FAILURE, BugCheckDriverPowerStateFailure),
    DEFINE_HANDLER(ASSERTION_FAILURE, BugCheckAssertionFailure),
    { 0, NULL, NULL }
};

static VOID
BugCheckDefaultHandler(
    VOID
    )
{
    __try {
        CONTEXT Context;

        RtlCaptureContext(&Context);
        BugCheckStackDump(&Context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

#pragma warning(pop)

KBUGCHECK_CALLBACK_ROUTINE BugCheckBugCheckCallback;

VOID                     
BugCheckBugCheckCallback(
    IN  PVOID               Argument,
    IN  ULONG               Length
    )
{
    extern PULONG_PTR       KiBugCheckData;
    ULONG                   Code;
    ULONG_PTR               Parameter1;
    ULONG_PTR               Parameter2;
    ULONG_PTR               Parameter3;
    ULONG_PTR               Parameter4;
    struct _BUG_CODE_ENTRY  *Entry;

    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Length);

    (VOID) SchedShutdownCode(SHUTDOWN_crash);

    LogPrintf(LOG_LEVEL_CRITICAL,
              "%s|BUGCHECK: ====>\n",
              __MODULE__);

    Code = (ULONG)KiBugCheckData[0];
    Parameter1 = KiBugCheckData[1];
    Parameter2 = KiBugCheckData[2];
    Parameter3 = KiBugCheckData[3];
    Parameter4 = KiBugCheckData[4];

    for (Entry = BugCodeTable; Entry->Code != 0; Entry++) {
        if (Code == Entry->Code) {
            LogPrintf(LOG_LEVEL_CRITICAL,
                      "%s|BUGCHECK: %s: %p %p %p %p\n",
                      __MODULE__,
                      Entry->Name,
                      (PVOID)Parameter1,
                      (PVOID)Parameter2,
                      (PVOID)Parameter3,
                      (PVOID)Parameter4);

            Entry->Handler(Parameter1,
                           Parameter2,
                           Parameter3,
                           Parameter4);

            goto done;
        }
    }

    LogPrintf(LOG_LEVEL_CRITICAL,
              "%s|BUGCHECK: %08X: %p %p %p %p\n",
              __MODULE__,
              Code,
              (PVOID)Parameter1,
              (PVOID)Parameter2,
              (PVOID)Parameter3,
              (PVOID)Parameter4);

    BugCheckDefaultHandler();

done:
    LogPrintf(LOG_LEVEL_CRITICAL,
              "%s|BUGCHECK: <====\n",
              __MODULE__);
}

#pragma warning(pop)

NTSTATUS
BugCheckInitialize(
    VOID)
{
    NTSTATUS    status;

    KeInitializeCallbackRecord(&BugCheckBugCheckCallbackRecord);

    status = STATUS_UNSUCCESSFUL;
    if (!KeRegisterBugCheckCallback(&BugCheckBugCheckCallbackRecord,
                                    BugCheckBugCheckCallback,
                                    NULL,
                                    0,
                                    (PUCHAR)__MODULE__))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}
