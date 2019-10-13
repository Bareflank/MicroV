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

#pragma warning(disable:4152)   // nonstandard extension, function/data pointer conversion in expression

#define XEN_API __declspec(dllexport)

#include <ntddk.h>
#include <stdlib.h>

#include "registry.h"
#include "log.h"
#include "assert.h"
#include "high.h"

#define LOG_BUFFER_SIZE 256

typedef struct _LOG_SLOT {
    LOG_LEVEL   Level;
    CHAR        Buffer[LOG_BUFFER_SIZE];
    ULONG       Offset;
} LOG_SLOT, *PLOG_SLOT;

struct _LOG_DISPOSITION {
    LOG_LEVEL   Mask;
    VOID        (*Function)(PVOID, PCHAR, ULONG);
    PVOID       Argument;
};

#define LOG_NR_SLOTS 32
#define LOG_NR_DISPOSITIONS 8

typedef struct _LOG_CONTEXT {
    LONG            References;
    BOOLEAN         Enabled;
    LOG_SLOT        Slot[LOG_NR_SLOTS];
    ULONG           Pending;
    LOG_DISPOSITION Disposition[LOG_NR_DISPOSITIONS];
    HIGH_LOCK       Lock;
    KDPC            Dpc;
} LOG_CONTEXT, *PLOG_CONTEXT;

static LOG_CONTEXT  LogContext;

static FORCEINLINE VOID
__LogFlushSlot(
    IN  PLOG_CONTEXT    Context,
    IN  PLOG_SLOT       Slot
    )
{
    ULONG               Index;

    for (Index = 0; Index < LOG_NR_DISPOSITIONS; Index++) {
        PLOG_DISPOSITION    Disposition = &Context->Disposition[Index];

        if (Slot->Level & Disposition->Mask)
            Disposition->Function(Disposition->Argument, Slot->Buffer,
                                  Slot->Offset);
    }

    RtlZeroMemory(Slot->Buffer, Slot->Offset);
    Slot->Offset = 0;
    Slot->Level = 0;
}

static VOID
LogFlush(
    IN  PLOG_CONTEXT    Context
    )
{
    ULONG               Index;

    for (Index = 0; Index < Context->Pending; Index++)
    {
        PLOG_SLOT   Slot = &Context->Slot[Index];

        __LogFlushSlot(Context, Slot);
    }

    Context->Pending = 0;
}

static FORCEINLINE VOID
__LogPut(
    IN  PLOG_SLOT   Slot,
    IN  CHAR        Character
    )
{
    if (Slot->Offset >= LOG_BUFFER_SIZE)
        return;

    Slot->Buffer[Slot->Offset++] = Character;
}

static PCHAR
LogFormatNumber(
    IN  PCHAR       Buffer,
    IN  ULONGLONG   Value,
    IN  UCHAR       Base,
    IN  BOOLEAN     UpperCase
    )
{
    ULONGLONG       Next = Value / Base;

    if (Next != 0)
        Buffer = LogFormatNumber(Buffer, Next, Base, UpperCase);

    Value %= Base;

    if (Value < 10)
        *Buffer++ = '0' + (CHAR)Value;
    else
        *Buffer++ = ((UpperCase) ? 'A' : 'a') + (CHAR)(Value - 10);

    *Buffer = '\0';

    return Buffer;
}

#define LOG_FORMAT_NUMBER(_Arguments, _Type, _Character, _Buffer)                               \
        do {                                                                                    \
            U ## _Type  _Value = va_arg((_Arguments), U ## _Type);                              \
            BOOLEAN     _UpperCase = FALSE;                                                     \
            UCHAR       _Base = 0;                                                              \
            ULONG       _Index = 0;                                                             \
                                                                                                \
            if ((_Character) == 'd' && (_Type)_Value < 0) {                                     \
                _Value = -((_Type)_Value);                                                      \
                (_Buffer)[_Index++] = '-';                                                      \
            }                                                                                   \
                                                                                                \
            switch (_Character) {                                                               \
            case 'o':                                                                           \
                _Base = 8;                                                                      \
                break;                                                                          \
                                                                                                \
            case 'd':                                                                           \
            case 'u':                                                                           \
                _Base = 10;                                                                     \
                break;                                                                          \
                                                                                                \
            case 'p':                                                                           \
            case 'X':                                                                           \
                _UpperCase = TRUE;                                                              \
                /* FALLTHRU */                                                                  \
                                                                                                \
            case 'x':                                                                           \
                _Base = 16;                                                                     \
                break;                                                                          \
            }                                                                                   \
                                                                                                \
            (VOID) LogFormatNumber(&(_Buffer)[_Index], (ULONGLONG)_Value, _Base, _UpperCase);   \
        } while (FALSE)

static VOID
LogWriteSlot(
    IN  PLOG_SLOT   Slot,
    IN  LONG        Count,
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    )
{
    CHAR            Character;

    while ((Character = *Format++) != '\0') {
        UCHAR   Pad = 0;
        UCHAR   Long = 0;
        BOOLEAN Wide = FALSE;
        BOOLEAN ZeroPrefix = FALSE;
        BOOLEAN OppositeJustification = FALSE;
        
        if (Character != '%') {
            __LogPut(Slot, Character);
            goto loop;
        }

        Character = *Format++;
        ASSERT(Character != '\0');

        if (Character == '-') {
            OppositeJustification = TRUE;
            Character = *Format++;
            ASSERT(Character != '\0');
        }

        if (isdigit((unsigned char)Character)) {
            ZeroPrefix = (Character == '0') ? TRUE : FALSE;

            while (isdigit((unsigned char)Character)) {
                Pad = (Pad * 10) + (Character - '0');
                Character = *Format++;
                ASSERT(Character != '\0');
            }
        }

        while (Character == 'l') {
            Long++;
            Character = *Format++;
            ASSERT(Character == 'd' ||
                   Character == 'u' ||
                   Character == 'o' ||
                   Character == 'x' ||
                   Character == 'X' ||
                   Character == 'l');
        }
        ASSERT3U(Long, <=, 2);

        while (Character == 'w') {
            Wide = TRUE;
            Character = *Format++;
            ASSERT(Character == 'c' ||
                   Character == 's' ||
                   Character == 'Z');
        }

        switch (Character) {
        case 'c': {
            if (Wide) {
                WCHAR   Value;
                Value = va_arg(Arguments, WCHAR);

                __LogPut(Slot, (CHAR)Value);
            } else { 
                CHAR    Value;

                Value = va_arg(Arguments, CHAR);

                __LogPut(Slot, Value);
            }
            break;
        }
        case 'p':
            ZeroPrefix = TRUE;
            Pad = sizeof (ULONG_PTR) * 2;
            Long = sizeof (ULONG_PTR) / sizeof (ULONG);
            /* FALLTHRU */

        case 'd':
        case 'u':
        case 'o':
        case 'x':
        case 'X': {
            CHAR    Buffer[23]; // Enough for 8 bytes in octal plus the NUL terminator
            ULONG   Length;
            ULONG   Index;

            if (Long == 2)
                LOG_FORMAT_NUMBER(Arguments, LONGLONG, Character, Buffer);
            else
                LOG_FORMAT_NUMBER(Arguments, LONG, Character, Buffer);

            Length = (ULONG)strlen(Buffer);
            if (!OppositeJustification) {
                while (Pad > Length) {
                    __LogPut(Slot, (ZeroPrefix) ? '0' : ' ');
                    --Pad;
                }
            }
            for (Index = 0; Index < Length; Index++)
                __LogPut(Slot, Buffer[Index]);
            if (OppositeJustification) {
                while (Pad > Length) {
                    __LogPut(Slot, ' ');
                    --Pad;
                }
            }

            break;
        }
        case 's': {
            if (Wide) {
                PWCHAR  Value = va_arg(Arguments, PWCHAR);
                ULONG   Length;
                ULONG   Index;

                if (Value == NULL)
                    Value = L"(null)";

                Length = (ULONG)wcslen(Value);

                if (OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(Slot, ' ');
                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++)
                    __LogPut(Slot, (CHAR)Value[Index]);

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(Slot, ' ');
                        --Pad;
                    }
                }
            } else {
                PCHAR   Value = va_arg(Arguments, PCHAR);
                ULONG   Length;
                ULONG   Index;

                if (Value == NULL)
                    Value = "(null)";

                Length = (ULONG)strlen(Value);

                if (OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(Slot, ' ');
                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++)
                    __LogPut(Slot, Value[Index]);

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(Slot, ' ');
                        --Pad;
                    }
                }
            }

            break;
        }
        case 'Z': {
            if (Wide) {
                PUNICODE_STRING Value = va_arg(Arguments, PUNICODE_STRING);
                PWCHAR          Buffer;
                ULONG           Length;
                ULONG           Index;

                if (Value == NULL) {
                    Buffer = L"(null)";
                    Length = sizeof ("(null)") - 1;
                } else {
                    Buffer = Value->Buffer;
                    Length = Value->Length / sizeof (WCHAR);
                }

                if (OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(Slot, ' ');
                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++)
                    __LogPut(Slot, (CHAR)Buffer[Index]);

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(Slot, ' ');
                        --Pad;
                    }
                }
            } else {
                PANSI_STRING Value = va_arg(Arguments, PANSI_STRING);
                PCHAR        Buffer;
                ULONG        Length;
                ULONG        Index;

                if (Value == NULL) {
                    Buffer = "(null)";
                    Length = sizeof ("(null)") - 1;
                } else {
                    Buffer = Value->Buffer;
                    Length = Value->Length / sizeof (CHAR);
                }

                if (OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(Slot, ' ');
                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++)
                    __LogPut(Slot, Buffer[Index]);

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(Slot, ' ');
                        --Pad;
                    }
                }
            }

            break;
        }
        default:
            __LogPut(Slot, Character);
            break;
        }

loop:
        if (--Count == 0)
            break;
    }
}

XEN_API
VOID
LogCchVPrintf(
    IN  LOG_LEVEL   Level,
    IN  ULONG       Count,
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    )
{
    PLOG_CONTEXT    Context = &LogContext;
    PLOG_SLOT       Slot;
    KIRQL           Irql;

    AcquireHighLock(&Context->Lock, &Irql);

    if (Context->Pending == ARRAYSIZE(Context->Slot))
        LogFlush(Context);

    Slot = &Context->Slot[Context->Pending++];

    Slot->Level = Level;
    LogWriteSlot(Slot,
                 __min(Count, LOG_BUFFER_SIZE),
                 Format,
                 Arguments);

    LogFlush(Context);

    ReleaseHighLock(&Context->Lock, Irql);
}

XEN_API
VOID
LogVPrintf(
    IN  LOG_LEVEL   Level,
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    )
{
    LogCchVPrintf(Level, LOG_BUFFER_SIZE, Format, Arguments);
}

XEN_API
VOID
LogCchPrintf(
    IN  LOG_LEVEL   Level,
    IN  ULONG       Count,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);
    LogCchVPrintf(Level, Count, Format, Arguments);
    va_end(Arguments);
}

XEN_API
VOID
LogPrintf(
    IN  LOG_LEVEL   Level,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);
    LogCchVPrintf(Level, LOG_BUFFER_SIZE, Format, Arguments);
    va_end(Arguments);
}

typedef VOID
(*DBG_PRINT_CALLBACK)(
    PANSI_STRING    Ansi,
    ULONG           ComponentId,
    ULONG           Level
    );

static
_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
LogDpc(
    IN  PKDPC       Dpc,
    IN  PVOID       _Context,
    IN  PVOID       Argument1,
    IN  PVOID       Argument2
    )
{
    PLOG_CONTEXT    Context = &LogContext;
    KIRQL           Irql;

    UNREFERENCED_PARAMETER(_Context);
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    AcquireHighLock(&Context->Lock, &Irql);
    LogFlush(Context);
    ReleaseHighLock(&Context->Lock, Irql);
}

static VOID
LogDebugPrint(
    IN  PANSI_STRING    Ansi,
    IN  ULONG           ComponentId,
    IN  ULONG           Level
    )
{
    PLOG_CONTEXT        Context = &LogContext;
    KIRQL               Irql;
    PLOG_SLOT           Slot;

    UNREFERENCED_PARAMETER(ComponentId);

    if (Ansi->Length == 0 || Ansi->Buffer == NULL)
        return;

    // If this is not a debug build then apply an aggressive
    // filter to reduce the noise.
#if !DBG
    if (Ansi->Length < sizeof ("xen"))
        return;

    if (Ansi->Buffer[0] != 'x' ||
        Ansi->Buffer[1] != 'e' ||
        Ansi->Buffer[2] != 'n')
        return;
#endif

    AcquireHighLock(&Context->Lock, &Irql);

    if (Context->Pending == ARRAYSIZE(Context->Slot))
        LogFlush(Context);

    Slot = &Context->Slot[Context->Pending++];

    Slot->Level = 1 << Level;
    RtlCopyMemory(Slot->Buffer, Ansi->Buffer, Ansi->Length);
    Slot->Offset = Ansi->Length;

    ReleaseHighLock(&Context->Lock, Irql);

    KeInsertQueueDpc(&Context->Dpc, NULL, NULL);
}

VOID
LogTeardown(
    VOID
    )
{
    PLOG_CONTEXT    Context = &LogContext;

    if (Context->Enabled) {
        (VOID) DbgSetDebugPrintCallback(LogDebugPrint, FALSE); 
        Context->Enabled = FALSE;
    }

    RtlZeroMemory(&Context->Dpc, sizeof (KDPC));
    RtlZeroMemory(&Context->Lock, sizeof (HIGH_LOCK));

    (VOID) InterlockedDecrement(&Context->References);

    ASSERT(IsZeroMemory(Context, sizeof (LOG_CONTEXT)));
}

NTSTATUS
LogAddDisposition(
    IN  LOG_LEVEL           Mask,
    IN  VOID                (*Function)(PVOID, PCHAR, ULONG),
    IN  PVOID               Argument OPTIONAL,
    OUT PLOG_DISPOSITION    *Disposition
    )
{
    PLOG_CONTEXT            Context = &LogContext;
    KIRQL                   Irql;
    ULONG                   Index;
    NTSTATUS                status;

    *Disposition = NULL;
    if (Mask == LOG_LEVEL_NONE)
        goto ignore;

    AcquireHighLock(&Context->Lock, &Irql);

    status = STATUS_UNSUCCESSFUL;
    for (Index = 0; Index < LOG_NR_DISPOSITIONS; Index++) {
        *Disposition = &Context->Disposition[Index];

        if ((*Disposition)->Mask == 0) {
            (*Disposition)->Mask = Mask;
            (*Disposition)->Function = Function;
            (*Disposition)->Argument = Argument;

            status = STATUS_SUCCESS;
            break;
        }
    }

    if (!NT_SUCCESS(status))
        goto fail1;

    ReleaseHighLock(&Context->Lock, Irql);

ignore:
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    ReleaseHighLock(&Context->Lock, Irql);

    *Disposition = NULL;

    return status;
}

extern VOID
LogRemoveDisposition(
    IN  PLOG_DISPOSITION    Disposition
    )
{
    PLOG_CONTEXT            Context = &LogContext;
    KIRQL                   Irql;
    ULONG                   Index;

    if (Disposition == NULL)
        return;

    AcquireHighLock(&Context->Lock, &Irql);

    for (Index = 0; Index < LOG_NR_DISPOSITIONS; Index++) {
        if (&Context->Disposition[Index] != Disposition)
            continue;

        RtlZeroMemory(&Context->Disposition[Index], sizeof (LOG_DISPOSITION));
    }

    ReleaseHighLock(&Context->Lock, Irql);
}

static FORCEINLINE BOOLEAN
__LogDbgPrintCallbackEnable(
    VOID
    )
{
    CHAR            Key[] = "XEN:DBG_PRINT=";
    PANSI_STRING    Option;
    PCHAR           Value;
    BOOLEAN         Enable;
    NTSTATUS        status;

    Enable = TRUE;

    status = RegistryQuerySystemStartOption(Key, &Option);
    if (!NT_SUCCESS(status))
        goto done;

    Value = Option->Buffer + sizeof (Key) - 1;

    if (strcmp(Value, "OFF") == 0)
        Enable = FALSE;

    RegistryFreeSzValue(Option);

done:
    return Enable;
}

XEN_API
VOID
LogResume(
    VOID
    )
{
    PLOG_CONTEXT    Context = &LogContext;

    if (!Context->Enabled)
        return;

    (VOID) DbgSetDebugPrintCallback(LogDebugPrint, FALSE);
    (VOID) DbgSetDebugPrintCallback(LogDebugPrint, TRUE);
}

typedef struct _XEN_LOG_LEVEL_NAME {
    const CHAR      *Name;
    LOG_LEVEL       LogLevel;
} XEN_LOG_LEVEL_NAME, *PXEN_LOG_LEVEL_NAME;

static const XEN_LOG_LEVEL_NAME XenLogLevelNames[] = {
    {   "TRACE",    LOG_LEVEL_TRACE     },
    {   "INFO",     LOG_LEVEL_INFO      },
    {   "WARNING",  LOG_LEVEL_WARNING   },
    {   "ERROR",    LOG_LEVEL_ERROR,    },
    {   "CRITICAL", LOG_LEVEL_CRITICAL  }
};

XEN_API
NTSTATUS
LogReadLogLevel(
    IN  HANDLE      Key,
    IN  PCHAR       Name,
    OUT PLOG_LEVEL  LogLevel
    )
{
    PANSI_STRING    Values;
    ULONG           Type;
    ULONG           Index;
    NTSTATUS        status;

    status = RegistryQuerySzValue(Key,
                                  Name,
                                  &Type,
                                  &Values);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    if (Type != REG_MULTI_SZ)
        goto fail2;

    *LogLevel = LOG_LEVEL_NONE;
    for (Index = 0; Values[Index].Buffer != NULL; ++Index) {
        PANSI_STRING    Value = &Values[Index];
        ULONG           Level;

        for (Level = 0; Level < ARRAYSIZE(XenLogLevelNames); ++Level) {
            if (_stricmp(XenLogLevelNames[Level].Name, Value->Buffer) == 0) {
                *LogLevel |= XenLogLevelNames[Level].LogLevel;
                break;
            }
        }
    }

    RegistryFreeSzValue(Values);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RegistryFreeSzValue(Values);

fail1:
    Error("fail1 (%08x)\n", status);

    *LogLevel = LOG_LEVEL_NONE;

    return status;
}

NTSTATUS
LogInitialize(
    VOID
    )
{
    PLOG_CONTEXT    Context = &LogContext;
    ULONG           References;
    NTSTATUS        status;

    References = InterlockedIncrement(&Context->References);

    status = STATUS_OBJECTID_EXISTS;
    if (References != 1)
        goto fail1;

    InitializeHighLock(&Context->Lock);

    KeInitializeDpc(&Context->Dpc, LogDpc, NULL);

    if (__LogDbgPrintCallbackEnable()) {
        status = DbgSetDebugPrintCallback(LogDebugPrint, TRUE);

        ASSERT(!Context->Enabled);
        Context->Enabled = NT_SUCCESS(status) ? TRUE : FALSE;
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}
