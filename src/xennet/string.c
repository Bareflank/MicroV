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

#include <ntddk.h>

#include "string.h"
#include "dbg_print.h"
#include "assert.h"

static FORCEINLINE NTSTATUS
__StringPut(
    IN  PSTRING String,
    IN  CHAR    Character
    )
{
    if (String->Length >= String->MaximumLength - 1)
        return STATUS_BUFFER_OVERFLOW;

    String->Buffer[String->Length++] = Character;
    return STATUS_SUCCESS;
}

static PCHAR
FormatNumber(
    IN  PCHAR       Buffer,
    IN  ULONGLONG   Value,
    IN  UCHAR       Base,
    IN  BOOLEAN     UpperCase
    )
{
    ULONGLONG       Next = Value / Base;

    if (Next != 0)
        Buffer = FormatNumber(Buffer, Next, Base, UpperCase);

    Value %= Base;

    if (Value < 10)
        *Buffer++ = '0' + (CHAR)Value;
    else
        *Buffer++ = ((UpperCase) ? 'A' : 'a') + (CHAR)(Value - 10);

    *Buffer = '\0';

    return Buffer;
}

#define FORMAT_NUMBER(_Arguments, _Type, _Character, _Buffer)                               \
        do {                                                                                \
            U ## _Type  _Value = va_arg((_Arguments), U ## _Type);                          \
            BOOLEAN     _UpperCase = FALSE;                                                 \
            UCHAR       _Base = 0;                                                          \
            ULONG       _Index = 0;                                                         \
                                                                                            \
            if ((_Character) == 'd' && (_Type)_Value < 0) {                                 \
                _Value = -((_Type)_Value);                                                  \
                (_Buffer)[_Index++] = '-';                                                  \
            }                                                                               \
                                                                                            \
            switch (_Character) {                                                           \
            case 'o':                                                                       \
                _Base = 8;                                                                  \
                break;                                                                      \
                                                                                            \
            case 'd':                                                                       \
            case 'u':                                                                       \
                _Base = 10;                                                                 \
                break;                                                                      \
                                                                                            \
            case 'p':                                                                       \
            case 'X':                                                                       \
                _UpperCase = TRUE;                                                          \
                /* FALLTHRU */                                                              \
                                                                                            \
            case 'x':                                                                       \
                _Base = 16;                                                                 \
                break;                                                                      \
            }                                                                               \
                                                                                            \
            (VOID) FormatNumber(&(_Buffer)[_Index], (ULONGLONG)_Value, _Base, _UpperCase);  \
        } while (FALSE)

static NTSTATUS
StringWriteBuffer(
    IN  PSTRING         String,
    IN  const CHAR      *Format,
    IN  va_list         Arguments
    )
{
    CHAR                Character;
    NTSTATUS            status;

    status = STATUS_SUCCESS;

    while ((Character = *Format++) != '\0') {
        UCHAR   Pad = 0;
        UCHAR   Long = 0;
        BOOLEAN Wide = FALSE;
        BOOLEAN ZeroPrefix = FALSE;
        BOOLEAN OppositeJustification = FALSE;

        if (Character != '%') {
            status = __StringPut(String, Character);
            if (!NT_SUCCESS(status))
                goto done;

            continue;
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

                status = __StringPut(String, (CHAR)Value);
                if (!NT_SUCCESS(status))
                    goto done;
            } else {
                CHAR    Value;

                Value = va_arg(Arguments, CHAR);

                status = __StringPut(String, Value);
                if (!NT_SUCCESS(status))
                    goto done;
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
                FORMAT_NUMBER(Arguments, LONGLONG, Character, Buffer);
            else
                FORMAT_NUMBER(Arguments, LONG, Character, Buffer);

            Length = (ULONG)strlen(Buffer);
            if (!OppositeJustification) {
                while (Pad > Length) {
                    status = __StringPut(String, (ZeroPrefix) ? '0' : ' ');
                    if (!NT_SUCCESS(status))
                        goto done;

                    --Pad;
                }
            }

            for (Index = 0; Index < Length; Index++) {
                status = __StringPut(String, Buffer[Index]);
                if (!NT_SUCCESS(status))
                    goto done;
            }

            if (OppositeJustification) {
                while (Pad > Length) {
                    status = __StringPut(String, ' ');
                    if (!NT_SUCCESS(status))
                        goto done;

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
                        status = __StringPut(String, ' ');
                        if (!NT_SUCCESS(status))
                            goto done;

                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++) {
                    status = __StringPut(String, (CHAR)Value[Index]);
                    if (!NT_SUCCESS(status))
                        goto done;
                }

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        status = __StringPut(String, ' ');
                        if (!NT_SUCCESS(status))
                            goto done;

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
                        status = __StringPut(String, ' ');
                        if (!NT_SUCCESS(status))
                            goto done;

                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++) {
                    status = __StringPut(String, Value[Index]);
                    if (!NT_SUCCESS(status))
                        goto done;
                }

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        status = __StringPut(String, ' ');
                        if (!NT_SUCCESS(status))
                            goto done;

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
                        status = __StringPut(String, ' ');
                        if (!NT_SUCCESS(status))
                            goto done;

                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++) {
                    status = __StringPut(String, (CHAR)Buffer[Index]);
                    if (!NT_SUCCESS(status))
                        goto done;
                }

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        status = __StringPut(String, ' ');
                        if (!NT_SUCCESS(status))
                            goto done;

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
                        status = __StringPut(String, ' ');
                        if (!NT_SUCCESS(status))
                            goto done;

                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++) {
                    status = __StringPut(String, Buffer[Index]);
                    if (!NT_SUCCESS(status))
                        goto done;
                }

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        status = __StringPut(String, ' ');
                        if (!NT_SUCCESS(status))
                            goto done;

                        --Pad;
                    }
                }
            }

            break;
        }
        default:
            status = __StringPut(String, Character);
            if (!NT_SUCCESS(status))
                goto done;

            break;
        }
    }

done:
    return status;
}

NTSTATUS
StringVPrintf(
    IN  PSTRING     String,
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    )
{
    NTSTATUS        status;

    status = StringWriteBuffer(String,
                               Format,
                               Arguments);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = __StringPut(String, '\0');
    if (!NT_SUCCESS(status))
        goto fail2;

    // Length should not include the NUL terminator
    --String->Length;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
StringPrintf(
    IN  PSTRING     String,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;
    NTSTATUS        status;

    va_start(Arguments, Format);
    status = StringVPrintf(String, Format, Arguments);
    va_end(Arguments);

    return status;
}
