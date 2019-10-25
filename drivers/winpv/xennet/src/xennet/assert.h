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

#ifndef _XENNET_ASSERT_H
#define _XENNET_ASSERT_H

#include <ntddk.h>

#include "dbg_print.h"

static FORCEINLINE VOID
__Bug(
    IN  ULONG       Code,
    IN  ULONG_PTR   Parameter1,
    IN  ULONG_PTR   Parameter2,
    IN  ULONG_PTR   Parameter3,
    IN  ULONG_PTR   Parameter4
    )
{
#pragma prefast(suppress:28159)
    KeBugCheckEx(Code,
                 Parameter1,
                 Parameter2,
                 Parameter3,
                 Parameter4);
}

#define ASSERTION_FAILURE   0x0000DEAD

#define BUG(_TEXT)                                              \
        do {                                                    \
            const CHAR  *_Text = (_TEXT);                       \
            const CHAR  *_File = __FILE__;                      \
            ULONG       _Line = __LINE__;                       \
                                                                \
            Error("BUG: " _TEXT "\n");                          \
            __Bug(ASSERTION_FAILURE,                            \
                  (ULONG_PTR)_Text,                             \
                  (ULONG_PTR)_File,                             \
                  (ULONG_PTR)_Line,                             \
                  0);                                           \
        } while (FALSE)

#define BUG_ON(_EXP)                \
        if (_EXP) BUG(#_EXP)

#undef  ASSERT

#if DBG

#define __NT_ASSERT(_EXP)                                       \
        ((!(_EXP)) ?                                            \
        (Error("ASSERTION FAILED: " #_EXP "\n"),                \
         __annotation(L"Debug", L"AssertFail", L#_EXP),         \
         DbgRaiseAssertionFailure(), FALSE) :                   \
        TRUE)

#define __ASSERT(_EXP)  __NT_ASSERT(_EXP)

#define ASSERT(_EXP)                    \
        do {                            \
            __ASSERT(_EXP);             \
            __analysis_assume(_EXP);    \
        } while (FALSE)

#define ASSERT3U(_X, _OP, _Y)                       \
        do {                                        \
            ULONGLONG   _Lval = (ULONGLONG)(_X);    \
            ULONGLONG   _Rval = (ULONGLONG)(_Y);    \
            if (!(_Lval _OP _Rval)) {               \
                Error("%s = %llu\n", #_X, _Lval);   \
                Error("%s = %llu\n", #_Y, _Rval);   \
                ASSERT((_X) _OP (_Y));              \
            }                                       \
        } while (FALSE)

#define ASSERT3S(_X, _OP, _Y)                       \
        do {                                        \
            LONGLONG    _Lval = (LONGLONG)(_X);     \
            LONGLONG    _Rval = (LONGLONG)(_Y);     \
            if (!(_Lval _OP _Rval)) {               \
                Error("%s = %lld\n", #_X, _Lval);   \
                Error("%s = %lld\n", #_Y, _Rval);   \
                ASSERT((_X) _OP (_Y));              \
            }                                       \
        } while (FALSE)

#define ASSERT3P(_X, _OP, _Y)                       \
        do {                                        \
            PVOID   _Lval = (PVOID)(_X);            \
            PVOID   _Rval = (PVOID)(_Y);            \
            if (!(_Lval _OP _Rval)) {               \
                Error("%s = %p\n", #_X, _Lval);     \
                Error("%s = %p\n", #_Y, _Rval);     \
                ASSERT((_X) _OP (_Y));              \
            }                                       \
        } while (FALSE)

#else   // DBG

#pragma warning(disable:4100)
#pragma warning(disable:4189)

#define ASSERT(_EXP)                    \
        do {                            \
            __analysis_assume(_EXP);    \
        } while (FALSE)

#define ASSERT3U(_X, _OP, _Y)           \
        ASSERT((_X) _OP (_Y))

#define ASSERT3S(_X, _OP, _Y)           \
        ASSERT((_X) _OP (_Y))

#define ASSERT3P(_X, _OP, _Y)           \
        ASSERT((_X) _OP (_Y))

#endif  // DBG

#ifndef TEST_MEMORY
#define TEST_MEMORY DBG
#endif

#if TEST_MEMORY

static __inline BOOLEAN
_IsZeroMemory(
    IN  const PCHAR Caller,
    IN  const PCHAR Name,
    IN  PVOID       Buffer,
    IN  ULONG       Length
    )
{
    ULONG           Offset;

    Offset = 0;
    while (Offset < Length) {
        if (*((PUCHAR)Buffer + Offset) != 0) {
            Error("%s: non-zero byte in %s (0x%p+0x%x)\n", Caller, Name, Buffer, Offset);
            return FALSE;
        }
        Offset++;
    }

    return TRUE;
}

#else   // TEST_MEMORY

static __inline BOOLEAN
_IsZeroMemory(
    IN  const PCHAR Caller,
    IN  const PCHAR Name,
    IN  PVOID       Buffer,
    IN  ULONG       Length
    )
{
    UNREFERENCED_PARAMETER(Caller);
    UNREFERENCED_PARAMETER(Name);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);

    return TRUE;
}

#endif  // TEST_MEMORY

#define IsZeroMemory(_Buffer, _Length) \
        _IsZeroMemory(__FUNCTION__, #_Buffer, (_Buffer), (_Length))

#define IMPLY(_X, _Y)   (!(_X) || (_Y))
#define EQUIV(_X, _Y)   (IMPLY((_X), (_Y)) && IMPLY((_Y), (_X)))

#endif  // _XENNET_ASSERT_H
