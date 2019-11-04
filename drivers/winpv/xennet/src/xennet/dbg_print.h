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

#ifndef _XENNET_DBG_PRINT_H
#define _XENNET_DBG_PRINT_H

#include <ntddk.h>
#include <stdarg.h>

#define stringify_literal(_text) #_text
#define stringify(_text) stringify_literal(_text)
#define __MODULE__ stringify(PROJECT)

#pragma warning(disable:4127)   // conditional expression is constant

static __inline VOID
__Error(
    IN  const CHAR  *Prefix,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);

#pragma prefast(suppress:6001) // Using uninitialized memory
    vDbgPrintExWithPrefix(Prefix,
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_ERROR_LEVEL,
                          Format,
                          Arguments);
    va_end(Arguments);
}

#define Error(...)  \
        __Error(__MODULE__ "|" __FUNCTION__ ": ", __VA_ARGS__)

static __inline VOID
__Warning(
    IN  const CHAR  *Prefix,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);

#pragma prefast(suppress:6001) // Using uninitialized memory
    vDbgPrintExWithPrefix(Prefix,
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_WARNING_LEVEL,
                          Format,
                          Arguments);
    va_end(Arguments);
}

#define Warning(...)  \
        __Warning(__MODULE__ "|" __FUNCTION__ ": ", __VA_ARGS__)

#if DBG
static __inline VOID
__Trace(
    IN  const CHAR  *Prefix,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);

#pragma prefast(suppress:6001) // Using uninitialized memory
    vDbgPrintExWithPrefix(Prefix,
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_TRACE_LEVEL,
                          Format,
                          Arguments);
    va_end(Arguments);
}

#define Trace(...)  \
        __Trace(__MODULE__ "|" __FUNCTION__ ": ", __VA_ARGS__)
#else   // DBG
#define Trace(...)  (VOID)(__VA_ARGS__)
#endif  // DBG

static __inline VOID
__Info(
    IN  const CHAR  *Prefix,
    IN  const CHAR  *Format,
    ...
    )
{
    va_list         Arguments;

    va_start(Arguments, Format);

#pragma prefast(suppress:6001) // Using uninitialized memory
    vDbgPrintExWithPrefix(Prefix,
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_INFO_LEVEL,
                          Format,
                          Arguments);
    va_end(Arguments);
}

#define Info(...)  \
        __Info(__MODULE__ "|"  __FUNCTION__ ": ", __VA_ARGS__)

#endif  // _XENNET_DBG_PRINT_H
