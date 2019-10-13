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

#ifndef _COMMON_HIGH_H
#define _COMMON_HIGH_H

#include <ntddk.h>

#pragma warning(disable:4127)   // conditional expression is constant

typedef LONG    HIGH_LOCK, *PHIGH_LOCK;

#define LOCK_MAGIC  0xFEEDFACE

static FORCEINLINE
__drv_maxIRQL(HIGH_LEVEL)
__drv_raisesIRQL(HIGH_LEVEL)
__drv_savesIRQL
KIRQL
__AcquireHighLock(
    IN  PHIGH_LOCK  Lock
    )
{
    KIRQL           Irql;

    KeRaiseIrql(HIGH_LEVEL, &Irql);

    while (InterlockedCompareExchange(Lock, LOCK_MAGIC, 0) != 0)
        _mm_pause();

    KeMemoryBarrier();

    return Irql;
}

#define AcquireHighLock(_Lock, _Irql)               \
        do {                                        \
            *(_Irql) = __AcquireHighLock(_Lock);    \
        } while (FALSE)

static FORCEINLINE
__drv_maxIRQL(HIGH_LEVEL)
__drv_requiresIRQL(HIGH_LEVEL)
VOID
ReleaseHighLock(
    IN  PHIGH_LOCK                  Lock,
    IN  __drv_restoresIRQL KIRQL    Irql
    )
{
    KeMemoryBarrier();

    InterlockedExchange(Lock, 0);
    KeLowerIrql(Irql);
}

static FORCEINLINE
VOID
InitializeHighLock(
    IN  PHIGH_LOCK  Lock
    )
{
    RtlZeroMemory(&Lock, sizeof (HIGH_LOCK));
}

#endif  // _COMMON_HIGH_H
