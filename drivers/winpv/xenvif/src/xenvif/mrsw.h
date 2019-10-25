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

#ifndef _XENVIF_MRSW_H
#define _XENVIF_MRSW_H

#include <ntddk.h>

#include "assert.h"
#include "util.h"

#pragma warning(disable:4127)   // conditional expression is constant

typedef struct _XENVIF_MRSW_HOLDER {
    PKTHREAD    Thread;
    LONG        Level;
} XENVIF_MRSW_HOLDER, *PXENVIF_MRSW_HOLDER;

typedef struct _XENVIF_MRSW_LOCK {
    volatile LONG64 Mask;
    XENVIF_MRSW_HOLDER     Holder[64];
    KEVENT          Event;
} XENVIF_MRSW_LOCK, *PXENVIF_MRSW_LOCK;

C_ASSERT(RTL_FIELD_SIZE(XENVIF_MRSW_LOCK, Holder) == RTL_FIELD_SIZE(XENVIF_MRSW_LOCK, Mask) * 8 * sizeof (XENVIF_MRSW_HOLDER));

#define XENVIF_MRSW_EXCLUSIVE_SLOT  0

static FORCEINLINE VOID
InitializeMrswLock(
    IN  PXENVIF_MRSW_LOCK   Lock
    )
{
    LONG                    Slot;

    RtlZeroMemory(Lock, sizeof (XENVIF_MRSW_LOCK));

    for (Slot = 0; Slot < sizeof (Lock->Mask) * 8; Slot++)
        Lock->Holder[Slot].Level = -1;

    KeInitializeEvent(&Lock->Event, NotificationEvent, FALSE);
}

static FORCEINLINE BOOLEAN
__ClaimExclusive(
    IN  PXENVIF_MRSW_LOCK   Lock
    )
{
    LONG64                  Old;
    LONG64                  New;

    Old = 0;
    New = 1ll << XENVIF_MRSW_EXCLUSIVE_SLOT;

    return (InterlockedCompareExchange64(&Lock->Mask, New, Old) == Old) ? TRUE : FALSE;
}

static FORCEINLINE KIRQL
__drv_maxIRQL(APC_LEVEL)
__drv_raisesIRQL(DISPATCH_LEVEL)
__drv_savesIRQL
__AcquireMrswLockExclusive(
    IN  PXENVIF_MRSW_LOCK   Lock
    )
{
    KIRQL                   Irql;
    LONG                    Slot;
    PKTHREAD                Self;
    PXENVIF_MRSW_HOLDER     Holder;

    ASSERT3U(KeGetCurrentIrql(), <, DISPATCH_LEVEL);
    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    Self = KeGetCurrentThread();

    // Make sure we do not already hold the lock
    for (Slot = 0; Slot < sizeof (Lock->Mask) * 8; Slot++)
        ASSERT(Lock->Holder[Slot].Thread != Self);

    for (;;) {
        if (__ClaimExclusive(Lock))
            break;

        KeLowerIrql(Irql);

        (VOID) KeWaitForSingleObject(&Lock->Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(&Lock->Event);

        KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    }

    Holder = &Lock->Holder[XENVIF_MRSW_EXCLUSIVE_SLOT];

    ASSERT3P(Holder->Thread, ==, NULL);
    Holder->Thread = Self;
    Holder->Level = 0;

    return Irql;
}

#define AcquireMrswLockExclusive(_Lock, _Irql)              \
        do {                                                \
            *(_Irql) = __AcquireMrswLockExclusive(_Lock);   \
        } while (FALSE)

static FORCEINLINE VOID
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
ReleaseMrswLockExclusive(
    IN  PXENVIF_MRSW_LOCK           Lock,
    IN  __drv_restoresIRQL KIRQL    Irql,
    IN  BOOLEAN                     Shared
    )
{
    LONG                            Slot;
    PKTHREAD                        Self;
    LONG64                          Old;
    LONG64                          New;
    PXENVIF_MRSW_HOLDER             Holder;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Slot = XENVIF_MRSW_EXCLUSIVE_SLOT + 1; // Choose any slot other than the exclusive slot

    Old = 1ll << XENVIF_MRSW_EXCLUSIVE_SLOT;
    New = (Shared) ? (1ll << Slot) : 0;

    Old = InterlockedCompareExchange64(&Lock->Mask, New, Old);
    ASSERT3U(Old, == , 1ll << XENVIF_MRSW_EXCLUSIVE_SLOT);

    Self = KeGetCurrentThread();

    ASSERT3P(Lock->Holder[XENVIF_MRSW_EXCLUSIVE_SLOT].Thread, ==, Self);

    // If we are leaving the lock held shared then we need to transfer
    // our identity information into the hew slot.
    if (Shared)
        Lock->Holder[Slot] = Lock->Holder[XENVIF_MRSW_EXCLUSIVE_SLOT];

    Holder = &Lock->Holder[XENVIF_MRSW_EXCLUSIVE_SLOT];

    Holder->Thread = NULL;
    Holder->Level = -1;

    KeLowerIrql(Irql);
}

static FORCEINLINE LONG
__ClaimShared(
    IN  PXENVIF_MRSW_LOCK   Lock
    )
{
    LONG                    Slot;
    LONG64                  Old;
    LONG64                  New;

    // Make sure the exclusive bit is set so that we don't find it
    Old = Lock->Mask | (1ll << XENVIF_MRSW_EXCLUSIVE_SLOT);

    Slot = __ffu((ULONG64)Old);
    ASSERT(Slot >= 0);
    ASSERT3U(Slot, != , XENVIF_MRSW_EXCLUSIVE_SLOT);

    Old &= ~(1ll << XENVIF_MRSW_EXCLUSIVE_SLOT);
    New = Old | (1ll << Slot);

    return (InterlockedCompareExchange64(&Lock->Mask, New, Old) == Old) ? Slot : -1;
}

static FORCEINLINE VOID
AcquireMrswLockShared(
    IN  PXENVIF_MRSW_LOCK   Lock
    )
{
    KIRQL                   Irql;
    LONG                    Level;
    LONG                    Slot;
    PKTHREAD                Self;
    PXENVIF_MRSW_HOLDER     Holder;

    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    Self = KeGetCurrentThread();

    // Do we already hold the lock? If so, get the nesting level
    Level = -1;
    for (Slot = 0; Slot < sizeof (Lock->Mask) * 8; Slot++) {
        if (Lock->Holder[Slot].Thread == Self && Lock->Holder[Slot].Level > Level)
            Level = Lock->Holder[Slot].Level;
    }
    Level++;

    for (;;) {
        Slot = __ClaimShared(Lock);
        if (Slot >= 0)
            break;

        _mm_pause();
    }

    Holder = &Lock->Holder[Slot];

    Holder->Thread = Self;
    Holder->Level = Level;

    KeLowerIrql(Irql);
}

static FORCEINLINE VOID
ReleaseMrswLockShared(
    IN  PXENVIF_MRSW_LOCK   Lock
    )
{
    KIRQL                   Irql;
    PKTHREAD                Self;
    LONG                    Level;
    LONG                    Deepest;
    LONG                    Slot;
    LONG64                  Old;
    LONG64                  New;
    PXENVIF_MRSW_HOLDER     Holder;

    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    Self = KeGetCurrentThread();

    Level = -1;
    Deepest = -1;
    for (Slot = 0; Slot < sizeof (Lock->Mask) * 8; Slot++) {
        if (Lock->Holder[Slot].Thread == Self && Lock->Holder[Slot].Level > Level) {
            Level = Lock->Holder[Slot].Level;
            Deepest = Slot;
        }
    }
    ASSERT(Level >= 0);

    Slot = Deepest;
    ASSERT3U(Slot, !=, XENVIF_MRSW_EXCLUSIVE_SLOT);

    Holder = &Lock->Holder[Slot];

    Holder->Thread = NULL;
    Holder->Level = -1;

    do {
        Old = Lock->Mask;
        New = Old & ~(1ll << Slot);
    } while (InterlockedCompareExchange64(&Lock->Mask, New, Old) != Old);

    KeSetEvent(&Lock->Event, IO_NO_INCREMENT, FALSE);
    KeLowerIrql(Irql);
}

#endif  // _XENVIF_MRSW_H
