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

#ifndef _COMMON_MUTEX_H
#define _COMMON_MUTEX_H

#include <ntddk.h>

#include "assert.h"

typedef struct _MUTEX {
    PKTHREAD    Owner;
    KEVENT      Event;
} MUTEX, *PMUTEX;

static FORCEINLINE VOID
InitializeMutex(
    IN  PMUTEX  Mutex
    )
{
    RtlZeroMemory(Mutex, sizeof (MUTEX));

    KeInitializeEvent(&Mutex->Event, SynchronizationEvent, TRUE);
}

static FORCEINLINE BOOLEAN
__drv_maxIRQL(PASSIVE_LEVEL)
TryAcquireMutex(
    IN  PMUTEX      Mutex
    )
{
    LARGE_INTEGER   Timeout;
    NTSTATUS        status;

    Timeout.QuadPart = 0;

    status = KeWaitForSingleObject(&Mutex->Event,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   &Timeout);
    if (status == STATUS_TIMEOUT)
        return FALSE;

    ASSERT(NT_SUCCESS(status));

    ASSERT3P(Mutex->Owner, ==, NULL);
    Mutex->Owner = KeGetCurrentThread();

    return TRUE;
}

static FORCEINLINE VOID
__drv_maxIRQL(PASSIVE_LEVEL)
AcquireMutex(
    IN  PMUTEX  Mutex
    )
{
    NTSTATUS    status;

    status = KeWaitForSingleObject(&Mutex->Event,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   NULL);

    ASSERT(NT_SUCCESS(status));

    ASSERT3P(Mutex->Owner, ==, NULL);
    Mutex->Owner = KeGetCurrentThread();
}

static FORCEINLINE VOID
__drv_maxIRQL(PASSIVE_LEVEL)
ReleaseMutex(
    IN  PMUTEX  Mutex
    )
{
    ASSERT3P(Mutex->Owner, ==, KeGetCurrentThread());
    Mutex->Owner = NULL;

    KeSetEvent(&Mutex->Event, IO_NO_INCREMENT, FALSE);
}

#endif  // _COMMON_MUTEX_H
