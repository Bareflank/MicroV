/* Copyright (c) Rafal Wojdyla <omeg@invisiblethingslab.com>
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

#ifndef _IRP_QUEUE_H_
#define _IRP_QUEUE_H_

#include <ntddk.h>

NTSTATUS
CsqInsertIrpEx(
    _In_  PIO_CSQ Csq,
    _In_  PIRP    Irp,
    _In_  PVOID   InsertContext
    );

VOID
CsqRemoveIrp(
    _In_  PIO_CSQ Csq,
    _In_  PIRP    Irp
    );

PIRP
CsqPeekNextIrp(
    _In_      PIO_CSQ Csq,
    _In_opt_  PIRP    Irp,
    _In_opt_  PVOID   PeekContext // PXENIFACE_CONTEXT_ID
    );

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Acquires_lock_(CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue)->IrpQueueLock)
VOID
CsqAcquireLock(
    _In_                                       PIO_CSQ Csq,
    _Out_ _At_(*Irql, _Post_ _IRQL_saves_)     PKIRQL  Irql
    );

_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(CONTAINING_RECORD(Csq, XENIFACE_FDO, IrpQueue)->IrpQueueLock)
VOID
CsqReleaseLock(
    _In_                    PIO_CSQ Csq,
    _In_ _IRQL_restores_    KIRQL   Irql
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
CsqCompleteCanceledIrp(
    _In_  PIO_CSQ             Csq,
    _In_  PIRP                Irp
    );

#endif
