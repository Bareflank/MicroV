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

#ifndef _XENIFACE_THREAD_H
#define _XENIFACE_THREAD_H

#include <ntddk.h>

typedef struct _XENIFACE_THREAD XENIFACE_THREAD, *PXENIFACE_THREAD;

typedef NTSTATUS (*XENIFACE_THREAD_FUNCTION)(PXENIFACE_THREAD, PVOID);

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
ThreadCreate(
    IN  XENIFACE_THREAD_FUNCTION  Function,
    IN  PVOID                   Context,
    OUT PXENIFACE_THREAD          *Thread
    );

extern PKEVENT
ThreadGetEvent(
    IN  PXENIFACE_THREAD  Self
    );

extern BOOLEAN
ThreadIsAlerted(
    IN  PXENIFACE_THREAD  Self
    );

extern VOID
ThreadWake(
    IN  PXENIFACE_THREAD  Thread
    );

extern VOID
ThreadAlert(
    IN  PXENIFACE_THREAD  Thread
    );

extern VOID
ThreadJoin(
    IN  PXENIFACE_THREAD  Thread
    );

#endif  // _XENIFACE_THREAD_H

