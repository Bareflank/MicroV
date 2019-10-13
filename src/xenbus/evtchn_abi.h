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
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRAN4TIES, 
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

#ifndef _XENBUS_EVTCHN_ABI_H
#define _XENBUS_EVTCHN_ABI_H

#include <ntddk.h>
#include <xen.h>

typedef PVOID *PXENBUS_EVTCHN_ABI_CONTEXT;

typedef NTSTATUS
(*XENBUS_EVTCHN_ABI_ACQUIRE)(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  Context
    );

typedef VOID
(*XENBUS_EVTCHN_ABI_RELEASE)(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  Context
    );

typedef BOOLEAN
(*XENBUS_EVTCHN_ABI_IS_PROCESSOR_ENABLED)(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  Context,
    IN  ULONG                       Index
    );

typedef BOOLEAN
(*XENBUS_EVTCHN_ABI_EVENT)(
    IN  PVOID   Argument,
    IN  ULONG   Port
    );

typedef BOOLEAN
(*XENBUS_EVTCHN_ABI_POLL)(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  Context,
    IN  ULONG                       Index,
    IN  XENBUS_EVTCHN_ABI_EVENT     Event,
    IN  PVOID                       Argument
    );

typedef NTSTATUS
(*XENBUS_EVTCHN_ABI_PORT_ENABLE)(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  Context,
    IN  ULONG                       Port
    );

typedef VOID
(*XENBUS_EVTCHN_ABI_PORT_DISABLE)(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  Context,
    IN  ULONG                       Port
    );

typedef VOID
(*XENBUS_EVTCHN_ABI_PORT_ACK)(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  Context,
    IN  ULONG                       Port
    );

typedef VOID
(*XENBUS_EVTCHN_ABI_PORT_MASK)(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  Context,
    IN  ULONG                       Port
    );

typedef BOOLEAN
(*XENBUS_EVTCHN_ABI_PORT_UNMASK)(
    IN  PXENBUS_EVTCHN_ABI_CONTEXT  Context,
    IN  ULONG                       Port
    );

typedef struct _XENBUS_EVTCHN_ABI {
    PXENBUS_EVTCHN_ABI_CONTEXT              Context;
    XENBUS_EVTCHN_ABI_ACQUIRE               EvtchnAbiAcquire;
    XENBUS_EVTCHN_ABI_RELEASE               EvtchnAbiRelease;
    XENBUS_EVTCHN_ABI_IS_PROCESSOR_ENABLED  EvtchnAbiIsProcessorEnabled;
    XENBUS_EVTCHN_ABI_POLL                  EvtchnAbiPoll;
    XENBUS_EVTCHN_ABI_PORT_ENABLE           EvtchnAbiPortEnable;
    XENBUS_EVTCHN_ABI_PORT_DISABLE          EvtchnAbiPortDisable;
    XENBUS_EVTCHN_ABI_PORT_ACK              EvtchnAbiPortAck;
    XENBUS_EVTCHN_ABI_PORT_MASK             EvtchnAbiPortMask;
    XENBUS_EVTCHN_ABI_PORT_UNMASK           EvtchnAbiPortUnmask;
} XENBUS_EVTCHN_ABI, *PXENBUS_EVTCHN_ABI;

#define XENBUS_EVTCHN_ABI(_Method, _Abi, ...)   \
    (_Abi)->EvtchnAbi ## _Method((_Abi)->Context, __VA_ARGS__)

#endif  // _XENBUS_EVTCHN_ABI_H
