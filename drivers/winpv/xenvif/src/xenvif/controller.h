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

#ifndef _XENVIF_CONTROLLER_H
#define _XENVIF_CONTROLLER_H

#include <ntddk.h>

#include <vif_interface.h>

#include "frontend.h"

typedef struct _XENVIF_CONTROLLER XENVIF_CONTROLLER, *PXENVIF_CONTROLLER;

extern NTSTATUS
ControllerInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_CONTROLLER  *Controller
    );

extern NTSTATUS
ControllerConnect(
    IN  PXENVIF_CONTROLLER  Controller
    );

extern NTSTATUS
ControllerStoreWrite(
    IN  PXENVIF_CONTROLLER          Controller,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    );

extern VOID
ControllerEnable(
    IN  PXENVIF_CONTROLLER  Controller
    );

extern VOID
ControllerDisable(
    IN  PXENVIF_CONTROLLER  Controller
    );

extern VOID
ControllerDisconnect(
    IN  PXENVIF_CONTROLLER  Controller
    );

extern VOID
ControllerTeardown(
    IN  PXENVIF_CONTROLLER  Controller
    );

extern NTSTATUS
ControllerSetHashAlgorithm(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  ULONG               Algorithm
    );

extern NTSTATUS
ControllerGetHashFlags(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  PULONG              Flags
    );

extern NTSTATUS
ControllerSetHashFlags(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  ULONG               Flags
    );

extern NTSTATUS
ControllerSetHashKey(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  PUCHAR              Key,
    IN  ULONG               Size
    );

extern NTSTATUS
ControllerGetHashMappingSize(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  PULONG              Size
    );

extern NTSTATUS
ControllerSetHashMappingSize(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  ULONG               Size
    );

extern NTSTATUS
ControllerSetHashMapping(
    IN  PXENVIF_CONTROLLER  Controller,
    IN  PULONG              Mapping,
    IN  ULONG               Size,
    IN  ULONG               Offset
    );


#endif  // _XENVIF_CONTROLLER_H
