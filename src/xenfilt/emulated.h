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

#ifndef _XENFILT_EMULATED_H
#define _XENFILT_EMULATED_H

#include <ntddk.h>
#include <xen.h>
#include <emulated_interface.h>

typedef struct _XENFILT_EMULATED_CONTEXT XENFILT_EMULATED_CONTEXT, *PXENFILT_EMULATED_CONTEXT;

typedef enum _XENFILT_EMULATED_OBJECT_TYPE {
    XENFILT_EMULATED_OBJECT_TYPE_UNKNOWN = 0,
    XENFILT_EMULATED_OBJECT_TYPE_PCI,
    XENFILT_EMULATED_OBJECT_TYPE_IDE
} XENFILT_EMULATED_OBJECT_TYPE, *PXENFILT_EMULATED_OBJECT_TYPE;

typedef struct _XENFILT_EMULATED_OBJECT XENFILT_EMULATED_OBJECT, *PXENFILT_EMULATED_OBJECT;

extern NTSTATUS
EmulatedInitialize(
    OUT PXENFILT_EMULATED_CONTEXT   *Context
    );

extern NTSTATUS
EmulatedGetInterface(
    IN      PXENFILT_EMULATED_CONTEXT   Context,
    IN      ULONG                       Version,
    IN OUT  PINTERFACE                  Interface,
    IN      ULONG                       Size
    );

extern VOID
EmulatedTeardown(
    IN  PXENFILT_EMULATED_CONTEXT   Context
    );

extern NTSTATUS
EmulatedAddObject(
    IN  PXENFILT_EMULATED_CONTEXT       Context,
    IN  PCHAR                           DeviceID,
    IN  PCHAR                           InstanceID,
    IN  XENFILT_EMULATED_OBJECT_TYPE    Type,
    OUT PXENFILT_EMULATED_OBJECT        *EmulatedObject
    );

extern VOID
EmulatedRemoveObject(
    IN  PXENFILT_EMULATED_CONTEXT   Context,
    IN  PXENFILT_EMULATED_OBJECT    EmulatedObject
    );

#endif  // _XENFILT_EMULATED_H
