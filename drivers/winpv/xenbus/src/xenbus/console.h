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

#ifndef _XENBUS_CONSOLE_H
#define _XENBUS_CONSOLE_H

#include <ntddk.h>
#include <xen.h>
#include <console_interface.h>

typedef struct _XENBUS_CONSOLE_CONTEXT  XENBUS_CONSOLE_CONTEXT, *PXENBUS_CONSOLE_CONTEXT;

#include "fdo.h"

extern NTSTATUS
ConsoleInitialize(
    IN  PXENBUS_FDO             Fdo,
    OUT PXENBUS_CONSOLE_CONTEXT *Context
    );

extern NTSTATUS
ConsoleGetInterface(
    IN      PXENBUS_CONSOLE_CONTEXT Context,
    IN      ULONG                   Version,
    IN OUT  PINTERFACE              Interface,
    IN      ULONG                   Size
    );

extern ULONG
ConsoleGetReferences(
    IN  PXENBUS_CONSOLE_CONTEXT Context
    );

extern VOID
ConsoleTeardown(
    IN  PXENBUS_CONSOLE_CONTEXT Context
    );

#endif  // _XENBUS_CONSOLE_H
