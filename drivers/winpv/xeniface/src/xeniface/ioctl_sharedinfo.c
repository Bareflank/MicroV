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

#include "driver.h"
#include "ioctls.h"
#include "xeniface_ioctls.h"
#include "log.h"

DECLSPEC_NOINLINE
NTSTATUS
IoctlSharedInfoGetTime(
    __in  PXENIFACE_FDO                 Fdo,
    __in  PCHAR                         Buffer,
    __in  ULONG                         InLen,
    __in  ULONG                         OutLen,
    __out PULONG_PTR                    Info
    )
{
    PXENIFACE_SHAREDINFO_GET_TIME_OUT   Out;
    LARGE_INTEGER                       Time;
    BOOLEAN                             Local;
    NTSTATUS                            status;

    status = STATUS_INVALID_BUFFER_SIZE;
    if (InLen != 0)
        goto fail1;

    if (OutLen != sizeof(XENIFACE_SHAREDINFO_GET_TIME_OUT))
        goto fail2;

    Out = (PXENIFACE_SHAREDINFO_GET_TIME_OUT)Buffer;
    XENBUS_SHARED_INFO(GetTime, &Fdo->SharedInfoInterface, &Time,
                       &Local);
    Out->Time.dwHighDateTime = Time.HighPart;
    Out->Time.dwLowDateTime = Time.LowPart;
    Out->Local = Local;
    *Info = (ULONG_PTR)sizeof(XENIFACE_SHAREDINFO_GET_TIME_OUT);

    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");
fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}
