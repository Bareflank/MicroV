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

#ifndef _XENIFACE_DRIVER_H
#define _XENIFACE_DRIVER_H



#include "fdo.h"
#include "types.h"
#include "thread.h"
#include "mutex.h"
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#pragma warning(disable:4100 4057)

#include <wmilib.h>
#include <ntifs.h>
extern PDRIVER_OBJECT   DriverObject;


#define MAX_DEVICE_ID_LEN   200

typedef struct _XENIFACE_PARAMETERS {
    UNICODE_STRING RegistryPath;

} XENIFACE_PARAMETERS, *PXENIFACE_PARAMETERS;

#define XENIFACE_POOL_TAG (ULONG) 'XIfc'

extern XENIFACE_PARAMETERS DriverParameters;

typedef struct _XENIFACE_DX {
    PDEVICE_OBJECT      DeviceObject;
    DEVICE_OBJECT_TYPE  Type;

    DEVICE_PNP_STATE    DevicePnpState;
    DEVICE_PNP_STATE    PreviousDevicePnpState;

    SYSTEM_POWER_STATE  SystemPowerState;
    DEVICE_POWER_STATE  DevicePowerState;

    CHAR                Name[MAX_DEVICE_ID_LEN];

    LIST_ENTRY          ListEntry;

    struct _XENIFACE_FDO     *Fdo;

} XENIFACE_DX, *PXENIFACE_DX;


#endif  // _XENIFACE_DRIVER_H
