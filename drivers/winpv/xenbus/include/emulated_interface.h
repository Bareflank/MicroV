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

/*! \file emulated_interface.h
    \brief XENFILT EMULATED Interface

    This interface provides primitives to determine whether emulated
    devices or disks are present in the VM
*/

#ifndef _XENFILT_EMULATED_INTERFACE_H
#define _XENFILT_EMULATED_INTERFACE_H

#ifndef _WINDLL

/*! \typedef XENFILT_EMULATED_ACQUIRE
    \brief Acquire a reference to the EMULATED interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENFILT_EMULATED_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENFILT_EMULATED_RELEASE
    \brief Release a reference to the EMULATED interface

    \param Interface The interface header
*/  
typedef VOID
(*XENFILT_EMULATED_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENFILT_EMULATED_IS_DEVICE_PRESENT
    \brief Determine whether a given device is present in the VM

    \param Interface The interface header
    \param DeviceID The DeviceID of the device
    \param InstanceID The (un-prefixed) InstanceID of the device or
           NULL to match any device instance
    \return TRUE if the specified device is present in the system or
    FALSE if it is not
*/  
typedef BOOLEAN
(*XENFILT_EMULATED_IS_DEVICE_PRESENT)(
    IN  PVOID   Context,
    IN  PCHAR   DeviceID,
    IN  PCHAR   InstanceID OPTIONAL
    );

typedef BOOLEAN
(*XENFILT_EMULATED_IS_DISK_PRESENT_V1)(
    IN  PVOID   Context,
    IN  ULONG   Controller,
    IN  ULONG   Target,
    IN  ULONG   Lun
    );
/*! \typedef XENFILT_EMULATED_IS_DISK_PRESENT
    \brief Determine whether a given emulated disk is present in the VM

    \param Interface The interface header
    \param Index The disk number of the paravirtual disk which the
                 emulated device is aliasing
    \return TRUE if an emulated disk aliasing the specified paravirtual
    disk index is present in the system or FALSE if not
*/  
typedef BOOLEAN
(*XENFILT_EMULATED_IS_DISK_PRESENT)(
    IN  PVOID   Context,
    IN  ULONG   Index
    );

// {959027A1-FCCE-4E78-BCF4-637384F499C5}
DEFINE_GUID(GUID_XENFILT_EMULATED_INTERFACE, 
0x959027a1, 0xfcce, 0x4e78, 0xbc, 0xf4, 0x63, 0x73, 0x84, 0xf4, 0x99, 0xc5);

/*! \struct _XENFILT_EMULATED_INTERFACE_V1
    \brief EMULATED interface version 1
    \ingroup interfaces
*/
struct _XENFILT_EMULATED_INTERFACE_V1 {
    INTERFACE                           Interface;
    XENFILT_EMULATED_ACQUIRE            EmulatedAcquire;
    XENFILT_EMULATED_RELEASE            EmulatedRelease;
    XENFILT_EMULATED_IS_DEVICE_PRESENT  EmulatedIsDevicePresent;
    XENFILT_EMULATED_IS_DISK_PRESENT_V1 EmulatedIsDiskPresentVersion1;
};

/*! \struct _XENFILT_EMULATED_INTERFACE_V2
    \brief EMULATED interface version 2
    \ingroup interfaces
*/
struct _XENFILT_EMULATED_INTERFACE_V2 {
    INTERFACE                           Interface;
    XENFILT_EMULATED_ACQUIRE            EmulatedAcquire;
    XENFILT_EMULATED_RELEASE            EmulatedRelease;
    XENFILT_EMULATED_IS_DEVICE_PRESENT  EmulatedIsDevicePresent;
    XENFILT_EMULATED_IS_DISK_PRESENT    EmulatedIsDiskPresent;
};

typedef struct _XENFILT_EMULATED_INTERFACE_V2 XENFILT_EMULATED_INTERFACE, *PXENFILT_EMULATED_INTERFACE;

/*! \def XENFILT_EMULATED
    \brief Macro at assist in method invocation
*/
#define XENFILT_EMULATED(_Method, _Interface, ...)    \
    (_Interface)->Emulated ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENFILT_EMULATED_INTERFACE_VERSION_MIN  1
#define XENFILT_EMULATED_INTERFACE_VERSION_MAX  2

#endif  // _XENFILT_EMULATED_INTERFACE_H

