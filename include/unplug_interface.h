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

/*! \file unplug_interface.h
    \brief XENBUS UNPLUG Interface

    This interface provides a method to request emulated device unplug
*/

#ifndef _XENBUS_UNPLUG_INTERFACE_H
#define _XENBUS_UNPLUG_INTERFACE_H

#ifndef _WINDLL

/*! \typedef XENBUS_UNPLUG_ACQUIRE
    \brief Acquire a reference to the UNPLUG interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENBUS_UNPLUG_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_UNPLUG_RELEASE
    \brief Release a reference to the UNPLUG interface

    \param Interface The interface header
*/  
typedef VOID
(*XENBUS_UNPLUG_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \enum _XENBUS_UNPLUG_DEVICE_TYPE
    \brief Type of device to be unplugged
*/
typedef enum _XENBUS_UNPLUG_DEVICE_TYPE {
    XENBUS_UNPLUG_DEVICE_TYPE_INVALID = 0,
    XENBUS_UNPLUG_DEVICE_TYPE_NICS,     /*!< NICs */
    XENBUS_UNPLUG_DEVICE_TYPE_DISKS,    /*!< Disks */
} XENBUS_UNPLUG_DEVICE_TYPE, *PXENBUS_UNPLUG_DEVICE_TYPE;

/*! \typedef XENBUS_UNPLUG_REQUEST
    \brief Request unplug of a type of emulated device

    \param Interface The interface header
    \param Type The type of device
    \param Make Set to TRUE if the request is being made, FALSE if it is
           being revoked.
*/  
typedef VOID
(*XENBUS_UNPLUG_REQUEST)(
    IN  PINTERFACE                  Interface,
    IN  XENBUS_UNPLUG_DEVICE_TYPE   Type,
    IN  BOOLEAN                     Make
    );

// {73db6517-3d06-4937-989f-199b7501e229}
DEFINE_GUID(GUID_XENBUS_UNPLUG_INTERFACE,
0x73db6517, 0x3d06, 0x4937, 0x98, 0x9f, 0x19, 0x9b, 0x75, 0x01, 0xe2, 0x29);

/*! \struct _XENBUS_UNPLUG_INTERFACE_V1
    \brief UNPLUG interface version 1
    \ingroup interfaces
*/
struct _XENBUS_UNPLUG_INTERFACE_V1 {
    INTERFACE               Interface;
    XENBUS_UNPLUG_ACQUIRE   UnplugAcquire;
    XENBUS_UNPLUG_RELEASE   UnplugRelease;
    XENBUS_UNPLUG_REQUEST   UnplugRequest;
};

typedef struct _XENBUS_UNPLUG_INTERFACE_V1 XENBUS_UNPLUG_INTERFACE, *PXENBUS_UNPLUG_INTERFACE;

/*! \def XENBUS_UNPLUG
    \brief Macro at assist in method invocation
*/
#define XENBUS_UNPLUG(_Method, _Interface, ...)    \
    (_Interface)->Unplug ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_UNPLUG_INTERFACE_VERSION_MIN  1
#define XENBUS_UNPLUG_INTERFACE_VERSION_MAX  1

#endif  // _XENBUS_UNPLUG_INTERFACE_H

