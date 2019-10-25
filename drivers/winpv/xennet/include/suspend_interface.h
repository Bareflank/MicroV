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

/*! \file suspend_interface.h
    \brief XENBUS SUSPEND Interface

    This interface provides primitives to handle VM suspend/resume
*/

#ifndef _XENBUS_SUSPEND_INTERFACE_H
#define _XENBUS_SUSPEND_INTERFACE_H

#ifndef _WINDLL

/*! \enum _XENBUS_SUSPEND_CALLBACK_TYPE
    \brief Suspend callback type to be registered
*/
typedef enum _XENBUS_SUSPEND_CALLBACK_TYPE {
    SUSPEND_CALLBACK_TYPE_INVALID = 0,
    SUSPEND_CALLBACK_EARLY,             /*!< Early */
    SUSPEND_CALLBACK_LATE               /*!< Late */
} XENBUS_SUSPEND_CALLBACK_TYPE, *PXENBUS_SUSPEND_CALLBACK_TYPE;

/*! \typedef XENBUS_SUSPEND_CALLBACK
    \brief Suspend callback handle
*/  
typedef struct _XENBUS_SUSPEND_CALLBACK   XENBUS_SUSPEND_CALLBACK, *PXENBUS_SUSPEND_CALLBACK;

/*! \typedef XENBUS_SUSPEND_ACQUIRE
    \brief Acquire a reference to the SUSPEND interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENBUS_SUSPEND_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_SUSPEND_RELEASE
    \brief Release a reference to the SUSPEND interface

    \param Interface The interface header
*/  
typedef VOID
(*XENBUS_SUSPEND_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_SUSPEND_FUNCTION
    \brief Suspend callback function

    \param Argument Context \a Argument supplied to \a XENBUS_SUSPEND_REGISTER

    Suspend callback functions are always invoked on one vCPU with all other
    vCPUs corralled at the same IRQL as the callback. \a Early callback
    functions are always invoked with IRQL == HIGH_LEVEL and \a Late callback
    functions are always invoked with IRQL == DISPATCH_LEVEL
*/  
typedef VOID
(*XENBUS_SUSPEND_FUNCTION)(
    IN  PVOID   Argument
    );

/*! \typedef XENBUS_SUSPEND_REGISTER
    \brief Register a suspend callback function

    \param Interface The interface header
    \param Type The type of callback function to register
    \param Function The callback function
    \param Argument An optional context argument passed to the callback
    \param Callback A pointer to a callback handle to be initialized
*/  
typedef NTSTATUS
(*XENBUS_SUSPEND_REGISTER)(
    IN  PINTERFACE                      Interface,
    IN  XENBUS_SUSPEND_CALLBACK_TYPE    Type,
    IN  XENBUS_SUSPEND_FUNCTION         Function,
    IN  PVOID                           Argument OPTIONAL,
    OUT PXENBUS_SUSPEND_CALLBACK        *Callback
    );

/*! \typedef XENBUS_SUSPEND_DEREGISTER
    \brief Deregister a suspend callback function

    \param Interface The interface header
    \param Callback The callback handle
*/
typedef VOID
(*XENBUS_SUSPEND_DEREGISTER)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_SUSPEND_CALLBACK    Callback
    );

/*! \typedef XENBUS_SUSPEND_TRIGGER
    \brief Trigger a VM suspend

    \param Interface The interface header

    This method must always be invoked with IRQL == PASSIVE_LEVEL
*/
typedef NTSTATUS
(*XENBUS_SUSPEND_TRIGGER)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_SUSPEND_GET_COUNT
    \brief Get the number of VM suspends that have occurred since boot

    \param Interface The interface header
    \return The number of VM suspends
*/
typedef ULONG
(*XENBUS_SUSPEND_GET_COUNT)(
    IN  PINTERFACE  Interface
    );

// {0554F2AF-B510-4C71-AC03-1C503E394238}
DEFINE_GUID(GUID_XENBUS_SUSPEND_INTERFACE,
0x554f2af, 0xb510, 0x4c71, 0xac, 0x3, 0x1c, 0x50, 0x3e, 0x39, 0x42, 0x38);

/*! \struct _XENBUS_SUSPEND_INTERFACE_V1
    \brief SUSPEND interface version 1
    \ingroup interfaces
*/
struct _XENBUS_SUSPEND_INTERFACE_V1 {
    INTERFACE                   Interface;
    XENBUS_SUSPEND_ACQUIRE      Acquire;
    XENBUS_SUSPEND_RELEASE      Release;
    XENBUS_SUSPEND_REGISTER     Register;
    XENBUS_SUSPEND_DEREGISTER   Deregister;
    XENBUS_SUSPEND_TRIGGER      Trigger;
    XENBUS_SUSPEND_GET_COUNT    GetCount;
};

typedef struct _XENBUS_SUSPEND_INTERFACE_V1 XENBUS_SUSPEND_INTERFACE, *PXENBUS_SUSPEND_INTERFACE;

/*! \def XENBUS_SUSPEND
    \brief Macro at assist in method invocation
*/
#define XENBUS_SUSPEND(_Method, _Interface, ...)    \
    (_Interface)-> ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_SUSPEND_INTERFACE_VERSION_MIN    1
#define XENBUS_SUSPEND_INTERFACE_VERSION_MAX    1

#endif  // _XENBUS_SUSPEND_INTERFACE_H

