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

/*! \file debug_interface.h
    \brief XENBUS DEBUG Interface

    This interface provides to register and invoke debug callbacks
*/

#ifndef _XENBUS_DEBUG_INTERFACE_H
#define _XENBUS_DEBUG_INTERFACE_H

#ifndef _WINDLL

/*! \typedef XENBUS_DEBUG_CALLBACK
    \brief Debug callback handle
*/
typedef struct _XENBUS_DEBUG_CALLBACK   XENBUS_DEBUG_CALLBACK, *PXENBUS_DEBUG_CALLBACK;

/*! \typedef XENBUS_DEBUG_ACQUIRE
    \brief Acquire a reference to the DEBUG interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENBUS_DEBUG_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_DEBUG_RELEASE
    \brief Release a reference to the DEBUG interface

    \param Interface The interface header
*/  
typedef VOID
(*XENBUS_DEBUG_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_DEBUG_FUNCTION
    \brief Debug callback function

    \param Argument Context \a Argument supplied to \a XENBUS_DEBUG_REGISTER
    \param Crashing This is set to TRUE if the function is invoked as
    part of pre-crash logging

    Debug callback functions are always invoked with IRQL == HIGH_LEVEL
*/  
typedef VOID
(*XENBUS_DEBUG_FUNCTION)(
    IN  PVOID   Argument,
    IN  BOOLEAN Crashing
    );

/*! \typedef XENBUS_DEBUG_REGISTER
    \brief Register a debug callback function

    \param Interface The interface header
    \param Prefix A prefix applied to each line logged by \a XENBUS_DEBUG_PRINTF
    \param Function The callback function
    \param Argument An optional context argument passed to the callback
    \param Callback A pointer to a callback handle to be initialized
*/  
typedef NTSTATUS
(*XENBUS_DEBUG_REGISTER)(
    IN  PINTERFACE              Interface,
    IN  PCHAR                   Prefix,
    IN  XENBUS_DEBUG_FUNCTION   Function,
    IN  PVOID                   Argument OPTIONAL,
    OUT PXENBUS_DEBUG_CALLBACK  *Callback
    );

/*! \typedef XENBUS_DEBUG_PRINTF
    \brief Print a debug message in to the log

    \param Interface The interface header
    \param Format A format specifier
    \param ... Additional parameters required by \a Format

    This method must only be invoked from the context of a debug
    callback
*/  
typedef VOID
(*XENBUS_DEBUG_PRINTF)(
    IN  PINTERFACE              Interface,
    IN  const CHAR              *Format,
    ...
    );

/*! \typedef XENBUS_DEBUG_DEREGISTER
    \brief Deregister a debug callback function

    \param Interface The interface header
    \param Callback The callback handle
*/
typedef VOID
(*XENBUS_DEBUG_DEREGISTER)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_DEBUG_CALLBACK  Callback
    );

/*! \typedef XENBUS_DEBUG_TRIGGER
    \brief Invoke debug callback functions

    \param Interface The interface header
    \param Callback Optional argument to restrict invocation to a singe
    debug callback (NULL invokes all debug callbacks)
*/
typedef VOID
(*XENBUS_DEBUG_TRIGGER)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_DEBUG_CALLBACK  Callback OPTIONAL
    );

// {0DF600AE-6B20-4227-BF94-03DA9A26A114}
DEFINE_GUID(GUID_XENBUS_DEBUG_INTERFACE, 
0xdf600ae, 0x6b20, 0x4227, 0xbf, 0x94, 0x3, 0xda, 0x9a, 0x26, 0xa1, 0x14);

/*! \struct _XENBUS_DEBUG_INTERFACE_V1
    \brief DEBUG interface version 1
    \ingroup interfaces
*/
struct _XENBUS_DEBUG_INTERFACE_V1 {
    INTERFACE               Interface;
    XENBUS_DEBUG_ACQUIRE    DebugAcquire;
    XENBUS_DEBUG_RELEASE    DebugRelease;
    XENBUS_DEBUG_REGISTER   DebugRegister;
    XENBUS_DEBUG_PRINTF     DebugPrintf;
    XENBUS_DEBUG_TRIGGER    DebugTrigger;
    XENBUS_DEBUG_DEREGISTER DebugDeregister;
};

typedef struct _XENBUS_DEBUG_INTERFACE_V1 XENBUS_DEBUG_INTERFACE, *PXENBUS_DEBUG_INTERFACE;

/*! \def XENBUS_DEBUG
    \brief Macro at assist in method invocation
*/
#define XENBUS_DEBUG(_Method, _Interface, ...)    \
    (_Interface)->Debug ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_DEBUG_INTERFACE_VERSION_MIN  1
#define XENBUS_DEBUG_INTERFACE_VERSION_MAX  1

#endif  // _XENBUS_DEBUG_INTERFACE_H

