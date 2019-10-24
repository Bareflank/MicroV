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

/*! \file console_interface.h
    \brief XENBUS CONSOLE Interface

    This interface provides access to XenConsole
*/

#ifndef _XENBUS_CONSOLE_INTERFACE_H
#define _XENBUS_CONSOLE_INTERFACE_H

#ifndef _WINDLL

/*! \typedef XENBUS_CONSOLE_WAKEUP
    \brief XenStore watch handle
*/
typedef struct _XENBUS_CONSOLE_WAKEUP   XENBUS_CONSOLE_WAKEUP, *PXENBUS_CONSOLE_WAKEUP;

/*! \typedef XENBUS_CONSOLE_ACQUIRE
    \brief Acquire a reference to the CONSOLE interface

    \param Interface The interface header
*/
typedef NTSTATUS
(*XENBUS_CONSOLE_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_CONSOLE_RELEASE
    \brief Release a reference to the CONSOLE interface

    \param Interface The interface header
*/
typedef VOID
(*XENBUS_CONSOLE_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_CONSOLE_CAN_READ
    \brief Get characters from the console

    \param Interface The interface header

    \return A boolean which is true if there is data to read
*/
typedef BOOLEAN
(*XENBUS_CONSOLE_CAN_READ)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_CONSOLE_READ
    \brief Get characters from the console

    \param Interface The interface header
    \param Buffer A character buffer
    \param Length The length of the buffer

    \return The number of characters read
*/
typedef ULONG
(*XENBUS_CONSOLE_READ)(
    IN  PINTERFACE  Interface,
    IN  PCHAR       Data,
    IN  ULONG       Length
    );

/*! \typedef XENBUS_CONSOLE_CAN_WRITE
    \brief Get characters from the console

    \param Interface The interface header

    \return A boolean which is true if there is space to write
*/
typedef BOOLEAN
(*XENBUS_CONSOLE_CAN_WRITE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_CONSOLE_WRITE
    \brief Send characters to the console

    \param Interface The interface header
    \param Buffer A character buffer
    \param Length The length of the buffer

    \return The number of characters written
*/
typedef ULONG
(*XENBUS_CONSOLE_WRITE)(
    IN  PINTERFACE  Interface,
    IN  PCHAR       Data,
    IN  ULONG       Length
    );

/*! \typedef XENBUS_CONSOLE_WAKEUP_ADD
    \brief Add a wakeup item

    \param Interface The interface header
    \param Event A pointer to an event object to be signalled when there
    is activity on the rings
    \param Wakeup A pointer to a wakeup handle to be initialized
*/
typedef NTSTATUS
(*XENBUS_CONSOLE_WAKEUP_ADD)(
    IN  PINTERFACE          	Interface,
    IN  PKEVENT             	Event,
    OUT PXENBUS_CONSOLE_WAKEUP	*Wakeup
    );

/*! \typedef XENBUS_CONSOLE_WAKEUP_REMOVE
    \brief Remove a wakeup item

    \param Interface The interface header
    \param Wakeup The wakeup handle
*/
typedef VOID
(*XENBUS_CONSOLE_WAKEUP_REMOVE)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_CONSOLE_WAKEUP  Wakeup
    );

// {04c4f738-034a-4268-bd20-a92ac90d4f82}
DEFINE_GUID(GUID_XENBUS_CONSOLE_INTERFACE,
0x04c4f738, 0x034a, 0x4268, 0xbd, 0x20, 0xa9, 0x2a, 0xc9, 0x0d, 0x4f, 0x82);

/*! \struct _XENBUS_CONSOLE_INTERFACE_V1
    \brief CONSOLE interface version 1
    \ingroup interfaces
*/
struct _XENBUS_CONSOLE_INTERFACE_V1 {
    INTERFACE                       Interface;
    XENBUS_CONSOLE_ACQUIRE          ConsoleAcquire;
    XENBUS_CONSOLE_RELEASE          ConsoleRelease;
    XENBUS_CONSOLE_CAN_READ         ConsoleCanRead;
    XENBUS_CONSOLE_READ             ConsoleRead;
    XENBUS_CONSOLE_CAN_WRITE        ConsoleCanWrite;
    XENBUS_CONSOLE_WRITE            ConsoleWrite;
    XENBUS_CONSOLE_WAKEUP_ADD       ConsoleWakeupAdd;
    XENBUS_CONSOLE_WAKEUP_REMOVE    ConsoleWakeupRemove;
};

typedef struct _XENBUS_CONSOLE_INTERFACE_V1 XENBUS_CONSOLE_INTERFACE, *PXENBUS_CONSOLE_INTERFACE;

/*! \def XENBUS_CONSOLE
    \brief Macro at assist in method invocation
*/
#define XENBUS_CONSOLE(_Method, _Interface, ...)    \
    (_Interface)->Console ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_CONSOLE_INTERFACE_VERSION_MIN  1
#define XENBUS_CONSOLE_INTERFACE_VERSION_MAX  1

#endif  // _XENBUS_CONSOLE_INTERFACE_H
