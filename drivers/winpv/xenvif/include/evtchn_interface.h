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

/*! \file evtchn_interface.h
    \brief XENBUS EVTCHN Interface

    This interface provides access to hypervisor event channels
*/

#ifndef _XENBUS_EVTCHN_INTERFACE_H
#define _XENBUS_EVTCHN_INTERFACE_H

#ifndef _WINDLL

/*! \enum _XENBUS_EVTCHN_TYPE
    \brief Event channel type to be opened
*/
typedef enum _XENBUS_EVTCHN_TYPE {
    XENBUS_EVTCHN_TYPE_INVALID = 0,
    XENBUS_EVTCHN_TYPE_FIXED,           /*!< Fixed */
    XENBUS_EVTCHN_TYPE_UNBOUND,         /*!< Unbound */
    XENBUS_EVTCHN_TYPE_INTER_DOMAIN,    /*!< Interdomain */
    XENBUS_EVTCHN_TYPE_VIRQ             /*!< VIRQ */
} XENBUS_EVTCHN_TYPE, *PXENBUS_EVTCHN_TYPE;

/*! \typedef XENBUS_EVTCHN_CHANNEL
    \brief Event channel handle
*/  
typedef struct _XENBUS_EVTCHN_CHANNEL XENBUS_EVTCHN_CHANNEL, *PXENBUS_EVTCHN_CHANNEL;

/*! \typedef XENBUS_EVTCHN_ACQUIRE
    \brief Acquire a reference to the EVTCHN interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENBUS_EVTCHN_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_EVTCHN_RELEASE
    \brief Release a reference to the EVTCHN interface

    \param Interface The interface header
*/  
typedef VOID
(*XENBUS_EVTCHN_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_EVTCHN_OPEN
    \brief Open an event channel

    \param Interface The interface header
    \param Type The type of event channel to open
    \param Function The callback function
    \param Argument An optional context argument passed to the callback
    \param ... Additional parameters required by \a Type

    \b Fixed:
    \param LocalPort The local port number of the (already bound) channel
    \param Mask Set to TRUE if the channel should be automatically masked before invoking the callback

    \b Unbound:
    \param RemoteDomain The domid of the remote domain which will bind the channel
    \param Mask Set to TRUE if the channel should be automatically masked before invoking the callback

    \b Interdomain:
    \param RemoteDomain The domid of the remote domain which has already bound the channel
    \param RemotePort The port number bound to the channel in the remote domain
    \param Mask Set to TRUE if the channel should be automatically masked before invoking the callback

    \b VIRQ:
    \param Index The index number of the VIRQ

    \return Event channel handle
*/  
typedef PXENBUS_EVTCHN_CHANNEL
(*XENBUS_EVTCHN_OPEN)(
    IN  PINTERFACE          Interface,
    IN  XENBUS_EVTCHN_TYPE  Type,
    IN  PKSERVICE_ROUTINE   Function,
    IN  PVOID               Argument OPTIONAL,
    ...
    );

/*! \typedef XENBUS_EVTCHN_BIND
    \brief Bind an event channel to a specific CPU

    \param Interface The interface header
    \param Channel The channel handle
    \param Group The group number of the CPU that should handle events
    \param Number The relative number of the CPU that should handle events
*/
typedef NTSTATUS
(*XENBUS_EVTCHN_BIND)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel,
    IN  USHORT                  Group,
    IN  UCHAR                   Number
    );

typedef VOID
(*XENBUS_EVTCHN_UNMASK_V4)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel,
    IN  BOOLEAN                 InCallback
    );

/*! \typedef XENBUS_EVTCHN_UNMASK
    \brief Unmask an event channel

    \param Interface The interface header
    \param Channel The channel handle
    \param InCallback Set to TRUE if this method is invoked in context of the channel callback
    \param Force Set to TRUE if the unmask must succeed, otherwise set to FALSE and the function will return FALSE if the unmask did not complete.
*/
typedef BOOLEAN
(*XENBUS_EVTCHN_UNMASK)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel,
    IN  BOOLEAN                 InCallback,
    IN  BOOLEAN                 Force
    );

typedef VOID
(*XENBUS_EVTCHN_SEND_V1)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel
    );

/*! \typedef XENBUS_EVTCHN_SEND
    \brief Send an event to the remote end of the channel

    It is assumed that the domain cannot suspend during this call so
    IRQL must be >= DISPATCH_LEVEL.

    \param Interface The interface header
    \param Channel The channel handle
*/  
typedef VOID
(*XENBUS_EVTCHN_SEND)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel
    );

/*! \typedef XENBUS_EVTCHN_TRIGGER
    \brief Send an event to the local end of the channel

    \param Interface The interface header
    \param Channel The channel handle
*/  
typedef VOID
(*XENBUS_EVTCHN_TRIGGER)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel
    );

/*! \typedef XENBUS_EVTCHN_GET_COUNT
    \brief Get the number of events received by the channel since it was opened

    \param Interface The interface header
    \param Channel The channel handle
    \return The number of events
*/
typedef ULONG
(*XENBUS_EVTCHN_GET_COUNT)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel
    );

typedef NTSTATUS
(*XENBUS_EVTCHN_WAIT_V5)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel,
    IN  PLARGE_INTEGER          Timeout OPTIONAL
    );

/*! \typedef XENBUS_EVTCHN_WAIT
    \brief Wait for events to the local end of the channel

    \param Interface The interface header
    \param Channel The channel handle
    \param Count The event count to wait for
    \param Timeout An optional timeout value (similar to KeWaitForSingleObject(), but non-zero values are allowed at DISPATCH_LEVEL).
*/
typedef NTSTATUS
(*XENBUS_EVTCHN_WAIT)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel,
    IN  ULONG                   Count,
    IN  PLARGE_INTEGER          Timeout OPTIONAL
    );

/*! \typedef XENBUS_EVTCHN_GET_PORT
    \brief Get the local port number bound to the channel

    \param Interface The interface header
    \param Channel The channel handle
    \return The port number
*/  
typedef ULONG
(*XENBUS_EVTCHN_GET_PORT)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel
    );

/*! \typedef XENBUS_EVTCHN_CLOSE
    \brief Close an event channel

    \param Interface The interface header
    \param Channel The channel handle
*/  
typedef VOID
(*XENBUS_EVTCHN_CLOSE)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_EVTCHN_CHANNEL  Channel
    );

// {BE2440AC-1098-4150-AF4D-452FADCEF923}
DEFINE_GUID(GUID_XENBUS_EVTCHN_INTERFACE, 
0xbe2440ac, 0x1098, 0x4150, 0xaf, 0x4d, 0x45, 0x2f, 0xad, 0xce, 0xf9, 0x23);

/*! \struct _XENBUS_EVTCHN_INTERFACE_V4
    \brief EVTCHN interface version 4
    \ingroup interfaces
*/
struct _XENBUS_EVTCHN_INTERFACE_V4 {
    INTERFACE               Interface;
    XENBUS_EVTCHN_ACQUIRE   EvtchnAcquire;
    XENBUS_EVTCHN_RELEASE   EvtchnRelease;
    XENBUS_EVTCHN_OPEN      EvtchnOpen;
    XENBUS_EVTCHN_BIND      EvtchnBind;
    XENBUS_EVTCHN_UNMASK_V4 EvtchnUnmaskVersion4;
    XENBUS_EVTCHN_SEND_V1   EvtchnSendVersion1;
    XENBUS_EVTCHN_TRIGGER   EvtchnTrigger;
    XENBUS_EVTCHN_GET_PORT  EvtchnGetPort;
    XENBUS_EVTCHN_CLOSE     EvtchnClose;
};

/*! \struct _XENBUS_EVTCHN_INTERFACE_V5
    \brief EVTCHN interface version 5
    \ingroup interfaces
*/
struct _XENBUS_EVTCHN_INTERFACE_V5 {
    INTERFACE               Interface;
    XENBUS_EVTCHN_ACQUIRE   EvtchnAcquire;
    XENBUS_EVTCHN_RELEASE   EvtchnRelease;
    XENBUS_EVTCHN_OPEN      EvtchnOpen;
    XENBUS_EVTCHN_BIND      EvtchnBind;
    XENBUS_EVTCHN_UNMASK_V4 EvtchnUnmaskVersion4;
    XENBUS_EVTCHN_SEND_V1   EvtchnSendVersion1;
    XENBUS_EVTCHN_TRIGGER   EvtchnTrigger;
    XENBUS_EVTCHN_WAIT_V5   EvtchnWaitVersion5;
    XENBUS_EVTCHN_GET_PORT  EvtchnGetPort;
    XENBUS_EVTCHN_CLOSE     EvtchnClose;
};

/*! \struct _XENBUS_EVTCHN_INTERFACE_V6
    \brief EVTCHN interface version 6
    \ingroup interfaces
*/
struct _XENBUS_EVTCHN_INTERFACE_V6 {
    INTERFACE               Interface;
    XENBUS_EVTCHN_ACQUIRE   EvtchnAcquire;
    XENBUS_EVTCHN_RELEASE   EvtchnRelease;
    XENBUS_EVTCHN_OPEN      EvtchnOpen;
    XENBUS_EVTCHN_BIND      EvtchnBind;
    XENBUS_EVTCHN_UNMASK_V4 EvtchnUnmaskVersion4;
    XENBUS_EVTCHN_SEND      EvtchnSend;
    XENBUS_EVTCHN_TRIGGER   EvtchnTrigger;
    XENBUS_EVTCHN_WAIT_V5   EvtchnWaitVersion5;
    XENBUS_EVTCHN_GET_PORT  EvtchnGetPort;
    XENBUS_EVTCHN_CLOSE     EvtchnClose;
};

/*! \struct _XENBUS_EVTCHN_INTERFACE_V7
    \brief EVTCHN interface version 7
    \ingroup interfaces
*/
struct _XENBUS_EVTCHN_INTERFACE_V7 {
    INTERFACE               Interface;
    XENBUS_EVTCHN_ACQUIRE   EvtchnAcquire;
    XENBUS_EVTCHN_RELEASE   EvtchnRelease;
    XENBUS_EVTCHN_OPEN      EvtchnOpen;
    XENBUS_EVTCHN_BIND      EvtchnBind;
    XENBUS_EVTCHN_UNMASK_V4 EvtchnUnmaskVersion4;
    XENBUS_EVTCHN_SEND      EvtchnSend;
    XENBUS_EVTCHN_TRIGGER   EvtchnTrigger;
    XENBUS_EVTCHN_GET_COUNT EvtchnGetCount;
    XENBUS_EVTCHN_WAIT      EvtchnWait;
    XENBUS_EVTCHN_GET_PORT  EvtchnGetPort;
    XENBUS_EVTCHN_CLOSE     EvtchnClose;
};

/*! \struct _XENBUS_EVTCHN_INTERFACE_V8
    \brief EVTCHN interface version 8
    \ingroup interfaces
*/
struct _XENBUS_EVTCHN_INTERFACE_V8 {
    INTERFACE               Interface;
    XENBUS_EVTCHN_ACQUIRE   EvtchnAcquire;
    XENBUS_EVTCHN_RELEASE   EvtchnRelease;
    XENBUS_EVTCHN_OPEN      EvtchnOpen;
    XENBUS_EVTCHN_BIND      EvtchnBind;
    XENBUS_EVTCHN_UNMASK    EvtchnUnmask;
    XENBUS_EVTCHN_SEND      EvtchnSend;
    XENBUS_EVTCHN_TRIGGER   EvtchnTrigger;
    XENBUS_EVTCHN_GET_COUNT EvtchnGetCount;
    XENBUS_EVTCHN_WAIT      EvtchnWait;
    XENBUS_EVTCHN_GET_PORT  EvtchnGetPort;
    XENBUS_EVTCHN_CLOSE     EvtchnClose;
};

typedef struct _XENBUS_EVTCHN_INTERFACE_V8 XENBUS_EVTCHN_INTERFACE, *PXENBUS_EVTCHN_INTERFACE;

/*! \def XENBUS_EVTCHN
    \brief Macro at assist in method invocation
*/
#define XENBUS_EVTCHN(_Method, _Interface, ...)    \
    (_Interface)->Evtchn ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_EVTCHN_INTERFACE_VERSION_MIN 4
#define XENBUS_EVTCHN_INTERFACE_VERSION_MAX 8

#endif  // _XENBUS_EVTCHN_INTERFACE_H

