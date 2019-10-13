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

/*! \file balloon_interface.h
    \brief XENBUS BALLOON Interface

    This interface provides primitives to inflate/deflate the
    balloon and query its current size.
*/

#ifndef _XENBUS_BALLOON_INTERFACE_H
#define _XENBUS_BALLOON_INTERFACE_H

#ifndef _WINDLL

/*! \typedef XENBUS_BALLOON_ACQUIRE
    \brief Acquire a reference to the BALLOON interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENBUS_BALLOON_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_BALLOON_RELEASE
    \brief Release a reference to the BALLOON interface

    \param Interface The interface header
*/  
typedef VOID
(*XENBUS_BALLOON_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_BALLOON_ADJUST
    \brief Adjust the balloon to the target \a Size

    \param Interface The interface header
    \param Size The target size of the balloon in pages
*/  
typedef NTSTATUS
(*XENBUS_BALLOON_ADJUST)(
    IN  PINTERFACE  Interface,
    IN  ULONGLONG   Size
    );

/*! \typedef XENBUS_BALLOON_GET_SIZE
    \brief Return the current size of the balloon in pages

    \param Interface The interface header
*/  
typedef ULONGLONG
(*XENBUS_BALLOON_GET_SIZE)(
    IN  PINTERFACE  Interface
    );

// {D92AA810-BECB-4BD5-A3DA-BD03C135A297}
DEFINE_GUID(GUID_XENBUS_BALLOON_INTERFACE, 
0xd92aa810, 0xbecb, 0x4bd5, 0xa3, 0xda, 0xbd, 0x3, 0xc1, 0x35, 0xa2, 0x97);

/*! \struct _XENBUS_BALLOON_INTERFACE_V1
    \brief BALLOON interface version 1
    \ingroup interfaces
*/  
struct _XENBUS_BALLOON_INTERFACE_V1 {
    INTERFACE                   Interface;
    XENBUS_BALLOON_ACQUIRE      BalloonAcquire;
    XENBUS_BALLOON_RELEASE      BalloonRelease;
    XENBUS_BALLOON_ADJUST       BalloonAdjust;
    XENBUS_BALLOON_GET_SIZE     BalloonGetSize;
};

typedef struct _XENBUS_BALLOON_INTERFACE_V1 XENBUS_BALLOON_INTERFACE, *PXENBUS_BALLOON_INTERFACE;

/*! \def XENBUS_BALLOON
    \brief Macro at assist in method invocation
*/
#define XENBUS_BALLOON(_Method, _Interface, ...)                      \
    (_Interface)->Balloon ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_BALLOON_INTERFACE_VERSION_MIN    1
#define XENBUS_BALLOON_INTERFACE_VERSION_MAX    1

#endif  // _XENBUS_BALLOON_INTERFACE_H

