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

/*! \file range_set_interface.h
    \brief XENBUS RANGE_SET Interface

    This interface provides access to XENBUS's range-set
    implementation.
*/

#ifndef _XENBUS_RANGE_SET_INTERFACE_H
#define _XENBUS_RANGE_SET_INTERFACE_H

#ifndef _WINDLL

/*! \typedef XENBUS_RANGE_SET
    \brief Range-set handle
*/
typedef struct _XENBUS_RANGE_SET    XENBUS_RANGE_SET, *PXENBUS_RANGE_SET;

/*! \typedef XENBUS_RANGE_SET_ACQUIRE
    \brief Acquire a reference to the RANGE_SET interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENBUS_RANGE_SET_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_RANGE_SET_RELEASE
    \brief Release a reference to the RANGE_SET interface

    \param Interface The interface header
*/  
typedef VOID
(*XENBUS_RANGE_SET_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_RANGE_SET_CREATE
    \brief Create a new empty range-set

    \param Interface The interface header
    \param Name A name for the ramge-set which will be used in debug output
    \param RangeSet A pointer to a range-set handle to be initialized
*/  
typedef NTSTATUS
(*XENBUS_RANGE_SET_CREATE)(
    IN  PINTERFACE          Interface,
    IN  const CHAR          *Name,
    OUT PXENBUS_RANGE_SET   *RangeSet
    );

/*! \typedef XENBUS_RANGE_SET_PUT
    \brief Put a range into a range-set

    \param Interface The interface header
    \param RangeSet The range-set handle
    \param Start The base of the range
    \param Count The number of items of the range
*/  
typedef NTSTATUS
(*XENBUS_RANGE_SET_PUT)(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_RANGE_SET   RangeSet,
    IN  LONGLONG            Start,
    IN  ULONGLONG           Count
    );

/*! \typedef XENBUS_RANGE_SET_POP
    \brief Pop a range out of a range-set

    \param Interface The interface header
    \param RangeSet The range-set handle
    \param Count The number of items required
    \param Start A pointer to a value which will be set to the base of
    a suitable range
*/  
typedef NTSTATUS
(*XENBUS_RANGE_SET_POP)(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_RANGE_SET   RangeSet,
    IN  ULONGLONG           Count,
    OUT PLONGLONG           Start
    );

/*! \typedef XENBUS_RANGE_SET_GET
    \brief Get a specific range out of a range-set

    \param Interface The interface header
    \param RangeSet The range-set handle
    \param Start The base of the range
    \param Count The number of items in the range
*/  
typedef NTSTATUS
(*XENBUS_RANGE_SET_GET)(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_RANGE_SET   RangeSet,
    IN  LONGLONG            Start,
    IN  ULONGLONG           Count
    );

/*! \typedef XENBUS_RANGE_SET_DESTROY
    \brief Destroy a range-set

    \param Interface The interface header
    \param RangeSet The range-set handle

    The range-set must be empty when it is destroyed
*/  
typedef VOID
(*XENBUS_RANGE_SET_DESTROY)(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_RANGE_SET   RangeSet
    );

// {EE7E78A2-6847-48C5-B123-BB012F0EABF4}
DEFINE_GUID(GUID_XENBUS_RANGE_SET_INTERFACE, 
0xee7e78a2, 0x6847, 0x48c5, 0xb1, 0x23, 0xbb, 0x1, 0x2f, 0xe, 0xab, 0xf4);

/*! \struct _XENBUS_RANGE_SET_INTERFACE_V1
    \brief RANGE_SET interface version 1
    \ingroup interfaces
*/
struct _XENBUS_RANGE_SET_INTERFACE_V1 {
    INTERFACE                   Interface;
    XENBUS_RANGE_SET_ACQUIRE    RangeSetAcquire;
    XENBUS_RANGE_SET_RELEASE    RangeSetRelease;
    XENBUS_RANGE_SET_CREATE     RangeSetCreate;
    XENBUS_RANGE_SET_PUT        RangeSetPut;
    XENBUS_RANGE_SET_POP        RangeSetPop;
    XENBUS_RANGE_SET_GET        RangeSetGet;
    XENBUS_RANGE_SET_DESTROY    RangeSetDestroy;
};

typedef struct _XENBUS_RANGE_SET_INTERFACE_V1 XENBUS_RANGE_SET_INTERFACE, *PXENBUS_RANGE_SET_INTERFACE;

/*! \def XENBUS_RANGE_SET
    \brief Macro at assist in method invocation
*/
#define XENBUS_RANGE_SET(_Method, _Interface, ...)    \
    (_Interface)->RangeSet ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_RANGE_SET_INTERFACE_VERSION_MIN 1
#define XENBUS_RANGE_SET_INTERFACE_VERSION_MAX 1

#endif  // _XENBUS_RANGE_SET_INTERFACE_H

