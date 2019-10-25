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

/*! \file cache_interface.h
    \brief XENBUS CACHE Interface

    This interface provides access to XENBUS's object cache
    implementation.
*/

#ifndef _XENBUS_CACHE_INTERFACE_H
#define _XENBUS_CACHE_INTERFACE_H

#ifndef _WINDLL

/*! \typedef XENBUS_CACHE
    \brief Cache handle
*/
typedef struct _XENBUS_CACHE    XENBUS_CACHE, *PXENBUS_CACHE;

/*! \typedef XENBUS_CACHE_ACQUIRE
    \brief Acquire a reference to the CACHE interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENBUS_CACHE_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_CACHE_RELEASE
    \brief Release a reference to the CACHE interface

    \param Interface The interface header
*/  
typedef VOID
(*XENBUS_CACHE_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_CACHE_CTOR
    \brief Object creator callback

    \param Argument Context \a Argument supplied to \a XENBUS_CACHE_CREATE
    \param Object Newly allocated object

    This callback is invoked just after a new object is allocated and may
    be used to initialize any object data prior to its insertion into the
    cache.
*/
typedef NTSTATUS
(*XENBUS_CACHE_CTOR)(
    IN  PVOID   Argument,
    IN  PVOID   Object
    );

/*! \typedef XENBUS_CACHE_DTOR
    \brief Object destructor callback

    \param Argument Context \a Argument supplied to \a XENBUS_CACHE_CREATE
    \param Object Object about to be freed

    This callback is invoked just after an object is removed from the
    cache and before it is freed and may be used to tear down any object data.
*/
typedef VOID
(*XENBUS_CACHE_DTOR)(
    IN  PVOID   Argument,
    IN  PVOID   Object
    );

/*! \typedef XENBUS_CACHE_ACQUIRE_LOCK
    \brief Cache lock callback

    \param Argument Context \a Argument supplied to \a XENBUS_CACHE_CREATE

    This callback is invoked if the cache implementation requires mutual
    exclusion.
*/
typedef VOID
(*XENBUS_CACHE_ACQUIRE_LOCK)(
    IN  PVOID   Argument
    );

/*! \typedef XENBUS_CACHE_RELEASE_LOCK
    \brief Cache unlock callback

    \param Argument Context \a Argument supplied to \a XENBUS_CACHE_CREATE

    This callback is invoked to release the mutual exclusion lock acquired
    by a previous invocation of \a XENBUS_CACHE_ACQUIRE_LOCK.
*/
typedef VOID
(*XENBUS_CACHE_RELEASE_LOCK)(
    IN  PVOID   Argument
    );

typedef NTSTATUS
(*XENBUS_CACHE_CREATE_V1)(
    IN  PINTERFACE                  Interface,
    IN  const CHAR                  *Name,
    IN  ULONG                       Size,
    IN  ULONG                       Reservation,
    IN  XENBUS_CACHE_CTOR           Ctor,
    IN  XENBUS_CACHE_DTOR           Dtor,
    IN  XENBUS_CACHE_ACQUIRE_LOCK   AcquireLock,
    IN  XENBUS_CACHE_RELEASE_LOCK   ReleaseLock,
    IN  PVOID                       Argument OPTIONAL,
    OUT PXENBUS_CACHE               *Cache
    );

/*! \typedef XENBUS_CACHE_CREATE
    \brief Create a cache of objects of the given \a Size

    \param Interface The interface header
    \param Name A name for the cache which will be used in debug output
    \param Size The size of each object in bytes
    \param Reservation The target minimum population of the cache
    \param Cap The maximum population of the cache
    \param Ctor A callback which is invoked when a new object created
    \param Dtor A callback which is invoked when an object is destroyed
    \param AcquireLock A callback invoked to acquire a spinlock
    \param ReleaseLock A callback invoked to release the spinlock
    \param Argument An optional context argument passed to the callbacks
    \param Cache A pointer to a cache handle to be initialized

    If a non-zero \a Reservation is specified then this method will fail
    unless that number of objects can be immediately created.
*/  
typedef NTSTATUS
(*XENBUS_CACHE_CREATE)(
    IN  PINTERFACE                  Interface,
    IN  const CHAR                  *Name,
    IN  ULONG                       Size,
    IN  ULONG                       Reservation,
    IN  ULONG                       Cap,
    IN  XENBUS_CACHE_CTOR           Ctor,
    IN  XENBUS_CACHE_DTOR           Dtor,
    IN  XENBUS_CACHE_ACQUIRE_LOCK   AcquireLock,
    IN  XENBUS_CACHE_RELEASE_LOCK   ReleaseLock,
    IN  PVOID                       Argument OPTIONAL,
    OUT PXENBUS_CACHE               *Cache
    );

/*! \typedef XENBUS_CACHE_GET
    \brief Get an object from a \a Cache

    \param Interface The interface header
    \param Cache The cache handle
    \param Locked If mutually exclusive access to the cache is already
    guaranteed then set this to TRUE
*/
typedef PVOID
(*XENBUS_CACHE_GET)(
    IN  PINTERFACE      Interface,
    IN  PXENBUS_CACHE   Cache,
    IN  BOOLEAN         Locked
    );

/*! \typedef XENBUS_CACHE_PUT
    \brief Return an object to a \a Cache

    \param Interface The interface header
    \param Cache The cache handle
    \param Locked If mutually exclusive access to the cache is already
    guaranteed then set this to TRUE
*/
typedef VOID
(*XENBUS_CACHE_PUT)(
    IN  PINTERFACE      Interface,
    IN  PXENBUS_CACHE   Cache,
    IN  PVOID           Object,
    IN  BOOLEAN         Locked
    );

/*! \typedef XENBUS_CACHE_DESTROY
    \brief Destroy a \a Cache

    \param Interface The interface header
    \param Cache The cache handle

    All objects must have been returned to the cache prior to destruction
*/
typedef VOID
(*XENBUS_CACHE_DESTROY)(
    IN  PINTERFACE      Interface,
    IN  PXENBUS_CACHE   Cache
    );

// {A98DFD78-416A-4949-92A5-E084F2F4B44E}
DEFINE_GUID(GUID_XENBUS_CACHE_INTERFACE, 
0xa98dfd78, 0x416a, 0x4949, 0x92, 0xa5, 0xe0, 0x84, 0xf2, 0xf4, 0xb4, 0x4e);

/*! \struct _XENBUS_CACHE_INTERFACE_V1
    \brief CACHE interface version 1
    \ingroup interfaces
*/
struct _XENBUS_CACHE_INTERFACE_V1 {
    INTERFACE               Interface;
    XENBUS_CACHE_ACQUIRE    CacheAcquire;
    XENBUS_CACHE_RELEASE    CacheRelease;
    XENBUS_CACHE_CREATE_V1  CacheCreateVersion1;
    XENBUS_CACHE_GET        CacheGet;
    XENBUS_CACHE_PUT        CachePut;
    XENBUS_CACHE_DESTROY    CacheDestroy;
};

/*! \struct _XENBUS_CACHE_INTERFACE_V2
    \brief CACHE interface version 1
    \ingroup interfaces
*/
struct _XENBUS_CACHE_INTERFACE_V2 {
    INTERFACE               Interface;
    XENBUS_CACHE_ACQUIRE    CacheAcquire;
    XENBUS_CACHE_RELEASE    CacheRelease;
    XENBUS_CACHE_CREATE     CacheCreate;
    XENBUS_CACHE_GET        CacheGet;
    XENBUS_CACHE_PUT        CachePut;
    XENBUS_CACHE_DESTROY    CacheDestroy;
};

typedef struct _XENBUS_CACHE_INTERFACE_V2 XENBUS_CACHE_INTERFACE, *PXENBUS_CACHE_INTERFACE;

/*! \def XENBUS_CACHE
    \brief Macro at assist in method invocation
*/
#define XENBUS_CACHE(_Method, _Interface, ...)    \
    (_Interface)->Cache ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_CACHE_INTERFACE_VERSION_MIN  1
#define XENBUS_CACHE_INTERFACE_VERSION_MAX  2

#endif  // _XENBUS_CACHE_INTERFACE_H
