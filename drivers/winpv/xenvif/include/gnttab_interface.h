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

/*! \file gnttab_interface.h
    \brief XENBUS GNTTAB Interface

    This interface provides access to the hypervisor grant table
*/

#ifndef _XENBUS_GNTTAB_INTERFACE_H
#define _XENBUS_GNTTAB_INTERFACE_H

#include <cache_interface.h>

#ifndef _WINDLL

/*! \typedef XENBUS_GNTTAB_ENTRY
    \brief Grant table entry handle
*/
typedef struct _XENBUS_GNTTAB_ENTRY XENBUS_GNTTAB_ENTRY, *PXENBUS_GNTTAB_ENTRY;

/*! \typedef XENBUS_GNTTAB_CACHE
    \brief Grant table cache handle
*/
typedef struct _XENBUS_GNTTAB_CACHE XENBUS_GNTTAB_CACHE, *PXENBUS_GNTTAB_CACHE;

/*! \typedef XENBUS_GNTTAB_ACQUIRE
    \brief Acquire a reference to the GNTTAB interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENBUS_GNTTAB_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_GNTTAB_RELEASE
    \brief Release a reference to the GNTTAB interface

    \param Interface The interface header
*/  
typedef VOID
(*XENBUS_GNTTAB_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_GNTTAB_CREATE_CACHE
    \brief Create a cache of grant table entries

    \param Interface The interface header
    \param Name A name for the cache which will be used in debug output
    \param Reservation The target minimum population of the cache
    \param AcquireLock A callback invoked to acquire a spinlock
    \param ReleaseLock A callback invoked to release the spinlock
    \param Argument An optional context argument passed to the callbacks
    \param Cache A pointer to a grant table cache handle to be initialized
*/  
typedef NTSTATUS
(*XENBUS_GNTTAB_CREATE_CACHE)(
    IN  PINTERFACE                  Interface,
    IN  const CHAR                  *Name,
    IN  ULONG                       Reservation,
    IN  XENBUS_CACHE_ACQUIRE_LOCK   AcquireLock,
    IN  XENBUS_CACHE_RELEASE_LOCK   ReleaseLock,
    IN  PVOID                       Argument OPTIONAL,
    OUT PXENBUS_GNTTAB_CACHE        *Cache
    );

/*! \typedef XENBUS_GNTTAB_PERMIT_FOREIGN_ACCESS
    \brief Get a table entry from the \a Cache permitting access to a given \a Pfn

    \param Interface The interface header
    \param Cache The grant table cache handle
    \param Locked If mutually exclusive access to the cache is already
    guaranteed then set this to TRUE
    \param Domain The domid of the domain being granted access
    \param Pfn The frame number of the page that we are granting access to
    \param ReadOnly Set to TRUE if the foreign domain is only being granted
    read access
    \param Entry A pointer to a grant table entry handle to be initialized
*/
typedef NTSTATUS
(*XENBUS_GNTTAB_PERMIT_FOREIGN_ACCESS)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_GNTTAB_CACHE        Cache,
    IN  BOOLEAN                     Locked,
    IN  USHORT                      Domain,
    IN  PFN_NUMBER                  Pfn,
    IN  BOOLEAN                     ReadOnly,
    OUT PXENBUS_GNTTAB_ENTRY        *Entry
    );

/*! \typedef XENBUS_GNTTAB_REVOKE_FOREIGN_ACCESS
    \brief Revoke foreign access and return the \a Entry to the \a Cache

    \param Interface The interface header
    \param Cache The grant table cache handle
    \param Locked If mutually exclusive access to the cache is already
    guaranteed then set this to TRUE
    \param Entry The grant table entry handle
*/
typedef NTSTATUS
(*XENBUS_GNTTAB_REVOKE_FOREIGN_ACCESS)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_GNTTAB_CACHE        Cache,
    IN  BOOLEAN                     Locked,
    IN  PXENBUS_GNTTAB_ENTRY        Entry
    );

/*! \typedef XENBUS_GNTTAB_GET_REFERENCE
    \brief Get the reference number of the entry

    \param Interface The interface header
    \param Entry The grant table entry handle
    \return The reference number
*/  
typedef ULONG
(*XENBUS_GNTTAB_GET_REFERENCE)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_GNTTAB_ENTRY        Entry
    );

/*! \typedef XENBUS_GNTTAB_QUERY_REFERENCE
    \brief Get the reference number of the entry

    \param Interface The interface header
    \param Reference The reference number
    \param Pfn An optional pointer to receive the value of the reference frame number
    \param ReadOnly An optional pointer to receive the boolean value of the read-only flag
*/
typedef NTSTATUS
(*XENBUS_GNTTAB_QUERY_REFERENCE)(
    IN  PINTERFACE  Interface,
    IN  ULONG       Reference,
    OUT PPFN_NUMBER Pfn OPTIONAL,
    OUT PBOOLEAN    ReadOnly OPTIONAL
    );

#define XENBUS_GNTTAB_CONSOLE_REFERENCE 0
#define XENBUS_GNTTAB_STORE_REFERENCE   1


/*! \typedef XENBUS_GNTTAB_DESTROY_CACHE
    \brief Destroy a cache of grant table entries

    \param Interface The interface header
    \param Cache The grant table cache handle

    All grant table entries must have been revoked prior to destruction
    of the cache 
*/  
typedef VOID
(*XENBUS_GNTTAB_DESTROY_CACHE)(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_GNTTAB_CACHE    Cache
    );

/*! \typedef XENBUS_GNTTAB_MAP_FOREIGN_PAGES
    \brief Map foreign memory pages into the system address space

    \param Interface The interface header
    \param Domain The domid of the foreign domain that granted the pages
    \param NumberPages Number of pages to map
    \param References Array of grant reference numbers shared by the foreign domain
    \param ReadOnly If TRUE, pages are mapped with read-only access
    \param Address The physical address that the foreign pages are mapped under
*/

typedef NTSTATUS
(*XENBUS_GNTTAB_MAP_FOREIGN_PAGES)(
    IN  PINTERFACE              Interface,
    IN  USHORT                  Domain,
    IN  ULONG                   NumberPages,
    IN  PULONG                  References,
    IN  BOOLEAN                 ReadOnly,
    OUT PHYSICAL_ADDRESS        *Address
    );

/*! \typedef XENBUS_GNTTAB_UNMAP_FOREIGN_PAGES
    \brief Unmap foreign memory pages from the system address space

    \param Interface The interface header
    \param Address The physical address that the foreign pages are mapped under
*/
typedef NTSTATUS
(*XENBUS_GNTTAB_UNMAP_FOREIGN_PAGES)(
    IN  PINTERFACE              Interface,
    IN  PHYSICAL_ADDRESS        Address
    );

// {763679C5-E5C2-4A6D-8B88-6BB02EC42D8E}
DEFINE_GUID(GUID_XENBUS_GNTTAB_INTERFACE, 
0x763679c5, 0xe5c2, 0x4a6d, 0x8b, 0x88, 0x6b, 0xb0, 0x2e, 0xc4, 0x2d, 0x8e);

/*! \struct _XENBUS_GNTTAB_INTERFACE_V1
    \brief GNTTAB interface version 1
    \ingroup interfaces
*/
struct _XENBUS_GNTTAB_INTERFACE_V1 {
    INTERFACE                           Interface;
    XENBUS_GNTTAB_ACQUIRE               GnttabAcquire;
    XENBUS_GNTTAB_RELEASE               GnttabRelease;
    XENBUS_GNTTAB_CREATE_CACHE          GnttabCreateCache;
    XENBUS_GNTTAB_PERMIT_FOREIGN_ACCESS GnttabPermitForeignAccess;
    XENBUS_GNTTAB_REVOKE_FOREIGN_ACCESS GnttabRevokeForeignAccess;
    XENBUS_GNTTAB_GET_REFERENCE         GnttabGetReference;
    XENBUS_GNTTAB_DESTROY_CACHE         GnttabDestroyCache;
};

/*! \struct _XENBUS_GNTTAB_INTERFACE_V2
    \brief GNTTAB interface version 2
    \ingroup interfaces
*/
struct _XENBUS_GNTTAB_INTERFACE_V2 {
    INTERFACE                           Interface;
    XENBUS_GNTTAB_ACQUIRE               GnttabAcquire;
    XENBUS_GNTTAB_RELEASE               GnttabRelease;
    XENBUS_GNTTAB_CREATE_CACHE          GnttabCreateCache;
    XENBUS_GNTTAB_PERMIT_FOREIGN_ACCESS GnttabPermitForeignAccess;
    XENBUS_GNTTAB_REVOKE_FOREIGN_ACCESS GnttabRevokeForeignAccess;
    XENBUS_GNTTAB_GET_REFERENCE         GnttabGetReference;
    XENBUS_GNTTAB_DESTROY_CACHE         GnttabDestroyCache;
    XENBUS_GNTTAB_MAP_FOREIGN_PAGES     GnttabMapForeignPages;
    XENBUS_GNTTAB_UNMAP_FOREIGN_PAGES   GnttabUnmapForeignPages;
};

/*! \struct _XENBUS_GNTTAB_INTERFACE_V3
    \brief GNTTAB interface version 3
    \ingroup interfaces
*/
struct _XENBUS_GNTTAB_INTERFACE_V3 {
    INTERFACE                           Interface;
    XENBUS_GNTTAB_ACQUIRE               GnttabAcquire;
    XENBUS_GNTTAB_RELEASE               GnttabRelease;
    XENBUS_GNTTAB_CREATE_CACHE          GnttabCreateCache;
    XENBUS_GNTTAB_PERMIT_FOREIGN_ACCESS GnttabPermitForeignAccess;
    XENBUS_GNTTAB_REVOKE_FOREIGN_ACCESS GnttabRevokeForeignAccess;
    XENBUS_GNTTAB_GET_REFERENCE         GnttabGetReference;
    XENBUS_GNTTAB_QUERY_REFERENCE       GnttabQueryReference;
    XENBUS_GNTTAB_DESTROY_CACHE         GnttabDestroyCache;
    XENBUS_GNTTAB_MAP_FOREIGN_PAGES     GnttabMapForeignPages;
    XENBUS_GNTTAB_UNMAP_FOREIGN_PAGES   GnttabUnmapForeignPages;
};

typedef struct _XENBUS_GNTTAB_INTERFACE_V3 XENBUS_GNTTAB_INTERFACE, *PXENBUS_GNTTAB_INTERFACE;

/*! \def XENBUS_GNTTAB
    \brief Macro at assist in method invocation
*/
#define XENBUS_GNTTAB(_Method, _Interface, ...)    \
    (_Interface)->Gnttab ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_GNTTAB_INTERFACE_VERSION_MIN 1
#define XENBUS_GNTTAB_INTERFACE_VERSION_MAX 3

#endif  // _XENBUS_GNTTAB_INTERFACE_H

