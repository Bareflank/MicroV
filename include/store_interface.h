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

/*! \file store_interface.h
    \brief XENBUS STORE Interface

    This interface provides access to XenStore
*/

#ifndef _XENBUS_STORE_INTERFACE_H
#define _XENBUS_STORE_INTERFACE_H

#ifndef _WINDLL

/*! \typedef XENBUS_STORE_TRANSACTION
    \brief XenStore transaction handle
*/
typedef struct _XENBUS_STORE_TRANSACTION    XENBUS_STORE_TRANSACTION, *PXENBUS_STORE_TRANSACTION;

/*! \typedef XENBUS_STORE_WATCH
    \brief XenStore watch handle
*/
typedef struct _XENBUS_STORE_WATCH          XENBUS_STORE_WATCH, *PXENBUS_STORE_WATCH;

/*! \typedef XENBUS_STORE_PERMISSION_MASK
    \brief Bitmask of XenStore key permissions
*/
typedef enum _XENBUS_STORE_PERMISSION_MASK {
    XENBUS_STORE_PERM_NONE = 0,
    XENBUS_STORE_PERM_READ = 1,
    XENBUS_STORE_PERM_WRITE = 2,
} XENBUS_STORE_PERMISSION_MASK;

/*! \typedef XENBUS_STORE_PERMISSION
    \brief XenStore key permissions entry for a single domain
*/
typedef struct _XENBUS_STORE_PERMISSION {
    USHORT                          Domain;
    XENBUS_STORE_PERMISSION_MASK    Mask;
} XENBUS_STORE_PERMISSION, *PXENBUS_STORE_PERMISSION;

/*! \typedef XENBUS_STORE_ACQUIRE
    \brief Acquire a reference to the STORE interface

    \param Interface The interface header
*/  
typedef NTSTATUS
(*XENBUS_STORE_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_STORE_RELEASE
    \brief Release a reference to the STORE interface

    \param Interface The interface header
*/  
typedef VOID
(*XENBUS_STORE_RELEASE)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_STORE_FREE
    \brief Free a memory buffer allocated by the STORE interface

    \param Interface The interface header
    \param Buffer Pointer to the memory buffer
*/  
typedef VOID
(*XENBUS_STORE_FREE)(
    IN  PINTERFACE  Interface,
    IN  PCHAR       Buffer
    );

/*! \typedef XENBUS_STORE_READ
    \brief Read a value from XenStore

    \param Interface The interface header
    \param Transaction The transaction handle (NULL if this read is not
    part of a transaction)
    \param Prefix An optional prefix for the \a Node
    \param Node The concatenation of the \a Prefix and this value specifies
    the XenStore key to read
    \param A pointer to a pointer that will be initialized with a memory
    buffer containing the value read

    The \a Buffer should be freed using \a XENBUS_STORE_FREE
*/  
typedef NTSTATUS
(*XENBUS_STORE_READ)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    OUT PCHAR                       *Buffer
    );

/*! \typedef XENBUS_STORE_PRINTF
    \brief Write a value to XenStore

    \param Interface The interface header
    \param Transaction The transaction handle (NULL if this write is not
    part of a transaction)
    \param Prefix An optional prefix for the \a Node
    \param Node The concatenation of the \a Prefix and this value specifies
    the XenStore key to write
    \param Format A format specifier
    \param ... Additional parameters required by \a Format

    If the \a Node does not exist then it is created
*/  
typedef NTSTATUS
(*XENBUS_STORE_PRINTF)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    IN  const CHAR                  *Format,
    ...
    );

/*! \typedef XENBUS_STORE_REMOVE
    \brief Remove a key from XenStore

    \param Interface The interface header
    \param Transaction The transaction handle (NULL if this removal is not
    part of a transaction)
    \param Prefix An optional prefix for the \a Node
    \param Node The concatenation of the \a Prefix and this value specifies
    the XenStore key to remove
*/  
typedef NTSTATUS
(*XENBUS_STORE_REMOVE)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node
    );

/*! \typedef XENBUS_STORE_DIRECTORY
    \brief Enumerate all immediate child keys of a XenStore key

    \param Interface The interface header
    \param Transaction The transaction handle (NULL if this removal is not
    part of a transaction)
    \param Prefix An optional prefix for the \a Node
    \param Node The concatenation of the \a Prefix and this value specifies
    the XenStore key to enumerate
    \param A pointer to a pointer that will be initialized with a memory
    buffer containing a NUL separated list of key names

    The \a Buffer should be freed using \a XENBUS_STORE_FREE
*/  
typedef NTSTATUS
(*XENBUS_STORE_DIRECTORY)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    OUT PCHAR                       *Buffer
    );

/*! \typedef XENBUS_STORE_TRANSACTION_START
    \brief Start a XenStore transaction

    \param Interface The interface header
    \param Transaction Pointer to a transaction handle to be initialized
*/  
typedef NTSTATUS
(*XENBUS_STORE_TRANSACTION_START)(
    IN  PINTERFACE                  Interface,
    OUT PXENBUS_STORE_TRANSACTION   *Transaction
    );

/*! \typedef XENBUS_STORE_TRANSACTION_END
    \brief End a XenStore transaction

    \param Interface The interface header
    \param Transaction The transaction handle
    \param Commit Set to TRUE if actions performed within the transaction should
    be made visible, or FALSE if they should not be

    If \a Commit is TRUE and the transaction to found to clash then
    STATUS_RETRY will be returned
*/  
typedef NTSTATUS
(*XENBUS_STORE_TRANSACTION_END)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  BOOLEAN                     Commit
    );

/*! \typedef XENBUS_STORE_WATCH_ADD
    \brief Add a XenStore watch

    \param Interface The interface header
    \param Prefix An optional prefix for the \a Node
    \param Node The concatenation of the \a Prefix and this value specifies
    the XenStore key to watch
    \param Event A pointer to an event object to be signalled when the
    watch fires
    \param Watch A pointer to a watch handle to be initialized
*/  
typedef NTSTATUS
(*XENBUS_STORE_WATCH_ADD)(
    IN  PINTERFACE          Interface,
    IN  PCHAR               Prefix OPTIONAL,
    IN  PCHAR               Node,
    IN  PKEVENT             Event,
    OUT PXENBUS_STORE_WATCH *Watch
    );

/*! \typedef XENBUS_STORE_WATCH_REMOVE
    \brief Remove a XenStore watch

    \param Interface The interface header
    \param Watch The watch handle
*/  
typedef NTSTATUS
(*XENBUS_STORE_WATCH_REMOVE)(
    IN  PINTERFACE          Interface,
    IN  PXENBUS_STORE_WATCH Watch
    );

/*! \typedef XENBUS_STORE_POLL
    \brief Poll for XenStore activity

    \param Interface The interface header

    If it is necessary to spin at DISPATCH_LEVEL waiting for XenStore
    activity then this will block the normal STORE interface DPC so this
    method must be regularly invoked during the spin loop to check for
    XenStore activity
*/  
typedef VOID
(*XENBUS_STORE_POLL)(
    IN  PINTERFACE  Interface
    );

/*! \typedef XENBUS_STORE_PERMISSIONS_SET
    \brief Set permissions for a XenStore key

    \param Interface The interface header
    \param Transaction The transaction handle (NULL if this is not
    part of a transaction)
    \param Prefix An optional prefix for the \a Node
    \param Node The concatenation of the \a Prefix and this value specifies
    the XenStore key to set permissions of
    \param Permissions An array of permissions to set
    \param NumberPermissions Number of elements in the \a Permissions array
*/
typedef NTSTATUS
(*XENBUS_STORE_PERMISSIONS_SET)(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    IN  PXENBUS_STORE_PERMISSION    Permissions,
    IN  ULONG                       NumberPermissions
    );

// {86824C3B-D34E-4753-B281-2F1E3AD214D7}
DEFINE_GUID(GUID_XENBUS_STORE_INTERFACE, 
0x86824c3b, 0xd34e, 0x4753, 0xb2, 0x81, 0x2f, 0x1e, 0x3a, 0xd2, 0x14, 0xd7);

/*! \struct _XENBUS_STORE_INTERFACE_V1
    \brief STORE interface version 1
    \ingroup interfaces
*/
struct _XENBUS_STORE_INTERFACE_V1 {
    INTERFACE                       Interface;
    XENBUS_STORE_ACQUIRE            StoreAcquire;
    XENBUS_STORE_RELEASE            StoreRelease;
    XENBUS_STORE_FREE               StoreFree;
    XENBUS_STORE_READ               StoreRead;
    XENBUS_STORE_PRINTF             StorePrintf;
    XENBUS_STORE_REMOVE             StoreRemove;
    XENBUS_STORE_DIRECTORY          StoreDirectory;
    XENBUS_STORE_TRANSACTION_START  StoreTransactionStart;
    XENBUS_STORE_TRANSACTION_END    StoreTransactionEnd;
    XENBUS_STORE_WATCH_ADD          StoreWatchAdd;
    XENBUS_STORE_WATCH_REMOVE       StoreWatchRemove;
    XENBUS_STORE_POLL               StorePoll;
};

/*! \struct _XENBUS_STORE_INTERFACE_V2
    \brief STORE interface version 2
    \ingroup interfaces
*/
struct _XENBUS_STORE_INTERFACE_V2 {
    INTERFACE                       Interface;
    XENBUS_STORE_ACQUIRE            StoreAcquire;
    XENBUS_STORE_RELEASE            StoreRelease;
    XENBUS_STORE_FREE               StoreFree;
    XENBUS_STORE_READ               StoreRead;
    XENBUS_STORE_PRINTF             StorePrintf;
    XENBUS_STORE_PERMISSIONS_SET    StorePermissionsSet;
    XENBUS_STORE_REMOVE             StoreRemove;
    XENBUS_STORE_DIRECTORY          StoreDirectory;
    XENBUS_STORE_TRANSACTION_START  StoreTransactionStart;
    XENBUS_STORE_TRANSACTION_END    StoreTransactionEnd;
    XENBUS_STORE_WATCH_ADD          StoreWatchAdd;
    XENBUS_STORE_WATCH_REMOVE       StoreWatchRemove;
    XENBUS_STORE_POLL               StorePoll;
};

typedef struct _XENBUS_STORE_INTERFACE_V2 XENBUS_STORE_INTERFACE, *PXENBUS_STORE_INTERFACE;

/*! \def XENBUS_STORE
    \brief Macro at assist in method invocation
*/
#define XENBUS_STORE(_Method, _Interface, ...)    \
    (_Interface)->Store ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENBUS_STORE_INTERFACE_VERSION_MIN  1
#define XENBUS_STORE_INTERFACE_VERSION_MAX  2

#endif  // _XENBUS_STORE_INTERFACE_H

