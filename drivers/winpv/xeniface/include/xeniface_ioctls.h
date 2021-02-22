/* Copyright (c) Citrix Systems Inc.
 * Copyright (c) Rafal Wojdyla <omeg@invisiblethingslab.com>
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

/*! \file xeniface_ioctls.h
    \brief User-mode IOCTL interfaces to the XENIFACE driver
*/

#ifndef _XENIFACE_IOCTLS_H_
#define _XENIFACE_IOCTLS_H_

#include <windef.h>

/*! \brief XENIFACE device GUID */
DEFINE_GUID(GUID_INTERFACE_XENIFACE, \
    0xb2cfb085, 0xaa5e, 0x47e1, 0x8b, 0xf7, 0x97, 0x93, 0xf3, 0x15, 0x45, 0x65);

/*! \brief Bitmask of XenStore key permissions */
typedef enum _XENIFACE_STORE_PERMISSION_MASK {
    XENIFACE_STORE_PERM_NONE  = 0, /*!< No access */
    XENIFACE_STORE_PERM_READ  = 1, /*!< Read access */
    XENIFACE_STORE_PERM_WRITE = 2, /*!< Write access */
} XENIFACE_STORE_PERMISSION_MASK;

/*! \brief XenStore key permissions entry for a single domain */
typedef struct _XENIFACE_STORE_PERMISSION {
    USHORT                         Domain; /*!< Target domain */
    XENIFACE_STORE_PERMISSION_MASK Mask;   /*!< Permissions for the domain */
} XENIFACE_STORE_PERMISSION, *PXENIFACE_STORE_PERMISSION;

/*! \brief Bitmask of all available XenStore permission values */
#define XENIFACE_STORE_ALLOWED_PERMISSIONS \
    (XENIFACE_STORE_PERM_NONE | XENIFACE_STORE_PERM_READ | XENIFACE_STORE_PERM_WRITE)

/*! \brief Read a value from XenStore

    Input: NUL-terminated CHAR array containing the requested key's path

    Output: NUL-terminated CHAR array containing the requested key's value
*/
#define IOCTL_XENIFACE_STORE_READ \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Write a value to XenStore

    Input: NUL-terminated CHAR array containing the requested key's path,
           NUL-terminated CHAR array containing the key's value,
           final NUL terminator

    Output: None
*/
#define IOCTL_XENIFACE_STORE_WRITE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Enumerate all immediate child keys of a XenStore key

    Input: NUL-terminated CHAR array containing the requested key's path

    Output: List of NUL-terminated CHAR arrays containing the child key names,
            followed by a NUL CHAR
*/
#define IOCTL_XENIFACE_STORE_DIRECTORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Remove a key from XenStore

    Input: NUL-terminated CHAR array containing the requested key's path

    Output: None
*/
#define IOCTL_XENIFACE_STORE_REMOVE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Set permissions for a XenStore key

    Input: XENIFACE_STORE_SET_PERMISSIONS_IN

    Output: None
*/
#define IOCTL_XENIFACE_STORE_SET_PERMISSIONS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_STORE_SET_PERMISSIONS */
typedef struct _XENIFACE_STORE_SET_PERMISSIONS_IN {
    PCHAR                     Path;                       /*!< NUL-terminated path to a XenStore key */
    ULONG                     PathLength;                 /*!< Size of Path in bytes, including the NUL terminator */
    ULONG                     NumberPermissions;          /*!< Number of permission entries */
    XENIFACE_STORE_PERMISSION Permissions[ANYSIZE_ARRAY]; /*!< Permission entries */
} XENIFACE_STORE_SET_PERMISSIONS_IN, *PXENIFACE_STORE_SET_PERMISSIONS_IN;

/*! \brief Add a XenStore watch

    Input: XENIFACE_STORE_ADD_WATCH_IN

    Output: XENIFACE_STORE_ADD_WATCH_OUT
*/
#define IOCTL_XENIFACE_STORE_ADD_WATCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_STORE_ADD_WATCH */
typedef struct _XENIFACE_STORE_ADD_WATCH_IN {
    PCHAR  Path;       /*!< NUL-terminated path to a XenStore key */
    ULONG  PathLength; /*!< Size of Path in bytes, including the NUL terminator */
    HANDLE Event;      /*!< Handle to an event object that will be signaled when the watch fires */
} XENIFACE_STORE_ADD_WATCH_IN, *PXENIFACE_STORE_ADD_WATCH_IN;

/*! \brief Output for IOCTL_XENIFACE_STORE_ADD_WATCH */
typedef struct _XENIFACE_STORE_ADD_WATCH_OUT {
    PVOID Context; /*!< Handle to the watch */
} XENIFACE_STORE_ADD_WATCH_OUT, *PXENIFACE_STORE_ADD_WATCH_OUT;

/*! \brief Remove a XenStore watch

    Input: XENIFACE_STORE_REMOVE_WATCH_IN

    Output: None
*/
#define IOCTL_XENIFACE_STORE_REMOVE_WATCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_STORE_REMOVE_WATCH */
typedef struct _XENIFACE_STORE_REMOVE_WATCH_IN {
    PVOID Context; /*!< Handle to the watch */
} XENIFACE_STORE_REMOVE_WATCH_IN, *PXENIFACE_STORE_REMOVE_WATCH_IN;

/*! \brief Open an event channel that was already bound by a remote domain

    Input: XENIFACE_EVTCHN_BIND_INTERDOMAIN_IN

    Output: XENIFACE_EVTCHN_BIND_INTERDOMAIN_OUT
*/
#define IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN */
typedef struct _XENIFACE_EVTCHN_BIND_INTERDOMAIN_IN {
    USHORT  RemoteDomain; /*!< Remote domain that has already bound the channel */
    ULONG   RemotePort;   /*!< Port number that is assigned to the event channel in the RemoteDomain */
    BOOLEAN Mask;         /*!< Set to TRUE if the event channel should be initially masked */
    HANDLE  Event;        /*!< Handle to an event object that will receive event channel notifications */
} XENIFACE_EVTCHN_BIND_INTERDOMAIN_IN, *PXENIFACE_EVTCHN_BIND_INTERDOMAIN_IN;

/*! \brief Output for IOCTL_XENIFACE_EVTCHN_BIND_INTERDOMAIN */
typedef struct _XENIFACE_EVTCHN_BIND_INTERDOMAIN_OUT {
    ULONG LocalPort; /*!< Local port number that is assigned to the event channel */
} XENIFACE_EVTCHN_BIND_INTERDOMAIN_OUT, *PXENIFACE_EVTCHN_BIND_INTERDOMAIN_OUT;

/*! \brief Open an unbound event channel

    Input: XENIFACE_EVTCHN_BIND_UNBOUND_IN

    Output: XENIFACE_EVTCHN_BIND_UNBOUND_OUT
*/
#define IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND */
typedef struct _XENIFACE_EVTCHN_BIND_UNBOUND_IN {
    USHORT  RemoteDomain; /*!< Remote domain that will bind the channel */
    BOOLEAN Mask;         /*!< Set to TRUE if the event channel should be initially masked */
    HANDLE  Event;        /*!< Handle to an event object that will receive event channel notifications */
} XENIFACE_EVTCHN_BIND_UNBOUND_IN, *PXENIFACE_EVTCHN_BIND_UNBOUND_IN;

/*! \brief Output for IOCTL_XENIFACE_EVTCHN_BIND_UNBOUND */
typedef struct _XENIFACE_EVTCHN_BIND_UNBOUND_OUT {
    ULONG LocalPort; /*!< Local port number that is assigned to the event channel */
} XENIFACE_EVTCHN_BIND_UNBOUND_OUT, *PXENIFACE_EVTCHN_BIND_UNBOUND_OUT;

/*! \brief Close an event channel

    Input: XENIFACE_EVTCHN_CLOSE_IN

    Output: None
*/
#define IOCTL_XENIFACE_EVTCHN_CLOSE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_EVTCHN_CLOSE */
typedef struct _XENIFACE_EVTCHN_CLOSE_IN {
    ULONG LocalPort; /*!< Local port number that is assigned to the event channel */
} XENIFACE_EVTCHN_CLOSE_IN, *PXENIFACE_EVTCHN_CLOSE_IN;

/*! \brief Notify the remote end of an event channel

    Input: XENIFACE_EVTCHN_CLOSE_IN

    Output: None
*/
#define IOCTL_XENIFACE_EVTCHN_NOTIFY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_EVTCHN_NOTIFY */
typedef struct _XENIFACE_EVTCHN_NOTIFY_IN {
    ULONG LocalPort; /*!< Local port number that is assigned to the event channel */
} XENIFACE_EVTCHN_NOTIFY_IN, *PXENIFACE_EVTCHN_NOTIFY_IN;

/*! \brief Unmask an event channel

    Input: XENIFACE_EVTCHN_CLOSE_IN

    Output: None
*/
#define IOCTL_XENIFACE_EVTCHN_UNMASK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_EVTCHN_UNMASK */
typedef struct _XENIFACE_EVTCHN_UNMASK_IN {
    ULONG LocalPort; /*!< Local port number that is assigned to the event channel */
} XENIFACE_EVTCHN_UNMASK_IN, *PXENIFACE_EVTCHN_UNMASK_IN;

/*! \brief Bitmask of XenStore key permissions */
typedef enum _XENIFACE_GNTTAB_PAGE_FLAGS {
    XENIFACE_GNTTAB_READONLY          = 1 << 0, /*!< If set, the granted/mapped pages are read-only */
    XENIFACE_GNTTAB_USE_NOTIFY_OFFSET = 1 << 1, /*!< If set, the NotifyOffset member of the grant/map IOCTL input is used */
    XENIFACE_GNTTAB_USE_NOTIFY_PORT   = 1 << 2, /*!< If set, the NotifyPort member of the grant/map IOCTL input is used */
} XENIFACE_GNTTAB_PAGE_FLAGS;

/*! \brief Grant permission to access local memory pages to a foreign domain
    \note This IOCTL must be asynchronous. The driver doesn't complete the request
          until the grant is explicitly revoked or the calling thread terminates.

    Input: XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_IN

    Output: XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT
*/
#define IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_NEITHER, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS */
typedef struct _XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_IN {
    ULONG                      RequestId;    /*!< A unique (for the calling process) number identifying the request */
    USHORT                     RemoteDomain; /*!< Remote domain that is being granted access */
    ULONG                      NumberPages;  /*!< Number of 4k pages to grant access to */
    XENIFACE_GNTTAB_PAGE_FLAGS Flags;        /*!< Additional flags */
    ULONG                      NotifyOffset; /*!< Offset of a byte in the granted region that will be set to 0 when the grant is revoked */
    ULONG                      NotifyPort;   /*!< Local port number of an open event channel that will be notified when the grant is revoked */
} XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_IN, *PXENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_IN;

/*! \brief Output for IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS */
typedef struct _XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT {
    PVOID Address;                   /*!< User-mode address of the granted memory region */
    ULONG References[ANYSIZE_ARRAY]; /*!< An array of Xen-assigned references for each granted page */
} XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT, *PXENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS_OUT;

/*! \brief Revoke a foreign domain access to previously granted memory region

    Input: XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_IN

    Output: None
*/
#define IOCTL_XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS */
typedef struct _XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_IN {
    ULONG RequestId; /*! Request ID used in the corresponding IOCTL_XENIFACE_GNTTAB_PERMIT_FOREIGN_ACCESS call */
} XENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_IN, *PXENIFACE_GNTTAB_REVOKE_FOREIGN_ACCESS_IN;

/*! \brief Map a foreign memory region into the current address space
    \note This IOCTL must be asynchronous. The driver doesn't complete the request
          until the memory is explicitly unmapped or the calling thread terminates.

    Input: XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN

    Output: XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT
*/
#define IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_NEITHER, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES */
typedef struct _XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN {
    ULONG                      RequestId;                 /*!< A unique (for the calling process) number identifying the request */
    USHORT                     RemoteDomain;              /*!< Remote domain that has granted access to the pages */
    ULONG                      NumberPages;               /*!< Number of 4k pages to map */
    XENIFACE_GNTTAB_PAGE_FLAGS Flags;                     /*!< Additional flags */
    ULONG                      NotifyOffset;              /*!< Offset of a byte in the mapped region that will be set to 0 when the region is unmapped */
    ULONG                      NotifyPort;                /*!< Local port number of an open event channel that will be notified when the region is unmapped */
    ULONG                      References[ANYSIZE_ARRAY]; /*!< An array of Xen-assigned references for each granted page */
} XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN, *PXENIFACE_GNTTAB_MAP_FOREIGN_PAGES_IN;

/*! \brief Output for IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES */
typedef struct _XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT {
    PVOID Address; /*!< User-mode address of the mapped memory region */
} XENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT, *PXENIFACE_GNTTAB_MAP_FOREIGN_PAGES_OUT;

/*! \brief Unmap a foreign memory region from the current address space

    Input: XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_IN

    Output: None
*/
#define IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES */
typedef struct _XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_IN {
    ULONG RequestId; /*! Request ID used in the corresponding IOCTL_XENIFACE_GNTTAB_MAP_FOREIGN_PAGES call */
} XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_IN, *PXENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES_IN;

/*! \brief Gets the current suspend count.

    Input: None

    Output: ULONG
*/
#define IOCTL_XENIFACE_SUSPEND_GET_COUNT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Input for IOCTL_XENIFACE_SUSPEND_REGISTER */
typedef struct _XENIFACE_SUSPEND_REGISTER_IN {
    HANDLE Event; /*!< Handle to an event object that will receive suspend notifications */
} XENIFACE_SUSPEND_REGISTER_IN, *PXENIFACE_SUSPEND_REGISTER_IN;

/*! \brief Input for IOCTL_XENIFACE_SUSPEND_DEREGISTER */
typedef struct _XENIFACE_SUSPEND_REGISTER_OUT {
    PVOID Context; /*!< Handle to the suspend event */
} XENIFACE_SUSPEND_REGISTER_OUT, *PXENIFACE_SUSPEND_REGISTER_OUT;

/*! \brief Registers an event which is signalled on resume-from-suspend

    Input: XENIFACE_SUSPEND_REGISTER_IN

    Output: XENIFACE_SUSPEND_REGISTER_OUT
*/
#define IOCTL_XENIFACE_SUSPEND_REGISTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Deregisters an event which is signalled on resume-from-suspend

    Input: XENIFACE_SUSPEND_REGISTER_OUT

    Output: None
*/
#define IOCTL_XENIFACE_SUSPEND_DEREGISTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Gets the current time.

    Input: None

    Output: LARGE_INTEGER
*/
#define IOCTL_XENIFACE_SHAREDINFO_GET_TIME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Output for IOCTL_XENIFACE_GNTTAB_UNMAP_FOREIGN_PAGES */
typedef struct _XENIFACE_SHAREDINFO_GET_TIME_OUT {
    FILETIME Time; /*!< Current wallclock time */
    BOOLEAN Local; /*!< TRUE is wallclock is in local time, FALSE if it is in UTC */
} XENIFACE_SHAREDINFO_GET_TIME_OUT, *PXENIFACE_SHAREDINFO_GET_TIME_OUT;

/*! \brief Logs a message to Dom0

    Input: NUL-terminated CHAR array containing the message to log
           Must be less than XENIFACE_LOG_MAX_LENGTH long, and only contain
           printable or newline characters ( isprint(x) || x == '\n' )

    Output: None
*/
#define IOCTL_XENIFACE_LOG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84F, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*! \brief Maximum number of CHARs for IOCTL_XENIFACE_LOG, including NUL terminator
*/
#define XENIFACE_LOG_MAX_LENGTH         256

#endif // _XENIFACE_IOCTLS_H_
