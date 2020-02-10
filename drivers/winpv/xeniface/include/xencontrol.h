#ifndef _XENCONTROL_H_
#define _XENCONTROL_H_

#include <windows.h>
#include <varargs.h>
#include "xeniface_ioctls.h"

#ifdef XENCONTROL_EXPORTS
#    define XENCONTROL_API __declspec(dllexport)
#else
#    define XENCONTROL_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*! \typedef PXENCONTROL_CONTEXT
    \brief Library handle representing a Xen Interface session
*/
struct _XENCONTROL_CONTEXT;
typedef struct _XENCONTROL_CONTEXT *PXENCONTROL_CONTEXT;

/*! \typedef XENCONTROL_LOG_LEVEL
    \brief Log levels used by the library
*/
typedef enum
_XENCONTROL_LOG_LEVEL {
    XLL_ERROR = 1,
    XLL_WARNING,
    XLL_INFO,
    XLL_DEBUG,
    XLL_TRACE,
} XENCONTROL_LOG_LEVEL;

/*! \typedef XENCONTROL_LOGGER
    \brief Callback for receiving diagnostic messages from the library
*/
typedef void
XENCONTROL_LOGGER(
    IN  XENCONTROL_LOG_LEVEL LogLevel,
    IN  const CHAR *Function,
    IN  const WCHAR *Message,
    IN  va_list Args
    );

/*! \brief Register a callback for receiving library's diagnostic messages
    \param Xc Xencontrol handle returned by XcOpen()
    \param Logger Callback to register
*/
XENCONTROL_API
void
XcRegisterLogger(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XENCONTROL_LOGGER *Logger
    );

/*! \brief Set log level threshold for library's diagnostic messages
    \param Xc Xencontrol handle returned by XcOpen()
    \param LogLevel Only messages with this level and above will be sent to the logger callback
*/
XENCONTROL_API
void
XcSetLogLevel(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  XENCONTROL_LOG_LEVEL LogLevel
    );

/*! \brief Open the Xen Interface device
    \param Logger Callback for receiving library's diagnostic messages
    \param Xc Xencontrol handle representing a Xen Interface session
    \return Error code
*/
XENCONTROL_API
DWORD
XcOpen(
    IN  XENCONTROL_LOGGER *Logger,
    OUT PXENCONTROL_CONTEXT *Xc
    );

/*! \brief Close the Xen Interface device
    \param Xc Xencontrol handle returned by XcOpen()
*/
XENCONTROL_API
void
XcClose(
    IN  PXENCONTROL_CONTEXT Xc
    );

/*! \brief Open an unbound event channel
    \param Xc Xencontrol handle returned by XcOpen()
    \param RemoteDomain ID of a remote domain that will bind the channel
    \param Event Handle to an event object that will receive event channel notifications
    \param Mask Set to TRUE if the event channel should be initially masked
    \param LocalPort Port number that is assigned to the event channel
    \return Error code
*/
XENCONTROL_API
DWORD
XcEvtchnOpenUnbound(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    );

/*! \brief Open an event channel that was already bound by a remote domain
    \param Xc Xencontrol handle returned by XcOpen()
    \param RemoteDomain ID of a remote domain that has already bound the channel
    \param RemotePort Port number that is assigned to the event channel in the \a RemoteDomain
    \param Event Handle to an event that will receive event channel notifications
    \param Mask Set to TRUE if the event object channel should be initially masked
    \param LocalPort Port number that is assigned to the event channel
    \return Error code
*/
XENCONTROL_API
DWORD
XcEvtchnBindInterdomain(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG RemotePort,
    IN  HANDLE Event,
    IN  BOOL Mask,
    OUT ULONG *LocalPort
    );

/*! \brief Close an event channel
    \param Xc Xencontrol handle returned by XcOpen()
    \param LocalPort Port number that is assigned to the event channel
    \return Error code
*/
XENCONTROL_API
DWORD
XcEvtchnClose(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    );

/*! \brief Notify the remote end of an event channel
    \param Xc Xencontrol handle returned by XcOpen()
    \param LocalPort Port number that is assigned to the event channel
    \return Error code
*/
XENCONTROL_API
DWORD
XcEvtchnNotify(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    );

/*! \brief Unmask an event channel
    \param Xc Xencontrol handle returned by XcOpen()
    \param LocalPort Port number that is assigned to the event channel
    \return Error code
*/
XENCONTROL_API
DWORD
XcEvtchnUnmask(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  ULONG LocalPort
    );

/*! \brief Grant a \a RemoteDomain permission to access local memory pages
    \param Xc Xencontrol handle returned by XcOpen()
    \param RemoteDomain ID of a remote domain that is being granted access
    \param NumberPages Number of 4k pages to grant access to
    \param NotifyOffset Offset of a byte in the granted region that will be set to 0 when the grant is revoked
    \param NotifyPort Local port number of an open event channel that will be notified when the grant is revoked
    \param Flags Grant options
    \param Address Local user mode address of the granted memory region
    \param References An array of Xen grant numbers for every granted page
    \return Error code
*/
XENCONTROL_API
DWORD
XcGnttabPermitForeignAccess(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  XENIFACE_GNTTAB_PAGE_FLAGS Flags,
    OUT PVOID *Address,
    OUT ULONG *References
    );

/*! \brief Revoke a foreign domain access to previously granted memory region
    \param Xc Xencontrol handle returned by XcOpen()
    \param Address Local user mode address of the granted memory region
    \return Error code
*/
XENCONTROL_API
DWORD
XcGnttabRevokeForeignAccess(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    );

/*! \brief Map a foreign memory region into the current address space
    \param Xc Xencontrol handle returned by XcOpen()
    \param RemoteDomain ID of a remote domain that has granted access to the pages
    \param NumberPages Number of 4k pages to map
    \param References An array of Xen grant numbers for every granted page
    \param NotifyOffset Offset of a byte in the mapped region that will be set to 0 when the region is unmapped
    \param NotifyPort Local port number of an open event channel that will be notified when the region is unmapped
    \param Flags Map options
    \param Address Local user mode address of the mapped memory region
    \return Error code
*/
XENCONTROL_API
DWORD
XcGnttabMapForeignPages(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  USHORT RemoteDomain,
    IN  ULONG NumberPages,
    IN  PULONG References,
    IN  ULONG NotifyOffset,
    IN  ULONG NotifyPort,
    IN  XENIFACE_GNTTAB_PAGE_FLAGS Flags,
    OUT PVOID *Address
    );

/*! \brief Unmap a foreign memory region from the current address space
    \param Xc Xencontrol handle returned by XcOpen()
    \param Address Local user mode address of the mapped memory region
    \return Error code
*/
XENCONTROL_API
DWORD
XcGnttabUnmapForeignPages(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Address
    );

/*! \brief Read a XenStore key
    \param Xc Xencontrol handle returned by XcOpen()
    \param Path Path to the key
    \param cbValue Size of the \a Value buffer, in bytes
    \param Value Buffer that receives the value
    \return Error code
*/
XENCONTROL_API
DWORD
XcStoreRead(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  DWORD cbValue,
    OUT CHAR *Value
    );

/*! \brief Write a value to a XenStore key
    \param Xc Xencontrol handle returned by XcOpen()
    \param Path Path to the key
    \param Value Value to write
    \return Error code
*/
XENCONTROL_API
DWORD
XcStoreWrite(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  PCHAR Value
    );

/*! \brief Enumerate all immediate child keys of a XenStore key
    \param Xc Xencontrol handle returned by XcOpen()
    \param Path Path to the key
    \param cbOutput Size of the \a Output buffer, in bytes
    \param Output Buffer that receives a NUL-separated child key names
    \return Error code
*/
XENCONTROL_API
DWORD
XcStoreDirectory(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  DWORD cbOutput,
    OUT CHAR *Output
    );

/*! \brief Remove a XenStore key
    \param Xc Xencontrol handle returned by XcOpen()
    \param Path Path to the key
    \return Error code
*/
XENCONTROL_API
DWORD
XcStoreRemove(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path
    );

/*! \brief Set permissions of a XenStore key
    \param Xc Xencontrol handle returned by XcOpen()
    \param Path Path to the key
    \param Count Number of permissions
    \param Permissions Array of permissions to set
    \return Error code
*/
XENCONTROL_API
DWORD
XcStoreSetPermissions(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  ULONG Count,
    IN  PXENIFACE_STORE_PERMISSION Permissions
    );

/*! \brief Add a XenStore key watch
    \param Xc Xencontrol handle returned by XcOpen()
    \param Path Path to the key to be watched
    \param Event Handle to an event that will be signaled when the watch fires
    \param Handle An opaque value representing the watch
    \return Error code
*/
XENCONTROL_API
DWORD
XcStoreAddWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PCHAR Path,
    IN  HANDLE Event,
    OUT PVOID *Handle
    );

/*! \brief Remove a XenStore watch
    \param Xc Xencontrol handle returned by XcOpen()
    \param Handle Watch handle returned by XcStoreAddWatch()
    \return Error code
*/
XENCONTROL_API
DWORD
XcStoreRemoveWatch(
    IN  PXENCONTROL_CONTEXT Xc,
    IN  PVOID Handle
    );

#ifdef __cplusplus
}
#endif

#endif // _XENCONTROL_H_
