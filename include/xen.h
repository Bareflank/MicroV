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

#ifndef _XEN_H
#define _XEN_H

#include <ntddk.h>

#include <xen-version.h>
#include <xen-types.h>
#include <xen-warnings.h>
#include <xen-errno.h>

#include <public/errno.h>
#include <public/xen.h>
#include <public/memory.h>
#include <public/event_channel.h>
#include <public/grant_table.h>
#include <public/sched.h>
#include <public/hvm/params.h>
#include <public/hvm/hvm_info_table.h>

// xs_wire.h gates the definition of the xsd_errors enumeration
// on whether EINVAL is defined. Unfortunately EINVAL is actually
// part of an enumeration and the #ifdef test thus fails.
// Override the enumeration value here with a #define.

#define EINVAL  XEN_EINVAL

#include <public/io/xs_wire.h>
#include <public/io/console.h>
#include <public/version.h>

#ifndef XEN_API
#define XEN_API __declspec(dllimport)
#endif  // XEN_API

// Dummy function to cause XEN.SYS to be loaded and initialized
XEN_API
NTSTATUS
XenTouch(
    IN  const CHAR  *Name,
    IN  ULONG       MajorVersion,
    IN  ULONG       MinorVersion,
    IN  ULONG       MicroVersion,
    IN  ULONG       BuildNumber
    );

// HYPERCALL

XEN_API
VOID
HypercallPopulate(
    VOID
    );

// HVM

__checkReturn
XEN_API
NTSTATUS
HvmSetParam(
    IN  ULONG       Parameter,
    IN  ULONGLONG   Value
    );

__checkReturn
XEN_API
NTSTATUS
HvmGetParam(
    IN  ULONG       Parameter,
    OUT PULONGLONG  Value
    );

__checkReturn
XEN_API
NTSTATUS
HvmPagetableDying(
    IN  PHYSICAL_ADDRESS    Address
    );

__checkReturn
XEN_API
NTSTATUS
HvmSetEvtchnUpcallVector(
    IN  unsigned int    vcpu_id,
    IN  UCHAR           Vector
    );

// MEMORY

__checkReturn
XEN_API
NTSTATUS
MemoryAddToPhysmap(
    IN  PFN_NUMBER  Pfn,
    IN  ULONG       Space,
    IN  ULONG_PTR   Offset
    );

#define PAGE_ORDER_4K   0
#define PAGE_ORDER_2M   9

__checkReturn
XEN_API
ULONG
MemoryDecreaseReservation(
    IN  ULONG       Order,
    IN  ULONG       Count,
    IN  PPFN_NUMBER PfnArray
    );

__checkReturn
XEN_API
ULONG
MemoryPopulatePhysmap(
    IN  ULONG       Order,
    IN  ULONG       Count,
    IN  PPFN_NUMBER PfnArray
    );

// EVENT CHANNEL

__checkReturn
XEN_API
NTSTATUS
EventChannelSend(
    IN  evtchn_port_t   Port
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelAllocateUnbound(
    IN  domid_t         Domain,
    OUT evtchn_port_t   *Port
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelBindInterDomain(
    IN  domid_t         RemoteDomain,
    IN  evtchn_port_t   RemotePort,
    OUT evtchn_port_t   *LocalPort
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelBindVirq(
    IN  uint32_t        Virq,
    OUT evtchn_port_t   *LocalPort
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelQueryInterDomain(
    IN  evtchn_port_t   LocalPort,
    OUT domid_t         *RemoteDomain,
    OUT evtchn_port_t   *RemotePort
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelClose(
    IN  evtchn_port_t   LocalPort
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelExpandArray(
    IN  PFN_NUMBER              Pfn
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelInitControl(
    IN  PFN_NUMBER              Pfn,
    IN  unsigned int            vcpu_id
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelReset(
    VOID
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelBindVirtualCpu(
    IN  ULONG               LocalPort,
    IN  unsigned int        vcpu_id
    );

__checkReturn
XEN_API
NTSTATUS
EventChannelUnmask(
    IN  ULONG   LocalPort
    );

// GRANT TABLE

__checkReturn
XEN_API
NTSTATUS
GrantTableSetVersion(
    IN  uint32_t    Version
    );

__checkReturn
XEN_API
NTSTATUS
GrantTableGetVersion(
    OUT uint32_t    *Version
    );

__checkReturn
XEN_API
NTSTATUS
GrantTableCopy(
    IN  struct gnttab_copy  op[],
    IN  ULONG               Count
    );

__checkReturn
XEN_API
NTSTATUS
GrantTableMapForeignPage(
    IN  USHORT                  Domain,
    IN  ULONG                   GrantRef,
    IN  PHYSICAL_ADDRESS        Address,
    IN  BOOLEAN                 ReadOnly,
    OUT ULONG                   *Handle
    );

__checkReturn
XEN_API
NTSTATUS
GrantTableUnmapForeignPage(
    IN  ULONG                   Handle,
    IN  PHYSICAL_ADDRESS        Address
    );

__checkReturn
XEN_API
NTSTATUS
GrantTableQuerySize(
    OUT uint32_t                *Current OPTIONAL,
    OUT uint32_t                *Maximum OPTIONAL
    );

// SCHED

__checkReturn
XEN_API
NTSTATUS
SchedShutdownCode(
    ULONG   Reason
    );

__checkReturn
XEN_API
NTSTATUS
SchedShutdown(
    ULONG   Reason
    );

XEN_API
VOID
SchedYield(
    VOID
    );

// XEN VERSION

__checkReturn
XEN_API
NTSTATUS
XenVersion(
    OUT PULONG  Major,
    OUT PULONG  Minor
    );

__checkReturn
XEN_API
NTSTATUS
XenVersionExtra(
    OUT PCHAR   Extra
    );

// MODULE

XEN_API
VOID
ModuleLookup(
    IN  ULONG_PTR   Address,
    OUT PCHAR       *Name,
    OUT PULONG_PTR  Offset
    );

// UNPLUG

typedef enum _UNPLUG_TYPE {
    UNPLUG_DISKS = 0,
    UNPLUG_NICS,
    UNPLUG_TYPE_COUNT
} UNPLUG_TYPE, *PUNPLUG_TYPE;

XEN_API
VOID
UnplugDevices(
    VOID
    );

XEN_API
NTSTATUS
UnplugIncrementValue(
    IN  UNPLUG_TYPE Type
    );

XEN_API
NTSTATUS
UnplugDecrementValue(
    IN  UNPLUG_TYPE Type
    );

// LOG

typedef enum _LOG_LEVEL {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_TRACE = 1 << DPFLTR_TRACE_LEVEL,
    LOG_LEVEL_INFO = 1 << DPFLTR_INFO_LEVEL,
    LOG_LEVEL_WARNING = 1 << DPFLTR_WARNING_LEVEL,
    LOG_LEVEL_ERROR = 1 << DPFLTR_ERROR_LEVEL,
    LOG_LEVEL_CRITICAL = 0x80000000
} LOG_LEVEL, *PLOG_LEVEL;

XEN_API
VOID
LogCchVPrintf(
    IN  LOG_LEVEL   Level,
    IN  ULONG       Count,
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    );

XEN_API
VOID
LogVPrintf(
    IN  LOG_LEVEL   Level,
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    );

XEN_API
VOID
LogCchPrintf(
    IN  LOG_LEVEL   Level,
    IN  ULONG       Count,
    IN  const CHAR  *Format,
    ...
    );

XEN_API
VOID
LogPrintf(
    IN  LOG_LEVEL   Level,
    IN  const CHAR  *Format,
    ...
    );

XEN_API
VOID
LogResume(
    VOID
    );

XEN_API
NTSTATUS
LogReadLogLevel(
    IN  HANDLE      Key,
    IN  PCHAR       Name,
    OUT PLOG_LEVEL  LogLevel
    );

typedef struct _LOG_DISPOSITION LOG_DISPOSITION, *PLOG_DISPOSITION;

XEN_API
NTSTATUS
LogAddDisposition(
    IN  LOG_LEVEL           Mask,
    IN  VOID                (*Function)(PVOID, PCHAR, ULONG),
    IN  PVOID               Argument OPTIONAL,
    OUT PLOG_DISPOSITION    *Disposition
    );

XEN_API
VOID
LogRemoveDisposition(
    IN  PLOG_DISPOSITION    Disposition
    );


// SYSTEM

XEN_API
ULONG
SystemProcessorCount(
    VOID
    );

XEN_API
NTSTATUS
SystemVirtualCpuIndex(
    IN  ULONG           Index,
    OUT unsigned int    *vcpu_id
    );

XEN_API
PHYSICAL_ADDRESS
SystemMaximumPhysicalAddress(
    VOID
    );

XEN_API
BOOLEAN
SystemRealTimeIsUniversal(
    VOID
    );

#endif  // _XEN_H
