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

#include <ntddk.h>
#include <stdarg.h>
#include <xen.h>

#include "names.h"
#include "dma.h"
#include "fdo.h"
#include "pdo.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#pragma warning(push)
#pragma warning(disable:4201) // nameless struct/union

/* 32-bit Server 2008 */

/*
0: kd> dt nt!_OBJECT_HEADER
   +0x000 PointerCount     : Int4B
   +0x004 HandleCount      : Int4B
   +0x004 NextToFree       : Ptr32 Void
   +0x008 Type             : Ptr32 _OBJECT_TYPE
   +0x00c NameInfoOffset   : UChar
   +0x00d HandleInfoOffset : UChar
   +0x00e QuotaInfoOffset  : UChar
   +0x00f Flags            : UChar
   +0x010 ObjectCreateInfo : Ptr32 _OBJECT_CREATE_INFORMATION
   +0x010 QuotaBlockCharged : Ptr32 Void
   +0x014 SecurityDescriptor : Ptr32 Void
   +0x018 Body             : _QUAD
*/

struct _OBJECT_HEADER {
    LONG            PointerCount;
    union {
        LONG        HandleCount;
        PVOID       NextToFree;
    };
    POBJECT_TYPE    Type;
    UCHAR           NameInfoOffset;
    UCHAR           HandleInfoOffset;
    UCHAR           QuotaInfoOffset;
    UCHAR           Flags;
    union {
        PVOID       ObjectCreateInfo;
        PVOID       QuotaBlockCharged;
    };
    PVOID           SecurityDescriptor;
};

/*
0: kd> dt hal!_ADAPTER_OBJECT
hal!_ADAPTER_OBJECT
   +0x000 DmaHeader        : _DMA_ADAPTER
   +0x008 MasterAdapter    : Ptr32 _ADAPTER_OBJECT
   +0x00c MapRegistersPerChannel : Uint4B
   +0x010 AdapterBaseVa    : Ptr32 Void
   +0x014 MapRegisterBase  : Ptr32 Void
   +0x018 NumberOfMapRegisters : Uint4B
   +0x01c CommittedMapRegisters : Uint4B
   +0x020 CurrentWcb       : Ptr32 _WAIT_CONTEXT_BLOCK
   +0x024 ChannelWaitQueue : _KDEVICE_QUEUE
   +0x038 RegisterWaitQueue : Ptr32 _KDEVICE_QUEUE
   +0x03c AdapterQueue     : _LIST_ENTRY
   +0x044 SpinLock         : Uint4B
   +0x048 MapRegisters     : Ptr32 _RTL_BITMAP
   +0x04c PagePort         : Ptr32 UChar
   +0x050 ChannelNumber    : UChar
   +0x051 AdapterNumber    : UChar
   +0x052 DmaPortAddress   : Uint2B
   +0x054 AdapterMode      : UChar
   +0x055 NeedsMapRegisters : UChar
   +0x056 MasterDevice     : UChar
   +0x057 Width16Bits      : UChar
   +0x058 ScatterGather    : UChar
   +0x059 IgnoreCount      : UChar
   +0x05a Dma32BitAddresses : UChar
   +0x05b Dma64BitAddresses : UChar
   +0x05c LegacyAdapter    : UChar
   +0x060 AdapterList      : _LIST_ENTRY
*/

struct _ADAPTER_OBJECT {
    DMA_ADAPTER             DmaHeader;
    struct _ADAPTER_OBJECT  *MasterAdapter;
    ULONG                   MapRegistersPerChannel;
    PVOID                   AdapterBaseVa;
    PVOID                   MapRegisterBase;
    ULONG                   NumberOfMapRegisters;
    ULONG                   CommittedMapRegisters;
    PVOID                   CurrentWcb;
    KDEVICE_QUEUE           ChannelWaitQueue;
    PKDEVICE_QUEUE          RegisterWaitQueue;
    LIST_ENTRY              AdapterQueue;
    KSPIN_LOCK              SpinLock;
    PRTL_BITMAP             MapRegisters;
    PUCHAR                  PagePort;
    UCHAR                   ChannelNumber;
    UCHAR                   AdapterNumber;
    USHORT                  DmaPortAddress;
    UCHAR                   AdapterMode;
    BOOLEAN                 NeedsMapRegisters;
    BOOLEAN                 MasterDevice;
    UCHAR                   Width16Bits;
    BOOLEAN                 ScatterGather;
    BOOLEAN                 IgnoreCount;
    BOOLEAN                 Dma32BitAddresses;
    BOOLEAN                 Dma64BitAddresses;
    BOOLEAN                 LegacyAdapter;
    LIST_ENTRY              AdapterList;
};

#pragma warning(pop)

typedef struct _XENBUS_DMA_CONTROL      XENBUS_DMA_CONTROL, *PXENBUS_DMA_CONTROL;
typedef struct _XENBUS_DMA_LIST_CONTROL XENBUS_DMA_LIST_CONTROL, *PXENBUS_DMA_LIST_CONTROL;
typedef struct _XENBUS_DMA_CONTEXT      XENBUS_DMA_CONTEXT, *PXENBUS_DMA_CONTEXT;

struct _XENBUS_DMA_CONTEXT {
    PXENBUS_DMA_CONTEXT         Next;
    PVOID                       Key;
    ULONG                       Version;
    KSPIN_LOCK                  Lock;
    LIST_ENTRY                  ControlList;
    LIST_ENTRY                  ListControlList;
    BOOLEAN                     Freed;
    PDMA_OPERATIONS             LowerOperations;
    PDMA_ADAPTER                LowerAdapter;
    PDEVICE_OBJECT              LowerDeviceObject;
    DMA_OPERATIONS              Operations;
    struct _OBJECT_HEADER       Header;
    struct _ADAPTER_OBJECT      Object;
};

struct _XENBUS_DMA_CONTROL {
    LIST_ENTRY          ListEntry;
    PXENBUS_DMA_CONTEXT Context;
    PDEVICE_OBJECT      DeviceObject;
    PVOID               TransferContext;
    PDRIVER_CONTROL     Function;
    PVOID               Argument;
};

struct _XENBUS_DMA_LIST_CONTROL {
    LIST_ENTRY              ListEntry;
    PXENBUS_DMA_CONTEXT     Context;
    PDEVICE_OBJECT          DeviceObject;
    PVOID                   TransferContext;
    PDRIVER_LIST_CONTROL    Function;
    PVOID                   Argument;
};

#define ASSERTIRQL(_X, _OP, _Y)                     \
        do {                                        \
            ULONG   _Lval = (ULONG)(_X);            \
            ULONG   _Rval = (ULONG)(_Y);            \
            if (!((_Lval _OP _Rval) || (_Lval > DISPATCH_LEVEL))) { \
                Error("%s = %u\n", #_X, _Lval);     \
                Error("%s = %u\n", #_Y, _Rval);     \
                ASSERT((_X _OP _Y) || (_X > DISPATCH_LEVEL));\
            }                                       \
        } while (FALSE)

#define DMA_TAG 'AMD'

static FORCEINLINE PVOID
__DmaAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, DMA_TAG);
}

static FORCEINLINE VOID
__DmaFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, DMA_TAG);
}

static VOID
DmaDumpDeviceDescription(
    IN  PDEVICE_DESCRIPTION DeviceDescription
    )
{
    Trace("Version = %u\n", DeviceDescription->Version);
    Trace("Master = %s\n", (DeviceDescription->Master) ? "TRUE" : "FALSE");
    Trace("ScatterGather = %s\n", (DeviceDescription->ScatterGather) ? "TRUE" : "FALSE");
    Trace("DemandMode = %s\n", (DeviceDescription->DemandMode) ? "TRUE" : "FALSE");
    Trace("AutoInitialize = %s\n", (DeviceDescription->AutoInitialize) ? "TRUE" : "FALSE");
    Trace("Dma32BitAddresses = %s\n", (DeviceDescription->Dma32BitAddresses) ? "TRUE" : "FALSE");
    Trace("IgnoreCount = %s\n", (DeviceDescription->IgnoreCount) ? "TRUE" : "FALSE");
    Trace("Dma64BitAddresses = %s\n", (DeviceDescription->Dma64BitAddresses) ? "TRUE" : "FALSE");
    Trace("BusNumber = %08x\n", DeviceDescription->BusNumber);
    Trace("DmaChannel = %08x\n", DeviceDescription->DmaChannel);
    Trace("InterfaceType = %s\n", InterfaceTypeName(DeviceDescription->InterfaceType));
    Trace("DmaWidth = %s\n", DmaWidthName(DeviceDescription->DmaWidth));
    Trace("DmaSpeed = %s\n", DmaSpeedName(DeviceDescription->DmaSpeed));
    Trace("MaximumLength = %08x\n", DeviceDescription->MaximumLength);
    Trace("DmaPort = %08x\n", DeviceDescription->DmaPort);
}

static PXENBUS_DMA_CONTEXT
DmaCreateContext(
    VOID
    )
{
    PXENBUS_DMA_CONTEXT Context;
    NTSTATUS            status;

    Context = __DmaAllocate(sizeof (XENBUS_DMA_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (Context == NULL)
        goto fail1;

    KeInitializeSpinLock(&Context->Lock);
    InitializeListHead(&Context->ControlList);
    InitializeListHead(&Context->ListControlList);

    Info("%p\n", Context);
    return Context;

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static VOID
DmaDestroyContext(
    IN  PXENBUS_DMA_CONTEXT Context
    )
{
    Info("%p\n", Context);

    ASSERT(IsListEmpty(&Context->ControlList));
    ASSERT(IsListEmpty(&Context->ListControlList));

   __DmaFree(Context);
}

#define NR_CONTEXT_BUCKETS  8

static KSPIN_LOCK           DmaContextLock;
static PXENBUS_DMA_CONTEXT  DmaContext[NR_CONTEXT_BUCKETS];

//
// Hash on the basis that multiple DMA_ADAPTER structures are unlikely
// to appear in the same 256 byte block of memory
//
#define DMA_CONTEXT_BUCKET(_Key)    \
    (((ULONG_PTR)(_Key) >> 8) % NR_CONTEXT_BUCKETS)

#pragma warning(suppress: 28167) // changes the IRQL and does not restore the IRQL before it exits
static KIRQL
DmaAcquireLock(
    IN  PKSPIN_LOCK         Lock
    )
{
    KIRQL       Irql;
    
    Irql = KeGetCurrentIrql();
    if (Irql > DISPATCH_LEVEL)
        return Irql;

    KeAcquireSpinLock(Lock, &Irql);
    return Irql;
}

#pragma warning(suppress: 28167) // changes the IRQL and does not restore the IRQL before it exits
static VOID
DmaReleaseLock(
    IN  PKSPIN_LOCK         Lock,
    IN  KIRQL               Irql
    )
{
    if (Irql > DISPATCH_LEVEL)
        return;

#pragma warning(suppress: 26110) // caller failing to hold lock
    KeReleaseSpinLock(Lock, Irql);
}

static VOID
DmaAddContext(
    IN  PVOID               Key,
    IN  PXENBUS_DMA_CONTEXT Context
    )
{
    KIRQL                   Irql;
    ULONG_PTR               Bucket;

    Context->Key = Key;

    Irql = DmaAcquireLock(&DmaContextLock);
    Bucket = DMA_CONTEXT_BUCKET(Key);
    Context->Next = DmaContext[Bucket];
    DmaContext[Bucket] = Context;
    DmaReleaseLock(&DmaContextLock, Irql);
}

static VOID
DmaRemoveContext(
    IN  PXENBUS_DMA_CONTEXT Context
    )
{
    PVOID                   Key;
    KIRQL                   Irql;
    ULONG_PTR               Bucket;
    PXENBUS_DMA_CONTEXT     *Entry;

    ASSERT(Context != NULL);
    Key = Context->Key;

    Irql = DmaAcquireLock(&DmaContextLock);
    Bucket = DMA_CONTEXT_BUCKET(Key);
    Entry = &DmaContext[Bucket];
    while (*Entry != NULL) {
        if (*Entry == Context) {
            *Entry = Context->Next;
            break;
        }
        Entry = &(*Entry)->Next;
    }
    DmaReleaseLock(&DmaContextLock, Irql);

    ASSERT(Context != NULL);
    Context->Key = 0;
}

static PXENBUS_DMA_CONTEXT
DmaFindContext(
    IN  PVOID           Key
    )
{
    KIRQL               Irql;
    ULONG_PTR           Bucket;
    PXENBUS_DMA_CONTEXT Context;

    Irql = DmaAcquireLock(&DmaContextLock);
    Bucket = DMA_CONTEXT_BUCKET(Key);
    for (Context = DmaContext[Bucket];
         Context != NULL;
         Context = Context->Next)
        if (Context->Key == Key)
            break;
    DmaReleaseLock(&DmaContextLock, Irql);

    ASSERT(Context != NULL);
    return Context;
}

static VOID
DmaPutAdapter(
    IN  PDMA_ADAPTER    Adapter
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;

    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    Operations->PutDmaAdapter(Context->LowerAdapter);

    DmaRemoveContext(Context);
    DmaDestroyContext(Context);
}

static PVOID
DmaAllocateCommonBuffer(
    IN  PDMA_ADAPTER        Adapter,
    IN  ULONG               Length,
    OUT PPHYSICAL_ADDRESS   LogicalAddress,
    IN  BOOLEAN             CacheEnabled
    )
{
    PXENBUS_DMA_CONTEXT     Context;
    PDMA_OPERATIONS         Operations;
    PVOID                   Buffer;

    ASSERTIRQL(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    Buffer = Operations->AllocateCommonBuffer(Context->LowerAdapter,
                                              Length,
                                              LogicalAddress,
                                              CacheEnabled);

    return Buffer;
}

static VOID
DmaFreeCommonBuffer(
    IN  PDMA_ADAPTER        Adapter,
    IN  ULONG               Length,
    IN  PHYSICAL_ADDRESS    LogicalAddress,
    IN  PVOID               VirtualAddress,
    IN  BOOLEAN             CacheEnabled
    )
{
    PXENBUS_DMA_CONTEXT     Context;
    PDMA_OPERATIONS         Operations;

    ASSERTIRQL(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    Operations->FreeCommonBuffer(Context->LowerAdapter,
                                 Length,
                                 LogicalAddress,
                                 VirtualAddress,
                                 CacheEnabled);
}

static PXENBUS_DMA_CONTROL
DmaAddControl(
    IN  PXENBUS_DMA_CONTEXT Context,
    IN  PDEVICE_OBJECT      DeviceObject,
    IN  PVOID               TransferContext OPTIONAL,
    IN  PDRIVER_CONTROL     Function,
    IN  PVOID               Argument
    )
{
    PXENBUS_DMA_CONTROL     Control;
    KIRQL                   Irql;
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    Control = __DmaAllocate(sizeof (XENBUS_DMA_CONTROL));

    status = STATUS_NO_MEMORY;
    if (Control == NULL)
        goto fail1;

    Control->Context = Context;
    Control->DeviceObject = DeviceObject;
    Control->TransferContext = TransferContext;
    Control->Function = Function;
    Control->Argument = Argument;

    KeAcquireSpinLock(&Context->Lock, &Irql);
    InsertTailList(&Context->ControlList, &Control->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return Control;

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static VOID
DmaRemoveControl(
    IN  PXENBUS_DMA_CONTROL Control
    )
{
    PXENBUS_DMA_CONTEXT     Context = Control->Context;
    KIRQL                   Irql;

    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    KeAcquireSpinLock(&Context->Lock, &Irql);
    RemoveEntryList(&Control->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    __DmaFree(Control);
}

DRIVER_CONTROL DmaAdapterControl;

IO_ALLOCATION_ACTION
DmaAdapterControl(
    IN  PDEVICE_OBJECT      DeviceObject,
    IN  PIRP                Irp,
    IN  PVOID               MapRegisterBase,
    IN  PVOID               _Context
    )
{
    PXENBUS_DMA_CONTROL     Control = _Context;
    IO_ALLOCATION_ACTION    Action;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    if (Control->Function != NULL) {
        Action = Control->Function(Control->DeviceObject,
                                   Control->DeviceObject->CurrentIrp,
                                   MapRegisterBase,
                                   Control->Argument);
    } else {
        Action = DeallocateObject;
    }

    DmaRemoveControl(Control);

    return Action;
}

static NTSTATUS
DmaAllocateAdapterChannel(
    IN  PDMA_ADAPTER    Adapter,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  ULONG           NumberOfMapRegisters,
    IN  PDRIVER_CONTROL Function,
    IN  PVOID           Argument
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PXENBUS_DMA_CONTROL Control;
    PDMA_OPERATIONS     Operations;
    NTSTATUS            status;

    UNREFERENCED_PARAMETER(DeviceObject);

    ASSERT3U(KeGetCurrentIrql(), >=, DISPATCH_LEVEL);

    Context = DmaFindContext(Adapter);

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        Operations = Context->LowerOperations;
        status = Operations->AllocateAdapterChannel(Context->LowerAdapter,
                                                    Context->LowerDeviceObject,
                                                    NumberOfMapRegisters,
                                                    Function,
                                                    Argument);
        return status;
    }

    Control = DmaAddControl(Context,
                              DeviceObject,
                              NULL,
                              Function,
                              Argument);

    status = STATUS_NO_MEMORY;
    if (Control == NULL)
        goto fail1;

    Operations = Context->LowerOperations;
    status = Operations->AllocateAdapterChannel(Context->LowerAdapter,
                                                Context->LowerDeviceObject,
                                                NumberOfMapRegisters,
                                                DmaAdapterControl,
                                                Control);
    if (!NT_SUCCESS(status))
        goto fail2;

    return status;

fail2:
    DmaRemoveControl(Control);

fail1:
    return status;
}

static NTSTATUS
DmaAllocateAdapterChannelEx(
    IN  PDMA_ADAPTER    Adapter,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PVOID           TransferContext,
    IN  ULONG           NumberOfMapRegisters,
    IN  ULONG           Flags,
    IN  PDRIVER_CONTROL Function OPTIONAL,
    IN  PVOID           Argument OPTIONAL,
    OUT PVOID           *MapRegisterBase OPTIONAL
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PXENBUS_DMA_CONTROL Control;
    PDMA_OPERATIONS     Operations;
    NTSTATUS            status;

    UNREFERENCED_PARAMETER(DeviceObject);

    ASSERT3U(KeGetCurrentIrql(), >=, DISPATCH_LEVEL);

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        Operations = Context->LowerOperations;
        status = Operations->AllocateAdapterChannelEx(Context->LowerAdapter,
                                                    Context->LowerDeviceObject,
                                                    TransferContext,
                                                    NumberOfMapRegisters,
                                                    Flags,
                                                    Function,
                                                    Argument,
                                                    MapRegisterBase);
        return status;
    }

    Control = DmaAddControl(Context,
                              DeviceObject,
                              TransferContext,
                              Function,
                              Argument);

    status = STATUS_NO_MEMORY;
    if (Control == NULL)
        goto fail1;

    Operations = Context->LowerOperations;
    status = Operations->AllocateAdapterChannelEx(Context->LowerAdapter,
                                                  Context->LowerDeviceObject,
                                                  TransferContext,
                                                  NumberOfMapRegisters,
                                                  Flags,
                                                  DmaAdapterControl,
                                                  Control,
                                                  MapRegisterBase);
    if (!NT_SUCCESS(status))
        goto fail2;

    return status;

fail2:
    DmaRemoveControl(Control);

fail1:
    return status;
}

static BOOLEAN
DmaFlushAdapterBuffers(
    IN  PDMA_ADAPTER    Adapter,
    IN  PMDL            Mdl,
    IN  PVOID           MapRegisterBase,
    IN  PVOID           CurrentVa,
    IN  ULONG           Length,
    IN  BOOLEAN         WriteToDevice
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;
    BOOLEAN             Success;

    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    Success = Operations->FlushAdapterBuffers(Context->LowerAdapter,
                                              Mdl,
                                              MapRegisterBase,
                                              CurrentVa,
                                              Length,
                                              WriteToDevice);

    return Success;
}

static VOID
DmaFreeAdapterChannel(
    IN  PDMA_ADAPTER    Adapter
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;

    ASSERT3U(KeGetCurrentIrql(), >=, DISPATCH_LEVEL);

    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    Operations->FreeAdapterChannel(Context->LowerAdapter);
}

static VOID
DmaFreeMapRegisters(
    IN  PDMA_ADAPTER    Adapter,
    IN  PVOID           MapRegisterBase,
    IN  ULONG           NumberOfMapRegisters
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;

    ASSERT3U(KeGetCurrentIrql(), >=, DISPATCH_LEVEL);

    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    Operations->FreeMapRegisters(Context->LowerAdapter,
                                 MapRegisterBase,
                                 NumberOfMapRegisters);

    if (Context->Freed) {
        DmaRemoveContext(Context);
        DmaDestroyContext(Context);
    }
}

static PHYSICAL_ADDRESS
DmaMapTransfer(
    IN      PDMA_ADAPTER    Adapter,
    IN      PMDL            Mdl,
    IN      PVOID           MapRegisterBase,
    IN      PVOID           CurrentVa,
    IN OUT  PULONG          Length,
    IN      BOOLEAN         WriteToDevice
    )
{
    PXENBUS_DMA_CONTEXT     Context;
    PDMA_OPERATIONS         Operations;
    PHYSICAL_ADDRESS        LogicalAddress;

    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    LogicalAddress = Operations->MapTransfer(Context->LowerAdapter,
                                             Mdl,
                                             MapRegisterBase,
                                             CurrentVa,
                                             Length,
                                             WriteToDevice);
    
    return LogicalAddress;
}

static ULONG
DmaGetAlignment(
    IN  PDMA_ADAPTER    Adapter
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;
    ULONG               Alignment;

    ASSERTIRQL(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    Alignment = Operations->GetDmaAlignment(Context->LowerAdapter);

    return Alignment;
}

static ULONG
DmaReadCounter(
    IN  PDMA_ADAPTER    Adapter
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;
    ULONG               Counter;

    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    Counter = Operations->ReadDmaCounter(Context->LowerAdapter);
    
    return Counter;
}

static PXENBUS_DMA_LIST_CONTROL
DmaAddListControl(
    IN  PXENBUS_DMA_CONTEXT     Context,
    IN  PDEVICE_OBJECT          DeviceObject,
    IN  PVOID                   TransferContext OPTIONAL,
    IN  PDRIVER_LIST_CONTROL    Function,
    IN  PVOID                   Argument
    )
{
    PXENBUS_DMA_LIST_CONTROL    ListControl;
    KIRQL                       Irql;
    NTSTATUS                    status;

    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    ListControl = __DmaAllocate(sizeof (XENBUS_DMA_LIST_CONTROL));

    status = STATUS_NO_MEMORY;
    if (ListControl == NULL)
        goto fail1;

    ListControl->Context = Context;
    ListControl->DeviceObject = DeviceObject;
    ListControl->TransferContext = TransferContext;
    ListControl->Function = Function;
    ListControl->Argument = Argument;

    KeAcquireSpinLock(&Context->Lock, &Irql);
    InsertTailList(&Context->ListControlList, &ListControl->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return ListControl;

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static VOID
DmaRemoveListControl(
    IN  PXENBUS_DMA_LIST_CONTROL    ListControl
    )
{
    PXENBUS_DMA_CONTEXT             Context = ListControl->Context;
    KIRQL                           Irql;

    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    KeAcquireSpinLock(&Context->Lock, &Irql);
    RemoveEntryList(&ListControl->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    __DmaFree(ListControl);
}

DRIVER_LIST_CONTROL DmaAdapterListControl;

VOID
DmaAdapterListControl(
    IN  PDEVICE_OBJECT          DeviceObject,
    IN  PIRP                    Irp,
    IN  PSCATTER_GATHER_LIST    ScatterGather,
    IN  PVOID                   _Context
    )
{
    PXENBUS_DMA_LIST_CONTROL    ListControl = _Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    ListControl->Function(ListControl->DeviceObject,
                          ListControl->DeviceObject->CurrentIrp,
                          ScatterGather,
                          ListControl->Argument);

    DmaRemoveListControl(ListControl);
}

static NTSTATUS
DmaGetScatterGatherList(
    IN  PDMA_ADAPTER            Adapter,
    IN  PDEVICE_OBJECT          DeviceObject,
    IN  PMDL                    Mdl,
    IN  PVOID                   CurrentVa,
    IN  ULONG                   Length,
    IN  PDRIVER_LIST_CONTROL    Function,
    IN  PVOID                   Argument,
    IN  BOOLEAN                 WriteToDevice
    )
{
    PXENBUS_DMA_CONTEXT         Context;
    PXENBUS_DMA_LIST_CONTROL    ListControl;
    PDMA_OPERATIONS             Operations;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(DeviceObject);

    ASSERT3U(KeGetCurrentIrql(), >=, DISPATCH_LEVEL);

    Context = DmaFindContext(Adapter);

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        Operations = Context->LowerOperations;
        status = Operations->GetScatterGatherList(Context->LowerAdapter,
                                                  Context->LowerDeviceObject,
                                                  Mdl,
                                                  CurrentVa,
                                                  Length,
                                                  Function,
                                                  Argument,
                                                  WriteToDevice);
        return status;
    }

    ListControl = DmaAddListControl(Context,
                                    DeviceObject,
                                    NULL,
                                    Function,
                                    Argument);
    status = STATUS_NO_MEMORY;
    if (ListControl == NULL)
        goto fail1;

    Operations = Context->LowerOperations;
    status = Operations->GetScatterGatherList(Context->LowerAdapter,
                                              Context->LowerDeviceObject,
                                              Mdl,
                                              CurrentVa,
                                              Length,
                                              DmaAdapterListControl,
                                              ListControl,
                                              WriteToDevice);
    if (!NT_SUCCESS(status))
        goto fail2;

    return status;

fail2:
    DmaRemoveListControl(ListControl);

fail1:
    return status;
}

static NTSTATUS
DmaGetScatterGatherListEx(
    IN  PDMA_ADAPTER            Adapter,
    IN  PDEVICE_OBJECT          DeviceObject,
    IN  PVOID                   TransferContext,
    IN  PMDL                    Mdl,
    IN  ULONGLONG               Offset,
    IN  ULONG                   Length,
    IN  ULONG                   Flags,
    IN  PDRIVER_LIST_CONTROL    Function,
    IN  PVOID                   Argument OPTIONAL,
    IN  BOOLEAN                 WriteToDevice,
    IN  PDMA_COMPLETION_ROUTINE CompletionRoutine OPTIONAL,
    IN  PVOID                   CompletionContext OPTIONAL,
    OUT PSCATTER_GATHER_LIST    *ScatterGatherList OPTIONAL
    )
{
    PXENBUS_DMA_CONTEXT         Context;
    PXENBUS_DMA_LIST_CONTROL    ListControl;
    PDMA_OPERATIONS             Operations;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(DeviceObject);

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        Operations = Context->LowerOperations;
        status = Operations->GetScatterGatherListEx(Context->LowerAdapter,
                                                    Context->LowerDeviceObject,
                                                    TransferContext,
                                                    Mdl,
                                                    Offset,
                                                    Length,
                                                    Flags,
                                                    Function,
                                                    Argument,
                                                    WriteToDevice,
                                                    CompletionRoutine,
                                                    CompletionContext,
                                                    ScatterGatherList);
        return status;
    }

    ListControl = DmaAddListControl(Context,
                                    DeviceObject,
                                    TransferContext,
                                    Function,
                                    Argument);
    status = STATUS_NO_MEMORY;
    if (ListControl == NULL)
        goto fail1;

    Operations = Context->LowerOperations;
    status = Operations->GetScatterGatherListEx(Context->LowerAdapter,
                                                Context->LowerDeviceObject,
                                                TransferContext,
                                                Mdl,
                                                Offset,
                                                Length,
                                                Flags,
                                                DmaAdapterListControl,
                                                ListControl,
                                                WriteToDevice,
                                                CompletionRoutine,
                                                CompletionContext,
                                                ScatterGatherList);
    if (!NT_SUCCESS(status))
        goto fail2;

    return status;

fail2:
    DmaRemoveListControl(ListControl);

fail1:
    return status;
}

static NTSTATUS
DmaCalculateScatterGatherList(
    IN  PDMA_ADAPTER    Adapter,
    IN  PMDL            Mdl OPTIONAL,
    IN  PVOID           CurrentVa,
    IN  ULONG           Length,
    OUT PULONG          ScatterGatherListSize,
    OUT PULONG          NumberOfMapRegisters OPTIONAL
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;
    NTSTATUS            status;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 2);

    Operations = Context->LowerOperations;
    status = Operations->CalculateScatterGatherList(Context->LowerAdapter,
                                                    Mdl,
                                                    CurrentVa,
                                                    Length,
                                                    ScatterGatherListSize,
                                                    NumberOfMapRegisters);

    return status;
}

static NTSTATUS
DmaBuildScatterGatherList(
    IN  PDMA_ADAPTER            Adapter,
    IN  PDEVICE_OBJECT          DeviceObject,
    IN  PMDL                    Mdl,
    IN  PVOID                   CurrentVa,
    IN  ULONG                   Length,
    IN  PDRIVER_LIST_CONTROL    Function,
    IN  PVOID                   Argument,
    IN  BOOLEAN                 WriteToDevice,
    IN  PVOID                   ScatterGatherBuffer,
    IN  ULONG                   ScatterGatherBufferLength
    )
{
    PXENBUS_DMA_CONTEXT         Context;
    PXENBUS_DMA_LIST_CONTROL    ListControl;
    PDMA_OPERATIONS             Operations;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(DeviceObject);

    ASSERT3U(KeGetCurrentIrql(), >=, DISPATCH_LEVEL);

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 2);

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        Operations = Context->LowerOperations;
        status = Operations->BuildScatterGatherList(Context->LowerAdapter,
                                                    Context->LowerDeviceObject,
                                                    Mdl,
                                                    CurrentVa,
                                                    Length,
                                                    Function,
                                                    Argument,
                                                    WriteToDevice,
                                                    ScatterGatherBuffer,
                                                    ScatterGatherBufferLength);
        return status;
    }

    ListControl = DmaAddListControl(Context,
                                    DeviceObject,
                                    NULL,
                                    Function,
                                    Argument);
    status = STATUS_NO_MEMORY;
    if (ListControl == NULL)
        goto fail1;

    Operations = Context->LowerOperations;
    status = Operations->BuildScatterGatherList(Context->LowerAdapter,
                                                Context->LowerDeviceObject,
                                                Mdl,
                                                CurrentVa,
                                                Length,
                                                DmaAdapterListControl,
                                                ListControl,
                                                WriteToDevice,
                                                ScatterGatherBuffer,
                                                ScatterGatherBufferLength);

    if (!NT_SUCCESS(status))
        goto fail2;

    return status;

fail2:
    DmaRemoveListControl(ListControl);

fail1:
    return status;
}

static NTSTATUS
DmaBuildScatterGatherListEx(
    IN  PDMA_ADAPTER            Adapter,
    IN  PDEVICE_OBJECT          DeviceObject,
    IN  PVOID                   TransferContext,
    IN  PMDL                    Mdl,
    IN  ULONGLONG               Offset,
    IN  ULONG                   Length,
    IN  ULONG                   Flags,
    IN  PDRIVER_LIST_CONTROL    Function OPTIONAL,
    IN  PVOID                   Argument OPTIONAL,
    IN  BOOLEAN                 WriteToDevice,
    IN  PVOID                   ScatterGatherBuffer,
    IN  ULONG                   ScatterGatherBufferLength,
    IN  PDMA_COMPLETION_ROUTINE CompletionRoutine OPTIONAL,
    IN  PVOID                   CompletionContext OPTIONAL,
    OUT PSCATTER_GATHER_LIST    *ScatterGatherList OPTIONAL
    )
{
    PXENBUS_DMA_CONTEXT         Context;
    PXENBUS_DMA_LIST_CONTROL    ListControl;
    PDMA_OPERATIONS             Operations;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(DeviceObject);

    ASSERTIRQL(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        Operations = Context->LowerOperations;
        status = Operations->BuildScatterGatherListEx(Context->LowerAdapter,
                                                      Context->LowerDeviceObject,
                                                      TransferContext,
                                                      Mdl,
                                                      Offset,
                                                      Length,
                                                      Flags,
                                                      Function,
                                                      Argument,
                                                      WriteToDevice,
                                                      ScatterGatherBuffer,
                                                      ScatterGatherBufferLength,
                                                      CompletionRoutine,
                                                      CompletionContext,
                                                      ScatterGatherList);
        return status;
    }

    ListControl = DmaAddListControl(Context,
                                    DeviceObject,
                                    TransferContext,
                                    Function,
                                    Argument);
    status = STATUS_NO_MEMORY;
    if (ListControl == NULL)
        goto fail1;

    Operations = Context->LowerOperations;
    status = Operations->BuildScatterGatherListEx(Context->LowerAdapter,
                                                  Context->LowerDeviceObject,
                                                  TransferContext,
                                                  Mdl,
                                                  Offset,
                                                  Length,
                                                  Flags,
                                                  DmaAdapterListControl,
                                                  ListControl,
                                                  WriteToDevice,
                                                  ScatterGatherBuffer,
                                                  ScatterGatherBufferLength,
                                                  CompletionRoutine,
                                                  CompletionContext,
                                                  ScatterGatherList);
    if (!NT_SUCCESS(status))
        goto fail2;

    return status;

fail2:
    DmaRemoveListControl(ListControl);

fail1:
    return status;
}

static VOID
DmaPutScatterGatherList(
    IN  PDMA_ADAPTER            Adapter,
    IN  PSCATTER_GATHER_LIST    ScatterGather,
    IN  BOOLEAN                 WriteToDevice
    )

{
    PXENBUS_DMA_CONTEXT         Context;
    PDMA_OPERATIONS             Operations;

    ASSERT3U(KeGetCurrentIrql(), >=, DISPATCH_LEVEL);
 
    Context = DmaFindContext(Adapter);

    Operations = Context->LowerOperations;
    Operations->PutScatterGatherList(Context->LowerAdapter,
                                     ScatterGather,
                                     WriteToDevice);
}

static NTSTATUS
DmaBuildMdlFromScatterGatherList(
    IN  PDMA_ADAPTER            Adapter,
    IN  PSCATTER_GATHER_LIST    ScatterGather,
    IN  PMDL                    OriginalMdl,
    IN  PMDL                    *TargetMdl
    )
{
    PXENBUS_DMA_CONTEXT         Context;
    PDMA_OPERATIONS             Operations;
    NTSTATUS                    status;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 2);

    Operations = Context->LowerOperations;
    status = Operations->BuildMdlFromScatterGatherList(Context->LowerAdapter,
                                                       ScatterGather,
                                                       OriginalMdl,
                                                       TargetMdl);  

    return status;
}

static BOOLEAN
DmaCancelAdapterChannel(
    IN  PDMA_ADAPTER    Adapter,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PVOID           TransferContext
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;
    BOOLEAN             Success;

    UNREFERENCED_PARAMETER(DeviceObject);

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    Success = Operations->CancelAdapterChannel(Context->LowerAdapter,
                                               Context->LowerDeviceObject,
                                               TransferContext);

    if (Success && KeGetCurrentIrql() <= DISPATCH_LEVEL) {
        PLIST_ENTRY ListEntry;

        ListEntry = Context->ControlList.Flink;
        while (ListEntry != &Context->ControlList) {
            PLIST_ENTRY         Next;
            PXENBUS_DMA_CONTROL Control;

            Next = ListEntry->Flink;

            Control = CONTAINING_RECORD(ListEntry, XENBUS_DMA_CONTROL, ListEntry);

            if (Control->TransferContext == TransferContext)
                DmaRemoveControl(Control);

            ListEntry = Next;
        }

        ListEntry = Context->ListControlList.Flink;
        while (ListEntry != &Context->ListControlList) {
            PLIST_ENTRY                 Next;
            PXENBUS_DMA_LIST_CONTROL    ListControl;

            Next = ListEntry->Flink;

            ListControl = CONTAINING_RECORD(ListEntry, XENBUS_DMA_LIST_CONTROL, ListEntry);

            if (ListControl->TransferContext == TransferContext)
                DmaRemoveListControl(ListControl);

            ListEntry = Next;
        }
    }

    return Success;
}

static NTSTATUS
DmaGetAdapterInfo(
    IN      PDMA_ADAPTER        Adapter,
    IN OUT  PDMA_ADAPTER_INFO   AdapterInfo
    )
{
    PXENBUS_DMA_CONTEXT         Context;
    PDMA_OPERATIONS             Operations;
    NTSTATUS                    status;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    status = Operations->GetDmaAdapterInfo(Context->LowerAdapter,
                                           AdapterInfo);

    return status;
}

static NTSTATUS
DmaGetTransferInfo(
    IN  PDMA_ADAPTER            Adapter,
    IN  PMDL                    Mdl,
    IN  ULONGLONG               Offset,
    IN  ULONG                   Length,
    IN  BOOLEAN                 WriteOnly,
    IN OUT  PDMA_TRANSFER_INFO  TransferInfo
    )
{
    PXENBUS_DMA_CONTEXT         Context;
    PDMA_OPERATIONS             Operations;
    NTSTATUS                    status;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    status = Operations->GetDmaTransferInfo(Context->LowerAdapter,
                                            Mdl,
                                            Offset,
                                            Length,
                                            WriteOnly,
                                            TransferInfo);

    return status;
}

static NTSTATUS
DmaInitializeTransferContext(
    IN  PDMA_ADAPTER    Adapter,
    OUT PVOID           TransferContext
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;
    NTSTATUS            status;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    status = Operations->InitializeDmaTransferContext(Context->LowerAdapter,
                                                      TransferContext);

    return status;
}

static PVOID
DmaAllocateCommonBufferEx(
    IN  PDMA_ADAPTER        Adapter,
    IN  PPHYSICAL_ADDRESS   MaximumAddress OPTIONAL,
    IN  ULONG               Length,
    OUT PPHYSICAL_ADDRESS   LogicalAddress,
    IN  BOOLEAN             CacheEnabled,
    IN  NODE_REQUIREMENT    PreferredNode
    )
{
    PXENBUS_DMA_CONTEXT     Context;
    PDMA_OPERATIONS         Operations;
    PVOID                   Buffer;

    ASSERTIRQL(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    Buffer = Operations->AllocateCommonBufferEx(Context->LowerAdapter,
                                                MaximumAddress,
                                                Length,
                                                LogicalAddress,
                                                CacheEnabled,
                                                PreferredNode);

    return Buffer;
}

static NTSTATUS
DmaConfigureAdapterChannel(
    IN  PDMA_ADAPTER    Adapter,
    IN  ULONG           FunctionNumber,
    IN  PVOID           Argument
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;
    NTSTATUS            status;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    status = Operations->ConfigureAdapterChannel(Context->LowerAdapter,
                                                 FunctionNumber,
                                                 Argument);

    return status;
}

static NTSTATUS
DmaMapTransferEx(
    IN      PDMA_ADAPTER            Adapter,
    IN      PMDL                    Mdl,
    IN      PVOID                   MapRegisterBase,
    IN      ULONGLONG               Offset,
    IN      ULONG                   DeviceOffset,
    IN OUT  PULONG                  Length,
    IN      BOOLEAN                 WriteToDevice,
    OUT     PSCATTER_GATHER_LIST    ScatterGatherBuffer OPTIONAL,
    IN      ULONG                   ScatterGatherBufferLength,
    IN      PDMA_COMPLETION_ROUTINE CompletionRoutine OPTIONAL,
    IN      PVOID                   CompletionContext OPTIONAL
    )
{
    PXENBUS_DMA_CONTEXT             Context;
    PDMA_OPERATIONS                 Operations;
    NTSTATUS                        status;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    status = Operations->MapTransferEx(Context->LowerAdapter,
                                       Mdl,
                                       MapRegisterBase,
                                       Offset,
                                       DeviceOffset,
                                       Length,
                                       WriteToDevice,
                                       ScatterGatherBuffer,
                                       ScatterGatherBufferLength,
                                       CompletionRoutine,
                                       CompletionContext);

    return status;
}

static NTSTATUS
DmaFlushAdapterBuffersEx(
    IN  PDMA_ADAPTER    Adapter,
    IN  PMDL            Mdl,
    IN  PVOID           MapRegisterBase,
    IN  ULONGLONG       Offset,
    IN  ULONG           Length,
    IN  BOOLEAN         WriteToDevice
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;
    NTSTATUS            status;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    status = Operations->FlushAdapterBuffersEx(Context->LowerAdapter,
                                               Mdl,
                                               MapRegisterBase,
                                               Offset,
                                               Length,
                                               WriteToDevice);

    return status;
}

static VOID
DmaFreeAdapterObject(
    IN  PDMA_ADAPTER            Adapter,
    IN  IO_ALLOCATION_ACTION    AllocationAction
    )
{
    PXENBUS_DMA_CONTEXT         Context;
    PDMA_OPERATIONS             Operations;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    Operations->FreeAdapterObject(Context->LowerAdapter,
                                  AllocationAction);

    switch (AllocationAction) {
    case DeallocateObject:
        DmaRemoveContext(Context);
        DmaDestroyContext(Context);
        break;

    case DeallocateObjectKeepRegisters:
        Context->Freed = TRUE;
        break;

    case KeepObject:
        break;

    default:
        ASSERT(FALSE);
        break;
    }
}

static NTSTATUS
DmaCancelMappedTransfer(
    IN  PDMA_ADAPTER    Adapter,
    IN  PVOID           TransferContext
    )
{
    PXENBUS_DMA_CONTEXT Context;
    PDMA_OPERATIONS     Operations;
    NTSTATUS            status;

    Context = DmaFindContext(Adapter);
    ASSERT3U(Context->Version, >=, 3);

    Operations = Context->LowerOperations;
    status = Operations->CancelMappedTransfer(Context->LowerAdapter,
                                              TransferContext);

    return status;
}

static DMA_OPERATIONS   DmaOperations = {
    0,

    // Version 1
    DmaPutAdapter,
    DmaAllocateCommonBuffer,
    DmaFreeCommonBuffer,
    DmaAllocateAdapterChannel,
    DmaFlushAdapterBuffers,
    DmaFreeAdapterChannel,
    DmaFreeMapRegisters,
    DmaMapTransfer,
    DmaGetAlignment,
    DmaReadCounter,
    DmaGetScatterGatherList,
    DmaPutScatterGatherList,

    // Version 2
    DmaCalculateScatterGatherList,
    DmaBuildScatterGatherList,
    DmaBuildMdlFromScatterGatherList,

    // Version 3
    DmaGetAdapterInfo,
    DmaGetTransferInfo,
    DmaInitializeTransferContext,
    DmaAllocateCommonBufferEx,
    DmaAllocateAdapterChannelEx,
    DmaConfigureAdapterChannel,
    DmaCancelAdapterChannel,
    DmaMapTransferEx,
    DmaGetScatterGatherListEx,
    DmaBuildScatterGatherListEx,
    DmaFlushAdapterBuffersEx,
    DmaFreeAdapterObject,
    DmaCancelMappedTransfer
};

#define DMA_OPERATIONS_SIZE1    (FIELD_OFFSET(DMA_OPERATIONS, CalculateScatterGatherList))
#define DMA_OPERATIONS_SIZE2    (FIELD_OFFSET(DMA_OPERATIONS, GetDmaAdapterInfo))
#define DMA_OPERATIONS_SIZE3    (sizeof (DMA_OPERATIONS))

PDMA_ADAPTER
DmaGetAdapter(
    IN  PXENBUS_PDO             Pdo,
    IN  XENBUS_DMA_ADAPTER_TYPE Type,
    IN  PDEVICE_DESCRIPTION     DeviceDescription,
    OUT PULONG                  NumberOfMapRegisters
    )
{
    PDMA_ADAPTER                LowerAdapter;
    PDEVICE_OBJECT              LowerDeviceObject;
    PXENBUS_DMA_CONTEXT         Context;
    PDMA_ADAPTER                Adapter;
    NTSTATUS                    status;

    DmaDumpDeviceDescription(DeviceDescription);

    // Hardcode use of PCIBus style dma adaptors to avoid
    // map register related races in Windows 2008
    DeviceDescription->InterfaceType = PCIBus;

    LowerAdapter = PdoGetDmaAdapter(Pdo,
                                    DeviceDescription,
                                    NumberOfMapRegisters);

    status = STATUS_UNSUCCESSFUL;
    if (LowerAdapter == NULL)
        goto fail1;

    if (Type == XENBUS_DMA_ADAPTER_NO_INTERCEPT) {
        Info("no interception\n");

        Adapter = LowerAdapter;
        goto done;
    }

    LowerDeviceObject = FdoGetPhysicalDeviceObject(PdoGetFdo(Pdo));

    Context = DmaCreateContext();

    status = STATUS_NO_MEMORY;
    if (Context == NULL)
        goto fail2;

    Context->LowerAdapter = LowerAdapter;
    Context->LowerOperations = LowerAdapter->DmaOperations; 
    Context->LowerDeviceObject = LowerDeviceObject;

    switch (Context->LowerOperations->Size) {
    case DMA_OPERATIONS_SIZE1:
        Info("VERSION 1\n");
        Context->Version = 1;
        break;

    case DMA_OPERATIONS_SIZE2:
        Info("VERSION 2\n");
        Context->Version = 2;
        break;

    case DMA_OPERATIONS_SIZE3:
        Info("VERSION 3\n");

        Context->Version = 3;
        break;

    default:
        ASSERT(FALSE);
    }

    // Copy in the requisite number of operations
    RtlCopyMemory(&Context->Operations,
                  &DmaOperations, 
                  Context->LowerOperations->Size);
    Context->Operations.Size = Context->LowerOperations->Size;

    if (Type == XENBUS_DMA_ADAPTER_SUBSTITUTE) {
        Context->Object.DmaHeader.Version = LowerAdapter->Version;
        Context->Object.DmaHeader.Size = sizeof (DMA_ADAPTER);
        Context->Object.DmaHeader.DmaOperations = &Context->Operations;

        Info("substitute adapter\n");
        Adapter = &Context->Object.DmaHeader;
    } else {
        ASSERT3U(Type, ==, XENBUS_DMA_ADAPTER_PASSTHRU);

        // Overwrite the lower adapter's DMA_OPERATIONS pointer with our own
        LowerAdapter->DmaOperations = &Context->Operations;

        Info("passthru adapter\n");
        Adapter = Context->LowerAdapter;
    }

    DmaAddContext(Adapter, Context);

done:
    return Adapter;

fail2:
    Error("fail2\n");

    LowerAdapter->DmaOperations->PutDmaAdapter(LowerAdapter);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}
