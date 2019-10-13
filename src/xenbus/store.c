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
#include <ntstrsafe.h>
#include <stdarg.h>
#include <stdlib.h>
#include <xen.h>

#include "store.h"
#include "evtchn.h"
#include "thread.h"
#include "fdo.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

extern ULONG
NTAPI
RtlRandomEx (
    __inout PULONG Seed
    );

#define STORE_TRANSACTION_MAGIC 'NART'

struct _XENBUS_STORE_TRANSACTION {
    LIST_ENTRY  ListEntry;
    ULONG       Magic;
    PVOID       Caller;
    uint32_t    Id;
    BOOLEAN     Active; // Must be tested at >= DISPATCH_LEVEL
};

#define STORE_WATCH_MAGIC 'CTAW'

struct _XENBUS_STORE_WATCH {
    LIST_ENTRY  ListEntry;
    ULONG       Magic;
    PVOID       Caller;
    USHORT      Id;
    PCHAR       Path;
    PKEVENT     Event;
    BOOLEAN     Active; // Must be tested at >= DISPATCH_LEVEL
};

typedef enum _XENBUS_STORE_REQUEST_STATE {
    XENBUS_STORE_REQUEST_INVALID = 0,
    XENBUS_STORE_REQUEST_PREPARED,
    XENBUS_STORE_REQUEST_SUBMITTED,
    XENBUS_STORE_REQUEST_PENDING,
    XENBUS_STORE_REQUEST_COMPLETED
} XENBUS_STORE_REQUEST_STATE, *PXENBUS_STORE_REQUEST_STATE;

typedef struct _XENBUS_STORE_SEGMENT {
    PCHAR   Data;
    ULONG   Offset;
    ULONG   Length;
} XENBUS_STORE_SEGMENT, *PXENBUS_STORE_SEGMENT;

enum {
    XENBUS_STORE_RESPONSE_HEADER_SEGMENT = 0,
    XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT,
    XENBUS_STORE_RESPONSE_SEGMENT_COUNT
};

typedef struct _XENBUS_STORE_RESPONSE {
    struct xsd_sockmsg      Header;
    CHAR                    Data[XENSTORE_PAYLOAD_MAX];
    XENBUS_STORE_SEGMENT    Segment[XENBUS_STORE_RESPONSE_SEGMENT_COUNT];
    ULONG                   Index;
} XENBUS_STORE_RESPONSE, *PXENBUS_STORE_RESPONSE;

#define XENBUS_STORE_REQUEST_SEGMENT_COUNT  8

typedef struct _XENBUS_STORE_REQUEST {
    volatile XENBUS_STORE_REQUEST_STATE State;
    struct xsd_sockmsg                  Header;
    XENBUS_STORE_SEGMENT                Segment[XENBUS_STORE_REQUEST_SEGMENT_COUNT];
    ULONG                               Count;
    ULONG                               Index;
    LIST_ENTRY                          ListEntry;
    PXENBUS_STORE_RESPONSE              Response;
} XENBUS_STORE_REQUEST, *PXENBUS_STORE_REQUEST;

#define XENBUS_STORE_BUFFER_MAGIC   'FFUB'

typedef struct _XENBUS_STORE_BUFFER {
    LIST_ENTRY  ListEntry;
    ULONG       Magic;
    PVOID       Caller;
    CHAR        Data[1];
} XENBUS_STORE_BUFFER, *PXENBUS_STORE_BUFFER;

struct _XENBUS_STORE_CONTEXT {
    PXENBUS_FDO                         Fdo;
    KSPIN_LOCK                          Lock;
    LONG                                References;
    struct xenstore_domain_interface    *Shared;
    USHORT                              RequestId;
    LIST_ENTRY                          SubmittedList;
    LIST_ENTRY                          PendingList;
    LIST_ENTRY                          TransactionList;
    USHORT                              WatchId;
    LIST_ENTRY                          WatchList;
    LIST_ENTRY                          BufferList;
    KDPC                                Dpc;
    ULONG                               Polls;
    ULONG                               Dpcs;
    ULONG                               Events;
    XENBUS_STORE_RESPONSE               Response;
    XENBUS_EVTCHN_INTERFACE             EvtchnInterface;
    PHYSICAL_ADDRESS                    Address;
    PXENBUS_EVTCHN_CHANNEL              Channel;
    XENBUS_SUSPEND_INTERFACE            SuspendInterface;
    XENBUS_DEBUG_INTERFACE              DebugInterface;
    XENBUS_GNTTAB_INTERFACE             GnttabInterface;
    PXENBUS_SUSPEND_CALLBACK            SuspendCallbackEarly;
    PXENBUS_SUSPEND_CALLBACK            SuspendCallbackLate;
    PXENBUS_DEBUG_CALLBACK              DebugCallback;
    PXENBUS_THREAD                      WatchdogThread;
    BOOLEAN                             Enabled;
};

C_ASSERT(sizeof (struct xenstore_domain_interface) <= PAGE_SIZE);

#define XENBUS_STORE_TAG    'ROTS'

static FORCEINLINE PVOID
__StoreAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENBUS_STORE_TAG);
}

static FORCEINLINE VOID
__StoreFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENBUS_STORE_TAG);
}

static NTSTATUS
StorePrepareRequest(
    IN  PXENBUS_STORE_CONTEXT       Context,
    OUT PXENBUS_STORE_REQUEST       Request,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  enum xsd_sockmsg_type       Type,
    IN  ...
    )
{
    ULONG                           Id;
    KIRQL                           Irql;
    PXENBUS_STORE_SEGMENT           Segment;
    va_list                         Arguments;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(Request, sizeof (XENBUS_STORE_REQUEST)));

    if (Transaction != NULL) {
        status = STATUS_UNSUCCESSFUL;
        if (!Transaction->Active)
            goto fail1;

        Id = Transaction->Id;
    } else {
        Id = 0;
    }

    Request->Header.type = Type;
    Request->Header.tx_id = Id;
    Request->Header.len = 0;

    KeAcquireSpinLock(&Context->Lock, &Irql);
    Request->Header.req_id = Context->RequestId++;
    KeReleaseSpinLock(&Context->Lock, Irql);

    Request->Count = 0;
    Segment = &Request->Segment[Request->Count++];

    Segment->Data = (PCHAR)&Request->Header;
    Segment->Offset = 0;
    Segment->Length = sizeof (struct xsd_sockmsg);

    va_start(Arguments, Type);
    for (;;) {
        PCHAR   Data;
        ULONG   Length;

        Data = va_arg(Arguments, PCHAR);
        Length = va_arg(Arguments, ULONG);
        
        if (Data == NULL) {
            ASSERT3U(Length, ==, 0);
            break;
        }

        Segment = &Request->Segment[Request->Count++];
        ASSERT3U(Request->Count, <, XENBUS_STORE_REQUEST_SEGMENT_COUNT);

        Segment->Data = Data;
        Segment->Offset = 0;
        Segment->Length = Length;

        Request->Header.len += Segment->Length;
    }
    va_end(Arguments);

    Request->State = XENBUS_STORE_REQUEST_PREPARED;

    return STATUS_SUCCESS;

fail1:
    return status;
}

static ULONG
StoreCopyToRing(
    IN  PXENBUS_STORE_CONTEXT           Context,
    IN  PCHAR                           Data,
    IN  ULONG                           Length
    )
{
    struct xenstore_domain_interface    *Shared;
    XENSTORE_RING_IDX                   cons;
    XENSTORE_RING_IDX                   prod;
    ULONG                               Offset;

    Shared = Context->Shared;

    KeMemoryBarrier();

    prod = Shared->req_prod;
    cons = Shared->req_cons;

    KeMemoryBarrier();

    Offset = 0;
    while (Length != 0) {
        ULONG   Available;
        ULONG   Index;
        ULONG   CopyLength;

        Available = cons + XENSTORE_RING_SIZE - prod;

        if (Available == 0)
            break;

        Index = MASK_XENSTORE_IDX(prod);

        CopyLength = __min(Length, Available);
        CopyLength = __min(CopyLength, XENSTORE_RING_SIZE - Index);

        RtlCopyMemory(&Shared->req[Index], Data + Offset, CopyLength);

        Offset += CopyLength;
        Length -= CopyLength;

        prod += CopyLength;
    }

    KeMemoryBarrier();

    Shared->req_prod = prod;

    KeMemoryBarrier();

    return Offset;    
}

static NTSTATUS
StoreSendSegment(
    IN      PXENBUS_STORE_CONTEXT   Context,
    IN OUT  PXENBUS_STORE_SEGMENT   Segment,
    IN OUT  PULONG                  Written
    )
{
    ULONG                           Copied;

    Copied = StoreCopyToRing(Context,
                             Segment->Data + Segment->Offset,
                             Segment->Length - Segment->Offset);

    Segment->Offset += Copied;
    *Written += Copied;

    ASSERT3U(Segment->Offset, <=, Segment->Length);
    return (Segment->Offset == Segment->Length) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static VOID
StoreSendRequests(
    IN      PXENBUS_STORE_CONTEXT   Context,
    IN OUT  PULONG                  Written
    )
{
    if (IsListEmpty(&Context->SubmittedList))
        return;

    while (!IsListEmpty(&Context->SubmittedList)) {
        PLIST_ENTRY             ListEntry;
        PXENBUS_STORE_REQUEST   Request;

        ListEntry = Context->SubmittedList.Flink;
        ASSERT3P(ListEntry, !=, &Context->SubmittedList);

        Request = CONTAINING_RECORD(ListEntry, XENBUS_STORE_REQUEST, ListEntry);

        ASSERT3U(Request->State, ==, XENBUS_STORE_REQUEST_SUBMITTED);

        while (Request->Index < Request->Count) {
            NTSTATUS    status;

            status = StoreSendSegment(Context,
                                      &Request->Segment[Request->Index],
                                      Written);
            if (!NT_SUCCESS(status))
                break;

            Request->Index++;
        }

        if (Request->Index < Request->Count)
            break;

        ListEntry = RemoveHeadList(&Context->SubmittedList);
        ASSERT3P(ListEntry, ==, &Request->ListEntry);

        InsertTailList(&Context->PendingList, &Request->ListEntry);
        Request->State = XENBUS_STORE_REQUEST_PENDING;
    }
}

static ULONG
StoreCopyFromRing(
    IN  PXENBUS_STORE_CONTEXT           Context,
    IN  PCHAR                           Data,
    IN  ULONG                           Length
    )
{
    struct xenstore_domain_interface    *Shared;
    XENSTORE_RING_IDX                   cons;
    XENSTORE_RING_IDX                   prod;
    ULONG                               Offset;

    Shared = Context->Shared;

    KeMemoryBarrier();

    cons = Shared->rsp_cons;
    prod = Shared->rsp_prod;

    KeMemoryBarrier();

    Offset = 0;
    while (Length != 0) {
        ULONG   Available;
        ULONG   Index;
        ULONG   CopyLength;

        Available = prod - cons;

        if (Available == 0)
            break;

        Index = MASK_XENSTORE_IDX(cons);

        CopyLength = __min(Length, Available);
        CopyLength = __min(CopyLength, XENSTORE_RING_SIZE - Index);

        RtlCopyMemory(Data + Offset, &Shared->rsp[Index], CopyLength);

        Offset += CopyLength;
        Length -= CopyLength;

        cons += CopyLength;
    }

    KeMemoryBarrier();

    Shared->rsp_cons = cons;

    KeMemoryBarrier();

    return Offset;    
}

static NTSTATUS
StoreReceiveSegment(
    IN      PXENBUS_STORE_CONTEXT   Context,
    IN OUT  PXENBUS_STORE_SEGMENT   Segment,
    IN OUT  PULONG                  Read
    )
{
    ULONG                           Copied;

    Copied = StoreCopyFromRing(Context,
                               Segment->Data + Segment->Offset,
                               Segment->Length - Segment->Offset);

    Segment->Offset += Copied;
    *Read += Copied;

    ASSERT3U(Segment->Offset, <=, Segment->Length);
    return (Segment->Offset == Segment->Length) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static BOOLEAN
StoreIgnoreHeaderType(
    IN  ULONG   Type
    )
{
    switch (Type) {
    case XS_DEBUG:
    case XS_GET_PERMS:
    case XS_INTRODUCE:
    case XS_RELEASE:
    case XS_GET_DOMAIN_PATH:
    case XS_MKDIR:
    case XS_IS_DOMAIN_INTRODUCED:
    case XS_RESUME:
    case XS_SET_TARGET:
    case XS_RESTRICT:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN
StoreVerifyHeader(
    struct xsd_sockmsg  *Header
    )
{
    BOOLEAN             Valid;

    Valid = TRUE;

    if (Header->type != XS_DIRECTORY &&
        Header->type != XS_READ &&
        Header->type != XS_WATCH &&
        Header->type != XS_UNWATCH &&
        Header->type != XS_TRANSACTION_START &&
        Header->type != XS_TRANSACTION_END &&
        Header->type != XS_WRITE &&
        Header->type != XS_RM &&
        Header->type != XS_SET_PERMS &&
        Header->type != XS_WATCH_EVENT &&
        Header->type != XS_ERROR &&
        !StoreIgnoreHeaderType(Header->type)) {
        Error("UNRECOGNIZED TYPE 0x%08x\n", Header->type);
        Valid = FALSE;
    }

    if (Header->len >= XENSTORE_PAYLOAD_MAX) {
        Error("ILLEGAL LENGTH 0x%08x\n", Header->len);
        Valid = FALSE;
    }

    return Valid;    
}

static NTSTATUS
StoreReceiveResponse(
    IN      PXENBUS_STORE_CONTEXT   Context,
    IN OUT  PULONG                  Read
    )
{
    PXENBUS_STORE_RESPONSE          Response = &Context->Response;
    NTSTATUS                        status;

    if (Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Data != NULL)
        goto payload;

    status = StoreReceiveSegment(Context,
                                 &Response->Segment[XENBUS_STORE_RESPONSE_HEADER_SEGMENT],
                                 Read);
    if (!NT_SUCCESS(status))
        goto done;

    ASSERT(StoreVerifyHeader(&Response->Header));

    if (Response->Header.len == 0)
        goto done;

    Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Length = Response->Header.len;
    Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Data = Response->Data;

payload:
    status = StoreReceiveSegment(Context,
                                 &Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT],
                                 Read);

done:
    return status;    
}

static PXENBUS_STORE_REQUEST
StoreFindRequest(
    IN  PXENBUS_STORE_CONTEXT   Context,
    IN  uint32_t                req_id
    )
{
    PLIST_ENTRY                 ListEntry;
    PXENBUS_STORE_REQUEST       Request;

    Request = NULL;
    for (ListEntry = Context->PendingList.Flink;
         ListEntry != &Context->PendingList;
         ListEntry = ListEntry->Flink) {

        Request = CONTAINING_RECORD(ListEntry, XENBUS_STORE_REQUEST, ListEntry);

        if (Request->Header.req_id == req_id)
            break;

        Request = NULL;
    }

    return Request;
}

static PXENBUS_STORE_WATCH
StoreFindWatch(
    IN  PXENBUS_STORE_CONTEXT   Context,
    IN  USHORT                  Id
    )
{
    PLIST_ENTRY                 ListEntry;
    PXENBUS_STORE_WATCH         Watch;

    Watch = NULL;
    for (ListEntry = Context->WatchList.Flink;
         ListEntry != &Context->WatchList;
         ListEntry = ListEntry->Flink) {

        Watch = CONTAINING_RECORD(ListEntry, XENBUS_STORE_WATCH, ListEntry);

        if (Watch->Id == Id)
            break;

        Watch = NULL;
    }

    return Watch;
}

static USHORT
StoreNextWatchId(
    IN  PXENBUS_STORE_CONTEXT   Context
    )
{
    USHORT                      Id;
    PXENBUS_STORE_WATCH         Watch;

    do {
        Id = Context->WatchId++;
        Watch = StoreFindWatch(Context, Id);
    } while (Watch != NULL);

    return Id;
}

#if defined(__i386__)
#define TOKEN_LENGTH    (sizeof ("TOK|XXXXXXXX|XXXX"))
#elif defined(__x86_64__)
#define TOKEN_LENGTH    (sizeof ("TOK|XXXXXXXXXXXXXXXX|XXXX"))
#else
#error 'Unrecognised architecture'
#endif

static NTSTATUS
StoreParseWatchEvent(
    IN  PCHAR   Data,
    IN  ULONG   Length,
    OUT PCHAR   *Path,
    OUT PVOID   *Caller,
    OUT PUSHORT Id
    )
{
    PCHAR       End;

    *Path = Data;
    while (*Data != '\0' && Length != 0) {
        Data++;
        --Length;
    }

    if (Length != TOKEN_LENGTH + 1)
        goto fail1;

    // Skip over the NUL
    Data++;
    --Length;

    if (Data[Length - 1] != '\0')
        goto fail2;

    if (strncmp(Data, "TOK|", 4) != 0) {
        Warning("UNRECOGNIZED PRE-AMBLE: %02X%02X%02X%02X\n",
                Data[0],
                Data[1],
                Data[2],
                Data[3]);

        goto fail3;
    }

    Data += 4;
    *Caller = (PVOID)(ULONG_PTR)_strtoui64(Data, &End, 16);

    if (*End != '|')
        goto fail4;

    Data = End + 1;
    *Id = (USHORT)strtoul(Data, &End, 16);

    if (*End != '\0')
        goto fail5;

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1\n");

    return STATUS_UNSUCCESSFUL;
}

static VOID
StoreProcessWatchEvent(
    IN  PXENBUS_STORE_CONTEXT   Context
    )
{
    PXENBUS_STORE_RESPONSE      Response;
    PCHAR                       Path;
    PVOID                       Caller;
    USHORT                      Id;
    PXENBUS_STORE_WATCH         Watch;
    NTSTATUS                    status;

    Response = &Context->Response;

    ASSERT3U(Response->Header.req_id, ==, 0);

    status = StoreParseWatchEvent(Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Data,
                                  Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Length,
                                  &Path,
                                  &Caller,
                                  &Id);
    if (!NT_SUCCESS(status))
        return;

    Trace("%04x (%s)\n", Id, Path);

    Watch = StoreFindWatch(Context, Id);

    if (Watch == NULL) {
        PCHAR       Name;
        ULONG_PTR   Offset;

        ModuleLookup((ULONG_PTR)Caller, &Name, &Offset);
        if (Name != NULL)
            Warning("SPURIOUS WATCH EVENT (%s) FOR %s + %p\n",
                    Path,
                    Name,
                    Offset);
        else
            Warning("SPURIOUS WATCH EVENT (%s) FOR %p\n",
                    Path,
                    Caller);

        return;
    }

    ASSERT3P(Caller, ==, Watch->Caller);

    if (Watch->Active)
        KeSetEvent(Watch->Event, 0, FALSE);
}

static VOID
StoreResetResponse(
    IN  PXENBUS_STORE_CONTEXT   Context
    )
{
    PXENBUS_STORE_RESPONSE      Response;
    PXENBUS_STORE_SEGMENT       Segment;

    Response = &Context->Response;

    RtlZeroMemory(Response, sizeof (XENBUS_STORE_RESPONSE));

    Segment = &Response->Segment[XENBUS_STORE_RESPONSE_HEADER_SEGMENT];

    Segment->Data = (PCHAR)&Response->Header;
    Segment->Offset = 0;
    Segment->Length = sizeof (struct xsd_sockmsg);
}

static PXENBUS_STORE_RESPONSE
StoreCopyResponse(
    IN  PXENBUS_STORE_CONTEXT   Context
    )
{
    PXENBUS_STORE_RESPONSE      Response;
    PXENBUS_STORE_SEGMENT       Segment;
    NTSTATUS                    status;

    Response = __StoreAllocate(sizeof (XENBUS_STORE_RESPONSE));

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail1;

    *Response = Context->Response;

    Segment = &Response->Segment[XENBUS_STORE_RESPONSE_HEADER_SEGMENT];
    ASSERT3P(Segment->Data, ==, (PCHAR)&Context->Response.Header);
    Segment->Data = (PCHAR)&Response->Header;

    Segment = &Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT];
    if (Segment->Length != 0) {
        ASSERT3P(Segment->Data, ==, Context->Response.Data);
        Segment->Data = Response->Data;
    } else {
        ASSERT3P(Segment->Data, ==, NULL);
    }

    return Response;

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static VOID
StoreFreeResponse(
    IN  PXENBUS_STORE_RESPONSE  Response
    )
{
    __StoreFree(Response);    
}

static VOID
StoreProcessResponse(
    IN  PXENBUS_STORE_CONTEXT   Context
    )
{
    PXENBUS_STORE_RESPONSE      Response;
    PXENBUS_STORE_REQUEST       Request;

    Response = &Context->Response;

    if (StoreIgnoreHeaderType(Response->Header.type)) {
        Warning("IGNORING RESPONSE TYPE %08X\n", Response->Header.type);
        StoreResetResponse(Context);
        return;
    }

    if (Response->Header.type == XS_WATCH_EVENT) {
        StoreProcessWatchEvent(Context);
        StoreResetResponse(Context);
        return;
    }

    Request = StoreFindRequest(Context, Response->Header.req_id);
    if (Request == NULL) {
        Warning("SPURIOUS RESPONSE ID %08X\n", Response->Header.req_id);
        StoreResetResponse(Context);
        return;
    }

    ASSERT3U(Request->State, ==, XENBUS_STORE_REQUEST_PENDING);

    RemoveEntryList(&Request->ListEntry);

    Request->Response = StoreCopyResponse(Context);
    StoreResetResponse(Context);

    Request->State = XENBUS_STORE_REQUEST_COMPLETED;

    KeMemoryBarrier();
}

static VOID
StorePollLocked(
    IN  PXENBUS_STORE_CONTEXT   Context
    )
{
    ULONG                       Read;
    ULONG                       Written;
    NTSTATUS                    status;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Context->Polls++;

    do {
        Read = Written = 0;

        StoreSendRequests(Context, &Written);
        if (Written != 0)
            (VOID) XENBUS_EVTCHN(Send,
                                 &Context->EvtchnInterface,
                                 Context->Channel);

        status = StoreReceiveResponse(Context, &Read);
        if (NT_SUCCESS(status))
            StoreProcessResponse(Context);

        if (Read != 0)
            (VOID) XENBUS_EVTCHN(Send,
                                 &Context->EvtchnInterface,
                                 Context->Channel);

    } while (Written != 0 || Read != 0);
}

static
_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
StoreDpc(
    IN  PKDPC               Dpc,
    IN  PVOID               _Context,
    IN  PVOID               Argument1,
    IN  PVOID               Argument2
    )
{
    PXENBUS_STORE_CONTEXT   Context = _Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Context != NULL);

    KeAcquireSpinLockAtDpcLevel(&Context->Lock);
    if (Context->References != 0)
        StorePollLocked(Context);
    KeReleaseSpinLockFromDpcLevel(&Context->Lock);
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define XENBUS_STORE_POLL_PERIOD 5

static PXENBUS_STORE_RESPONSE
StoreSubmitRequest(
    IN  PXENBUS_STORE_CONTEXT   Context,
    IN  PXENBUS_STORE_REQUEST   Request
    )
{
    PXENBUS_STORE_RESPONSE      Response;
    KIRQL                       Irql;
    ULONG                       Count;
    LARGE_INTEGER               Timeout;

    ASSERT3U(Request->State, ==, XENBUS_STORE_REQUEST_PREPARED);

    // Make sure we don't suspend
    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    KeAcquireSpinLockAtDpcLevel(&Context->Lock);

    InsertTailList(&Context->SubmittedList, &Request->ListEntry);

    Request->State = XENBUS_STORE_REQUEST_SUBMITTED;

    Count = XENBUS_EVTCHN(GetCount,
                          &Context->EvtchnInterface,
                          Context->Channel);

    StorePollLocked(Context);
    KeMemoryBarrier();

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(XENBUS_STORE_POLL_PERIOD));

    while (Request->State != XENBUS_STORE_REQUEST_COMPLETED) {
        NTSTATUS    status;

        status = XENBUS_EVTCHN(Wait,
                               &Context->EvtchnInterface,
                               Context->Channel,
                               Count + 1,
                               &Timeout);
        if (status == STATUS_TIMEOUT)
            Warning("TIMED OUT\n");

        Count = XENBUS_EVTCHN(GetCount,
                              &Context->EvtchnInterface,
                              Context->Channel);

        StorePollLocked(Context);
        KeMemoryBarrier();
    }

    KeReleaseSpinLockFromDpcLevel(&Context->Lock);

    Response = Request->Response;
    ASSERT(Response == NULL ||
           Response->Header.type == XS_ERROR ||
           Response->Header.type == Request->Header.type);

    RtlZeroMemory(Request, sizeof (XENBUS_STORE_REQUEST));

    KeLowerIrql(Irql);

    return Response;
}

static NTSTATUS
StoreCheckResponse(
    IN  PXENBUS_STORE_RESPONSE  Response
    )
{
    NTSTATUS                    status;

    status = STATUS_SUCCESS;

    if (Response->Header.type == XS_ERROR) {
        PCHAR   Error;
        ULONG   Length;
        ULONG   Index;

        Error = Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Data;
        Length = Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Length;

        if (strncmp(Error, "EQUOTA", Length) == 0) {
            status = STATUS_QUOTA_EXCEEDED;
            goto done;
        }

        for (Index = 0;
             Index < sizeof (xsd_errors) / sizeof (xsd_errors[0]);
             Index++) {
            struct xsd_errors   *Entry = &xsd_errors[Index];
            
            if (strncmp(Error, Entry->errstring, Length) == 0) {
                ERRNO_TO_STATUS(Entry->errnum, status);
                goto done;
            }
        }

        status = STATUS_UNSUCCESSFUL;
    }

done:
    return status;
}

static PXENBUS_STORE_BUFFER
StoreCopyPayload(
    IN  PXENBUS_STORE_CONTEXT   Context,
    IN  PXENBUS_STORE_RESPONSE  Response,
    IN  PVOID                   Caller
    )
{
    PCHAR                       Data;
    ULONG                       Length;
    PXENBUS_STORE_BUFFER        Buffer;
    KIRQL                       Irql;
    NTSTATUS                    status;

    Data = Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Data;
    Length = Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Length;

    Buffer = __StoreAllocate(FIELD_OFFSET(XENBUS_STORE_BUFFER, Data) +
                             Length +
                             (sizeof (CHAR) * 2));  // Double-NUL terminate

    status  = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Buffer->Magic = XENBUS_STORE_BUFFER_MAGIC;
    Buffer->Caller = Caller;

    RtlCopyMemory(Buffer->Data, Data, Length);

    KeAcquireSpinLock(&Context->Lock, &Irql);
    InsertTailList(&Context->BufferList, &Buffer->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return Buffer;        

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static VOID
StoreFreePayload(
    IN  PXENBUS_STORE_CONTEXT   Context,
    IN  PXENBUS_STORE_BUFFER    Buffer
    )
{
    KIRQL                       Irql;

    ASSERT3U(Buffer->Magic, ==, XENBUS_STORE_BUFFER_MAGIC);

    KeAcquireSpinLock(&Context->Lock, &Irql);
    RemoveEntryList(&Buffer->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    __StoreFree(Buffer);
}

static VOID
StoreFree(
    IN  PINTERFACE          Interface,
    IN  PCHAR               Value
    )
{
    PXENBUS_STORE_CONTEXT   Context = Interface->Context;
    PXENBUS_STORE_BUFFER    Buffer;

    Buffer = CONTAINING_RECORD(Value, XENBUS_STORE_BUFFER, Data);

    StoreFreePayload(Context, Buffer);
}

extern USHORT
RtlCaptureStackBackTrace(
    __in        ULONG   FramesToSkip,
    __in        ULONG   FramesToCapture,
    __out       PVOID   *BackTrace,
    __out_opt   PULONG  BackTraceHash
    );

static NTSTATUS
StoreRead(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    OUT PCHAR                       *Value
    )
{
    PXENBUS_STORE_CONTEXT           Context = Interface->Context;
    PVOID                           Caller;
    XENBUS_STORE_REQUEST            Request;
    PXENBUS_STORE_RESPONSE          Response;
    PXENBUS_STORE_BUFFER            Buffer;
    NTSTATUS                        status;

    (VOID) RtlCaptureStackBackTrace(1, 1, &Caller, NULL);    

    RtlZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST));

    if (Prefix == NULL) {
        status = StorePrepareRequest(Context,
                                     &Request,
                                     Transaction,
                                     XS_READ,
                                     Node, strlen(Node),
                                     "", 1,
                                     NULL, 0);
    } else {
        status = StorePrepareRequest(Context,
                                     &Request,
                                     Transaction,
                                     XS_READ,
                                     Prefix, strlen(Prefix),
                                     "/", 1,
                                     Node, strlen(Node),
                                     "", 1,
                                     NULL, 0);
    }

    if (!NT_SUCCESS(status))
        goto fail1;

    Response = StoreSubmitRequest(Context, &Request);

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail2;

    status = StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail3;

    Buffer = StoreCopyPayload(Context, Response, Caller);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail4;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    *Value = Buffer->Data;

    return STATUS_SUCCESS;

fail4:
fail3:
    StoreFreeResponse(Response);

fail2:
fail1:
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    return status;
}

static NTSTATUS
StoreWrite(
    IN  PXENBUS_STORE_CONTEXT       Context,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    IN  PCHAR                       Value
    )
{
    XENBUS_STORE_REQUEST            Request;
    PXENBUS_STORE_RESPONSE          Response;
    NTSTATUS                        status;

    RtlZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST));

    if (Prefix == NULL) {
        status = StorePrepareRequest(Context,
                                     &Request,
                                     Transaction,
                                     XS_WRITE,
                                     Node, strlen(Node),
                                     "", 1,
                                     Value, strlen(Value),
                                     NULL, 0);
    } else {
        status = StorePrepareRequest(Context,
                                     &Request,
                                     Transaction,
                                     XS_WRITE,
                                     Prefix, strlen(Prefix),
                                     "/", 1,
                                     Node, strlen(Node),
                                     "", 1,
                                     Value, strlen(Value),
                                     NULL, 0);
    }

    if (!NT_SUCCESS(status))
        goto fail1;

    Response = StoreSubmitRequest(Context, &Request);

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail2;

    status = StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail3;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    return STATUS_SUCCESS;

fail3:
    StoreFreeResponse(Response);

fail2:
fail1:
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    return status;
}

static NTSTATUS
StoreVPrintf(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    IN  const CHAR                  *Format,
    IN  va_list                     Arguments
    )
{
    PXENBUS_STORE_CONTEXT           Context = Interface->Context;
    PCHAR                           Buffer;
    ULONG                           Length;
    NTSTATUS                        status;

    Length = 32;
    for (;;) {
        Buffer = __StoreAllocate(Length);

        status = STATUS_NO_MEMORY;
        if (Buffer == NULL)
            goto fail1;

        status = RtlStringCbVPrintfA(Buffer,
                                     Length,
                                     Format,
                                     Arguments);
        if (NT_SUCCESS(status))
            break;

        if (status != STATUS_BUFFER_OVERFLOW)
            goto fail2;

        __StoreFree(Buffer);
        Length <<= 1;

        ASSERT3U(Length, <=, 1024);
    }

    status = StoreWrite(Context,
                          Transaction,
                          Prefix,
                          Node,
                          Buffer);
    if (!NT_SUCCESS(status))
        goto fail3;

    __StoreFree(Buffer);

    return STATUS_SUCCESS;

fail3:
fail2:
    __StoreFree(Buffer);

fail1:
    return status;
}

static NTSTATUS
StorePrintf(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    IN  const CHAR                  *Format,
    ...
    )
{
    va_list                         Arguments;
    NTSTATUS                        status;

    va_start(Arguments, Format);
    status = StoreVPrintf(Interface,
                            Transaction,
                            Prefix,
                            Node,
                            Format,
                            Arguments);
    va_end(Arguments);

    return status;
}

static NTSTATUS
StoreRemove(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node
    )
{
    PXENBUS_STORE_CONTEXT           Context = Interface->Context;
    XENBUS_STORE_REQUEST            Request;
    PXENBUS_STORE_RESPONSE          Response;
    NTSTATUS                        status;

    RtlZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST));

    if (Prefix == NULL) {
        status = StorePrepareRequest(Context,
                                     &Request,
                                     Transaction,
                                     XS_RM,
                                     Node, strlen(Node),
                                     "", 1,
                                     NULL, 0);
    } else {
        status = StorePrepareRequest(Context,
                                     &Request,
                                     Transaction,
                                     XS_RM,
                                     Prefix, strlen(Prefix),
                                     "/", 1,
                                     Node, strlen(Node),
                                     "", 1,
                                     NULL, 0);
    }

    if (!NT_SUCCESS(status))
        goto fail1;

    Response = StoreSubmitRequest(Context, &Request);

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail2;

    status = StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail3;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    return STATUS_SUCCESS;

fail3:
    StoreFreeResponse(Response);

fail2:
fail1:
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    return status;
}

static NTSTATUS
StoreDirectory(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    OUT PCHAR                       *Value
    )
{
    PXENBUS_STORE_CONTEXT           Context = Interface->Context;
    PVOID                           Caller;
    XENBUS_STORE_REQUEST            Request;
    PXENBUS_STORE_RESPONSE          Response;
    PXENBUS_STORE_BUFFER            Buffer;
    NTSTATUS                        status;

    (VOID) RtlCaptureStackBackTrace(1, 1, &Caller, NULL);    

    RtlZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST));

    if (Prefix == NULL) {
        status = StorePrepareRequest(Context,
                                     &Request,
                                     Transaction,
                                     XS_DIRECTORY,
                                     Node, strlen(Node),
                                     "", 1,
                                     NULL, 0);
    } else {
        status = StorePrepareRequest(Context,
                                     &Request,
                                     Transaction,
                                     XS_DIRECTORY,
                                     Prefix, strlen(Prefix),
                                     "/", 1,
                                     Node, strlen(Node),
                                     "", 1,
                                     NULL, 0);
    }

    if (!NT_SUCCESS(status))
        goto fail1;

    Response = StoreSubmitRequest(Context, &Request);

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail2;

    status = StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail3;

    Buffer = StoreCopyPayload(Context, Response, Caller);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail4;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    *Value = Buffer->Data;

    return STATUS_SUCCESS;

fail4:
fail3:
    StoreFreeResponse(Response);

fail2:
fail1:
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    return status;
}

static NTSTATUS
StoreTransactionStart(
    IN  PINTERFACE                  Interface,
    OUT PXENBUS_STORE_TRANSACTION   *Transaction
    )
{
    PXENBUS_STORE_CONTEXT           Context = Interface->Context;
    XENBUS_STORE_REQUEST            Request;
    PXENBUS_STORE_RESPONSE          Response;
    KIRQL                           Irql;
    NTSTATUS                        status;

    *Transaction = __StoreAllocate(sizeof (XENBUS_STORE_TRANSACTION));

    status = STATUS_NO_MEMORY;
    if (*Transaction == NULL)
        goto fail1;

    (*Transaction)->Magic = STORE_TRANSACTION_MAGIC;
    (VOID) RtlCaptureStackBackTrace(1, 1, &(*Transaction)->Caller, NULL);    

    RtlZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST));

    status = StorePrepareRequest(Context,
                                 &Request,
                                 NULL,
                                 XS_TRANSACTION_START,
                                 "", 1,
                                 NULL, 0);
    ASSERT(NT_SUCCESS(status));

    Response = StoreSubmitRequest(Context, &Request);

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail2;

    status = StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail3;

    (*Transaction)->Id = (uint32_t)strtoul(Response->Segment[XENBUS_STORE_RESPONSE_PAYLOAD_SEGMENT].Data,
                                           NULL,
                                           10);
    ASSERT((*Transaction)->Id != 0);

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    KeAcquireSpinLock(&Context->Lock, &Irql);
    (*Transaction)->Active = TRUE;
    InsertTailList(&Context->TransactionList, &(*Transaction)->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    (*Transaction)->Caller = NULL;
    (*Transaction)->Magic = 0;

    ASSERT(IsZeroMemory(*Transaction, sizeof (XENBUS_STORE_TRANSACTION)));
    __StoreFree(*Transaction);

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
StoreTransactionEnd(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  BOOLEAN                     Commit
    )
{
    PXENBUS_STORE_CONTEXT           Context = Interface->Context;
    XENBUS_STORE_REQUEST            Request;
    PXENBUS_STORE_RESPONSE          Response;
    KIRQL                           Irql;
    NTSTATUS                        status;

    ASSERT3U(Transaction->Magic, ==, STORE_TRANSACTION_MAGIC);

    KeAcquireSpinLock(&Context->Lock, &Irql);

    status = STATUS_RETRY;
    if (!Transaction->Active)
        goto done;

    KeReleaseSpinLock(&Context->Lock, Irql);

    RtlZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST));

    status = StorePrepareRequest(Context,
                                 &Request,
                                 Transaction,
                                 XS_TRANSACTION_END,
                                 (Commit) ? "T" : "F", 2,
                                 NULL, 0);
    ASSERT(NT_SUCCESS(status));

    Response = StoreSubmitRequest(Context, &Request);

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail1;

    status = StoreCheckResponse(Response);
    if (!NT_SUCCESS(status) && status != STATUS_RETRY)
        goto fail2;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    KeAcquireSpinLock(&Context->Lock, &Irql);
    Transaction->Active = FALSE;

done:
    RemoveEntryList(&Transaction->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    RtlZeroMemory(&Transaction->ListEntry, sizeof (LIST_ENTRY));

    Transaction->Id = 0;

    Transaction->Caller = NULL;
    Transaction->Magic = 0;

    ASSERT(IsZeroMemory(Transaction, sizeof (XENBUS_STORE_TRANSACTION)));
    __StoreFree(Transaction);

    return status;

fail2:
    ASSERT3U(status, !=, STATUS_RETRY);

    StoreFreeResponse(Response);

fail1:
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    return status;
}

static NTSTATUS
StoreWatchAdd(
    IN  PINTERFACE              Interface,
    IN  PCHAR                   Prefix OPTIONAL,
    IN  PCHAR                   Node,
    IN  PKEVENT                 Event,
    OUT PXENBUS_STORE_WATCH     *Watch
    )
{
    PXENBUS_STORE_CONTEXT       Context = Interface->Context;
    ULONG                       Length;
    PCHAR                       Path;
    CHAR                        Token[TOKEN_LENGTH];
    XENBUS_STORE_REQUEST        Request;
    PXENBUS_STORE_RESPONSE      Response;
    KIRQL                       Irql;
    NTSTATUS                    status;

    *Watch = __StoreAllocate(sizeof (XENBUS_STORE_WATCH));

    status = STATUS_NO_MEMORY;
    if (*Watch == NULL)
        goto fail1;

    (*Watch)->Magic = STORE_WATCH_MAGIC;
    (VOID) RtlCaptureStackBackTrace(1, 1, &(*Watch)->Caller, NULL);    

    if (Prefix == NULL)
        Length = (ULONG)strlen(Node) + sizeof (CHAR);
    else
        Length = (ULONG)strlen(Prefix) + 1 + (ULONG)strlen(Node) + sizeof (CHAR);

    Path = __StoreAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Path == NULL)
        goto fail2;

    status = (Prefix == NULL) ?
             RtlStringCbPrintfA(Path, Length, "%s", Node) :
             RtlStringCbPrintfA(Path, Length, "%s/%s", Prefix, Node);
    ASSERT(NT_SUCCESS(status));
    
    (*Watch)->Path = Path;
    (*Watch)->Event = Event;

    KeAcquireSpinLock(&Context->Lock, &Irql);
    (*Watch)->Id = StoreNextWatchId(Context);
    (*Watch)->Active = TRUE;
    InsertTailList(&Context->WatchList, &(*Watch)->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    status = RtlStringCbPrintfA(Token,
                                sizeof (Token),
                                "TOK|%p|%04X",
                                (*Watch)->Caller,
                                (*Watch)->Id);
    ASSERT(NT_SUCCESS(status));
    ASSERT3U(strlen(Token), ==, TOKEN_LENGTH - 1);

    RtlZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST));

    status = StorePrepareRequest(Context,
                                 &Request,
                                 NULL,
                                 XS_WATCH,
                                 Path, strlen(Path),
                                 "", 1,
                                 Token, strlen(Token), 
                                 "", 1,
                                 NULL, 0);
    ASSERT(NT_SUCCESS(status));

    Response = StoreSubmitRequest(Context, &Request);

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail3;

    status = StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail4;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    StoreFreeResponse(Response);

fail3:
    Error("fail3\n");

    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    KeAcquireSpinLock(&Context->Lock, &Irql);
    (*Watch)->Active = FALSE;
    (*Watch)->Id = 0;
    RemoveEntryList(&(*Watch)->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    RtlZeroMemory(&(*Watch)->ListEntry, sizeof (LIST_ENTRY));

    (*Watch)->Event = NULL;
    (*Watch)->Path = NULL;

    __StoreFree(Path);

fail2:
    Error("fail2\n");

    (*Watch)->Caller = NULL;
    (*Watch)->Magic = 0;

    ASSERT(IsZeroMemory(*Watch, sizeof (XENBUS_STORE_WATCH)));
    __StoreFree(*Watch);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
StoreWatchRemove(
    IN  PINTERFACE              Interface,
    IN  PXENBUS_STORE_WATCH     Watch
    )
{
    PXENBUS_STORE_CONTEXT       Context = Interface->Context;
    PCHAR                       Path;
    CHAR                        Token[TOKEN_LENGTH];
    XENBUS_STORE_REQUEST        Request;
    PXENBUS_STORE_RESPONSE      Response;
    KIRQL                       Irql;
    NTSTATUS                    status;

    ASSERT3U(Watch->Magic, ==, STORE_WATCH_MAGIC);

    Path = Watch->Path;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (!Watch->Active)
        goto done;

    KeReleaseSpinLock(&Context->Lock, Irql);

    status = RtlStringCbPrintfA(Token,
                                sizeof (Token),
                                "TOK|%p|%04X",
                                Watch->Caller,
                                Watch->Id);
    ASSERT(NT_SUCCESS(status));
    ASSERT3U(strlen(Token), ==, TOKEN_LENGTH - 1);

    RtlZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST));

    status = StorePrepareRequest(Context,
                                 &Request,
                                 NULL,
                                 XS_UNWATCH,
                                 Path, strlen(Path),
                                 "", 1,
                                 Token, strlen(Token), 
                                 "", 1,
                                 NULL, 0);
    ASSERT(NT_SUCCESS(status));

    Response = StoreSubmitRequest(Context, &Request);

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail1;

    status = StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail2;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    KeAcquireSpinLock(&Context->Lock, &Irql);
    Watch->Active = FALSE;

done:
    Watch->Id = 0;
    RemoveEntryList(&Watch->ListEntry);
    KeReleaseSpinLock(&Context->Lock, Irql);

    RtlZeroMemory(&Watch->ListEntry, sizeof (LIST_ENTRY));

    Watch->Event = NULL;
    Watch->Path = NULL;

    __StoreFree(Path);

    Watch->Caller = NULL;
    Watch->Magic = 0;

    ASSERT(IsZeroMemory(Watch, sizeof (XENBUS_STORE_WATCH)));
    __StoreFree(Watch);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    StoreFreeResponse(Response);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    return status;
}

static VOID
StorePoll(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_STORE_CONTEXT   Context = Interface->Context;

    KeAcquireSpinLockAtDpcLevel(&Context->Lock);
    if (Context->References != 0)
        StorePollLocked(Context);
    KeReleaseSpinLockFromDpcLevel(&Context->Lock);
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define XENBUS_STORE_WATCHDOG_PERIOD 15

static NTSTATUS
StoreWatchdog(
    IN  PXENBUS_THREAD                  Self,
    IN  PVOID                           _Context
    )
{
    PXENBUS_STORE_CONTEXT               Context = _Context;
    LARGE_INTEGER                       Timeout;
    XENSTORE_RING_IDX                   req_prod;
    XENSTORE_RING_IDX                   req_cons;
    XENSTORE_RING_IDX                   rsp_prod;
    XENSTORE_RING_IDX                   rsp_cons;

    Trace("====>\n");

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(XENBUS_STORE_WATCHDOG_PERIOD));

    req_prod = 0;
    req_cons = 0;
    rsp_prod = 0;
    rsp_cons = 0;

    for (;;) {
        PKEVENT Event;
        KIRQL   Irql;

        Event = ThreadGetEvent(Self);

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     &Timeout);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        KeRaiseIrql(DISPATCH_LEVEL, &Irql);
        KeAcquireSpinLockAtDpcLevel(&Context->Lock);

        if (Context->Enabled) {
            struct xenstore_domain_interface    *Shared;

            Shared = Context->Shared;

            KeMemoryBarrier();

            if ((Shared->rsp_prod != rsp_prod &&
                 Shared->rsp_cons == rsp_cons) ||
                (Shared->req_prod != req_prod &&
                 Shared->req_cons == req_cons)) {
                XENBUS_DEBUG(Trigger,
                             &Context->DebugInterface,
                             Context->DebugCallback);

                // Try to move things along
                (VOID) XENBUS_EVTCHN(Send,
                                     &Context->EvtchnInterface,
                                     Context->Channel);
                StorePollLocked(Context);
            }

            KeMemoryBarrier();

            req_prod = Shared->req_prod;
            req_cons = Shared->req_cons;
            rsp_prod = Shared->rsp_prod;
            rsp_cons = Shared->rsp_cons;
        }

        KeReleaseSpinLockFromDpcLevel(&Context->Lock);
        KeLowerIrql(Irql);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static NTSTATUS
StorePermissionToString(
    IN  PXENBUS_STORE_PERMISSION    Permission,
    OUT PCHAR                       Buffer,
    IN  ULONG                       BufferSize,
    OUT PULONG                      UsedSize
    )
{
    size_t                          Remaining;
    NTSTATUS                        status;

    ASSERT(BufferSize > 1);

    switch (Permission->Mask) {
    case XENBUS_STORE_PERM_NONE:
        *Buffer = 'n';
        break;

    case XENBUS_STORE_PERM_READ:
        *Buffer = 'r';
        break;

    case XENBUS_STORE_PERM_WRITE:
        *Buffer = 'w';
        break;

    case XENBUS_STORE_PERM_READ | XENBUS_STORE_PERM_WRITE:
        *Buffer = 'b';
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        goto fail1;
    }

    status = RtlStringCbPrintfExA(Buffer + 1,
                                  BufferSize - 1,
                                  NULL,
                                  &Remaining,
                                  0,
                                  "%u",
                                  Permission->Domain);
    if (!NT_SUCCESS(status))
        goto fail2;

    *UsedSize = BufferSize - (ULONG)Remaining + 1;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
StorePermissionsSet(
    IN  PINTERFACE                  Interface,
    IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,
    IN  PCHAR                       Prefix OPTIONAL,
    IN  PCHAR                       Node,
    IN  PXENBUS_STORE_PERMISSION    Permissions,
    IN  ULONG                       NumberPermissions
    )
{
    PXENBUS_STORE_CONTEXT           Context = Interface->Context;
    XENBUS_STORE_REQUEST            Request;
    PXENBUS_STORE_RESPONSE          Response;
    NTSTATUS                        status;
    ULONG                           Index;
    ULONG                           Length;
    ULONG                           Used;
    PCHAR                           Path;
    PCHAR                           PermissionString;
    PCHAR                           Segment;

    PermissionString = __StoreAllocate(XENSTORE_PAYLOAD_MAX);

    status = STATUS_NO_MEMORY;
    if (PermissionString == NULL)
        goto fail1;

    if (Prefix == NULL)
        Length = (ULONG)strlen(Node) + sizeof (CHAR);
    else
        Length = (ULONG)strlen(Prefix) + 1 + (ULONG)strlen(Node) + sizeof (CHAR);

    Path = __StoreAllocate(Length);

    if (Path == NULL)
        goto fail2;

    status = (Prefix == NULL) ?
             RtlStringCbPrintfA(Path, Length, "%s", Node) :
             RtlStringCbPrintfA(Path, Length, "%s/%s", Prefix, Node);
    ASSERT(NT_SUCCESS(status));

    RtlZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST));

    for (Index = 0, Segment = PermissionString, Length = XENSTORE_PAYLOAD_MAX;
         Index < NumberPermissions;
         Index++) {
        status = StorePermissionToString(&Permissions[Index],
                                         Segment,
                                         Length,
                                         &Used);
        if (!NT_SUCCESS(status))
            goto fail3;

        Segment += Used;
        Length -= Used;
    }

    status = StorePrepareRequest(Context,
                                 &Request,
                                 Transaction,
                                 XS_SET_PERMS,
                                 Path, strlen(Path),
                                 "", 1,
                                 PermissionString, XENSTORE_PAYLOAD_MAX - Length,
                                 NULL, 0);
    if (!NT_SUCCESS(status))
        goto fail4;

    Response = StoreSubmitRequest(Context, &Request);

    status = STATUS_NO_MEMORY;
    if (Response == NULL)
        goto fail5;

    status = StoreCheckResponse(Response);
    if (!NT_SUCCESS(status))
        goto fail6;

    StoreFreeResponse(Response);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

    __StoreFree(Path);
    __StoreFree(PermissionString);

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");
    StoreFreeResponse(Response);

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    __StoreFree(Path);
    ASSERT(IsZeroMemory(&Request, sizeof (XENBUS_STORE_REQUEST)));

fail2:
    Error("fail2\n");

    __StoreFree(PermissionString);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static
_Function_class_(KSERVICE_ROUTINE)
_IRQL_requires_(HIGH_LEVEL)
_IRQL_requires_same_
BOOLEAN
StoreEvtchnCallback(
    IN  PKINTERRUPT InterruptObject,
    IN  PVOID       Argument
    )
{
    PXENBUS_STORE_CONTEXT  Context = Argument;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Context != NULL);

    Context->Events++;

    if (KeInsertQueueDpc(&Context->Dpc, NULL, NULL))
        Context->Dpcs++;

    return TRUE;
}

static VOID
StoreDisable(
    IN PXENBUS_STORE_CONTEXT    Context
    )
{
    LogPrintf(LOG_LEVEL_INFO,
              "STORE: DISABLE\n");

    Context->Enabled = FALSE;

    XENBUS_EVTCHN(Close,
                  &Context->EvtchnInterface,
                  Context->Channel);
    Context->Channel = NULL;
}

static VOID
StoreEnable(
    IN PXENBUS_STORE_CONTEXT    Context
    )
{
    ULONGLONG                   Value;
    ULONG                       Port;
    NTSTATUS                    status;

    status = HvmGetParam(HVM_PARAM_STORE_EVTCHN, &Value);
    ASSERT(NT_SUCCESS(status));

    Port = (ULONG)Value;

    Context->Channel = XENBUS_EVTCHN(Open,
                                     &Context->EvtchnInterface,
                                     XENBUS_EVTCHN_TYPE_FIXED,
                                     StoreEvtchnCallback,
                                     Context,
                                     Port,
                                     FALSE);
    ASSERT(Context->Channel != NULL);

    (VOID) XENBUS_EVTCHN(Unmask,
                         &Context->EvtchnInterface,
                         Context->Channel,
                         FALSE,
                         TRUE);

    Context->Enabled = TRUE;

    LogPrintf(LOG_LEVEL_INFO,
              "STORE: ENABLE (%u)\n",
              Port);

    // Trigger an initial poll
    if (KeInsertQueueDpc(&Context->Dpc, NULL, NULL))
        Context->Dpcs++;
}

static
StoreGetAddress(
    IN  PXENBUS_STORE_CONTEXT   Context,
    OUT PPHYSICAL_ADDRESS       Address
    )
{
    PFN_NUMBER                  Pfn;
    NTSTATUS                    status;

    status = XENBUS_GNTTAB(QueryReference,
                           &Context->GnttabInterface,
                           XENBUS_GNTTAB_STORE_REFERENCE,
                           &Pfn,
                           NULL);
    if (!NT_SUCCESS(status))
        goto fail1;

    Address->QuadPart = Pfn << PAGE_SHIFT;

    LogPrintf(LOG_LEVEL_INFO,
              "STORE: PAGE @ %08x.%08x\n",
              Address->HighPart,
              Address->LowPart);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
StoreSuspendCallbackEarly(
    IN  PVOID               Argument
    )
{
    PXENBUS_STORE_CONTEXT   Context = Argument;
    PLIST_ENTRY             ListEntry;

    for (ListEntry = Context->TransactionList.Flink;
         ListEntry != &(Context->TransactionList);
         ListEntry = ListEntry->Flink) {
        PXENBUS_STORE_TRANSACTION   Transaction;

        Transaction = CONTAINING_RECORD(ListEntry, XENBUS_STORE_TRANSACTION, ListEntry);

        Transaction->Active = FALSE;
    }

    for (ListEntry = Context->WatchList.Flink;
         ListEntry != &(Context->WatchList);
         ListEntry = ListEntry->Flink) {
        PXENBUS_STORE_WATCH Watch;

        Watch = CONTAINING_RECORD(ListEntry, XENBUS_STORE_WATCH, ListEntry);

        Watch->Active = FALSE;
    }
}

static VOID
StoreSuspendCallbackLate(
    IN  PVOID                           Argument
    )
{
    PXENBUS_STORE_CONTEXT               Context = Argument;
    PLIST_ENTRY                         ListEntry;
    KIRQL                               Irql;
    PHYSICAL_ADDRESS                    Address;
    NTSTATUS                            status;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    status = StoreGetAddress(Context, &Address);
    ASSERT(NT_SUCCESS(status));
    ASSERT3U(Address.QuadPart, ==, Context->Address.QuadPart);

    StoreDisable(Context);
    StoreResetResponse(Context);
    StoreEnable(Context);

    for (ListEntry = Context->WatchList.Flink;
         ListEntry != &(Context->WatchList);
         ListEntry = ListEntry->Flink) {
        PXENBUS_STORE_WATCH Watch;

        Watch = CONTAINING_RECORD(ListEntry, XENBUS_STORE_WATCH, ListEntry);

        KeSetEvent(Watch->Event, 0, FALSE);
    }

    KeReleaseSpinLock(&Context->Lock, Irql);
}

static VOID
StoreDebugCallback(
    IN  PVOID               Argument,
    IN  BOOLEAN             Crashing
    )
{
    PXENBUS_STORE_CONTEXT   Context = Argument;

    XENBUS_DEBUG(Printf,
                 &Context->DebugInterface,
                 "Address = %08x.%08x\n",
                 Context->Address.HighPart,
                 Context->Address.LowPart);

    if (!Crashing) {
        struct xenstore_domain_interface *Shared;

        Shared = Context->Shared;

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "req_cons = %08x req_prod = %08x\n",
                     Shared->req_cons,
                     Shared->req_prod);

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "rsp_cons = %08x rsp_prod = %08x\n",
                     Shared->rsp_cons,
                     Shared->rsp_prod);
    }

    XENBUS_DEBUG(Printf,
                 &Context->DebugInterface,
                 "Events = %lu Dpcs = %lu Polls = %lu\n",
                 Context->Events,
                 Context->Dpcs,
                 Context->Polls);

    if (!IsListEmpty(&Context->BufferList)) {
        PLIST_ENTRY ListEntry;

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "BUFFERS:\n");

        for (ListEntry = Context->BufferList.Flink;
             ListEntry != &(Context->BufferList);
             ListEntry = ListEntry->Flink) {
            PXENBUS_STORE_BUFFER    Buffer;
            PCHAR                   Name;
            ULONG_PTR               Offset;

            Buffer = CONTAINING_RECORD(ListEntry, XENBUS_STORE_BUFFER, ListEntry);

            ModuleLookup((ULONG_PTR)Buffer->Caller, &Name, &Offset);

            if (Name != NULL) {
                XENBUS_DEBUG(Printf,
                             &Context->DebugInterface,
                             "- (%p) %s + %p\n",
                             Buffer->Data,
                             Name,
                             (PVOID)Offset);
            } else {
                XENBUS_DEBUG(Printf,
                             &Context->DebugInterface,
                             "- (%p) %p\n",
                             Buffer->Data,
                             Buffer->Caller);
            }
        }
    }

    if (!IsListEmpty(&Context->WatchList)) {
        PLIST_ENTRY ListEntry;

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "WATCHES:\n");

        for (ListEntry = Context->WatchList.Flink;
             ListEntry != &(Context->WatchList);
             ListEntry = ListEntry->Flink) {
            PXENBUS_STORE_WATCH Watch;
            PCHAR               Name;
            ULONG_PTR           Offset;

            Watch = CONTAINING_RECORD(ListEntry, XENBUS_STORE_WATCH, ListEntry);

            ModuleLookup((ULONG_PTR)Watch->Caller, &Name, &Offset);

            if (Name != NULL) {
                XENBUS_DEBUG(Printf,
                             &Context->DebugInterface,
                             "- (%04X) ON %s BY %s + %p [%s]\n",
                             Watch->Id,
                             Watch->Path,
                             Name,
                             (PVOID)Offset,
                             (Watch->Active) ? "ACTIVE" : "EXPIRED");
            } else {
                XENBUS_DEBUG(Printf,
                             &Context->DebugInterface,
                             "- (%04X) ON %s BY %p [%s]\n",
                             Watch->Id,
                             Watch->Path,
                             (PVOID)Watch->Caller,
                             (Watch->Active) ? "ACTIVE" : "EXPIRED");
            }
        }
    }

    if (!IsListEmpty(&Context->TransactionList)) {
        PLIST_ENTRY ListEntry;

        XENBUS_DEBUG(Printf,
                     &Context->DebugInterface,
                     "TRANSACTIONS:\n");

        for (ListEntry = Context->TransactionList.Flink;
             ListEntry != &(Context->TransactionList);
             ListEntry = ListEntry->Flink) {
            PXENBUS_STORE_TRANSACTION   Transaction;
            PCHAR                       Name;
            ULONG_PTR                   Offset;

            Transaction = CONTAINING_RECORD(ListEntry, XENBUS_STORE_TRANSACTION, ListEntry);

            ModuleLookup((ULONG_PTR)Transaction->Caller, &Name, &Offset);

            if (Name != NULL) {
                XENBUS_DEBUG(Printf,
                             &Context->DebugInterface,
                             "- (%08X) BY %s + %p [%s]\n",
                             Transaction->Id,
                             Name,
                             (PVOID)Offset,
                             (Transaction->Active) ? "ACTIVE" : "EXPIRED");
            } else {
                XENBUS_DEBUG(Printf,
                             &Context->DebugInterface,
                             "- (%04X) ON %s BY %p [%s]\n",
                             Transaction->Id,
                             (PVOID)Transaction->Caller,
                             (Transaction->Active) ? "ACTIVE" : "EXPIRED");
            }
        }
    }
}

static NTSTATUS
StoreAcquire(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_STORE_CONTEXT   Context = Interface->Context;
    KIRQL                   Irql;
    PHYSICAL_ADDRESS        Address;
    NTSTATUS                status;

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    status = XENBUS_GNTTAB(Acquire, &Context->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = StoreGetAddress(Context, &Address);
    if (!NT_SUCCESS(status))
        goto fail2;

    Context->Address = Address;
    Context->Shared = (struct xenstore_domain_interface *)MmMapIoSpace(Context->Address,
                                                                       PAGE_SIZE,
                                                                       MmCached);
    status = STATUS_UNSUCCESSFUL;
    if (Context->Shared == NULL)
        goto fail3;

    status = XENBUS_EVTCHN(Acquire, &Context->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    StoreResetResponse(Context);
    StoreEnable(Context);

    status = XENBUS_SUSPEND(Acquire, &Context->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_SUSPEND(Register,
                            &Context->SuspendInterface,
                            SUSPEND_CALLBACK_EARLY,
                            StoreSuspendCallbackEarly,
                            Context,
                            &Context->SuspendCallbackEarly);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = XENBUS_SUSPEND(Register,
                            &Context->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            StoreSuspendCallbackLate,
                            Context,
                            &Context->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = XENBUS_DEBUG(Acquire, &Context->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = XENBUS_DEBUG(Register,
                          &Context->DebugInterface,
                          __MODULE__ "|STORE",
                          StoreDebugCallback,
                          Context,
                          &Context->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail9;

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);

    return STATUS_SUCCESS;

fail9:
    Error("fail9\n");

    XENBUS_DEBUG(Release, &Context->DebugInterface);

fail8:
    Error("fail8\n");

    XENBUS_SUSPEND(Deregister,
                   &Context->SuspendInterface,
                   Context->SuspendCallbackLate);
    Context->SuspendCallbackLate = NULL;

fail7:
    Error("fail7\n");

    XENBUS_SUSPEND(Deregister,
                   &Context->SuspendInterface,
                   Context->SuspendCallbackEarly);
    Context->SuspendCallbackEarly = NULL;

fail6:
    Error("fail6\n");

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

fail5:
    Error("fail5\n");

    StoreDisable(Context);
    RtlZeroMemory(&Context->Response, sizeof (XENBUS_STORE_RESPONSE));

    XENBUS_EVTCHN(Release, &Context->EvtchnInterface);

fail4:
    Error("fail4\n");

    MmUnmapIoSpace(Context->Shared, PAGE_SIZE);
    Context->Shared = NULL;

fail3:
    Error("fail3\n");

    Context->Address.QuadPart = 0;

fail2:
    Error("fail2\n");

    XENBUS_GNTTAB(Release, &Context->GnttabInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    Context->Address.QuadPart = 0;

    --Context->References;
    ASSERT3U(Context->References, ==, 0);
    KeReleaseSpinLock(&Context->Lock, Irql);

    return status;
}

static VOID
StoreRelease(
    IN  PINTERFACE          Interface
    )
{
    PXENBUS_STORE_CONTEXT   Context = Interface->Context;
    KIRQL                   Irql;    

    KeAcquireSpinLock(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    if (!IsListEmpty(&Context->WatchList))
        BUG("OUTSTANDING WATCHES");

    if (!IsListEmpty(&Context->TransactionList))
        BUG("OUTSTANDING TRANSACTIONS");

    if (!IsListEmpty(&Context->BufferList))
        BUG("OUTSTANDING BUFFER");

    XENBUS_DEBUG(Deregister,
                 &Context->DebugInterface,
                 Context->DebugCallback);
    Context->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Context->DebugInterface);

    XENBUS_SUSPEND(Deregister,
                   &Context->SuspendInterface,
                   Context->SuspendCallbackLate);
    Context->SuspendCallbackLate = NULL;

    XENBUS_SUSPEND(Deregister,
                   &Context->SuspendInterface,
                   Context->SuspendCallbackEarly);
    Context->SuspendCallbackEarly = NULL;

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

    StoreDisable(Context);
    StorePollLocked(Context);
    RtlZeroMemory(&Context->Response, sizeof (XENBUS_STORE_RESPONSE));

    XENBUS_EVTCHN(Release, &Context->EvtchnInterface);

    MmUnmapIoSpace(Context->Shared, PAGE_SIZE);
    Context->Shared = NULL;

    Context->Address.QuadPart = 0;

    XENBUS_GNTTAB(Release, &Context->GnttabInterface);

    Trace("<====\n");

done:
    KeReleaseSpinLock(&Context->Lock, Irql);
}

static struct _XENBUS_STORE_INTERFACE_V1 StoreInterfaceVersion1 = {
    { sizeof (struct _XENBUS_STORE_INTERFACE_V1), 1, NULL, NULL, NULL },
    StoreAcquire,
    StoreRelease,
    StoreFree,
    StoreRead,
    StorePrintf,
    StoreRemove,
    StoreDirectory,
    StoreTransactionStart,
    StoreTransactionEnd,
    StoreWatchAdd,
    StoreWatchRemove,
    StorePoll
};
                     
static struct _XENBUS_STORE_INTERFACE_V2 StoreInterfaceVersion2 = {
    { sizeof (struct _XENBUS_STORE_INTERFACE_V2), 2, NULL, NULL, NULL },
    StoreAcquire,
    StoreRelease,
    StoreFree,
    StoreRead,
    StorePrintf,
    StorePermissionsSet,
    StoreRemove,
    StoreDirectory,
    StoreTransactionStart,
    StoreTransactionEnd,
    StoreWatchAdd,
    StoreWatchRemove,
    StorePoll
};

NTSTATUS
StoreInitialize(
    IN  PXENBUS_FDO             Fdo,
    OUT PXENBUS_STORE_CONTEXT   *Context
    )
{
    LARGE_INTEGER               Now;
    ULONG                       Seed;
    NTSTATUS                    status;

    Trace("====>\n");

    *Context = __StoreAllocate(sizeof (XENBUS_STORE_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (*Context == NULL)
        goto fail1;

    status = GnttabGetInterface(FdoGetGnttabContext(Fdo),
                                XENBUS_GNTTAB_INTERFACE_VERSION_MAX,
                                (PINTERFACE)&(*Context)->GnttabInterface,
                                sizeof ((*Context)->GnttabInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT((*Context)->GnttabInterface.Interface.Context != NULL);

    status = EvtchnGetInterface(FdoGetEvtchnContext(Fdo),
                                XENBUS_EVTCHN_INTERFACE_VERSION_MAX,
                                (PINTERFACE)&(*Context)->EvtchnInterface,
                                sizeof ((*Context)->EvtchnInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT((*Context)->EvtchnInterface.Interface.Context != NULL);

    status = SuspendGetInterface(FdoGetSuspendContext(Fdo),
                                 XENBUS_SUSPEND_INTERFACE_VERSION_MAX,
                                 (PINTERFACE)&(*Context)->SuspendInterface,
                                 sizeof ((*Context)->SuspendInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT((*Context)->SuspendInterface.Interface.Context != NULL);

    status = DebugGetInterface(FdoGetDebugContext(Fdo),
                               XENBUS_DEBUG_INTERFACE_VERSION_MAX,
                               (PINTERFACE)&(*Context)->DebugInterface,
                               sizeof ((*Context)->DebugInterface));
    ASSERT(NT_SUCCESS(status));
    ASSERT((*Context)->DebugInterface.Interface.Context != NULL);

    KeInitializeSpinLock(&(*Context)->Lock);

    KeQuerySystemTime(&Now);
    Seed = Now.LowPart;

    (*Context)->RequestId = (USHORT)RtlRandomEx(&Seed);
    InitializeListHead(&(*Context)->SubmittedList);
    InitializeListHead(&(*Context)->PendingList);

    InitializeListHead(&(*Context)->TransactionList);

    (*Context)->WatchId = (USHORT)RtlRandomEx(&Seed);
    InitializeListHead(&(*Context)->WatchList);

    InitializeListHead(&(*Context)->BufferList);

    KeInitializeDpc(&(*Context)->Dpc, StoreDpc, *Context);

    status = ThreadCreate(StoreWatchdog,
                          *Context,
                          &(*Context)->WatchdogThread);
    if (!NT_SUCCESS(status))
        goto fail2;

    (*Context)->Fdo = Fdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RtlZeroMemory(&(*Context)->Dpc, sizeof (KDPC));

    RtlZeroMemory(&(*Context)->BufferList, sizeof (LIST_ENTRY));

    RtlZeroMemory(&(*Context)->WatchList, sizeof (LIST_ENTRY));
    (*Context)->WatchId = 0;

    RtlZeroMemory(&(*Context)->TransactionList, sizeof (LIST_ENTRY));

    RtlZeroMemory(&(*Context)->PendingList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&(*Context)->SubmittedList, sizeof (LIST_ENTRY));
    (*Context)->RequestId = 0;

    RtlZeroMemory(&(*Context)->Lock, sizeof (KSPIN_LOCK));

    RtlZeroMemory(&(*Context)->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&(*Context)->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&(*Context)->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&(*Context)->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    ASSERT(IsZeroMemory(*Context, sizeof (XENBUS_STORE_CONTEXT)));
    __StoreFree(*Context);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
StoreGetInterface(
    IN      PXENBUS_STORE_CONTEXT   Context,
    IN      ULONG                   Version,
    IN OUT  PINTERFACE              Interface,
    IN      ULONG                   Size
    )
{
    NTSTATUS                        status;

    ASSERT(Context != NULL);

    switch (Version) {
    case 1: {
        struct _XENBUS_STORE_INTERFACE_V1  *StoreInterface;

        StoreInterface = (struct _XENBUS_STORE_INTERFACE_V1 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENBUS_STORE_INTERFACE_V1))
            break;

        *StoreInterface = StoreInterfaceVersion1;

        ASSERT3U(Interface->Version, ==, Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    case 2: {
        struct _XENBUS_STORE_INTERFACE_V2  *StoreInterface;

        StoreInterface = (struct _XENBUS_STORE_INTERFACE_V2 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENBUS_STORE_INTERFACE_V2))
            break;

        *StoreInterface = StoreInterfaceVersion2;

        ASSERT3U(Interface->Version, == , Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    return status;
}   

ULONG
StoreGetReferences(
    IN  PXENBUS_STORE_CONTEXT   Context
    )
{
    return Context->References;
}

VOID
StoreTeardown(
    IN  PXENBUS_STORE_CONTEXT   Context
    )
{
    Trace("====>\n");

    ThreadAlert(Context->WatchdogThread);
    ThreadJoin(Context->WatchdogThread);
    Context->WatchdogThread = NULL;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    KeFlushQueuedDpcs();

    Context->Polls = 0;
    Context->Dpcs = 0;
    Context->Events = 0;

    Context->Fdo = NULL;

    RtlZeroMemory(&Context->Dpc, sizeof (KDPC));

    RtlZeroMemory(&Context->BufferList, sizeof (LIST_ENTRY));

    RtlZeroMemory(&Context->WatchList, sizeof (LIST_ENTRY));
    Context->WatchId = 0;

    RtlZeroMemory(&Context->TransactionList, sizeof (LIST_ENTRY));

    RtlZeroMemory(&Context->PendingList, sizeof (LIST_ENTRY));
    RtlZeroMemory(&Context->SubmittedList, sizeof (LIST_ENTRY));
    Context->RequestId = 0;

    RtlZeroMemory(&Context->Lock, sizeof (KSPIN_LOCK));

    RtlZeroMemory(&Context->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Context->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&Context->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&Context->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    ASSERT(IsZeroMemory(Context, sizeof (XENBUS_STORE_CONTEXT)));
    __StoreFree(Context);

    Trace("<====\n");
}
