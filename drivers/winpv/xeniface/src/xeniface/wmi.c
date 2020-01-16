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


#include <ntifs.h>
#include <initguid.h>
#include <wmistr.h>
#include <wmilib.h>
#include <stdio.h>
#include <guiddef.h>
#define NTSTRSAFE_LIB
#include<ntstrsafe.h>
#include "wmi.h"
#include "driver.h"
#include "..\..\include\store_interface.h"
#include "..\..\include\suspend_interface.h"
#include "log.h"
#include "xeniface_ioctls.h"
#include <version.h>

void LockSessions(
        XENIFACE_FDO* fdoData)
{
    AcquireMutex(&fdoData->SessionLock);
}


void UnlockSessions(
        XENIFACE_FDO* fdoData)
{
    ReleaseMutex(&fdoData->SessionLock);
}

void GetUnicodeString(UNICODE_STRING *unicode, USHORT maxlength, LPWSTR location)
{
    int i;
    USHORT length=0;
    unicode->MaximumLength=maxlength;
    unicode->Buffer=location;
    // No appropriate fucntion to determine the length of a possibly null
    // terminated string withing a fixed sized buffer exists.
    for (i=0; (i*sizeof(WCHAR))<maxlength; i++) {
        if (location[i] != L'\0')
            length+=sizeof(WCHAR);
        else
            break;
    }
    unicode->Length = (USHORT)length;
}

NTSTATUS GetAnsiString(ANSI_STRING *ansi, USHORT maxlength, LPWSTR location) {
    UNICODE_STRING unicode;
    NTSTATUS status;
    GetUnicodeString(&unicode, maxlength, location);
    status = RtlUnicodeStringToAnsiString(ansi, &unicode, TRUE);
    return status;
}

// Rather inconveniently, xenstore needs UTF8 data, WMI works in UTF16
// and windows doesn't provide conversion functions in any version
// prior to Windows 7.

USHORT Utf32FromUtf16(ULONG *utf32, const WCHAR* utf16) {
    ULONG w;
    ULONG u;
    ULONG xa;
    ULONG xb;
    ULONG x;

    if (((utf16[0]) & 0xFC00) == 0xD800) {
        w = ((utf16[0]) & 0X03FF) >>6;
        u = w+1;
        xa = utf16[0] & 0x3F;
        xb = utf16[1] & 0x03FF;
        x = (xa<<10) | xb;
        *utf32 = (u<<16) + x;
        return 2;
    }
    else {
        *utf32 = *utf16;
        return 1;
    }
}

USHORT Utf32FromUtf8(ULONG *utf32, const CHAR *utf8) {
    ULONG y;
    ULONG x;
    ULONG z;
    ULONG ua;
    ULONG ub;
    ULONG u;

    if ((utf8[0] & 0x80) == 0) {
        *utf32 = utf8[0];
        return 1;
    }
    else if ((utf8[0] & 0xE0) == 0xC0) {
        y = utf8[0] & 0x1F;
        x = utf8[1] & 0x3F;
        *utf32 = (y<<6) | x;
        return 2;
    }
    else if ((utf8[0] & 0xF0) == 0xE0) {
        z = utf8[0] & 0x0F;
        y = utf8[1] & 0x3F;
        x = utf8[2] & 0x3F;
       *utf32 = (z <<12) | (y<<6) | x;
       return 3;
    }
    else {
        ua = utf8[0] & 0x7;
        ub = (utf8[1] & 0x30) >> 4;
        u = (ua << 2) | ub;
        z = utf8[1] & 0x0f;
        y = utf8[2] & 0x3f;
        x = utf8[3] & 0x3f;
        *utf32 = (u<<16) | (z <<12) | (y <<6) | x;
        return 4;
    }

}

USHORT Utf16FromUtf32(WCHAR *utf16, const ULONG utf32) {
    WCHAR u;
    WCHAR w;
    WCHAR x;
    if ((utf32 > 0xFFFF)) {
        u = (utf32 & 0x1F0000) >> 16;
        w = u-1;
        x = utf32 & 0xFFFF;
        utf16[0] = 0xD800 | (w<<6) | (x>>10);
        utf16[1] = 0xDC00 | (x & 0x3F);
        return 2;
    }
    else {
        utf16[0] = utf32 & 0xFFFF;
        return 1;
    }
}


#define UTF8MASK2 0x1FFF80
#define UTF8MASK3 0x1FF800
#define UTF8MASK4 0x1F0000

USHORT CountUtf8FromUtf32(ULONG utf32) {
    if (utf32 & UTF8MASK4)
        return 4;
    if (utf32 & UTF8MASK3)
        return 3;
    if (utf32 & UTF8MASK2)
        return 2;
    return 1;
}

USHORT CountUtf16FromUtf32(ULONG utf32) {
    if ((utf32 & 0xFF0000) > 0) {
        return 2;
    }
    return 1;
}

USHORT Utf8FromUtf32(CHAR *dest, ULONG utf32) {
    CHAR u;
    CHAR y;
    CHAR x;
    CHAR z;

    if (utf32 & UTF8MASK4) {
        x = utf32 & 0x3f;
        y = (utf32 >> 6) & 0x3f;
        z = (utf32 >> 12) & 0xf;
        u = (utf32 >> 16) & 0x1f;
        dest[0] = 0xf0 | u>>2;
        dest[1] = 0x80 | (u & 0x3) << 4 | z;
        dest[2] = 0x80 | y;
        dest[3] = 0x80 | x;
        return 4;
    }
    else if (utf32 & UTF8MASK3) {
        x = utf32 & 0x3f;
        y = (utf32 >> 6) & 0x3f;
        z = (utf32 >> 12) & 0xf;
        dest[0] = 0xe0 | z;
        dest[1] = 0x80 | y;
        dest[2] = 0x80 | x;
        return 3;
    }
    else if (utf32 & UTF8MASK2) {
        x = utf32 & 0x3f;
        y = (utf32 >> 6) & 0x3f;
        dest[0] = 0xc0 | y;
        dest[1] = 0x80 | x;
        return 2;
    }
    else {
        x = utf32 & 0x7f;
        dest[0] = x;
        return 1;
    }
}

typedef struct {
    USHORT Length;
    CHAR Buffer[1];
} UTF8_STRING;

USHORT CountBytesUtf16FromUtf8String(const UTF8_STRING *utf8) {
    ULONG utf32;
    int i = 0;
    USHORT bytecount = 0;
    while (i<utf8->Length && utf8->Buffer[i] !=0) {
        i += Utf32FromUtf8(&utf32, &utf8->Buffer[i]);
        bytecount += CountUtf16FromUtf32(utf32);
    }
    return bytecount * sizeof(WCHAR);
}
USHORT CountBytesUtf16FromUtf8(const UCHAR *utf8) {
    ULONG utf32;
    int i = 0;
    USHORT bytecount = 0;
    while (utf8[i] !=0) {
        i += Utf32FromUtf8(&utf32, &utf8[i]);
        bytecount += CountUtf16FromUtf32(utf32);
    }
    return bytecount * sizeof(WCHAR);
}
NTSTATUS GetUTF8String(UTF8_STRING** utf8, USHORT bufsize, LPWSTR ustring)
{
    USHORT bytecount = 0;
    USHORT i;
    ULONG utf32;
    i = 0;
    while (i < (bufsize/sizeof(WCHAR))) {
        i += Utf32FromUtf16(&utf32, &ustring[i]);
        bytecount += CountUtf8FromUtf32(utf32);
    }

    *utf8 = ExAllocatePoolWithTag(NonPagedPool, sizeof(UTF8_STRING)+bytecount, 'XIU8');
    if ((*utf8) == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    (*utf8)->Length = bytecount;
    (*utf8)->Buffer[bytecount]=0;

    bytecount = 0;
    i=0;
    while (i < bufsize/sizeof(WCHAR)) {
        i += Utf32FromUtf16(&utf32, &ustring[i]);
        bytecount += Utf8FromUtf32(&((*utf8)->Buffer[bytecount]), utf32);
    }

    return STATUS_SUCCESS;
}

void FreeUTF8String(UTF8_STRING *utf8) {
    ExFreePoolWithTag(utf8, 'XIU8');
}

NTSTATUS GetCountedUTF8String(UTF8_STRING **utf8, UCHAR *location)
{
    USHORT bufsize = *(USHORT*)location;
    LPWSTR ustring = (LPWSTR)(location+sizeof(USHORT));
    return GetUTF8String(utf8, bufsize, ustring);

}

void GetCountedUnicodeString(UNICODE_STRING *unicode, UCHAR *location)
{
    USHORT bufsize = *(USHORT*)location;
    LPWSTR ustring = (LPWSTR)(location+sizeof(USHORT));
    GetUnicodeString(unicode, bufsize, ustring);
}

NTSTATUS GetCountedAnsiString(ANSI_STRING *ansi, UCHAR *location)
{
    USHORT bufsize = *(USHORT*)location;
    LPWSTR ustring = (LPWSTR)(location+sizeof(USHORT));
    return GetAnsiString(ansi, bufsize, ustring);
}

typedef enum {
    WMI_DONE,
    WMI_STRING,
    WMI_BOOLEAN,
    WMI_SINT8,
    WMI_UINT8,
    WMI_SINT16,
    WMI_UINT16,
    WMI_INT32,
    WMI_UINT32,
    WMI_SINT64,
    WMI_UINT64,
    WMI_DATETIME,
    WMI_BUFFER,
    WMI_OFFSET,
    WMI_STRINGOFFSET
} WMI_TYPE;

int AccessWmiBuffer(PUCHAR Buffer, int readbuffer, ULONG * RequiredSize,
                    size_t BufferSize, ...) {
    va_list vl;
    ULONG_PTR offset;
    ULONG_PTR offby;
    PUCHAR position = Buffer;
    PUCHAR endbuffer = Buffer + BufferSize;
    int overflow=0;
    va_start(vl, BufferSize);
    for(;;) {
        WMI_TYPE type = va_arg(vl, WMI_TYPE);
        if (type != WMI_DONE) {
#define WMITYPECASE(_wmitype, _type, _align) \
            case _wmitype: {\
                _type** val; \
                offby = ((ULONG_PTR)position)%(_align); \
                offset = ((_align)-offby)%(_align) ; \
                position += offset;\
                if (position + sizeof(_type) > endbuffer) \
                    overflow = TRUE;\
                val = va_arg(vl, _type**); \
                *val = NULL; \
                if (!overflow) \
                    *val = (_type *)position; \
                position += sizeof(_type); } \
                break
            switch (type) {
                case WMI_STRING:
                    {
                        UCHAR **countstr;
                        USHORT strsize;
                        offset = (2-((ULONG_PTR)position%2))%2;
                        position+=offset;
                        if (position + sizeof(USHORT) > endbuffer)
                            overflow = TRUE;
                        if (readbuffer) {
                            if (!overflow)
                                strsize = *(USHORT*)position;
                            else
                                strsize = 0;
                            strsize+=sizeof(USHORT);
                        }
                        else {
                            strsize = va_arg(vl, USHORT);
                        }
                        if (position + strsize  >endbuffer)
                            overflow = TRUE;
                        countstr = va_arg(vl, UCHAR**);
                        *countstr = NULL;
                        if (!overflow)
                            *countstr = position;
                        position +=strsize;
                    }
                    break;
                case WMI_BUFFER:
                    {
                        ULONG size = va_arg(vl, ULONG);
                        UCHAR **buffer;
                        if (position + size > endbuffer)
                            overflow = TRUE;
                        buffer = va_arg(vl, UCHAR**);
                        *buffer = NULL;
                        if (!overflow)
                            *buffer = position;
                        position += size;
                    }
                    break;
                case WMI_OFFSET:
                    {
                        ULONG inpos = va_arg(vl, ULONG);
                        UCHAR *bufferpos = Buffer + inpos;
                        ULONG insize = va_arg(vl, ULONG);
                        UCHAR **writebuf = va_arg(vl, UCHAR**);
                        *writebuf = NULL;
                        if (bufferpos+ insize > endbuffer) {;
                            overflow = TRUE;
                        }
                        else {
                            *writebuf = bufferpos;
                        }
                        // Only update position if it extends
                        // the required size of the buffer
                        if (bufferpos+insize > position)
                            position = bufferpos+insize;
                    }
                    break;
                    case WMI_STRINGOFFSET:
                    {
                        UCHAR **countstr;
                        USHORT strsize;
                        ULONG inpos = va_arg(vl, ULONG);
                        UCHAR *bufferpos = Buffer + inpos;
                        if (bufferpos + sizeof(USHORT) > endbuffer)
                            overflow = TRUE;
                        if (readbuffer) {
                            if (!overflow)
                                strsize = *(USHORT*)bufferpos;
                            else
                                strsize = 0;
                            strsize+=sizeof(USHORT);
                        }
                        else {
                            strsize = va_arg(vl, USHORT);
                        }
                        if (bufferpos + strsize  >endbuffer)
                            overflow = TRUE;
                        countstr = va_arg(vl, UCHAR**);
                        *countstr = NULL;
                        if (!overflow)
                            *countstr = bufferpos;
                        if (bufferpos+strsize > position)
                            position =bufferpos+strsize;
                    }
                    break;
                WMITYPECASE(WMI_BOOLEAN, UCHAR, 1);
                WMITYPECASE(WMI_SINT8, CHAR, 1);
                WMITYPECASE(WMI_UINT8, UCHAR, 1);
                WMITYPECASE(WMI_SINT16, SHORT, 2);
                WMITYPECASE(WMI_UINT16, USHORT, 2);
                WMITYPECASE(WMI_INT32, LONG, 4);
                WMITYPECASE(WMI_UINT32, ULONG, 4);
                WMITYPECASE(WMI_SINT64, LONGLONG, 8);
                WMITYPECASE(WMI_UINT64, ULONGLONG, 8);
                case WMI_DATETIME:
                    {
                        LPWSTR *val;
                        offset = (2-((ULONG_PTR)position%2))%2;
                        position += offset;
                        if (position + sizeof(WCHAR)*25 > endbuffer)
                            overflow = TRUE;
                        val = va_arg(vl, LPWSTR*);
                        *val = NULL;
                        if (!overflow)
                            *val = (LPWSTR )position;
                        position += sizeof(WCHAR)*25;
                    }
                    break;
                default:
                    return FALSE;
            }
        }
        else {
            break;
        }
    }
    *RequiredSize = (ULONG)(position - Buffer);
    va_end(vl);
    if (overflow)
        return FALSE;
    return TRUE;
}


NTSTATUS
WriteCountedUnicodeString(
    const UNICODE_STRING *ustr,
    UCHAR *location
    )
{
    *((USHORT*)location) = ustr->Length;
    RtlCopyMemory(location+sizeof(USHORT), ustr->Buffer,
                  ustr->Length);

    return STATUS_SUCCESS;
}

NTSTATUS
WriteCountedUTF8String(const char * string, UCHAR *location) {
    UNICODE_STRING unicode;

    int i=0;
    USHORT b;
    USHORT bytesize=0;
    ULONG utf32;
    NTSTATUS status = STATUS_SUCCESS;
    WCHAR *buffer;
    bytesize = CountBytesUtf16FromUtf8(string);
    buffer = ExAllocatePoolWithTag(NonPagedPool, bytesize+sizeof(WCHAR), 'XSUc');

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    buffer[bytesize/sizeof(WCHAR)] = 0;

    i=0;
    b=0;
    while (string[i] != 0) {
        i += Utf32FromUtf8(&utf32, &string[i]);
        b += Utf16FromUtf32(&buffer[b], utf32);
    }
    RtlInitUnicodeString(&unicode, buffer);
    status = WriteCountedUnicodeString(&unicode, location);
    ExFreePoolWithTag(buffer, 'XSUc');

    return status;
}

NTSTATUS
WriteCountedString(
    const char * string,
    UCHAR * location
    )
{
    ANSI_STRING ansi;
    UNICODE_STRING unicode;
    NTSTATUS status;

    RtlInitAnsiString(&ansi, string);

    status = RtlAnsiStringToUnicodeString(&unicode, &ansi, TRUE);
    if (NT_SUCCESS(status)) {

        status = WriteCountedUnicodeString(&unicode, location);
        RtlFreeUnicodeString(&unicode);
    }

    return status;
}

void AllocUnicodeStringBuffer(UNICODE_STRING *string, USHORT buffersize) {
    string->Buffer = ExAllocatePoolWithTag(NonPagedPool, buffersize, 'XIUC');
    string->Length = 0;
    if (string->Buffer == NULL) {
        string->MaximumLength=0;
        return;
    }
    string->MaximumLength=(USHORT)buffersize;
    string->Buffer[0]=0;
    return;
}
void FreeUnicodeStringBuffer(UNICODE_STRING *string) {
    if (string->Buffer)
        ExFreePoolWithTag(string->Buffer, 'XIUC');
    string->Length=0;
    string->MaximumLength=0;
    string->Buffer = NULL;
}

NTSTATUS
CloneUnicodeString(UNICODE_STRING *dest, UNICODE_STRING *src) {
    NTSTATUS status;
    AllocUnicodeStringBuffer(dest, src->Length);
    if (dest->Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    status = RtlUnicodeStringCopy(dest, src);
    if (!NT_SUCCESS(status)) {
        FreeUnicodeStringBuffer(dest);
    }
    return status;
}

NTSTATUS
StringToUnicode(UNICODE_STRING *ustr, const char * str) {
    ANSI_STRING ansi;
    RtlInitAnsiString(&ansi, str);
    return RtlAnsiStringToUnicodeString(ustr, &ansi, TRUE);
}

size_t
GetCountedSize(const char * string) {
    ANSI_STRING ansi;
    RtlInitAnsiString(&ansi, string);
    return sizeof(USHORT)+sizeof(WCHAR)*ansi.Length;
}

size_t
GetCountedUtf8Size(const char *utf8) {
    return sizeof(USHORT) + CountBytesUtf16FromUtf8(utf8);
}

size_t
GetCountedUnicodeStringSize(UNICODE_STRING *string) {
    return sizeof(USHORT)+string->Length;
}

size_t
GetInstanceNameSize(XENIFACE_FDO* FdoData, const char *string) {
    ANSI_STRING ansi;
    RtlInitAnsiString(&ansi, string);
    return sizeof(USHORT) +
            FdoData->SuggestedInstanceName.Length +
            sizeof(WCHAR) +
            sizeof(WCHAR)*ansi.Length;

}


NTSTATUS
GetInstanceName(UNICODE_STRING *dest, XENIFACE_FDO* FdoData, const char *string) {
    ANSI_STRING ansi;
    UNICODE_STRING unicode;
    NTSTATUS status;
    size_t destsz;

    RtlInitAnsiString(&ansi, string);
    status = RtlAnsiStringToUnicodeString(&unicode, &ansi, TRUE);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    destsz = FdoData->SuggestedInstanceName.Length +
                sizeof(WCHAR) +
                unicode.Length;

    AllocUnicodeStringBuffer(dest, (USHORT)destsz);
    if (dest->Buffer == NULL ) {
        RtlFreeUnicodeString(&unicode);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = RtlUnicodeStringPrintf(dest, L"%s\\%s",
                FdoData->SuggestedInstanceName.Buffer,
                unicode.Buffer);
    if (!NT_SUCCESS(status)) {
        RtlFreeUnicodeString(&unicode);
        FreeUnicodeStringBuffer(dest);
        return status;
    }
    RtlFreeUnicodeString(&unicode);
    return STATUS_SUCCESS;
}

NTSTATUS
WriteInstanceName(XENIFACE_FDO* FdoData, const char *string, UCHAR *location)
{
    UNICODE_STRING destination;
    NTSTATUS status;
    status = GetInstanceName(&destination, FdoData, string);
    if (!NT_SUCCESS(status))
        return status;
    status = WriteCountedUnicodeString(&destination, location);
    FreeUnicodeStringBuffer(&destination);
    return status;
}

#define MAX_WATCH_COUNT (MAXIMUM_WAIT_OBJECTS -1)

typedef struct _XenStoreSession {
    LIST_ENTRY listentry;
    LONG id;
    UNICODE_STRING stringid;
    UNICODE_STRING instancename;
    PXENBUS_STORE_TRANSACTION transaction;
    LIST_ENTRY watches;
    int watchcount;
    KEVENT* watchevents[MAXIMUM_WAIT_OBJECTS];
    KWAIT_BLOCK watchwaitblockarray[MAXIMUM_WAIT_OBJECTS];
    KEVENT SessionChangedEvent;
    XENIFACE_MUTEX WatchMapLock;
    BOOLEAN mapchanged;
    BOOLEAN closing;
    BOOLEAN suspended;
    PKTHREAD WatchThread;
} XenStoreSession;

typedef struct _XenStoreWatch {
    LIST_ENTRY listentry;
    UNICODE_STRING path;
    XENIFACE_FDO *fdoData;

    ULONG   suspendcount;
    BOOLEAN finished;
    KEVENT watchevent;
    PXENBUS_STORE_WATCH watchhandle;

} XenStoreWatch;

void UnicodeShallowCopy(UNICODE_STRING *dest, UNICODE_STRING *src) {
    dest->Buffer = src->Buffer;
    dest->Length = src->Length;
    dest->MaximumLength = src->MaximumLength;
}


XenStoreSession*
FindSessionLocked(XENIFACE_FDO *fdoData,
                                LONG id) {
    XenStoreSession *session;

    session = (XenStoreSession *)fdoData->SessionHead.Flink;
    while (session != (XenStoreSession *)&fdoData->SessionHead){
        if (session->id == id) {
            if (session->suspended)
                return NULL;
            return session;
        }
        session = (XenStoreSession *)session->listentry.Flink;
    }
    return NULL;
}


int CompareUnicodeStrings(PCUNICODE_STRING string1, PCUNICODE_STRING string2) {
    if (string1->Length == string2->Length) {
        return RtlCompareMemory(string1->Buffer,string2->Buffer, string1->Length) != string1->Length;
    }
    return 1;

}

XenStoreWatch *
SessionFindWatchLocked(XenStoreSession *session,
                        UNICODE_STRING *path) {
    XenStoreWatch * watch;

    Trace("Wait for session watch lock\n");
    AcquireMutex(&session->WatchMapLock);
    Trace("got session watch lock\n");
    watch = (XenStoreWatch *)session->watches.Flink;

    while (watch != (XenStoreWatch *)&session->watches){
        if (CompareUnicodeStrings(path, &watch->path)==0) {
            return watch;
        }
        watch = (XenStoreWatch *)watch->listentry.Flink;
    }

    Warning("couldn't find watch\n");
    return NULL;

}

VOID
WmiFireSuspendEvent(
    IN  PXENIFACE_FDO   Fdo
    )
{
    Info("Ready to unsuspend Event\n");
    KeSetEvent(&Fdo->registryWriteEvent, IO_NO_INCREMENT, FALSE);

    if (!Fdo->WmiReady)
        return;

    Trace("Fire Suspend Event\n");
    WmiFireEvent(Fdo->Dx->DeviceObject,
                 (LPGUID)&OBJECT_GUID(XenStoreUnsuspendedEvent),
                 0,
                 0,
                 NULL);
}

void FireWatch(XenStoreWatch* watch) {
    UCHAR * eventdata;
    ULONG RequiredSize;
    UCHAR *sesbuf;

    AccessWmiBuffer(0, FALSE, &RequiredSize, 0,
            WMI_STRING, GetCountedUnicodeStringSize(&watch->path),
                &sesbuf,
            WMI_DONE);

    eventdata = ExAllocatePoolWithTag(NonPagedPool, RequiredSize,'XIEV');
    if (eventdata!=NULL) {
        AccessWmiBuffer(eventdata, FALSE, &RequiredSize, RequiredSize,
            WMI_STRING, GetCountedUnicodeStringSize(&watch->path),
                &sesbuf,
            WMI_DONE);

        WriteCountedUnicodeString(&watch->path, sesbuf);
    }

    if (eventdata !=NULL) {
        Trace("Fire Watch Event\n");
        WmiFireEvent(watch->fdoData->Dx->DeviceObject,
                     (LPGUID)&OBJECT_GUID(XenStoreWatchEvent),
                     0,
                     RequiredSize,
                     eventdata);
    }
}


KSTART_ROUTINE WatchCallbackThread;
NTSTATUS
StartWatch(XENIFACE_FDO *fdoData, XenStoreWatch *watch)
{
    char *tmppath;
    ANSI_STRING ansipath;
    NTSTATUS status;
    status = RtlUnicodeStringToAnsiString(&ansipath, &watch->path, TRUE);
    if (!NT_SUCCESS(status)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    tmppath = ExAllocatePoolWithTag(NonPagedPool, ansipath.Length+1, 'XenP');
    if (!tmppath) {
        RtlFreeAnsiString(&ansipath);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(tmppath, ansipath.Length+1);
    RtlCopyBytes(tmppath,ansipath.Buffer, ansipath.Length);

    status = XENBUS_STORE(WatchAdd, &fdoData->StoreInterface, NULL, tmppath, &watch->watchevent, &watch->watchhandle );
    if (!NT_SUCCESS(status)) {
        ExFreePool(tmppath);
        RtlFreeAnsiString(&ansipath);
        return status;
    }

    Info("Start Watch %p\n", watch->watchhandle);

    ExFreePool(tmppath);
    RtlFreeAnsiString(&ansipath);

    return STATUS_SUCCESS;
}


VOID WatchCallbackThread(__in PVOID StartContext) {
    NTSTATUS status;
    int i=0;
    XenStoreSession * session = (XenStoreSession*) StartContext;

    for(;;) {
        AcquireMutex(&session->WatchMapLock);
        if (session->mapchanged) {
            // Construct a new mapping
            XenStoreWatch *watch;
            Trace("Construct a new mapping\n");
            watch = (XenStoreWatch *)session->watches.Flink;
            for (i=0; watch != (XenStoreWatch *)&session->watches; i++) {
                session->watchevents[i] = &watch->watchevent;
                watch = (XenStoreWatch *)watch->listentry.Flink;
            }
            session->mapchanged = FALSE;
            session->watchevents[i] = &session->SessionChangedEvent;
        }
        ReleaseMutex(&session->WatchMapLock);
        Trace("Wait for new event\n");
        status = KeWaitForMultipleObjects(i+1, session->watchevents, WaitAny, Executive, KernelMode, TRUE, NULL, session->watchwaitblockarray);
        Trace("got new event\n");
        if ((status >= STATUS_WAIT_0) && (status < STATUS_WAIT_0 +i )) {
            XenStoreWatch *watch;
            Trace("watch or suspend\n");
            watch = CONTAINING_RECORD(session->watchevents[status-STATUS_WAIT_0], XenStoreWatch, watchevent );
            AcquireMutex(&session->WatchMapLock);
            KeClearEvent(&watch->watchevent);


            if (watch->finished) {
                FreeUnicodeStringBuffer(&watch->path);
                RemoveEntryList((LIST_ENTRY*)watch);
                ExFreePool(watch);
                session->mapchanged = TRUE;
                session->watchcount --;
            } else if (!session->suspended &&
                       watch->suspendcount != XENBUS_SUSPEND(GetCount, &watch->fdoData->SuspendInterface)) {
                watch->suspendcount = XENBUS_SUSPEND(GetCount, &watch->fdoData->SuspendInterface);
                Info("SessionSuspendResumeUnwatch %p\n", watch->watchhandle);

                XENBUS_STORE(WatchRemove, &watch->fdoData->StoreInterface, watch->watchhandle);
                watch->watchhandle = NULL;
                StartWatch(watch->fdoData, watch);
            } else {
                FireWatch(watch);
            }
            ReleaseMutex(&session->WatchMapLock);
        }
        else if ( status == STATUS_WAIT_0 + i) {
            AcquireMutex(&session->WatchMapLock);
            KeClearEvent(&session->SessionChangedEvent);
            if (session->closing==TRUE) {
                Trace("Trying to end session thread\n");
                if (session->watchcount != 0) {
                    XenStoreWatch *watch;
                    for (watch = (XenStoreWatch *)session->watches.Flink;
                        watch!=(XenStoreWatch *)&session->watches;
                        watch=(XenStoreWatch *)session->watches.Flink) {
                            FreeUnicodeStringBuffer(&watch->path);
                            RemoveEntryList((LIST_ENTRY*)watch);
                            ExFreePool(watch);
                            session->mapchanged = TRUE;
                            session->watchcount --;
                    }
                }
                ReleaseMutex(&session->WatchMapLock);
                Trace("Ending session thread\n");
                PsTerminateSystemThread(STATUS_SUCCESS);
                //ReleaseMutex(&session->WatchMapLock);
            }
            else {

                ReleaseMutex(&session->WatchMapLock);
            }
        }

    }
}

NTSTATUS
SessionAddWatchLocked(XenStoreSession *session,
                        XENIFACE_FDO* fdoData,
                        UNICODE_STRING *path,
                        XenStoreWatch **watch) {


    NTSTATUS status;
    XenStoreWatch *pwatch;

    if (session->watchcount >= MAX_WATCH_COUNT) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *watch = ExAllocatePoolWithTag(NonPagedPool, sizeof(XenStoreWatch), 'XenP');
    if (*watch == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    (*watch)->finished = FALSE;
    (*watch)->fdoData = fdoData;
    UnicodeShallowCopy(&(*watch)->path, path);



    (*watch)->suspendcount = XENBUS_SUSPEND(GetCount, &fdoData->SuspendInterface);


    KeInitializeEvent(&(*watch)->watchevent, NotificationEvent, FALSE);


    status = StartWatch(fdoData, *watch);
    if ((!NT_SUCCESS(status)) || ((*watch)->watchhandle == NULL)) {
        ExFreePool(*watch);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    AcquireMutex(&session->WatchMapLock);
    session->mapchanged = TRUE;
    KeSetEvent(&session->SessionChangedEvent, IO_NO_INCREMENT,FALSE);
    session->watchcount++;
    InsertHeadList(&session->watches,(PLIST_ENTRY)(*watch));

    Trace("WATCHLIST for session %p-----------\n", session);
    pwatch = (XenStoreWatch *)session->watches.Flink;

    while (pwatch != (XenStoreWatch *)&session->watches){
        Trace("WATCHLIST %p\n", pwatch->watchhandle);
        pwatch = (XenStoreWatch *)pwatch->listentry.Flink;
    }
    Trace("WATCHLIST-------------------\n");

    ReleaseMutex(&session->WatchMapLock);
    return STATUS_SUCCESS;

}

void SessionRemoveWatchLocked(XenStoreSession *session, XenStoreWatch *watch) {

    XenStoreWatch *pwatch;
    Trace("Remove watch locked\n");
    Trace("watch %p\n", watch);
    Trace("handle %p\n", watch->watchhandle);

    if (watch->watchhandle) {
        XENBUS_STORE(WatchRemove, &watch->fdoData->StoreInterface, watch->watchhandle);
        watch->watchhandle=NULL;
        watch->finished = TRUE;
        Trace("WATCHLIST for session %p-----------\n", session);
    pwatch = (XenStoreWatch *)session->watches.Flink;

    while (pwatch != (XenStoreWatch *)&session->watches){
        Trace("WATCHLIST %p\n", pwatch->watchhandle);
        pwatch = (XenStoreWatch *)pwatch->listentry.Flink;
    }
    Trace("WATCHLIST-------------------\n");
        KeSetEvent(&watch->watchevent, IO_NO_INCREMENT,FALSE);
    }

}

void SessionRemoveWatchesLocked(XenStoreSession *session) {
    XenStoreWatch *watch;

    Trace("wait remove mutex\n");
    AcquireMutex(&session->WatchMapLock);
    for (watch = (XenStoreWatch *)session->watches.Flink;
         watch!=(XenStoreWatch *)&session->watches;
         watch=(XenStoreWatch *)watch->listentry.Flink) {

        Trace("try remove %p\n", session->watches.Flink);
        SessionRemoveWatchLocked(session, watch);
    }
    Trace("release remove mutex\n");
    ReleaseMutex(&session->WatchMapLock);
}


XenStoreSession*
FindSessionByInstanceLocked(XENIFACE_FDO *fdoData,
                            UNICODE_STRING *instance) {
    XenStoreSession *session;

    session = (XenStoreSession *)fdoData->SessionHead.Flink;
    while (session != (XenStoreSession *)&fdoData->SessionHead) {
        if (CompareUnicodeStrings(instance, &session->instancename)==0) {
            if (session->suspended)
                return NULL;
            return session;
        }
        session = (XenStoreSession *)session->listentry.Flink;
    }
    return NULL;
}


__checkReturn
__success(return!=NULL)
XenStoreSession *
FindSessionByInstanceAndLock(XENIFACE_FDO *fdoData,
                                UNICODE_STRING *instance) {
    XenStoreSession *session;
    LockSessions(fdoData);
    session = FindSessionByInstanceLocked(fdoData, instance);
    if (session == NULL) {
         UnlockSessions(fdoData);
    }
    return session;
}

PSTR Xmasprintf(const char *fmt, ...) {
    va_list argv;
    PSTR out;
    size_t basesize = 128;
    size_t unused;
    NTSTATUS status;
    va_start(argv, fmt);
    do{
        basesize = basesize * 2;
        out =  ExAllocatePoolWithTag(NonPagedPool, basesize, 'XenP');
        if (out == NULL)
            return NULL;

        status = RtlStringCbVPrintfExA(out, basesize, NULL, &unused,0, fmt, argv);

        ExFreePool(out);
    }while (status != STATUS_SUCCESS);

    out = ExAllocatePoolWithTag(NonPagedPool, basesize-unused +1, 'XenP');
    if (out == NULL)
        return NULL;

    RtlStringCbVPrintfA(out, basesize-unused+1, fmt, argv);

    va_end(argv);
    return out;
}

NTSTATUS
CreateNewSession(XENIFACE_FDO *fdoData,
                    UNICODE_STRING *stringid,
                    ULONG *sessionid) {
    XenStoreSession *session;
    PSTR iname;
    NTSTATUS status;
    ANSI_STRING ansi;
    HANDLE hthread;
    int count = 0;
    OBJECT_ATTRIBUTES oa;
    if (fdoData->Sessions == MAX_SESSIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    session = ExAllocatePoolWithTag(NonPagedPool, sizeof(XenStoreSession), 'XenP');
    if (session == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(session, sizeof(XenStoreSession));

    InitializeMutex(&session->WatchMapLock);
    session->mapchanged = TRUE;
    status = RtlUnicodeStringToAnsiString(&ansi, stringid, TRUE);
    if (!NT_SUCCESS(status)) {
        ExFreePool(session);
        return status;
    }
    LockSessions(fdoData);
    do {
        FreeUnicodeStringBuffer(&session->instancename);
        iname = Xmasprintf("Session_%s_%d", ansi.Buffer, count);

        status = STATUS_NO_MEMORY;
        if (iname == NULL) {
            UnlockSessions(fdoData);
            RtlFreeAnsiString(&ansi);
            ExFreePool(session);
            return status;
        }

        status = GetInstanceName(&session->instancename ,fdoData,iname);
        ExFreePool(iname);
        if (!NT_SUCCESS(status)) {
            UnlockSessions(fdoData);
            RtlFreeAnsiString(&ansi);
            ExFreePool(session);
            return status;
        }
        count++;

    } while (FindSessionByInstanceLocked(fdoData, &session->instancename) != NULL);





    if (fdoData->SessionHead.Flink==&fdoData->SessionHead) {
        session->id=0;
    }
    else {
        session->id =((XenStoreSession*)(fdoData->SessionHead.Flink))->id+1;
        while (FindSessionLocked(fdoData, session->id))
            session->id = (session->id + 1) % MAX_SESSIONS;
    }
    session->transaction=NULL;
    InsertHeadList((PLIST_ENTRY)&fdoData->SessionHead, (PLIST_ENTRY)session);
    *sessionid = session->id;
    UnicodeShallowCopy(&session->stringid, stringid);

    InitializeListHead((PLIST_ENTRY)&session->watches);

    KeInitializeEvent(&session->SessionChangedEvent, NotificationEvent, FALSE);
    session->closing = FALSE;
    if (fdoData->InterfacesAcquired){
        Trace("Add session unsuspended\n");
        session->suspended=FALSE;
    }
    else {
        Trace("Add session suspended\n");
        session->suspended=TRUE;
    }
    fdoData->Sessions++;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(&hthread, THREAD_ALL_ACCESS, &oa, NULL, NULL, WatchCallbackThread, session);
    if (!NT_SUCCESS(status)) {
            RtlFreeAnsiString(&ansi);
            ExFreePool(session);
            return status;
    }
    ObReferenceObjectByHandle(hthread, THREAD_ALL_ACCESS, NULL, KernelMode,  &session->WatchThread, NULL);
    UnlockSessions(fdoData);
    RtlFreeAnsiString(&ansi);
    return STATUS_SUCCESS;
}

void
RemoveSessionLocked(XENIFACE_FDO *fdoData,
                    XenStoreSession *session) {

    Trace("RemoveSessionLocked\n");
    RemoveEntryList((LIST_ENTRY*)session);
    fdoData->Sessions--;
    SessionRemoveWatchesLocked(session);
    if (session->transaction != NULL) {
        XENBUS_STORE(TransactionEnd, &fdoData->StoreInterface, session->transaction, FALSE);
        session->transaction = NULL;
    }
    session->closing = TRUE;
    KeSetEvent(&session->SessionChangedEvent, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(session->WatchThread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(session->WatchThread);
    FreeUnicodeStringBuffer(&session->stringid);
    FreeUnicodeStringBuffer(&session->instancename);
    ExFreePool(session);
}

void
RemoveSession(XENIFACE_FDO *fdoData,
                    XenStoreSession *session) {
    Trace("RemoveSession\n");
    LockSessions(fdoData);
    RemoveSessionLocked(fdoData, session);
    UnlockSessions(fdoData);
}

void SessionsRemoveAll(XENIFACE_FDO *fdoData) {
    LockSessions(fdoData);
    while (fdoData->SessionHead.Flink != &fdoData->SessionHead) {
        RemoveSessionLocked(fdoData, (XenStoreSession *)fdoData->SessionHead.Flink);
    }
    UnlockSessions(fdoData);
}



void SessionUnwatchWatchesLocked(XenStoreSession *session)
{
    int i;
    XenStoreWatch *watch;
    AcquireMutex(&session->WatchMapLock);
    watch = (XenStoreWatch *)session->watches.Flink;
    for (i=0; watch != (XenStoreWatch *)&session->watches; i++) {
        Trace("Suspend unwatch %p\n", watch->watchhandle);

        XENBUS_STORE(WatchRemove, &watch->fdoData->StoreInterface, watch->watchhandle);
        watch->watchhandle = NULL;
        watch = (XenStoreWatch *)watch->listentry.Flink;
    }
    Trace("WATCHLIST for session %p-----------\n",session);
    watch = (XenStoreWatch *)session->watches.Flink;

    while (watch != (XenStoreWatch *)&session->watches){
        Trace("WATCHLIST %p\n",watch->watchhandle);
        watch = (XenStoreWatch *)watch->listentry.Flink;
    }
    Trace("WATCHLIST-------------------\n");
    session->suspended=1;
    ReleaseMutex(&session->WatchMapLock);
}

void SuspendSessionLocked(XENIFACE_FDO *fdoData,
                         XenStoreSession *session) {
    SessionUnwatchWatchesLocked(session);
    if (session->transaction != NULL) {
        Trace("End transaction %p\n",session->transaction);

        XENBUS_STORE(TransactionEnd, &fdoData->StoreInterface, session->transaction, FALSE);
        session->transaction = NULL;
    }
}

VOID
WmiSessionsSuspendAll(
    IN  PXENIFACE_FDO   Fdo
    )
{
    XenStoreSession *session;

    LockSessions(Fdo);
    Trace("Suspend all sessions\n");
    session = (XenStoreSession *)Fdo->SessionHead.Flink;
    while (session != (XenStoreSession *)&Fdo->SessionHead) {
        SuspendSessionLocked(Fdo, session);
        session = (XenStoreSession *)session->listentry.Flink;
    }
    UnlockSessions(Fdo);
}

void SessionRenewWatchesLocked(XenStoreSession *session) {
    int i;
    XenStoreWatch *watch;
    AcquireMutex(&session->WatchMapLock);
    watch = (XenStoreWatch *)session->watches.Flink;
    for (i=0; watch != (XenStoreWatch *)&session->watches; i++) {
        if (!watch->finished) {
            watch->suspendcount = XENBUS_SUSPEND(GetCount, &watch->fdoData->SuspendInterface);
            StartWatch(watch->fdoData, watch);
        }
        watch = (XenStoreWatch *)watch->listentry.Flink;
    }
    Trace("WATCHLIST for session %p-----------\n",session);
    watch = (XenStoreWatch *)session->watches.Flink;

    while (watch != (XenStoreWatch *)&session->watches){
        Trace("WATCHLIST %p\n",watch->watchhandle);
        watch = (XenStoreWatch *)watch->listentry.Flink;
    }
    Trace("WATCHLIST-------------------\n");
    session->suspended=0;
    session->mapchanged = TRUE;
    KeSetEvent(&session->SessionChangedEvent, IO_NO_INCREMENT,FALSE);
    ReleaseMutex(&session->WatchMapLock);
}

void ResumeSessionLocked(XENIFACE_FDO *fdoData,
                         XenStoreSession *session) {
    SessionRenewWatchesLocked(session);
}

VOID
WmiSessionsResumeAll(
    IN  PXENIFACE_FDO   Fdo
    )
{
    XenStoreSession *session;

    LockSessions(Fdo);
    Trace("Resume all sessions\n");
    session = (XenStoreSession *)Fdo->SessionHead.Flink;
    while (session != (XenStoreSession *)&Fdo->SessionHead) {
        ResumeSessionLocked(Fdo, session);
        session = (XenStoreSession *)session->listentry.Flink;
    }
    UnlockSessions(Fdo);
}

NTSTATUS
WmiRegister(
    IN  PXENIFACE_FDO   Fdo
    )
{
    NTSTATUS            status;

    if (Fdo->WmiReady)
        return STATUS_SUCCESS;

    Trace("%s\n",__FUNCTION__);
    Info("DRV: XenIface WMI Initialisation\n");

    status = IoWMIRegistrationControl(Fdo->Dx->DeviceObject,
                                      WMIREG_ACTION_REGISTER);
    if (!NT_SUCCESS(status))
        goto fail1;

    Fdo->WmiReady = 1;
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);
    return status;
}

VOID
WmiDeregister(
    IN  PXENIFACE_FDO   Fdo
    )
{
    if (!Fdo->WmiReady)
        return;

    Info("DRV: XenIface WMI Finalisation\n");
    Trace("%s\n",__FUNCTION__);

    SessionsRemoveAll(Fdo);
    (VOID) IoWMIRegistrationControl(Fdo->Dx->DeviceObject,
                                    WMIREG_ACTION_DEREGISTER);
    Fdo->WmiReady = 0;
}

NTSTATUS
WmiChangeSingleInstance(
    PXENIFACE_FDO Fdo,
    PIO_STACK_LOCATION stack
   )
{
    UNREFERENCED_PARAMETER(Fdo);
    UNREFERENCED_PARAMETER(stack);
    Trace("%s\n",__FUNCTION__);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
WmiChangeSingleItem(
    IN PXENIFACE_FDO Fdo,
    IN PIO_STACK_LOCATION stack
   )
{
    UNREFERENCED_PARAMETER(Fdo);
    UNREFERENCED_PARAMETER(stack);
    Trace("%s\n",__FUNCTION__);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
WmiDisableCollection(
    IN PXENIFACE_FDO Fdo,
    IN PIO_STACK_LOCATION stack
   )
{
    UNREFERENCED_PARAMETER(Fdo);
    UNREFERENCED_PARAMETER(stack);
    Trace("%s\n",__FUNCTION__);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
WmiDisableEvents(
    IN PXENIFACE_FDO Fdo,
    IN PIO_STACK_LOCATION stack
   )
{
    UNREFERENCED_PARAMETER(Fdo);
    UNREFERENCED_PARAMETER(stack);
    Trace("%s\n",__FUNCTION__);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
WmiEnableCollection(
    IN PXENIFACE_FDO Fdo,
    IN PIO_STACK_LOCATION stack
   )
{
    UNREFERENCED_PARAMETER(Fdo);
    UNREFERENCED_PARAMETER(stack);
    Trace("%s\n",__FUNCTION__);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
WmiEnableEvents(
    IN PXENIFACE_FDO Fdo,
    IN PIO_STACK_LOCATION stack
   )
{
    UNREFERENCED_PARAMETER(Fdo);
    UNREFERENCED_PARAMETER(stack);
    Trace("%s\n",__FUNCTION__);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NodeTooSmall(UCHAR *Buffer,
                    ULONG BufferSize,
                    ULONG Needed,
                    ULONG_PTR *byteswritten) {
    WNODE_TOO_SMALL *node;
    ULONG RequiredSize;
    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_TOO_SMALL), &node,
                            WMI_DONE))
    {
        *byteswritten = RequiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }
    node->WnodeHeader.BufferSize=sizeof(WNODE_TOO_SMALL);
    KeQuerySystemTime(&node->WnodeHeader.TimeStamp);
    node->WnodeHeader.Flags = WNODE_FLAG_TOO_SMALL;
    node->SizeNeeded = Needed;
    *byteswritten = sizeof(WNODE_TOO_SMALL);
    return STATUS_SUCCESS;
}

NTSTATUS
SessionExecuteRemoveValue(UCHAR *InBuffer,
                            ULONG InBufferSize,
                            UCHAR *OutBuffer,
                            ULONG OutBufferSize,
                            XENIFACE_FDO* fdoData,
                            UNICODE_STRING *instance,
                            OUT ULONG_PTR *byteswritten) {
    ULONG RequiredSize;
    NTSTATUS status;
    UCHAR* upathname;
    UTF8_STRING *pathname;
    XenStoreSession *session;
    char *tmpbuffer;

    *byteswritten=0;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                            WMI_STRING, &upathname,
                            WMI_DONE))
        return STATUS_INVALID_DEVICE_REQUEST;
    if (!fdoData->InterfacesAcquired) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = GetCountedUTF8String(&pathname, upathname);
    if (!NT_SUCCESS(status))
        return status;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmpbuffer = ExAllocatePoolWithTag(NonPagedPool, pathname->Length+1, 'XenP');
    if (!tmpbuffer) {
        goto fail1;
    }
    RtlZeroMemory(tmpbuffer, pathname->Length+1);
    RtlCopyBytes(tmpbuffer,pathname->Buffer, pathname->Length);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        goto fail2;
    }
    status = XENBUS_STORE(Remove, &fdoData->StoreInterface, session->transaction, NULL, tmpbuffer);
    UnlockSessions(fdoData);

fail2:
    ExFreePool(tmpbuffer);

fail1:
    FreeUTF8String(pathname);
    return status;

}

NTSTATUS
SessionExecuteRemoveWatch(UCHAR *InBuffer,
                            ULONG InBufferSize,
                            UCHAR *OutBuffer,
                            ULONG OutBufferSize,
                            XENIFACE_FDO* fdoData,
                            UNICODE_STRING *instance,
                            OUT ULONG_PTR *byteswritten) {
    ULONG RequiredSize;
    UCHAR* upathname;
    XenStoreWatch* watch;
    UNICODE_STRING unicpath_notbacked;
    XenStoreSession *session;

    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                            WMI_STRING, &upathname,
                            WMI_DONE))
        return STATUS_INVALID_DEVICE_REQUEST;


    GetCountedUnicodeString(&unicpath_notbacked, upathname);

    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        return STATUS_WMI_INSTANCE_NOT_FOUND;
    }


    Trace("Find Watch\n");

    watch = SessionFindWatchLocked(session, &unicpath_notbacked);

    if (watch) {

        SessionRemoveWatchLocked(session, watch);
    }
    else {
        Warning("No Watch\n");
    }
#pragma prefast (suppress:26110)
    ReleaseMutex(&session->WatchMapLock);
    UnlockSessions(fdoData);

    *byteswritten=0;



    return STATUS_SUCCESS;

}


NTSTATUS
SessionExecuteSetWatch(UCHAR *InBuffer,
                            ULONG InBufferSize,
                            UCHAR *OutBuffer,
                            ULONG OutBufferSize,
                            XENIFACE_FDO* fdoData,
                            UNICODE_STRING *instance,
                            OUT ULONG_PTR *byteswritten) {
    ULONG RequiredSize;
    NTSTATUS status;
    UCHAR* upathname;
    XenStoreWatch* watch;
    XenStoreSession *session;
    UNICODE_STRING unicpath_notbacked;
    UNICODE_STRING unicpath_backed;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                            WMI_STRING, &upathname,
                            WMI_DONE))
        return STATUS_INVALID_DEVICE_REQUEST;


    GetCountedUnicodeString(&unicpath_notbacked, upathname);
    status = CloneUnicodeString(&unicpath_backed, &unicpath_notbacked);
    if (!NT_SUCCESS(status)) return status;

    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        FreeUnicodeStringBuffer(&unicpath_backed);
        return STATUS_WMI_INSTANCE_NOT_FOUND;
    }

    status = SessionAddWatchLocked(session, fdoData, &unicpath_backed, &watch);

    UnlockSessions(fdoData);
    if (!NT_SUCCESS(status)) {
        FreeUnicodeStringBuffer(&unicpath_backed);
        return status;
    }


    *byteswritten=0;



    return STATUS_SUCCESS;

}
NTSTATUS
SessionExecuteEndSession(UCHAR *InBuffer,
                            ULONG InBufferSize,
                            UCHAR *OutBuffer,
                            ULONG OutBufferSize,
                            XENIFACE_FDO* fdoData,
                            UNICODE_STRING *instance,
                            OUT ULONG_PTR *byteswritten) {
    XenStoreSession *session;
    Trace("ExecuteEndSession\n");
    *byteswritten = 0;
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        return STATUS_WMI_INSTANCE_NOT_FOUND;
    }

    RemoveSessionLocked(fdoData, session);
    UnlockSessions(fdoData);
    return STATUS_SUCCESS;
}
NTSTATUS
SessionExecuteSetValue(UCHAR *InBuffer,
                            ULONG InBufferSize,
                            UCHAR *OutBuffer,
                            ULONG OutBufferSize,
                            XENIFACE_FDO* fdoData,
                            UNICODE_STRING *instance,
                            OUT ULONG_PTR *byteswritten) {
    ULONG RequiredSize;
    NTSTATUS status;
    UCHAR* upathname;
    UCHAR* uvalue;
    UTF8_STRING* pathname;
    UTF8_STRING* value;
    XenStoreSession *session;
    char *tmppath;
    char* tmpvalue;

    Trace(" Try to write\n");
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                            WMI_STRING, &upathname,
                            WMI_STRING, &uvalue,
                            WMI_DONE))
        return STATUS_INVALID_DEVICE_REQUEST;
    if (!fdoData->InterfacesAcquired) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = GetCountedUTF8String(&pathname, upathname);
    if (!NT_SUCCESS(status))
        return status;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = ExAllocatePoolWithTag(NonPagedPool, pathname->Length+1, 'XenP');
    if (!tmppath) {
        goto fail1;
    }
    RtlZeroMemory(tmppath, pathname->Length+1);
    RtlCopyBytes(tmppath,pathname->Buffer, pathname->Length);
    status = GetCountedUTF8String(&value, uvalue);
    if (!NT_SUCCESS(status)){
        goto fail2;
    }
    status = STATUS_INSUFFICIENT_RESOURCES;
    tmpvalue = ExAllocatePoolWithTag(NonPagedPool,value->Length+1,'XenP');
    if (!tmpvalue) {
        goto fail3;
    }
    RtlZeroMemory(tmpvalue, value->Length+1);
    RtlCopyBytes(tmpvalue,value->Buffer, value->Length);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        goto fail4;
    }
    status = XENBUS_STORE(Printf, &fdoData->StoreInterface, session->transaction, NULL, tmppath, "%s", tmpvalue);
    Trace(" Write %s to %s (%p)\n", tmpvalue, tmppath, status);
    UnlockSessions(fdoData);

fail4:
    ExFreePool(tmpvalue);

fail3:
    FreeUTF8String(value);

fail2:
    ExFreePool(tmppath);

fail1:
    FreeUTF8String(pathname);

    *byteswritten = 0;
    return status;

}
NTSTATUS
SessionExecuteGetFirstChild(UCHAR *InBuffer,
                            ULONG InBufferSize,
                            UCHAR *OutBuffer,
                            ULONG OutBufferSize,
                            XENIFACE_FDO* fdoData,
                            UNICODE_STRING *instance,
                            OUT ULONG_PTR *byteswritten) {
    ULONG RequiredSize;
    UCHAR *uloc;
    NTSTATUS status;
    UTF8_STRING* path;
    PCHAR listresults;
    size_t stringarraysize;
    UCHAR *valuepos;
    XenStoreSession *session;
    char *tmppath;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                            WMI_STRING, &uloc,
                            WMI_DONE)){
        return  STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!fdoData->InterfacesAcquired) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = GetCountedUTF8String(&path, uloc);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = ExAllocatePoolWithTag(NonPagedPool,path->Length+1, 'XenP');
    if (!tmppath) {
        goto fail1;
    }
    RtlZeroMemory(tmppath, path->Length+1);
    RtlCopyBytes(tmppath,path->Buffer, path->Length);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        goto fail2;
    }
    status = XENBUS_STORE(Directory,&fdoData->StoreInterface, session->transaction, NULL, tmppath, &listresults);
    UnlockSessions(fdoData);

    if (!NT_SUCCESS(status)) {
        goto fail2;
    }

    stringarraysize = 0;
    if ((listresults != NULL ) && (listresults[0]!=0)) {
        stringarraysize+=CountBytesUtf16FromUtf8String(path);
        if ((path->Length!=1)||(path->Buffer[0]!='/')) {
            // If the path isn't '/', we need to insert a
            // '/' between pathname and nodename;
            stringarraysize+=sizeof(WCHAR);
        }
        stringarraysize+=GetCountedUtf8Size(listresults);
    }
    else {
        stringarraysize+=GetCountedUtf8Size("");
    }

    status = STATUS_BUFFER_TOO_SMALL;
    if (!AccessWmiBuffer(InBuffer, FALSE, &RequiredSize, OutBufferSize,
                            WMI_STRING, stringarraysize, &valuepos,
                            WMI_DONE)){
        goto fail3;
    }

    status = STATUS_SUCCESS;
    if ((listresults != NULL) && (listresults[0] != 0)) {
        PSTR fullpath;
        if ((path->Length==1) && (path->Buffer[0]=='/')) {
            fullpath = Xmasprintf("/%s", listresults);
        }
        else {
            fullpath = Xmasprintf("%s/%s",
                                    path->Buffer, listresults);
        }

        if (fullpath == NULL) {
            status = STATUS_NO_MEMORY;
            goto fail4;
        }

        WriteCountedUTF8String(fullpath, valuepos);
        valuepos+=GetCountedUtf8Size(fullpath);
        ExFreePool(fullpath);
    }
    else {
        WriteCountedUTF8String("", valuepos);
    }

fail4:
fail3:
    XENBUS_STORE(Free, &fdoData->StoreInterface, listresults);

    *byteswritten = RequiredSize;

fail2:
    ExFreePool(tmppath);

fail1:
    FreeUTF8String(path);

    return status;

}

NTSTATUS
SessionExecuteGetNextSibling(UCHAR *InBuffer,
                            ULONG InBufferSize,
                            UCHAR *OutBuffer,
                            ULONG OutBufferSize,
                            XENIFACE_FDO* fdoData,
                            UNICODE_STRING *instance,
                            OUT ULONG_PTR *byteswritten) {
    ULONG RequiredSize;
    UCHAR *uloc;
    NTSTATUS status;
    UTF8_STRING* path;
    ANSI_STRING checkleaf;
    PCHAR listresults;
    PCHAR nextresult;
    size_t stringarraysize;
    UCHAR *valuepos;
    XenStoreSession *session;
    char *tmppath;
    char *tmpleaf;
    int leafoffset;
    char *attemptstring;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                            WMI_STRING, &uloc,
                            WMI_DONE)){
        return  STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!fdoData->InterfacesAcquired) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = GetCountedUTF8String(&path, uloc);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = ExAllocatePoolWithTag(NonPagedPool,path->Length+1,'XenP');

    if (!tmppath) {
        goto fail1;
    }
    RtlZeroMemory(tmppath, path->Length+1);
    tmpleaf = ExAllocatePoolWithTag(NonPagedPool,path->Length+1,'XenP');
    if (!tmpleaf) {
        goto fail2;
    }
    RtlZeroMemory(tmpleaf, path->Length+1);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        goto fail3;
    }

    leafoffset = 0;
    if (path->Length>1) {
        leafoffset = path->Length;
        while ((leafoffset!=0) && (path->Buffer[leafoffset] != '/'))
            leafoffset--;
    }
    if (leafoffset != 0){
#pragma warning(suppress:6386) // buffer overrun
        RtlCopyBytes(tmppath,path->Buffer, leafoffset);
        RtlCopyBytes(tmpleaf, path->Buffer+leafoffset+1, path->Length-leafoffset-1);
    }
    else {

        if (path->Buffer[0] == '/') {
            if (path->Length>1)
                RtlCopyBytes(tmpleaf, path->Buffer+1, path->Length-1);
            tmppath[0]='/';
        }
        else {
#pragma warning(suppress:6386) // buffer overrun
            RtlCopyBytes(tmpleaf, path->Buffer, path->Length);
        }

    }

    status = XENBUS_STORE(Directory,&fdoData->StoreInterface, session->transaction, NULL, tmppath, &listresults);
    UnlockSessions(fdoData);

    if (!NT_SUCCESS(status)) {
        goto fail3;
    }

    stringarraysize = 0;
    RtlInitAnsiString(&checkleaf, tmpleaf);

    nextresult = listresults;

    while (*nextresult != 0) {
        ANSI_STRING checkstr;
        RtlInitAnsiString(&checkstr, nextresult);
        if (RtlEqualString(&checkstr, &checkleaf, TRUE)) {
            break;
        }
        while (*nextresult!=0) {
            nextresult++;
        }
        nextresult++;
    }


    attemptstring = NULL;
    while (*nextresult !=0) {
        nextresult++;
    }
    nextresult++;
    if (*nextresult!=0) {
        attemptstring = nextresult;
    }

    if (attemptstring!=NULL) {
        stringarraysize+=CountBytesUtf16FromUtf8(tmppath); //sizeof(WCHAR)*leafoffset;
        if ((path->Length!=1)||(path->Buffer[0]!='/')) {
            // If the path isn't '/', we need to insert a
            // '/' between pathname and nodename;
            stringarraysize+=sizeof(WCHAR);
        }
        stringarraysize+=GetCountedUtf8Size(attemptstring);
    }
    else {
        stringarraysize+=GetCountedUtf8Size("");
    }

    status = STATUS_BUFFER_TOO_SMALL;
    if (!AccessWmiBuffer(InBuffer, FALSE, &RequiredSize, OutBufferSize,
                            WMI_STRING, stringarraysize, &valuepos,
                            WMI_DONE)){
        goto fail4;
    }

    status = STATUS_SUCCESS;
    if (attemptstring != NULL) {
        PSTR fullpath;
        if ((leafoffset==1) && (path->Buffer[0]=='/')) {
            fullpath = Xmasprintf("/%s", attemptstring);
        }
        else {
            fullpath = Xmasprintf("%s/%s",
                                    tmppath, attemptstring);
        }

        if (fullpath == NULL) {
            status = STATUS_NO_MEMORY;
            goto fail5;
        }

        WriteCountedUTF8String(fullpath, valuepos);
        ExFreePool(fullpath);
    }
    else {
        WriteCountedUTF8String("", valuepos);
        valuepos+=GetCountedUtf8Size("");
    }


fail5:
fail4:
    XENBUS_STORE(Free, &fdoData->StoreInterface, listresults);

fail3:
    ExFreePool(tmpleaf);

fail2:
    ExFreePool(tmppath);

fail1:
    FreeUTF8String(path);
    *byteswritten = RequiredSize;
    return status;

}

NTSTATUS
SessionExecuteGetChildren(UCHAR *InBuffer,
                            ULONG InBufferSize,
                            UCHAR *OutBuffer,
                            ULONG OutBufferSize,
                            XENIFACE_FDO* fdoData,
                            UNICODE_STRING *instance,
                            OUT ULONG_PTR *byteswritten) {
    int i;
    ULONG RequiredSize;
    UCHAR *uloc;
    NTSTATUS status;
    UTF8_STRING* path;
    PCHAR listresults;
    PCHAR nextresults;
    ULONG *noofnodes;
    size_t stringarraysize;
    UCHAR *valuepos;
    XenStoreSession *session;
    char *tmppath;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                            WMI_STRING, &uloc,
                            WMI_DONE)){
        return  STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!fdoData->InterfacesAcquired) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = GetCountedUTF8String(&path, uloc);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = ExAllocatePoolWithTag(NonPagedPool,path->Length+1,'XenP');
    if (!tmppath) {
        goto fail1;
    }
    RtlZeroMemory(tmppath, path->Length+1);
    RtlCopyBytes(tmppath,path->Buffer, path->Length);

    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        goto fail2;
    }
    status = XENBUS_STORE(Directory,&fdoData->StoreInterface,session->transaction,NULL, tmppath, &listresults);
    UnlockSessions(fdoData);

    if (!NT_SUCCESS(status)) {
        goto fail2;
    }

    stringarraysize = 0;

    nextresults=listresults;
    while (*nextresults != 0) {
        stringarraysize+=sizeof(WCHAR)*path->Length;
        if ((path->Length!=1)||(path->Buffer[0]!='/')) {
            // If the path isn't '/', we need to insert a
            // '/' between pathname and nodename;
            stringarraysize+=sizeof(WCHAR);
        }
        stringarraysize+=GetCountedUtf8Size(nextresults);
        for (;*nextresults!=0;nextresults++);
        nextresults++;
    }

    status = STATUS_BUFFER_TOO_SMALL;
    if (!AccessWmiBuffer(InBuffer, FALSE, &RequiredSize, OutBufferSize,
                            WMI_UINT32, &noofnodes,
                            WMI_STRING, stringarraysize, &valuepos,
                            WMI_DONE)){
        goto fail3;
    }

    status = STATUS_SUCCESS;
    nextresults = listresults;
    i=0;
    while(*nextresults!=0) {
        PSTR fullpath;
        if ((path->Length==1) && (path->Buffer[0]=='/')) {
            fullpath = Xmasprintf("/%s", nextresults);
        }
        else {
            fullpath = Xmasprintf("%s/%s",
                                    path->Buffer, nextresults);
        }

        if (fullpath == NULL) {
            status = STATUS_NO_MEMORY;
            goto fail4;
        }

        WriteCountedUTF8String(fullpath, valuepos);
        valuepos+=GetCountedUtf8Size(fullpath);
        ExFreePool(fullpath);
        for (;*nextresults!=0;nextresults++);
        nextresults++;
        i++;


    }
    *noofnodes = i;

fail4:
fail3:
    XENBUS_STORE(Free, &fdoData->StoreInterface, listresults);

fail2:
    ExFreePool(tmppath);

fail1:
    FreeUTF8String(path);
    *byteswritten = RequiredSize;
    return status;
}


NTSTATUS
SessionExecuteLog(UCHAR *InBuffer,
                        ULONG InBufferSize,
                        UCHAR *OutBuffer,
                        ULONG OutBufferSize,
                        XENIFACE_FDO* fdoData,
                        UNICODE_STRING *instance,
                        OUT ULONG_PTR *byteswritten) {

    ULONG RequiredSize;
    UCHAR *uloc;
    NTSTATUS status;
    ANSI_STRING message;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                                            WMI_STRING, &uloc,
                                            WMI_DONE))
        return STATUS_INVALID_DEVICE_REQUEST;

    status = GetCountedAnsiString(&message, uloc);

    if (!NT_SUCCESS(status))
        return status;

    Info("USER: %s\n", message.Buffer);

    RtlFreeAnsiString(&message);
    *byteswritten = 0;
    return STATUS_SUCCESS;

}

NTSTATUS
SessionExecuteStartTransaction(UCHAR *InBuffer,
                        ULONG InBufferSize,
                        UCHAR *OutBuffer,
                        ULONG OutBufferSize,
                        XENIFACE_FDO* fdoData,
                        UNICODE_STRING *instance,
                        OUT ULONG_PTR *byteswritten) {

    NTSTATUS status = STATUS_SUCCESS;
    XenStoreSession *session;

    if (!fdoData->InterfacesAcquired) {
        status= STATUS_INSUFFICIENT_RESOURCES;
        goto failnotinitialised;
    }
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        status= STATUS_WMI_INSTANCE_NOT_FOUND;
        goto failsessionnotfound;
    }

    if (session->transaction!=NULL) {
        status = STATUS_REQUEST_OUT_OF_SEQUENCE;
        goto failtransactionactive;
    }

    XENBUS_STORE(TransactionStart, &fdoData->StoreInterface, &session->transaction);


failtransactionactive:
    UnlockSessions(fdoData);
failsessionnotfound:
failnotinitialised:

    *byteswritten = 0;
    return status;

}
NTSTATUS
SessionExecuteCommitTransaction(UCHAR *InBuffer,
                        ULONG InBufferSize,
                        UCHAR *OutBuffer,
                        ULONG OutBufferSize,
                        XENIFACE_FDO* fdoData,
                        UNICODE_STRING *instance,
                        OUT ULONG_PTR *byteswritten) {

    NTSTATUS status = STATUS_SUCCESS;
    XenStoreSession *session;

    if (!fdoData->InterfacesAcquired) {
        status= STATUS_INSUFFICIENT_RESOURCES;
        goto failnotinitialised;
    }
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        status= STATUS_WMI_INSTANCE_NOT_FOUND;
        goto failsessionnotfound;
    }

    if (session->transaction==NULL) {
        status = STATUS_REQUEST_OUT_OF_SEQUENCE;
        goto failtransactionnotactive;
    }

    status = XENBUS_STORE(TransactionEnd,&fdoData->StoreInterface, session->transaction, TRUE);

    session->transaction = NULL;

failtransactionnotactive:
    UnlockSessions(fdoData);
failsessionnotfound:
failnotinitialised:

    *byteswritten = 0;
    return status;

}
NTSTATUS
SessionExecuteAbortTransaction(UCHAR *InBuffer,
                        ULONG InBufferSize,
                        UCHAR *OutBuffer,
                        ULONG OutBufferSize,
                        XENIFACE_FDO* fdoData,
                        UNICODE_STRING *instance,
                        OUT ULONG_PTR *byteswritten) {

    NTSTATUS status = STATUS_SUCCESS;
    XenStoreSession *session;

    if (!fdoData->InterfacesAcquired) {
        status= STATUS_INSUFFICIENT_RESOURCES;
        goto failnotinitialised;
    }
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        status= STATUS_WMI_INSTANCE_NOT_FOUND;
        goto failsessionnotfound;
    }

    if (session->transaction==NULL) {
        status = STATUS_REQUEST_OUT_OF_SEQUENCE;
        goto failtransactionnotactive;
    }

    status = XENBUS_STORE(TransactionEnd, &fdoData->StoreInterface, session->transaction, FALSE);

    session->transaction = NULL;

failtransactionnotactive:
    UnlockSessions(fdoData);
failsessionnotfound:
failnotinitialised:

    *byteswritten = 0;
    return status;

}

NTSTATUS
SessionExecuteGetValue(UCHAR *InBuffer,
                        ULONG InBufferSize,
                        UCHAR *OutBuffer,
                        ULONG OutBufferSize,
                        XENIFACE_FDO* fdoData,
                        UNICODE_STRING *instance,
                        OUT ULONG_PTR *byteswritten) {
    NTSTATUS status;
    UTF8_STRING* path;
    UCHAR *uloc;
    char *value;
    UCHAR *valuepos;
    char *tmppath;
    ULONG RequiredSize;
    XenStoreSession *session;

    *byteswritten = 0;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                                            WMI_STRING, &uloc,
                                            WMI_DONE))
        return STATUS_INVALID_DEVICE_REQUEST;
    if (!fdoData->InterfacesAcquired) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = GetCountedUTF8String(&path, uloc);

    if (!NT_SUCCESS(status))
        return status;;

    status = STATUS_INSUFFICIENT_RESOURCES;
    tmppath = ExAllocatePoolWithTag(NonPagedPool,path->Length+1,'XenP');
    if (!tmppath) {
        goto fail1;
    }
    RtlZeroMemory(tmppath, path->Length+1);
    RtlCopyBytes(tmppath,path->Buffer, path->Length);


    status = STATUS_WMI_INSTANCE_NOT_FOUND;
    if ((session = FindSessionByInstanceAndLock(fdoData, instance)) ==
            NULL){
        goto fail2;
    }
    status = XENBUS_STORE(Read, &fdoData->StoreInterface, session->transaction, NULL, tmppath, &value);
    UnlockSessions(fdoData);

    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_BUFFER_TOO_SMALL;
    if (!AccessWmiBuffer(OutBuffer, FALSE, &RequiredSize, OutBufferSize,
                            WMI_STRING, GetCountedUtf8Size(value), &valuepos,
                            WMI_DONE)) {
        goto fail3;
    }
    status = STATUS_SUCCESS;
    WriteCountedUTF8String(value, valuepos);

fail3:
    XENBUS_STORE(Free, &fdoData->StoreInterface, value);
    *byteswritten = RequiredSize;

fail2:
    ExFreePool(tmppath);

fail1:
    FreeUTF8String(path);
    return status;
}
NTSTATUS
BaseExecuteAddSession(UCHAR *InBuffer,
                        ULONG InBufferSize,
                        UCHAR *OutBuffer,
                        ULONG OutBufferSize,
                        XENIFACE_FDO* fdoData,
                        OUT ULONG_PTR *byteswritten) {
    ULONG RequiredSize;
    UNICODE_STRING ustring;
    ULONG *id;
    UCHAR* stringid;
    NTSTATUS status;
    *byteswritten = 0;
    if (!AccessWmiBuffer(InBuffer, TRUE, &RequiredSize, InBufferSize,
                            WMI_STRING, &stringid,
                            WMI_DONE)){
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!AccessWmiBuffer(OutBuffer, FALSE, &RequiredSize, OutBufferSize,
                            WMI_UINT32, &id,
                            WMI_DONE)) {
        *byteswritten = RequiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    AllocUnicodeStringBuffer(&ustring, *(USHORT*)(stringid));
    if (ustring.Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    status = RtlUnicodeStringCbCopyStringN(&ustring,
                                            (LPCWSTR)(stringid+sizeof(USHORT)),
                                            *(USHORT*)(stringid));
    if (!NT_SUCCESS(status)) {
        FreeUnicodeStringBuffer(&ustring);
        return status;
    }
    status = CreateNewSession(fdoData, &ustring, id);
    if (!NT_SUCCESS(status)) {
        FreeUnicodeStringBuffer(&ustring);
        return status;
    }

    *byteswritten = RequiredSize;
    return STATUS_SUCCESS;

}


NTSTATUS
SessionExecuteMethod(UCHAR *Buffer,
                    ULONG BufferSize,
                    XENIFACE_FDO* fdoData,
                    OUT ULONG_PTR *byteswritten) {
    ULONG RequiredSize;
    WNODE_METHOD_ITEM *Method;
    UCHAR *InBuffer;
    NTSTATUS status;
    UNICODE_STRING instance;
    UCHAR *InstStr;
    Trace("%s\n",__FUNCTION__);
    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_METHOD_ITEM),
                                &Method,
                            WMI_DONE))
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_METHOD_ITEM),
                                &Method,
                            WMI_STRINGOFFSET, Method->OffsetInstanceName,
                                &InstStr,
                            WMI_DONE))
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    InBuffer = Buffer + Method->DataBlockOffset;

    GetCountedUnicodeString(&instance, InstStr);


    Trace("Method Id %d\n", Method->MethodId);
    switch (Method->MethodId) {
        case GetValue:
            status = SessionExecuteGetValue(InBuffer, Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case SetValue:
            status = SessionExecuteSetValue(InBuffer, Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case GetChildren:
            status = SessionExecuteGetChildren(InBuffer, Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case SetWatch:
            status = SessionExecuteSetWatch(InBuffer, Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case EndSession:
            status = SessionExecuteEndSession(InBuffer, Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case RemoveWatch:
            status = SessionExecuteRemoveWatch(InBuffer, Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case RemoveValue:
            status = SessionExecuteRemoveValue(InBuffer, Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case Log:
            status = SessionExecuteLog(InBuffer,  Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case StartTransaction:
            status = SessionExecuteStartTransaction(InBuffer,  Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case CommitTransaction:
            status = SessionExecuteCommitTransaction(InBuffer,  Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case AbortTransaction:
            status = SessionExecuteAbortTransaction(InBuffer,  Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case GetFirstChild:
            status = SessionExecuteGetFirstChild(InBuffer,  Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;
        case GetNextSibling:
            status = SessionExecuteGetNextSibling(InBuffer,  Method->SizeDataBlock,
                                              Buffer+Method->DataBlockOffset,
                                              BufferSize-Method->DataBlockOffset,
                                              fdoData,
                                              &instance,
                                              byteswritten);
            break;


        default:
            Info("DRV: Unknown WMI method %d\n", Method->MethodId);
            return STATUS_WMI_ITEMID_NOT_FOUND;
    }
    Method->SizeDataBlock = (ULONG)*byteswritten;
    *byteswritten+=Method->DataBlockOffset;
    if (status == STATUS_BUFFER_TOO_SMALL) {
        return NodeTooSmall(Buffer, BufferSize, (ULONG)*byteswritten, byteswritten);
    }

    Method->WnodeHeader.BufferSize = (ULONG)*byteswritten;
     return status;
}
NTSTATUS
BaseExecuteMethod(UCHAR *Buffer,
                    ULONG BufferSize,
                    XENIFACE_FDO* fdoData,
                    OUT ULONG_PTR *byteswritten) {
    ULONG RequiredSize;
    WNODE_METHOD_ITEM *Method;
    UCHAR *InBuffer;
    NTSTATUS status;
    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_METHOD_ITEM),
                                &Method,
                            WMI_DONE))
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    InBuffer = Buffer + Method->DataBlockOffset;

    switch (Method->MethodId) {
        case AddSession:
            status = BaseExecuteAddSession(InBuffer, Method->SizeDataBlock,
                                             Buffer+Method->DataBlockOffset,
                                             BufferSize-Method->DataBlockOffset,
                                             fdoData,
                                             byteswritten);
            Method->SizeDataBlock = (ULONG)*byteswritten;
            *byteswritten+=Method->DataBlockOffset;
            Method->WnodeHeader.BufferSize = (ULONG)*byteswritten;
            return status;

        default:
            return STATUS_WMI_ITEMID_NOT_FOUND;
    }
}

NTSTATUS
WmiExecuteMethod(
    IN PXENIFACE_FDO fdoData,
    IN PIO_STACK_LOCATION stack,
    OUT ULONG_PTR *byteswritten
   )
{
    if (IsEqualGUID(stack->Parameters.WMI.DataPath,
                    &OBJECT_GUID(XenStoreBase))) {
        return BaseExecuteMethod(stack->Parameters.WMI.Buffer,
                                    stack->Parameters.WMI.BufferSize,
                                    fdoData,  byteswritten);
    }
    else if (IsEqualGUID(stack->Parameters.WMI.DataPath,
                         &OBJECT_GUID(XenStoreSession))) {
        return SessionExecuteMethod(stack->Parameters.WMI.Buffer,
                                    stack->Parameters.WMI.BufferSize,
                                    fdoData,  byteswritten);
    }

    else
        return STATUS_NOT_SUPPORTED;
}

NTSTATUS
GenerateSessionBlock(UCHAR *Buffer,
                        ULONG BufferSize,
                        PXENIFACE_FDO fdoData,
                        ULONG_PTR *byteswritten) {
    WNODE_ALL_DATA *node;
    ULONG RequiredSize;
    size_t nodesizerequired;
    size_t namesizerequired;
    int entries;
    XenStoreSession *session;
    OFFSETINSTANCEDATAANDLENGTH* dataoffsets;
    ULONG* nameoffsets;
    UCHAR *data;
    UCHAR *names;


    LockSessions(fdoData);

    //work out how much space we need for each session structure
    nodesizerequired = 0;
    namesizerequired = 0;
    entries = 0;
    session = (XenStoreSession *)fdoData->SessionHead.Flink;
    //work out names for each session entry
    while (session !=  (XenStoreSession *)&fdoData->SessionHead) {
        ULONG *id;
        UCHAR *sesbuf;
        UCHAR *inamebuf;

        AccessWmiBuffer((PUCHAR)nodesizerequired, FALSE, &RequiredSize, 0,
                        WMI_UINT32, &id,
                        WMI_STRING,
                            GetCountedUnicodeStringSize(&session->stringid),
                            &sesbuf,
                        WMI_DONE);
        nodesizerequired += RequiredSize;

        AccessWmiBuffer((PUCHAR)namesizerequired, FALSE, &RequiredSize, 0,
                        WMI_STRING,
                            GetCountedUnicodeStringSize(&session->instancename),
                            &inamebuf,
                        WMI_DONE);
        namesizerequired += RequiredSize;
        entries++;
        session = (XenStoreSession *)session->listentry.Flink;
    }

    //perform the access check
    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_ALL_DATA), &node,
                            WMI_BUFFER, sizeof(OFFSETINSTANCEDATAANDLENGTH)*
                                            entries, &dataoffsets,
                            WMI_BUFFER, sizeof(ULONG)*entries, &nameoffsets,
                            WMI_BUFFER, nodesizerequired, &data,
                            WMI_BUFFER, namesizerequired, &names,
                            WMI_DONE)) {
        UnlockSessions(fdoData);
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, byteswritten);
    }

    node->DataBlockOffset = (ULONG)(data - Buffer);
    node->OffsetInstanceNameOffsets = (ULONG)((UCHAR *)nameoffsets - Buffer);
    node->WnodeHeader.BufferSize = RequiredSize;
    KeQuerySystemTime(&node->WnodeHeader.TimeStamp);
    node->WnodeHeader.Flags = WNODE_FLAG_ALL_DATA;
    node->InstanceCount = entries;
    *byteswritten = RequiredSize;

    session = (XenStoreSession *)fdoData->SessionHead.Flink;
    {
        int entrynum = 0;
        UCHAR *datapos = data;
        UCHAR *namepos = names;
        //work out names for each session entry
        while (session !=  (XenStoreSession *)&fdoData->SessionHead){
            ULONG *id;
            UCHAR *sesbuf;
            UCHAR *inamebuf;

            AccessWmiBuffer(datapos, FALSE, &RequiredSize, BufferSize+Buffer-datapos,
                            WMI_UINT32, &id,
                            WMI_STRING,
                                GetCountedUnicodeStringSize(&session->stringid),
                                &sesbuf,
                            WMI_DONE);

            node->OffsetInstanceDataAndLength[entrynum].OffsetInstanceData =
                (ULONG)((UCHAR *)id - Buffer);
            node->OffsetInstanceDataAndLength[entrynum].LengthInstanceData =
                RequiredSize;
            *id = session->id;
            WriteCountedUnicodeString(&session->stringid, sesbuf);
            datapos+=RequiredSize;

            AccessWmiBuffer(namepos, FALSE, &RequiredSize, BufferSize+Buffer-namepos,
                            WMI_STRING,
                                GetCountedUnicodeStringSize(&session->instancename),
                                &inamebuf,
                            WMI_DONE);

            nameoffsets[entrynum] = (ULONG)(namepos-Buffer);
            WriteCountedUnicodeString(&session->instancename, inamebuf);
            namepos+=RequiredSize;

            namesizerequired += RequiredSize;
            entrynum++;
            session = (XenStoreSession *)session->listentry.Flink;
        }

    }

    UnlockSessions(fdoData);

    return STATUS_SUCCESS;

}

NTSTATUS
GenerateBaseBlock(  XENIFACE_FDO *fdoData,
                    UCHAR *Buffer,
                    ULONG BufferSize,
                    ULONG_PTR *byteswritten) {
    WNODE_ALL_DATA *node;
    ULONG RequiredSize;
    ULONGLONG *time;
    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_ALL_DATA), &node,
                            WMI_UINT64, &time,
                            WMI_DONE))
    {
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, byteswritten);
    }

    node->DataBlockOffset =(ULONG)( ((UCHAR *)time)-Buffer);
    node->WnodeHeader.BufferSize = RequiredSize;
    KeQuerySystemTime(&node->WnodeHeader.TimeStamp);
    node->WnodeHeader.Flags = WNODE_FLAG_ALL_DATA |
                                WNODE_FLAG_FIXED_INSTANCE_SIZE |
                                WNODE_FLAG_PDO_INSTANCE_NAMES;
    if (fdoData->InterfacesAcquired) {
        LARGE_INTEGER info;

        XENBUS_SHARED_INFO(GetTime, &fdoData->SharedInfoInterface, &info, NULL);
        *time = info.QuadPart;
    }
    else {
        *time = 0;
    }
    node->InstanceCount = 1;
    node->FixedInstanceSize = sizeof(ULONGLONG);
    *byteswritten = RequiredSize;
    return STATUS_SUCCESS;
}
NTSTATUS
GenerateBaseInstance(
                    XENIFACE_FDO *fdoData,
                    UCHAR *Buffer,
                    ULONG BufferSize,
                    ULONG_PTR *byteswritten) {
    WNODE_SINGLE_INSTANCE *node;
    ULONG RequiredSize;
    ULONGLONG *time;
    UCHAR * dbo;
    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_SINGLE_INSTANCE), &node,
                            WMI_DONE))
    {
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, byteswritten);
    }
    if (!AccessWmiBuffer(Buffer, FALSE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_SINGLE_INSTANCE), &node,
                            WMI_OFFSET, node->DataBlockOffset, 0 ,&dbo,
                            WMI_DONE))
    {
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, byteswritten);
    }
    if (!AccessWmiBuffer(dbo, FALSE, &RequiredSize, BufferSize-node->DataBlockOffset,
                            WMI_UINT64, &time,
                            WMI_DONE)){
        return NodeTooSmall(Buffer, BufferSize, RequiredSize+node->DataBlockOffset,
                            byteswritten);
    }

    if (node->InstanceIndex != 0) {
        return STATUS_WMI_ITEMID_NOT_FOUND;
    }
    if (fdoData->InterfacesAcquired) {
        LARGE_INTEGER info;

        XENBUS_SHARED_INFO(GetTime, &fdoData->SharedInfoInterface, &info, NULL);
        *time = info.QuadPart;
    }
    else {
        *time = 0;
    }


    node->WnodeHeader.BufferSize = node->DataBlockOffset+RequiredSize;
    node->SizeDataBlock = RequiredSize;

    *byteswritten = node->DataBlockOffset+RequiredSize;

    return STATUS_SUCCESS;
}

NTSTATUS
GenerateSessionInstance(UCHAR *Buffer,
                    ULONG BufferSize,
                    XENIFACE_FDO *fdoData,
                    ULONG_PTR *byteswritten) {
    WNODE_SINGLE_INSTANCE *node;
    ULONG RequiredSize;
    UCHAR *dbo;
    UCHAR *InstStr;
    UNICODE_STRING instance;
    ULONG* id;
    XenStoreSession *session;
    UCHAR *sesbuf;

    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_SINGLE_INSTANCE), &node,
                            WMI_DONE))
    {
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, byteswritten);
    }
    if (!AccessWmiBuffer(Buffer, TRUE, &RequiredSize, BufferSize,
                            WMI_BUFFER, sizeof(WNODE_SINGLE_INSTANCE), &node,
                            WMI_STRINGOFFSET, node->OffsetInstanceName, &InstStr,
                            WMI_OFFSET, node->DataBlockOffset, 0, &dbo,
                            WMI_DONE))
    {
        return NodeTooSmall(Buffer, BufferSize, RequiredSize, byteswritten);
    }

    GetCountedUnicodeString(&instance, InstStr);
    LockSessions(fdoData);
    if ((session = FindSessionByInstanceLocked(fdoData, &instance))==NULL){
        UnlockSessions(fdoData);
        return STATUS_WMI_INSTANCE_NOT_FOUND;
    }

    if (!AccessWmiBuffer(dbo, FALSE, &RequiredSize, BufferSize-node->DataBlockOffset,
                            WMI_UINT32, &id,
                            WMI_STRING,
                                GetCountedUnicodeStringSize(&session->stringid),
                                &sesbuf,
                            WMI_DONE)) {
        UnlockSessions(fdoData);
        return NodeTooSmall(Buffer, BufferSize, RequiredSize+node->DataBlockOffset,
                            byteswritten);
    }

    *id = session->id;
    WriteCountedUnicodeString(&session->stringid, sesbuf);
    UnlockSessions(fdoData);
    node->SizeDataBlock = RequiredSize;
    node->WnodeHeader.BufferSize = node->DataBlockOffset + RequiredSize;
    *byteswritten = node->DataBlockOffset + RequiredSize;




    return STATUS_SUCCESS;
}


NTSTATUS
WmiQueryAllData(
    IN PXENIFACE_FDO fdoData,
    IN PIO_STACK_LOCATION stack,
    OUT ULONG_PTR *byteswritten
   )
{

    if (IsEqualGUID(stack->Parameters.WMI.DataPath,
                    &OBJECT_GUID(XenStoreBase))) {
        return GenerateBaseBlock(   fdoData,
                                    stack->Parameters.WMI.Buffer,
                                    stack->Parameters.WMI.BufferSize,
                                    byteswritten);
    }
    else if (IsEqualGUID(stack->Parameters.WMI.DataPath,
                         &OBJECT_GUID(XenStoreSession))) {
        return GenerateSessionBlock(stack->Parameters.WMI.Buffer,
                                    stack->Parameters.WMI.BufferSize,
                                    fdoData,
                                    byteswritten);
    }
    else
        return STATUS_NOT_SUPPORTED;


}

NTSTATUS
WmiQuerySingleInstance(
    IN PXENIFACE_FDO fdoData,
    IN PIO_STACK_LOCATION stack,
    OUT ULONG_PTR *byteswritten
    )
{
    if (IsEqualGUID(stack->Parameters.WMI.DataPath,
                    &OBJECT_GUID(XenStoreBase))) {
        return GenerateBaseInstance(fdoData,
                                    stack->Parameters.WMI.Buffer,
                                    stack->Parameters.WMI.BufferSize,
                                    byteswritten);
    }
    else if (IsEqualGUID(stack->Parameters.WMI.DataPath,
                         &OBJECT_GUID(XenStoreSession))) {
        return GenerateSessionInstance(stack->Parameters.WMI.Buffer,
                                    stack->Parameters.WMI.BufferSize,
                                    fdoData,
                                    byteswritten);
    }
    else
        return STATUS_NOT_SUPPORTED;

}


NTSTATUS
WmiRegInfo(
    IN PXENIFACE_FDO fdoData,
    IN PIO_STACK_LOCATION stack,
    OUT ULONG_PTR *byteswritten
   )
{
    WMIREGINFO *reginfo;
    WMIREGGUID *guiddata;
    UCHAR *mofnameptr;
    UCHAR *regpath;
    ULONG RequiredSize;
    int entries = 4;
    const static UNICODE_STRING mofname = RTL_CONSTANT_STRING(L"XENIFACEMOF");

    size_t mofnamesz;


    WMIREGGUID * guid;
    Trace("%s\n",__FUNCTION__);

    if  (stack->Parameters.WMI.DataPath == WMIREGISTER) {
        mofnamesz = mofname.Length + sizeof(USHORT);
    }
    else {
        mofnamesz = 0;
    }
    if(!AccessWmiBuffer(stack->Parameters.WMI.Buffer, FALSE,
                        &RequiredSize,
                        stack->Parameters.WMI.BufferSize,
                        WMI_BUFFER, sizeof(WMIREGINFO), (UCHAR **)&reginfo,
                        WMI_BUFFER, entries * sizeof(WMIREGGUID), (UCHAR **)&guiddata,
                        WMI_STRING, mofnamesz, &mofnameptr,
                        WMI_STRING, DriverParameters.RegistryPath.Length+sizeof(USHORT),
                                    &regpath,
                        WMI_DONE)){
        reginfo->BufferSize = RequiredSize;
        *byteswritten = sizeof(ULONG);
        return STATUS_BUFFER_TOO_SMALL;

    }
    if (stack->Parameters.WMI.DataPath == WMIREGISTER) {
        reginfo->MofResourceName = (ULONG)((ULONG_PTR)mofnameptr - (ULONG_PTR)reginfo);
        WriteCountedUnicodeString(&mofname, mofnameptr);
        reginfo->RegistryPath = (ULONG)((ULONG_PTR)regpath - (ULONG_PTR)reginfo);
        WriteCountedUnicodeString(&DriverParameters.RegistryPath, regpath);
    }

    reginfo->BufferSize = RequiredSize;
    reginfo->NextWmiRegInfo = 0;
    reginfo->GuidCount = entries;

    guid = &reginfo->WmiRegGuid[0];
    guid->InstanceCount = 1;
    guid->Guid = OBJECT_GUID(XenStoreBase);
    guid->Flags = WMIREG_FLAG_INSTANCE_PDO;
    guid->Pdo = (ULONG_PTR)fdoData->PhysicalDeviceObject;
    ObReferenceObject(fdoData->PhysicalDeviceObject);

    guid = &reginfo->WmiRegGuid[1];
    guid->Guid = OBJECT_GUID(XenStoreSession);
    guid->Flags =0;

    guid = &reginfo->WmiRegGuid[2];
    guid->InstanceCount = 1;
    guid->Guid = OBJECT_GUID(XenStoreWatchEvent);
    guid->Flags = WMIREG_FLAG_INSTANCE_PDO |
                WMIREG_FLAG_EVENT_ONLY_GUID ;
    guid->Pdo = (ULONG_PTR)fdoData->PhysicalDeviceObject;
    ObReferenceObject(fdoData->PhysicalDeviceObject);

    guid = &reginfo->WmiRegGuid[3];
    guid->InstanceCount = 1;
    guid->Guid = OBJECT_GUID(XenStoreUnsuspendedEvent);
    guid->Flags = WMIREG_FLAG_INSTANCE_PDO |
                WMIREG_FLAG_EVENT_ONLY_GUID ;
    guid->Pdo = (ULONG_PTR)fdoData->PhysicalDeviceObject;
    ObReferenceObject(fdoData->PhysicalDeviceObject);


    *byteswritten = RequiredSize;
    return STATUS_SUCCESS;
}

NTSTATUS
WmiRegInfoEx(
    IN PXENIFACE_FDO fdoData,
    IN PIO_STACK_LOCATION stack,
    OUT ULONG_PTR *byteswritten
   )
{

    Trace("%s\n",__FUNCTION__);
    return WmiRegInfo(fdoData, stack, byteswritten);
}

NTSTATUS
WmiProcessMinorFunction(
    IN  PXENIFACE_FDO   Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  Stack;

    Stack = IoGetCurrentIrpStackLocation(Irp);

    if (Stack->Parameters.WMI.ProviderId != (ULONG_PTR)Fdo->Dx->DeviceObject) {
        Trace("ProviderID %p %p",
              Stack->Parameters.WMI.ProviderId,
              Fdo->PhysicalDeviceObject);
        return STATUS_NOT_SUPPORTED;
    } else {
        Trace("ProviderID Match %p %p",
              Stack->Parameters.WMI.ProviderId,
              Fdo->PhysicalDeviceObject);
    }

    switch (Stack->MinorFunction) {
    case IRP_MN_CHANGE_SINGLE_INSTANCE:
        return WmiChangeSingleInstance(Fdo, Stack);
    case IRP_MN_CHANGE_SINGLE_ITEM:
        return WmiChangeSingleItem(Fdo, Stack);
    case IRP_MN_DISABLE_COLLECTION:
        return WmiDisableCollection(Fdo, Stack);
    case IRP_MN_DISABLE_EVENTS:
        return WmiDisableEvents(Fdo, Stack);
    case IRP_MN_ENABLE_COLLECTION:
        return WmiEnableCollection(Fdo, Stack);
    case IRP_MN_ENABLE_EVENTS:
        return WmiEnableEvents(Fdo, Stack);
    case IRP_MN_EXECUTE_METHOD:
        return WmiExecuteMethod(Fdo, Stack,  &Irp->IoStatus.Information);
    case IRP_MN_QUERY_ALL_DATA:
        return WmiQueryAllData(Fdo, Stack, &Irp->IoStatus.Information);
    case IRP_MN_QUERY_SINGLE_INSTANCE:
        return WmiQuerySingleInstance(Fdo, Stack, &Irp->IoStatus.Information);
    case IRP_MN_REGINFO:
        return WmiRegInfo(Fdo, Stack, &Irp->IoStatus.Information);
    case IRP_MN_REGINFO_EX:
        return WmiRegInfoEx(Fdo, Stack, &Irp->IoStatus.Information);
    default:
        return STATUS_NOT_SUPPORTED;
    }
}

PCHAR
WMIMinorFunctionString (
    __in UCHAR MinorFunction
)
/*++

Updated Routine Description:
    WMIMinorFunctionString does not change in this stage of the function driver.
--*/
{
    switch (MinorFunction)
    {
    case IRP_MN_CHANGE_SINGLE_INSTANCE:
        return "IRP_MN_CHANGE_SINGLE_INSTANCE";
    case IRP_MN_CHANGE_SINGLE_ITEM:
        return "IRP_MN_CHANGE_SINGLE_ITEM";
    case IRP_MN_DISABLE_COLLECTION:
        return "IRP_MN_DISABLE_COLLECTION";
    case IRP_MN_DISABLE_EVENTS:
        return "IRP_MN_DISABLE_EVENTS";
    case IRP_MN_ENABLE_COLLECTION:
        return "IRP_MN_ENABLE_COLLECTION";
    case IRP_MN_ENABLE_EVENTS:
        return "IRP_MN_ENABLE_EVENTS";
    case IRP_MN_EXECUTE_METHOD:
        return "IRP_MN_EXECUTE_METHOD";
    case IRP_MN_QUERY_ALL_DATA:
        return "IRP_MN_QUERY_ALL_DATA";
    case IRP_MN_QUERY_SINGLE_INSTANCE:
        return "IRP_MN_QUERY_SINGLE_INSTANCE";
    case IRP_MN_REGINFO:
        return "IRP_MN_REGINFO";
    default:
        return "unknown_syscontrol_irp";
    }
}

NTSTATUS
WmiInitialize(
    IN  PXENIFACE_FDO   Fdo
    )
{
    NTSTATUS            status;

    status = IoWMISuggestInstanceName(Fdo->PhysicalDeviceObject,
                                      NULL,
                                      FALSE,
                                      &Fdo->SuggestedInstanceName);
    if (!NT_SUCCESS(status))
        goto fail1;

    Fdo->Sessions = 0;
    InitializeListHead(&Fdo->SessionHead);
    InitializeMutex(&Fdo->SessionLock);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);
    return status;
}

VOID
WmiTeardown(
    IN  PXENIFACE_FDO   Fdo
    )
{
    ASSERT(Fdo->Sessions == 0);

    RtlZeroMemory(&Fdo->SessionLock, sizeof(FAST_MUTEX));
    RtlZeroMemory(&Fdo->SessionHead, sizeof(LIST_ENTRY));

    RtlFreeUnicodeString(&Fdo->SuggestedInstanceName);
    RtlZeroMemory(&Fdo->SuggestedInstanceName, sizeof(UNICODE_STRING));
}
